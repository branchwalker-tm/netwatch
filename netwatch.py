#!/usr/bin/env python3
"""
netwatch.py — CLI Network Activity Monitor with Threat Detection + Blocking + DNS Sinkhole
Requires: Python 3.7+, scapy, blessed
Install:   pip3 install scapy blessed
Run:       sudo python3 netwatch.py --iface en0
           sudo python3 netwatch.py --iface en0 --no-block     (detect only, no pf changes)
           sudo python3 netwatch.py --iface en0 --no-sinkhole  (disable DNS ad blocking)
           sudo python3 netwatch.py --iface en0 --no-feeds     (offline/heuristics only)
"""

import argparse
import collections
import datetime
import ipaddress
import math
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import warnings

warnings.filterwarnings("ignore")
os.environ["SCAPY_IFACE_DEFAULT_SUPPRESS"] = "1"

try:
    import logging
    logging.getLogger("scapy").setLevel(logging.CRITICAL)
    from scapy.all import (sniff, send, sendp,
                           IP, IPv6, UDP, TCP,
                           DNS, DNSQR, DNSRR, Raw,
                           Ether, conf as scapy_conf)
    scapy_conf.verb     = 0
    scapy_conf.logLevel = 40
except ImportError:
    sys.exit("Missing dependency: pip3 install scapy")

try:
    from blessed import Terminal
except ImportError:
    sys.exit("Missing dependency: pip3 install blessed")

# ── constants ─────────────────────────────────────────────────────────────────
HISTORY_LEN  = 60
TOP_N        = 10
RESOLVE_TTL  = 300
REFRESH_HZ   = 1
SPARK_CHARS  = " ▁▂▃▄▅▆▇█"

URLHAUS_FEED      = "https://urlhaus.abuse.ch/downloads/text/"
EMERGING_FEED     = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
# Steven Black unified hosts — ~76k ad/tracker/malware domains, updated daily
ADBLOCK_HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
FEED_TTL          = 3600      # refresh all feeds every hour
ADBLOCK_TTL       = 86400     # refresh ad blocklist once per day

PF_ANCHOR = "netwatch"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"

def _reason_severity(reason):
    if reason.startswith("🔴"): return SEVERITY_CRITICAL
    if reason.startswith("🟠"): return SEVERITY_HIGH
    if reason.startswith("🟡"): return SEVERITY_MEDIUM
    return SEVERITY_LOW

def _is_blockable(reason):
    return _reason_severity(reason) in (SEVERITY_CRITICAL, SEVERITY_HIGH)

DGA_ENTROPY_THRESHOLD = 3.6
DGA_MIN_LENGTH        = 8
DGA_CONSONANT_RATIO   = 0.72
DNS_TUNNEL_LABEL_LEN  = 40
DNS_TUNNEL_DEPTH      = 5

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".xyz", ".club", ".work",
    ".loan", ".click", ".download",
    ".stream", ".racing", ".win",
}

WHITELIST_SUFFIXES = (
    "apple.com", "icloud.com", "mzstatic.com", "apple-dns.net",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "cloudflare.com", "cloudflare-dns.com",
    "amazon.com", "amazonaws.com",
    "microsoft.com", "windows.com", "live.com", "office.com",
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com",
    "fastly.net", "digicert.com", "letsencrypt.org",
)

PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]
PRIVATE_V6_NETS = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("ff00::/8"),
]

# ── local IP discovery ────────────────────────────────────────────────────────
def _get_local_ips():
    local = set()
    try:
        out = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                if len(parts) >= 2: local.add(parts[1])
            elif line.startswith("inet6 "):
                parts = line.split()
                if len(parts) >= 2: local.add(parts[1].split("%")[0])
    except Exception:
        pass
    return local

LOCAL_IPS = _get_local_ips()

def _is_local(ip_str):
    if ip_str in LOCAL_IPS: return True
    try:
        addr = ipaddress.ip_address(ip_str)
        nets = PRIVATE_V4 if isinstance(addr, ipaddress.IPv4Address) else PRIVATE_V6_NETS
        return any(addr in n for n in nets)
    except ValueError:
        return True

def _is_mine(ip_str):
    return ip_str in LOCAL_IPS

# ── DNS sinkhole state ────────────────────────────────────────────────────────
_sh_lock          = threading.Lock()
_sinkhole_domains: set  = set()        # ad/tracker domains (Steven Black)
_sinkhole_enabled: bool = True         # disabled with --no-sinkhole
_sh_status:        str  = "⏳ loading ad blocklist..."
_sh_total:         int  = 0            # total domains loaded
_sh_sunk_count:    int  = 0            # DNS queries sinkhol'd this session
_sh_sunk_recent:   collections.deque = collections.deque(maxlen=8)  # last N sunk domains

def _load_adblock_hosts():
    """Download Steven Black unified hosts file and extract blocked domains."""
    global _sh_status, _sh_total
    domains = set()
    try:
        req = urllib.request.Request(
            ADBLOCK_HOSTS_URL,
            headers={"User-Agent": "netwatch/1.0 (dns-sinkhole)"}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            for line in r.read().decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: "0.0.0.0 ad.example.com"
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    domain = parts[1].lower()
                    # Skip localhost entries
                    if domain not in ("localhost", "localhost.localdomain",
                                      "local", "broadcasthost", "0.0.0.0"):
                        domains.add(domain)
        with _sh_lock:
            _sinkhole_domains.update(domains)
            _sh_total   = len(_sinkhole_domains)
            _sh_status  = f"✓ {_sh_total:,} ad domains loaded"
    except Exception as e:
        with _sh_lock:
            _sh_status = f"⚠ blocklist load failed: {e}"

def _adblock_loop():
    while True:
        _load_adblock_hosts()
        time.sleep(ADBLOCK_TTL)

def _is_ad_domain(hostname: str) -> bool:
    """Check if hostname or any parent domain is in the ad blocklist."""
    if not _sinkhole_enabled:
        return False
    h = hostname.lower().rstrip(".")
    with _sh_lock:
        if h in _sinkhole_domains:
            return True
        # also check registrable domain (e.g. "sub.ads.com" → "ads.com")
        parts = h.split(".")
        if len(parts) >= 2:
            reg = ".".join(parts[-2:])
            return reg in _sinkhole_domains
    return False

def _sinkhole_dns(pkt):
    """
    Forge a DNS NXDOMAIN / 0.0.0.0 response and send it back to the requester.
    This makes the ad/tracker domain appear to not exist, so the browser
    never makes an HTTP connection to it.
    """
    global _sh_sunk_count
    try:
        if pkt.haslayer(IP):
            ip_layer = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        elif pkt.haslayer(IPv6):
            ip_layer = IPv6(dst=pkt[IPv6].src, src=pkt[IPv6].dst)
        else:
            return

        qname = pkt[DNSQR].qname
        qtype = pkt[DNSQR].qtype

        # Build forged response:
        # QR=1 (response), AA=1 (authoritative), RCODE=0 (no error)
        # Answer with 0.0.0.0 for A queries, :: for AAAA, NXDOMAIN for others
        if qtype == 1:   # A record → answer with 0.0.0.0
            dns_resp = DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=pkt[DNS].rd, ra=1,
                qdcount=1, ancount=1,
                qd=DNSQR(qname=qname, qtype=qtype),
                an=DNSRR(rrname=qname, type="A", ttl=60, rdata="0.0.0.0")
            )
        elif qtype == 28:  # AAAA record → answer with ::
            dns_resp = DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=pkt[DNS].rd, ra=1,
                qdcount=1, ancount=1,
                qd=DNSQR(qname=qname, qtype=qtype),
                an=DNSRR(rrname=qname, type="AAAA", ttl=60, rdata="::")
            )
        else:             # anything else → NXDOMAIN
            dns_resp = DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=pkt[DNS].rd, ra=1, rcode=3,
                qdcount=1, ancount=0,
                qd=DNSQR(qname=qname, qtype=qtype),
            )

        udp_layer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        resp_pkt  = ip_layer / udp_layer / dns_resp
        send(resp_pkt, verbose=False, iface=_sniff_iface)

        with _sh_lock:
            _sh_sunk_count += 1
            domain = qname.decode("utf-8", errors="replace").rstrip(".")
            _sh_sunk_recent.appendleft(
                (datetime.datetime.now().strftime("%H:%M:%S"), domain)
            )
    except Exception:
        pass

# ── pfctl blocking ────────────────────────────────────────────────────────────
_pf_lock       = threading.Lock()
_blocked_ips   = {}
_block_enabled = True

def _pf_init():
    try:
        subprocess.run(["pfctl", "-a", PF_ANCHOR, "-F", "rules"], capture_output=True)
    except Exception:
        pass

def _pf_flush():
    try:
        subprocess.run(["pfctl", "-a", PF_ANCHOR, "-F", "rules"], capture_output=True)
    except Exception:
        pass

def _pf_rebuild():
    with _pf_lock:
        ips = list(_blocked_ips.keys())
    if not ips:
        _pf_flush(); return
    rules = []
    for ip in ips:
        try: ipaddress.ip_address(ip)
        except ValueError: continue
        rules.append(f"block drop quick from {ip} to any")
        rules.append(f"block drop quick from any to {ip}")
    try:
        subprocess.run(["pfctl", "-a", PF_ANCHOR, "-f", "-"],
                       input=("\n".join(rules) + "\n").encode(), capture_output=True)
        subprocess.run(["pfctl", "-e"], capture_output=True)
    except Exception:
        pass

def _block_ip(ip, reason):
    if not _block_enabled: return
    with _pf_lock:
        if ip in _blocked_ips: return
        _blocked_ips[ip] = (reason, datetime.datetime.now().strftime("%H:%M:%S"))
    _pf_rebuild()

def _resolve_and_block(hostname, reason):
    if not _block_enabled: return
    try:
        for r in socket.getaddrinfo(hostname, None):
            ip = r[4][0]
            if not _is_local(ip):
                _block_ip(ip, f"hostname:{hostname} — {reason}")
    except Exception:
        pass

# ── shared capture state ──────────────────────────────────────────────────────
_lock          = threading.Lock()
_sni_hosts     = collections.Counter()
_dns_hosts     = collections.Counter()
_inbound_ips   = collections.Counter()
_outbound_ips  = collections.Counter()
_bytes_per_sec = collections.deque([0] * HISTORY_LEN, maxlen=HISTORY_LEN)
_pkts_per_sec  = collections.deque([0] * HISTORY_LEN, maxlen=HISTORY_LEN)
_cur_bytes     = 0
_cur_pkts      = 0
_total_bytes   = 0
_total_pkts    = 0
_start_time    = time.time()
_sniff_iface   = None   # set in main(), used by sinkhole sender

# ── reverse DNS ───────────────────────────────────────────────────────────────
_rdns_cache   = {}
_rdns_lock    = threading.Lock()
_rdns_pool    = threading.Semaphore(8)
_rdns_running = set()

def _rdns_lookup(ip):
    with _rdns_pool:
        try: name = socket.gethostbyaddr(ip)[0]
        except Exception: name = ip
        with _rdns_lock:
            _rdns_cache[ip] = (name, time.time() + RESOLVE_TTL)
            _rdns_running.discard(ip)

def resolve(ip):
    with _rdns_lock:
        entry = _rdns_cache.get(ip)
        if entry and time.time() < entry[1]: return entry[0]
        if ip not in _rdns_running:
            _rdns_running.add(ip)
            threading.Thread(target=_rdns_lookup, args=(ip,), daemon=True).start()
    return ip

# ── threat state ──────────────────────────────────────────────────────────────
_threat_lock  = threading.Lock()
_mal_domains  = set()
_mal_ips      = set()
_feed_status  = "⏳ loading feeds..."
_threats      = []
_threats_seen = set()
_seen_hosts   = set()
_seen_ips     = set()
_check_queue  = collections.deque()
_check_lock   = threading.Lock()

# ── threat feeds ──────────────────────────────────────────────────────────────
def _load_feeds():
    global _feed_status
    domains, ips, errs = set(), set(), []
    try:
        req = urllib.request.Request(URLHAUS_FEED, headers={"User-Agent": "netwatch/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            for line in r.read().decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                m = re.search(r"https?://([^/:\s]+)", line)
                if m: domains.add(m.group(1).lower())
    except Exception as e: errs.append(f"URLhaus({e})")
    try:
        req = urllib.request.Request(EMERGING_FEED, headers={"User-Agent": "netwatch/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            for line in r.read().decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                try: ipaddress.ip_address(line); ips.add(line)
                except ValueError: pass
    except Exception as e: errs.append(f"ET({e})")
    with _threat_lock:
        _mal_domains.update(domains); _mal_ips.update(ips)
        _feed_status = ("⚠ partial: " + ", ".join(errs)) if errs else \
                       f"✓ {len(_mal_domains):,} domains · {len(_mal_ips):,} IPs"

def _feed_loop():
    while True:
        _load_feeds()
        time.sleep(FEED_TTL)

# ── heuristics ────────────────────────────────────────────────────────────────
def _entropy(s):
    if not s: return 0.0
    freq = collections.Counter(s); l = len(s)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())

def _consonant_ratio(s):
    cons = set("bcdfghjklmnpqrstvwxyz")
    lets = [c for c in s.lower() if c.isalpha()]
    return sum(1 for c in lets if c in cons)/len(lets) if lets else 0.0

def _whitelisted(h):
    h = h.lower().rstrip(".")
    return any(h == w or h.endswith("." + w) for w in WHITELIST_SUFFIXES)

def _is_legitimate_arpa(h):
    if h.endswith(".in-addr.arpa"):
        parts = h[:-len(".in-addr.arpa")].split(".")
        return len(parts)==4 and all(p.isdigit() and 0<=int(p)<=255 for p in parts)
    if h.endswith(".ip6.arpa"):
        parts = h[:-len(".ip6.arpa")].split(".")
        return len(parts)==32 and all(len(p)==1 and p in "0123456789abcdef" for p in parts)
    return False

def _check_host(hostname):
    if _whitelisted(hostname): return []
    h = hostname.lower().rstrip(".")
    if h.endswith(".arpa"):
        return [] if _is_legitimate_arpa(h) else \
               ["🔴 suspicious .arpa abuse (non-PTR format — possible phishing infrastructure)"]
    parts = h.split(".")
    tld   = "." + parts[-1] if parts else ""
    labels = parts[:-2] if len(parts) > 2 else []
    reasons = []
    with _threat_lock:
        reg = ".".join(parts[-2:]) if len(parts)>=2 else h
        if h in _mal_domains or reg in _mal_domains:
            reasons.append("🔴 threat feed match")
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"🟠 suspicious TLD ({tld})")
    if any(len(lb) >= DNS_TUNNEL_LABEL_LEN for lb in labels):
        reasons.append("🟠 possible DNS tunnel (long label)")
    if len(parts) >= DNS_TUNNEL_DEPTH:
        reasons.append(f"🟡 deep subdomain ({len(parts)} levels)")
    for lb in labels:
        if len(lb) >= DGA_MIN_LENGTH:
            e = _entropy(lb); c = _consonant_ratio(lb)
            if e >= DGA_ENTROPY_THRESHOLD and c >= DGA_CONSONANT_RATIO:
                reasons.append(f"🟠 DGA? entropy={e:.1f} ({lb[:24]})"); break
    return reasons

def _check_ip(ip):
    with _threat_lock:
        return ["🔴 threat feed match"] if ip in _mal_ips else []

def _record_threat(indicator, reasons, blocked=False):
    key = indicator + reasons[0]
    if key in _threats_seen:
        for i,(ts,ind,rsn,sev,blk) in enumerate(_threats):
            if ind==indicator and rsn==reasons[0] and not blk and blocked:
                _threats[i] = (ts,ind,rsn,sev,True)
        return
    _threats_seen.add(key)
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    _threats.append((ts, indicator, reasons[0], _reason_severity(reasons[0]), blocked))
    if len(_threats) > 50: _threats.pop(0)

def _check_worker():
    while True:
        time.sleep(0.05)
        try:
            with _check_lock:
                if not _check_queue: continue
                kind, value = _check_queue.popleft()
            reasons = _check_host(value) if kind=="host" else _check_ip(value)
            if not reasons: continue
            blocked = False
            if _is_blockable(reasons[0]):
                if kind == "ip":
                    _block_ip(value, reasons[0]); blocked = True
                else:
                    threading.Thread(target=_resolve_and_block,
                                     args=(value, reasons[0]), daemon=True).start()
                    blocked = True
            with _threat_lock:
                _record_threat(value, reasons, blocked)
        except Exception:
            pass

# ── TLS SNI parser ────────────────────────────────────────────────────────────
def _extract_sni(payload):
    try:
        if len(payload)<9 or payload[0]!=0x16 or payload[5]!=0x01: return None
        pos=43
        if pos>=len(payload): return None
        sid=payload[pos]; pos+=1+sid
        if pos+2>len(payload): return None
        cs=int.from_bytes(payload[pos:pos+2],"big"); pos+=2+cs
        if pos+1>len(payload): return None
        cm=payload[pos]; pos+=1+cm
        if pos+2>len(payload): return None
        ext_end=pos+2+int.from_bytes(payload[pos:pos+2],"big"); pos+=2
        while pos+4<=ext_end and pos+4<=len(payload):
            et=int.from_bytes(payload[pos:pos+2],"big")
            el=int.from_bytes(payload[pos+2:pos+4],"big")
            ed=payload[pos+4:pos+4+el]; pos+=4+el
            if et==0x0000 and len(ed)>=5:
                nl=int.from_bytes(ed[3:5],"big")
                return ed[5:5+nl].decode("utf-8",errors="replace")
    except Exception:
        pass
    return None

# ── packet handler ────────────────────────────────────────────────────────────
def _enqueue(kind, value):
    with _check_lock:
        _check_queue.append((kind, value))

def packet_handler(pkt):
    global _cur_bytes, _cur_pkts, _total_bytes, _total_pkts
    try:
        plen = len(pkt)
        with _lock:
            _cur_bytes+=plen; _cur_pkts+=1
            _total_bytes+=plen; _total_pkts+=1

        if   pkt.haslayer(IP):   src, dst = pkt[IP].src,   pkt[IP].dst
        elif pkt.haslayer(IPv6): src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else: return

        # ── DNS sinkhole ──────────────────────────────────────────────────────
        # Intercept outbound UDP port-53 queries from this machine before they
        # leave the network. If the queried domain is in the ad blocklist,
        # forge a 0.0.0.0 response immediately so the browser never connects.
        if (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and
                pkt.haslayer(UDP) and pkt[UDP].dport == 53 and
                _is_mine(src) and pkt[DNS].qr == 0):   # QR=0 → query (not response)
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                if qname:
                    with _lock:
                        _dns_hosts[qname] += 1
                    if _is_ad_domain(qname):
                        # sinkhole in a thread so we don't block the capture loop
                        threading.Thread(target=_sinkhole_dns, args=(pkt,),
                                         daemon=True).start()
                        return   # drop — don't record as normal traffic
                    if qname not in _seen_hosts:
                        _seen_hosts.add(qname); _enqueue("host", qname)
            except Exception:
                pass

        # ── TLS SNI ───────────────────────────────────────────────────────────
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and _is_mine(src):
            if pkt[TCP].dport in (443, 853, 8443):
                sni = _extract_sni(bytes(pkt[Raw]))
                if sni:
                    with _lock: _sni_hosts[sni] += 1
                    if sni not in _seen_hosts:
                        _seen_hosts.add(sni); _enqueue("host", sni)

        # ── inbound ───────────────────────────────────────────────────────────
        if not _is_local(src) and _is_mine(dst):
            with _lock: _inbound_ips[src] += 1
            if src not in _seen_ips:
                _seen_ips.add(src); _enqueue("ip", src)

        # ── outbound ──────────────────────────────────────────────────────────
        if _is_mine(src) and not _is_local(dst):
            with _lock: _outbound_ips[dst] += 1
            if dst not in _seen_ips:
                _seen_ips.add(dst); _enqueue("ip", dst)

    except Exception:
        pass

# ── ticker ────────────────────────────────────────────────────────────────────
def ticker():
    global _cur_bytes, _cur_pkts
    while True:
        time.sleep(1)
        with _lock:
            _bytes_per_sec.append(_cur_bytes); _pkts_per_sec.append(_cur_pkts)
            _cur_bytes=0; _cur_pkts=0

# ── render helpers ────────────────────────────────────────────────────────────
def sparkline(data, width=28):
    vals=list(data)[-width:]; mx=max(vals) if max(vals)>0 else 1
    return "".join(SPARK_CHARS[min(int(v/mx*(len(SPARK_CHARS)-1)),len(SPARK_CHARS)-1)] for v in vals)

def human_bytes(n):
    for u in ("B","KB","MB","GB"):
        if n<1024: return f"{n:.1f} {u}"
        n/=1024
    return f"{n:.1f} TB"

def bar(count, max_count, width=10):
    f=int(width*count/max_count) if max_count else 0
    return "█"*f + "░"*(width-f)

# ── draw ──────────────────────────────────────────────────────────────────────
def draw(term, iface):
    with _lock:
        sni_snap=(_sni_hosts+_dns_hosts).most_common(TOP_N)
        in_snap=_inbound_ips.most_common(TOP_N)
        out_snap=_outbound_ips.most_common(TOP_N)
        bps_snap=list(_bytes_per_sec); pps_snap=list(_pkts_per_sec)
        tot_b=_total_bytes; tot_p=_total_pkts

    with _threat_lock:
        thr_snap=list(_threats); feed_status=_feed_status

    with _pf_lock:
        blocked_snap=dict(_blocked_ips)

    with _sh_lock:
        sh_count=_sh_sunk_count; sh_recent=list(_sh_sunk_recent)
        sh_status=_sh_status; sh_enabled=_sinkhole_enabled

    elapsed=int(time.time()-_start_time)
    now_str=datetime.datetime.now().strftime("%H:%M:%S")
    W=term.width; lines=[]; ln=lines.append

    # ── header ────────────────────────────────────────────────────────────────
    tags = []
    if not _block_enabled:   tags.append("no-block")
    if not sh_enabled:       tags.append("no-sinkhole")
    tag_str = f"  [{', '.join(tags)}]" if tags else ""
    title = f" 🔍  netwatch  │  iface: {iface}  │  {now_str}  │  uptime: {elapsed}s{tag_str} "
    ln(term.bold + term.white + term.on_blue + title.ljust(W) + term.normal)

    # ── throughput ────────────────────────────────────────────────────────────
    bps_now=bps_snap[-1] if bps_snap else 0; pps_now=pps_snap[-1] if pps_snap else 0
    ln(term.bold + " Throughput (last 60 s)" + term.normal)
    ln(f"  Bytes/s [{term.cyan+sparkline(collections.deque(bps_snap))+term.normal}] "
       f"{term.cyan+human_bytes(bps_now)+term.normal}/s  total: {human_bytes(tot_b)}")
    ln(f"  Pkts /s [{term.green+sparkline(collections.deque(pps_snap))+term.normal}] "
       f"{term.green+str(pps_now)+term.normal} pkt/s  total: {tot_p:,} pkts")
    ln("")

    # ── traffic columns ───────────────────────────────────────────────────────
    col_w=max((W-6)//3,28)
    def hdr(lbl): return term.bold+term.yellow+f" {lbl} ".center(col_w,"─")+term.normal

    ln(hdr("🌐 Hostnames (TLS SNI + DNS)")+"  "+hdr("📤 Outbound IPs")+"  "+hdr("📥 Inbound IPs"))

    sni_max=sni_snap[0][1] if sni_snap else 1
    out_max=out_snap[0][1] if out_snap else 1
    in_max=in_snap[0][1]   if in_snap  else 1

    if not sni_snap and not out_snap and not in_snap:
        ln(term.dim+"  (waiting for traffic — open a new browser tab...)"+term.normal)
    else:
        for i in range(min(max(len(sni_snap),len(out_snap),len(in_snap)),TOP_N)):
            if i<len(sni_snap):
                h,c=sni_snap[i]; disp=h[:col_w-14].ljust(col_w-14)
                c1=f" {disp} {term.cyan+bar(c,sni_max)+term.normal} {c:>4}"
            else: c1=" "*col_w
            if i<len(out_snap):
                ip,c=out_snap[i]; lbl=resolve(ip)[:col_w-14].ljust(col_w-14)
                tag=term.bold+term.red+"⛔"+term.normal if ip in blocked_snap else "  "
                c2=f"{tag}{lbl} {term.yellow+bar(c,out_max)+term.normal} {c:>4}"
            else: c2=" "*col_w
            if i<len(in_snap):
                ip,c=in_snap[i]; lbl=resolve(ip)[:col_w-14].ljust(col_w-14)
                tag=term.bold+term.red+"⛔"+term.normal if ip in blocked_snap else "  "
                c3=f"{tag}{lbl} {term.red+bar(c,in_max)+term.normal} {c:>4}"
            else: c3=" "*col_w
            ln(c1[:col_w]+"  "+c2[:col_w]+"  "+c3[:col_w])

    ln("")

    # ── DNS sinkhole panel ────────────────────────────────────────────────────
    if sh_enabled:
        sh_color = term.on_magenta if sh_count > 0 else term.on_blue
        sh_hdr = (f" 🕳  DNS SINKHOLE  │  {sh_count:,} ads blocked this session"
                  f"  │  {sh_status} ")
        ln(term.bold + term.white + sh_color + sh_hdr.ljust(W) + term.normal)
        if sh_recent:
            # sparkline-style summary row
            ln(term.dim + "  Recently sinkhol'd:" + term.normal)
            for ts, domain in sh_recent[:5]:
                d = domain[:W-20].ljust(W-20)
                ln(f"  {term.magenta+ts+term.normal}  {term.dim+d+term.normal}  → 0.0.0.0")
        else:
            ln(term.dim + "  No ads intercepted yet — browse to a news site to test." + term.normal)
        ln("")

    # ── threat panel ──────────────────────────────────────────────────────────
    n_blocked=len(blocked_snap); n_threats=len(thr_snap)
    if thr_snap:
        hdr_txt=(f" 🚨  {n_threats} THREAT(S)  │  🚫 {n_blocked} IP(S) BLOCKED  │  feeds: {feed_status} ")
        ln(term.bold+term.white+term.on_red+hdr_txt.ljust(W)+term.normal)
        ln(term.dim+"  🔴 CRITICAL/🟠 HIGH → auto-blocked via pf  │  🟡 MEDIUM → alert only  │  ⛔ = pf blocked"+term.normal)
        ln("")
        blocked_t=[(ts,i,r,s,b) for ts,i,r,s,b in thr_snap if b]
        warned_t =[(ts,i,r,s,b) for ts,i,r,s,b in thr_snap if not b]
        if blocked_t:
            ln(term.bold+term.red+"  ⛔ BLOCKED"+term.normal)
            for ts,ind,rsn,sev,blk in reversed(blocked_t[-5:]):
                ln(f"    {term.bold+term.red+ts+term.normal}  {term.bold+term.red+ind[:W-46].ljust(W-46)+term.normal}  {rsn}")
        if warned_t:
            ln(term.bold+term.yellow+"  ⚠  WARNINGS"+term.normal)
            for ts,ind,rsn,sev,blk in reversed(warned_t[-5:]):
                ln(f"    {term.bold+term.yellow+ts+term.normal}  {term.yellow+ind[:W-46].ljust(W-46)+term.normal}  {rsn}")
    else:
        hdr_txt=f" ✅  No Threats  │  feeds: {feed_status} "
        ln(term.bold+term.white+term.on_green+hdr_txt.ljust(W)+term.normal)
        ln(term.dim+"  All observed hostnames and IPs look clean."+term.normal)

    ln("")
    ln(term.dim+f"  [Ctrl-C to quit — pf rules cleared on exit]  "
       f"my IPs: {', '.join(sorted(LOCAL_IPS)[:3])}"+term.normal)

    sys.stdout.write(term.home+term.clear+"\n".join(lines))
    sys.stdout.flush()

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    global _block_enabled, _sinkhole_enabled, _feed_status, _sh_status, _sniff_iface

    parser = argparse.ArgumentParser(description="netwatch — network monitor + threat blocking + DNS sinkhole")
    parser.add_argument("--iface",        "-i", default=None)
    parser.add_argument("--filter",       "-f", default="")
    parser.add_argument("--no-block",     action="store_true", help="Disable pf threat blocking")
    parser.add_argument("--no-sinkhole",  action="store_true", help="Disable DNS ad sinkhole")
    parser.add_argument("--no-feeds",     action="store_true", help="Skip all feed downloads")
    args = parser.parse_args()

    _block_enabled    = not args.no_block
    _sinkhole_enabled = not args.no_sinkhole
    _sniff_iface      = args.iface

    iface = args.iface
    term  = Terminal()

    if os.geteuid() != 0:
        print("⚠  netwatch requires sudo (raw packet capture + pf + DNS injection).")
        sys.exit(1)

    if _block_enabled:
        _pf_init()

    devnull = open(os.devnull, "w")

    threading.Thread(target=ticker,        daemon=True).start()
    threading.Thread(target=_check_worker, daemon=True).start()

    if not args.no_feeds:
        threading.Thread(target=_feed_loop,    daemon=True).start()
        if _sinkhole_enabled:
            threading.Thread(target=_adblock_loop, daemon=True).start()
    else:
        _feed_status = "disabled (--no-feeds)"
        _sh_status   = "disabled (--no-feeds)"

    def _sniff():
        sys.stderr = devnull
        sniff(iface=iface, prn=packet_handler, store=False,
              filter=args.filter or None)

    threading.Thread(target=_sniff, daemon=True).start()
    time.sleep(0.3)

    try:
        with term.fullscreen(), term.hidden_cursor():
            while True:
                draw(term, iface or "auto")
                time.sleep(1/REFRESH_HZ)
    except KeyboardInterrupt:
        pass

    if _block_enabled:
        _pf_flush()
        print(term.normal + f"\nCleared {len(_blocked_ips)} pf block rule(s).")

    with _sh_lock:
        final_count = _sh_sunk_count
    print(f"DNS sinkhole intercepted {final_count:,} ad queries this session.")
    print("netwatch stopped.")

if __name__ == "__main__":
    main()
