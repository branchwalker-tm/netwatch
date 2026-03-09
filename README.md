# 🔍 netwatch

A real-time CLI network monitor for macOS with threat detection, automatic IP blocking, and DNS ad sinkholing — all in one terminal window.

![Python](https://img.shields.io/badge/python-3.7%2B-blue) ![Platform](https://img.shields.io/badge/platform-macOS-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green) ![Requires Root](https://img.shields.io/badge/requires-sudo-red)

```
 🔍  netwatch  │  iface: en0  │  14:32:07  │  uptime: 183s
 Throughput (last 60 s)
  Bytes/s [▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▂▃▅▆▇▆▅▄▃▂▁▂▃] 248.3 KB/s  total: 42.1 MB
  Pkts /s [▁▁▂▂▃▄▅▆▅▄▃▂▂▁▁▂▃▄▅▆▅▄▃▂▁▁▂▃] 312 pkt/s   total: 58,204 pkts

 ──── 🌐 Hostnames (TLS SNI + DNS) ────   ──── 📤 Outbound IPs ────   ──── 📥 Inbound IPs ────
  www.google.com          ████████   42    162.159.135.234  ████   18    35.244.165.252  ██   9
  api.github.com          ██████     31    18.97.36.52      ███    14    162.159.136.234 ██   7
  cdn.jsdelivr.net        █████      24    45.60.75.132     ██      9

 🕳  DNS SINKHOLE  │  1,842 ads blocked this session  │  ✓ 76,455 ad domains loaded
  Recently sinkhol'd:
  14:32:01  doubleclick.net                              → 0.0.0.0
  14:31:58  googleadservices.com                         → 0.0.0.0
  14:31:44  ads.pubmatic.com                             → 0.0.0.0

 ✅  No Threats Detected  │  feeds: ✓ 3,241 domains · 18,904 IPs
  All observed hostnames and IPs look clean.
```

---

## Features

- **Live traffic monitoring** — real-time sparkline graphs of bytes/sec and packets/sec over the last 60 seconds, with running totals
- **Hostname visibility** — extracts hostnames from both plain DNS queries and TLS SNI (Server Name Indication) in HTTPS ClientHellos, so you see what your Mac is actually connecting to even over encrypted connections
- **IPv4 + IPv6** — full support for both protocol stacks
- **DNS ad sinkhole** — intercepts outbound DNS queries and forges `0.0.0.0` responses for ~76,000 known ad/tracker domains using the [Steven Black unified hosts list](https://github.com/StevenBlack/hosts), refreshed daily. No browser extension needed — works system-wide for every app on your machine
- **Threat detection** with multiple layers:
  - Live feed matching against [URLhaus](https://urlhaus.abuse.ch/) malware domains and [Emerging Threats](https://rules.emergingthreats.net/) compromised IPs
  - DGA (Domain Generation Algorithm) detection via Shannon entropy scoring — catches malware C2 beaconing
  - DNS tunneling detection (suspiciously long labels, excessive subdomain depth)
  - Suspicious TLD flagging (`.tk`, `.ml`, `.xyz`, `.loan`, etc.)
  - Smart `.arpa` abuse detection — passes legitimate reverse DNS PTR lookups, but flags non-PTR `.arpa` A records used in phishing campaigns
- **Automatic IP blocking** — High and Critical severity threats are blocked via macOS `pfctl` in a dedicated `netwatch` anchor, leaving your existing firewall rules completely untouched. All rules flush on clean exit
- **Reverse DNS resolution** — IP addresses resolve to hostnames asynchronously in the background
- **⛔ visual indicators** — blocked IPs are tagged inline in the traffic columns

---

## Requirements

| Requirement | Notes |
|---|---|
| macOS | Uses `pfctl` and `ifconfig` — Linux not currently supported |
| Python 3.7+ | Tested on Python 3.11–3.14 |
| `sudo` | Required for raw packet capture (`/dev/bpf*`), DNS response injection, and `pfctl` |
| `scapy` | Packet capture and DNS forgery |
| `blessed` | Terminal UI rendering |

---

## Installation

**1. Install Python dependencies**

```bash
pip3 install scapy blessed
```

If you get a permissions error, try:

```bash
pip3 install scapy blessed --user
```

Or if you use Homebrew Python:

```bash
brew install python
pip3 install scapy blessed
```

**2. Download netwatch**

```bash
curl -O https://raw.githubusercontent.com/branchwalker-tm/netwatch/main/netwatch.py
```

Or clone the repo:

```bash
git clone https://github.com/branchwalker-tm/netwatch.git
cd netwatch
```

**3. Find your network interface**

```bash
# Find the interface your traffic actually uses
route get google.com | grep interface

# Or list all interfaces
networksetup -listallhardwareports
```

Common macOS interface names:

| Interface | Typical use |
|---|---|
| `en0` | Wi-Fi (most MacBooks) |
| `en1` | Ethernet or second adapter |
| `utun0`–`utun3` | VPN tunnel |

---

## Usage

**Full monitoring — all features enabled**

```bash
sudo python3 netwatch.py --iface en0
```

**Specify a different interface**

```bash
sudo python3 netwatch.py --iface en1
sudo python3 netwatch.py --iface utun2   # VPN
```

**Disable ad sinkholing (monitor only, no DNS interception)**

```bash
sudo python3 netwatch.py --iface en0 --no-sinkhole
```

**Disable threat blocking (detect and alert, no pfctl changes)**

```bash
sudo python3 netwatch.py --iface en0 --no-block
```

**Offline mode (heuristics only, no feed downloads)**

```bash
sudo python3 netwatch.py --iface en0 --no-feeds
```

**Filter to specific traffic using BPF syntax**

```bash
sudo python3 netwatch.py --iface en0 --filter "tcp port 443"
sudo python3 netwatch.py --iface en0 --filter "udp port 53"
```

**All flags**

```
usage: netwatch.py [-h] [--iface IFACE] [--filter FILTER]
                   [--no-block] [--no-sinkhole] [--no-feeds]

options:
  -h, --help       show this help message and exit
  --iface, -i      Network interface to sniff (e.g. en0)
  --filter, -f     BPF filter string (e.g. 'tcp port 443')
  --no-block       Detect threats but make no pfctl changes
  --no-sinkhole    Disable DNS ad blocking
  --no-feeds       Skip all threat/ad feed downloads (offline mode)
```

Press **Ctrl-C** to quit. All `pfctl` block rules are automatically flushed on exit.

---

## How it works

### Hostname extraction

Modern macOS routes DNS through `mDNSResponder` using DNS-over-HTTPS, so there are few plaintext UDP port 53 packets to sniff. netwatch instead reads **TLS SNI** (Server Name Indication) — the destination hostname that every browser includes in plaintext in the HTTPS `ClientHello` handshake, visible on the wire without any decryption. Plain UDP DNS queries are also captured when present.

### DNS sinkhole

When your Mac sends a DNS query for an ad/tracker domain, netwatch intercepts the outgoing packet with scapy and immediately sends a forged DNS response back with `0.0.0.0` as the answer (or `::` for IPv6, or NXDOMAIN for non-A/AAAA queries). Your browser receives this forged response before the real DNS server can reply and never makes an HTTP connection to the ad server. The blocklist is sourced from the [Steven Black unified hosts file](https://github.com/StevenBlack/hosts) and refreshes every 24 hours.

### Threat detection severity levels

| Indicator | Severity | Action |
|---|---|---|
| 🔴 Threat feed match (URLhaus / Emerging Threats) | CRITICAL | Auto-blocked via pf |
| 🔴 Suspicious `.arpa` abuse (non-PTR A record) | CRITICAL | Auto-blocked via pf |
| 🟠 DGA domain (high entropy label, looks machine-generated) | HIGH | Auto-blocked via pf |
| 🟠 Suspicious TLD (`.tk`, `.xyz`, `.loan`, etc.) | HIGH | Auto-blocked via pf |
| 🟠 DNS tunneling signal (long label / encoded data) | HIGH | Auto-blocked via pf |
| 🟡 Deep subdomain (5+ levels) | MEDIUM | Alert only |

### pfctl integration

Blocked IPs are written into a dedicated `netwatch` pf anchor — completely isolated from any firewall rules you already have. Rules are applied atomically. On exit, the anchor is flushed so nothing remains blocked after netwatch stops.

To inspect active block rules while netwatch is running:

```bash
sudo pfctl -a netwatch -s rules
```

---

## Troubleshooting

**No data appears / columns stay empty**

First confirm your interface is correct:

```bash
route get google.com | grep interface
```

Then verify scapy can capture on it:

```bash
sudo python3 -c "
from scapy.all import sniff, IP, IPv6
def show(p):
    src = p[IP].src if p.haslayer(IP) else str(p[IPv6].src)
    print(src)
sniff(iface='en0', prn=show, count=5, timeout=10)
"
```

**Permission denied on /dev/bpf**

```bash
sudo chmod o+r /dev/bpf*
```

To make this persist across reboots, save the following as `/Library/LaunchDaemons/fix-bpf.plist` and load it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>fix-bpf</string>
  <key>ProgramArguments</key>
  <array>
    <string>chmod</string><string>o+r</string>
    <string>/dev/bpf0</string><string>/dev/bpf1</string><string>/dev/bpf2</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
```

```bash
sudo launchctl load /Library/LaunchDaemons/fix-bpf.plist
```

**Sinkhole not intercepting ads**

The sinkhole works for plain UDP port 53 DNS queries. If your browser uses its own built-in DNS-over-HTTPS (DoH), it bypasses port 53 entirely. To disable DoH:

- **Chrome**: Settings → Privacy and Security → Use secure DNS → turn off
- **Firefox**: Settings → Network Settings → DNS over HTTPS → turn off
- **Safari**: uses the system resolver by default — no change needed

**Terminal rendering issues**

Run in Terminal.app or iTerm2. Avoid VS Code's embedded terminal or bare `ssh` sessions without a proper `$TERM` set. If colors look wrong, try:

```bash
export TERM=xterm-256color
sudo python3 netwatch.py --iface en0
```

---

## Threat feeds

| Feed | Provider | Content | Refresh |
|---|---|---|---|
| URLhaus | [abuse.ch](https://urlhaus.abuse.ch/) | Active malware distribution domains | Hourly |
| Emerging Threats | [emergingthreats.net](https://rules.emergingthreats.net/) | Compromised and malicious IPs | Hourly |
| Steven Black hosts | [github.com/StevenBlack](https://github.com/StevenBlack/hosts) | Ad, tracker, and malware domains | Every 24 hours |

All feeds are free and require no API key or account.

---

## Privacy

netwatch processes all traffic locally on your machine. No packet contents, hostnames, or IP addresses are transmitted anywhere. The only outbound connections netwatch makes are the periodic feed downloads listed above.

---

## License

MIT
