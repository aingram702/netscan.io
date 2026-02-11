# NetScanner Pro - Home Assistant Add-on

## Overview

NetScanner Pro is a real nmap-powered network scanner that runs as a Home Assistant add-on. It appears in your HA sidebar for quick access to network scanning with a full web UI.

## Features

- **9 scan types**: Ping, Quick, Full, Stealth, Service, OS, UDP, Vulnerability, Aggressive
- **Proxychains**: Route scans through SOCKS4/5 or HTTP proxy chains
- **Real-time results**: NDJSON streaming shows results as each host is scanned
- **5 visualizations**: Network topology, port distribution, services, OS, vulnerabilities
- **Export**: JSON, CSV (injection-protected), and PDF reports with charts
- **Proxy file import**: Load proxy lists from `.txt` files

## Installation

1. Navigate to **Settings > Add-ons > Add-on Store**
2. Click the three-dot menu (top right) > **Repositories**
3. Add this repository URL: `https://github.com/aingram702/netscan.net`
4. Find **NetScanner Pro** in the store and click **Install**
5. After install, click **Start**
6. The scanner appears in your sidebar as **NetScanner**

### Local Installation (alternative)

```bash
cd /addons
git clone https://github.com/aingram702/netscan.net.git netscan
```

Then go to **Settings > Add-ons > Add-on Store**, click the refresh button, and NetScanner Pro will appear under **Local add-ons**.

## Usage

Click **NetScanner** in the sidebar to open the scanner. Enter a target IP, CIDR range, or hostname, select a scan type, and click **Start Scan**.

### Scan Types

| Type | Description | Notes |
|------|-------------|-------|
| Ping | Host discovery only | Fastest |
| Quick | Top 100 ports | Good default |
| Full | All 65,535 ports | Slow but thorough |
| Stealth | SYN half-open scan | Quieter on IDS |
| Service | Service version detection | Identifies software |
| OS | OS fingerprinting | Detects operating systems |
| UDP | Top 100 UDP ports | DNS, SNMP, NTP, etc. |
| Vulnerability | Runs vuln scripts | Finds CVEs |
| Aggressive | All-in-one | OS + services + scripts + traceroute |

### Proxychains

Enable "Route through Proxychains" to send scans through proxy servers. Add proxies manually or import from a file.

Supported file formats (one proxy per line):
- `socks5 127.0.0.1 9050`
- `socks5://127.0.0.1:9050`
- `127.0.0.1:9050` (defaults to SOCKS5)

## Network Access

This add-on runs with `host_network: true` so nmap can reach your local network. The scanner binds to port 5000 internally and is accessed through Home Assistant's ingress proxy (no port exposure needed).

## Legal Notice

Only scan networks you own or have explicit written authorization to test. Unauthorized scanning is illegal.
