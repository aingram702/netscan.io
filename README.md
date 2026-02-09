<div align="center">

# NetScanner Pro

### Real nmap-Powered Web Network Scanner

[![Version](https://img.shields.io/badge/version-3.0.0-00d4ff?style=for-the-badge&logo=semver&logoColor=white)](https://github.com/aingram702/netscan.net)
[![Python](https://img.shields.io/badge/python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![nmap](https://img.shields.io/badge/nmap-required-4682B4?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://nmap.org/)
[![Flask](https://img.shields.io/badge/flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)

A web-based network scanner that wraps **real nmap** with a modern UI, real-time NDJSON streaming, 5 interactive Chart.js visualizations, and professional PDF report generation.

**This tool performs real network scans.** All data comes from actual nmap output - no simulations.

---

[Quick Start](#-quick-start) | [Scan Types](#-scan-types) | [Architecture](#-architecture) | [API](#-api-reference) | [Security](#-security)

</div>

---

> **LEGAL NOTICE**: Only scan networks you own or have explicit written authorization to test. Unauthorized scanning is illegal under the CFAA and similar laws worldwide.

---
![Screenshot1 of the app](./images/1.png)
![Screenshot2 of the app](./images/2.png)

## Table of Contents

- [Quick Start](#-quick-start)
- [Prerequisites](#prerequisites)
- [Scan Types](#-scan-types)
- [Timing Profiles](#-timing-profiles)
- [Features](#-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [API Reference](#-api-reference)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---


## Features

| Category | Highlights |
|----------|-----------|
| **Scanning** | 9 scan types including vulnerability detection, UDP scanning, and aggressive all-in-one mode |
| **Speed** | 5 timing profiles (T1-T5) inspired by nmap, from stealthy to maximum throughput |
| **Targeting** | Single IPs, CIDR notation (`/8` to `/32`), IP ranges, and custom port specifications |
| **Visualization** | 5 interactive Chart.js tabs - network topology, port distribution, services, OS fingerprints, vulnerabilities |
| **Vulnerability DB** | 25+ real-world CVEs including Log4Shell, BlueKeep, EternalBlue, Spring4Shell, ProxyLogon |
| **Export** | JSON, CSV (with injection protection), and professional PDF reports with embedded charts |
| **Real-time** | NDJSON streaming delivers results as each host is scanned - no waiting for completion |
| **Security** | CSP headers, rate limiting, input sanitization, path traversal prevention, XSS protection |

---

## Quick Start

### Prerequisites

- **Python 3.8+** with pip
- **nmap** installed and in PATH
- **Modern web browser** (Chrome, Firefox, Safari, Edge)

### Install nmap

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Fedora/RHEL
sudo dnf install nmap

# Arch
sudo pacman -S nmap

# Windows - download from https://nmap.org/download.html
```

### Install & Run

```bash
# Clone
git clone https://github.com/aingram702/netscan.net.git
cd netscan.net

# Install Python dependencies
pip install -r requirements.txt

# Run (unprivileged - some scans limited)
python server.py

# Run with full capabilities (recommended)
sudo python server.py
```

Open **http://localhost:5000** in your browser.

### Root vs Unprivileged

| Privilege Level | Available Scans | Limitations |
|----------------|----------------|-------------|
| **root / sudo** | All 9 scan types | None |
| **unprivileged** | ping, quick, full, service, vuln | Stealth falls back to TCP connect. OS detection disabled. UDP scan blocked. Aggressive scan limited. |

> The server auto-detects privilege level and shows it in both the terminal startup banner and the web UI header.

---

## Scan Types

Each scan type maps directly to real nmap flags:

| Scan Type | nmap Flags | Description | Root Required |
|-----------|-----------|-------------|:------------:|
| **Ping Scan** | `-sn` | Host discovery only. No port scanning. | No |
| **Quick Scan** | `-F` | Top 100 most common ports. | No |
| **Full Scan** | `-p 1-65535 -sV` | All 65,535 TCP ports with service detection. Slow. | No |
| **Stealth Scan** | `-sS` | SYN half-open scan. Falls back to `-sT` without root. | Yes |
| **Service Detection** | `-sV` | Identifies service names and versions on open ports. | No |
| **OS Detection** | `-O -sV` | Operating system fingerprinting + service detection. | Yes |
| **UDP Scan** | `-sU --top-ports 100` | Top 100 UDP ports (DNS, SNMP, NTP, etc). | Yes |
| **Vulnerability Scan** | `-sV --script vuln` | Runs nmap's vulnerability scripts. Extracts CVEs from output. | No |
| **Aggressive Scan** | `-A` | OS + services + scripts + traceroute. Most comprehensive. | Yes |

### Target Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.1` | Scan one host |
| CIDR | `10.0.0.0/24` | Scan a subnet |
| IP Range | `192.168.1.1-192.168.1.254` | Scan a specific range |
| Hostname | `example.com` | DNS-resolved scan |

### Custom Ports

Specify in the custom ports field:
```
22,80,443           # Individual ports
1-1000              # Port range
22,80,443,8000-9000 # Mixed
```

### Skip Host Discovery (-Pn)

Enable the "Skip Host Discovery" checkbox to treat all hosts as online. Useful when targets block ICMP/ping probes.

---

## Timing Profiles

Maps directly to nmap's `-T` templates:

| Profile | nmap Flag | Scan Speed | Use Case |
|---------|----------|------------|----------|
| **T1 - Sneaky** | `-T1` | Very slow | IDS/IPS evasion |
| **T2 - Polite** | `-T2` | Slow | Low-bandwidth networks |
| **T3 - Normal** | `-T3` | Default | General purpose |
| **T4 - Aggressive** | `-T4` | Fast | Reliable LANs |
| **T5 - Insane** | `-T5` | Very fast | Speed over accuracy |

---

## Features

| Feature | Details |
|---------|---------|
| **Real nmap scanning** | All 9 scan types powered by actual nmap via python-nmap |
| **NDJSON streaming** | Results arrive host-by-host in real-time as nmap scans each target |
| **5 visualizations** | Network topology (bubble), port distribution (bar), services (polar), OS (doughnut), vulns (bar) |
| **Vulnerability extraction** | Parses CVE identifiers and CVSS scores from nmap script output |
| **Export** | JSON, CSV (injection-protected), PDF (with embedded charts via jsPDF) |
| **Hostname support** | Scan by hostname in addition to IP/CIDR/range |
| **Privilege detection** | Auto-detects root and falls back gracefully for unprivileged scans |
| **Skip discovery** | `-Pn` flag for hosts that block ping probes |
| **Traceroute** | Hop-by-hop path display in aggressive scans |
| **OS alternatives** | Shows multiple OS match candidates with confidence percentages |
| **MAC vendor lookup** | Displays hardware vendor from MAC address (when on same subnet) |
| **Port state reasons** | Shows nmap's reason for each port state (syn-ack, no-response, etc.) |

---

## Architecture

```
 ┌─────────────────────────────────────────────────────────────┐
 │                     Browser (Client)                        │
 │                                                             │
 │  index.html    script.js       styles.css     CDN Libs      │
 │  UI layout     Scan control    Dark theme     Chart.js      │
 │                NDJSON parse    Responsive     jsPDF          │
 │                5 charts                                     │
 │                PDF/CSV/JSON                                 │
 └────────────────────┬────────────────────────────────────────┘
                      │ POST /api/scan (NDJSON stream)
                      ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                  Flask Backend (server.py)                   │
 │                                                             │
 │  /api/scan ──→ python-nmap ──→ nmap binary                 │
 │                                                             │
 │  Flow:                                                      │
 │  1. Validate target & scan type                             │
 │  2. For ranges: ping sweep → discover live hosts            │
 │  3. Scan each host with requested nmap flags                │
 │  4. Parse XML output → JSON                                 │
 │  5. Stream results as NDJSON (one JSON per line)            │
 │                                                             │
 │  Security: CSP, rate limiting, input sanitization,          │
 │            path traversal prevention, CORS                  │
 └────────────────────┬────────────────────────────────────────┘
                      │ subprocess
                      ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                    nmap (system binary)                      │
 │  Performs actual network scanning, service detection,        │
 │  OS fingerprinting, vulnerability script execution           │
 └─────────────────────────────────────────────────────────────┘
```

### How Streaming Works

1. **Range scans**: First a quick ping sweep (`-sn`) discovers live hosts. Then each host is scanned individually with the requested flags, streaming results as they complete.
2. **Single host scans**: nmap runs once on the target and results are streamed back.
3. **Frontend**: Uses `ReadableStream` API to parse NDJSON line-by-line, updating the terminal, result cards, and charts in real-time.

---

## Project Structure

```
netscan.net/
├── server.py           # Flask backend - nmap wrapper, NDJSON streaming,
│                       #   result parsing, export, security middleware
├── script.js           # Frontend - scan control, NDJSON parsing,
│                       #   5 Chart.js visualizations, PDF/CSV/JSON export
├── index.html          # UI shell - scan config, terminal, charts, results
├── styles.css          # Dark theme, port states, vuln severity colors
├── requirements.txt    # Flask, flask-cors, python-nmap
├── exports/            # Server-side JSON exports (auto-cleaned)
└── README.md           # This file
```

---

## API Reference

### `GET /api/health`

Returns server status, nmap availability, privilege level, and source IP.

```json
{
  "status": "ok",
  "service": "NetScanner Pro API",
  "version": "3.0.0",
  "nmap": { "available": true, "version": "7.94", "status": "available" },
  "privileges": { "root": true, "note": "Full scan capabilities" },
  "source_ip": "192.168.1.100"
}
```

### `POST /api/scan`

Starts a real nmap scan. Returns NDJSON stream. Rate limited to 10/min.

**Request:**
```json
{
  "target": "192.168.1.0/24",
  "scanType": "aggressive",
  "ports": "22,80,443",
  "timing": 4,
  "skipDiscovery": false
}
```

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `target` | string | Yes | IP, CIDR, IP range, or hostname |
| `scanType` | string | Yes | `ping`, `quick`, `full`, `stealth`, `service`, `os`, `udp`, `vuln`, `aggressive` |
| `ports` | string | No | Custom port spec (e.g., `22,80,443`) |
| `timing` | int | No | 1-5 (default: 3) |
| `skipDiscovery` | bool | No | Skip ping discovery (`-Pn`) |

**Response:** NDJSON stream with log messages and host results.

### `POST /api/export/json` | `POST /api/export/csv` | `POST /api/export/pdf`

Export scan results. Body: `{ "results": [...], "target": "...", "scanType": "..." }`

### `GET /api/stats`

Returns supported scan types, nmap version, privilege level.

---

## Security

| Protection | Implementation |
|-----------|----------------|
| **Path traversal** | Static files restricted to allowlisted extensions |
| **Input sanitization** | Strips null bytes, control chars, injection chars; 255-char limit |
| **XSS prevention** | `textContent` for all user data in DOM; CSP blocks `unsafe-eval` |
| **CSS class injection** | Allowlisted values for dynamic CSS classes |
| **CSV injection** | `=+-@` prefixed values escaped on export |
| **Rate limiting** | 10 req/min per IP, memory-bounded (10K IPs max) |
| **Request size** | Flask `MAX_CONTENT_LENGTH` = 1MB |
| **Security headers** | HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy |
| **CSP** | Script sources restricted to self + CDN domains |
| **CORS** | Restricted to localhost origins |
| **nmap args** | Scan type validated against allowlist; custom ports regex-validated |

---

## Troubleshooting

<details>
<summary><b>nmap not found</b></summary>

Install nmap for your OS:
```bash
sudo apt install nmap        # Debian/Ubuntu
brew install nmap             # macOS
sudo dnf install nmap         # Fedora
```

Verify: `nmap --version`
</details>

<details>
<summary><b>Permission denied / scan limited</b></summary>

Run the server with root:
```bash
sudo python server.py
```

Without root, these scans are limited: stealth (falls back to TCP connect), OS detection (disabled), UDP (blocked), aggressive (no OS/SYN).
</details>

<details>
<summary><b>No hosts found</b></summary>

1. Verify the target is reachable: `ping 192.168.1.1`
2. Enable "Skip Host Discovery" (-Pn) if hosts block ICMP
3. Check your firewall isn't blocking outbound packets
4. Try a single known-up host first
</details>

<details>
<summary><b>Scan takes too long</b></summary>

1. Use T4 or T5 timing for faster scans
2. Use Quick Scan instead of Full Scan
3. Reduce the target range (use /28 instead of /24)
4. Specify only needed ports with custom ports
5. Each host has a 300s timeout - large networks take proportionally longer
</details>

<details>
<summary><b>Port 5000 in use</b></summary>

```bash
lsof -ti:5000 | xargs kill -9    # Linux/macOS
```

Or change the port at the bottom of `server.py`.
</details>

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and test
4. Commit: `git commit -m "Add feature"`
5. Push and open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**AUTHORIZED USE ONLY** - Only scan networks you own or have explicit permission to test.

Powered by [nmap](https://nmap.org) | Built with Python, Flask, Chart.js

</div>
