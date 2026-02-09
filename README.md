<div align="center">

# NetScanner Pro

### Web-Based Network Reconnaissance Simulator

[![Version](https://img.shields.io/badge/version-2.0.0-00d4ff?style=for-the-badge&logo=semver&logoColor=white)](https://github.com/aingram702/netscan.net)
[![Python](https://img.shields.io/badge/python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Chart.js](https://img.shields.io/badge/chart.js-4.4.0-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)](https://www.chartjs.org/)

A powerful, real-time network scanning simulator built for **cybersecurity education** and **authorized penetration testing practice**. Features 9 scan types, 5 interactive visualizations, vulnerability detection with 25+ real-world CVEs, and professional PDF report generation.

> **No actual network packets are sent** - all data is simulated server-side for safe, legal training.

---

[Features](#-features) | [Quick Start](#-quick-start) | [Scan Types](#-scan-types-in-depth) | [Architecture](#-architecture) | [API](#-api-reference) | [Security](#-security) | [Contributing](#-contributing)

</div>

---

> **LEGAL NOTICE**: This is an educational simulation tool. Only scan networks you own or have explicit written permission to test. Unauthorized network scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

---
![Screenshot1 of the app](./images/1.png)
![Screenshot2 of the app](./images/2.png)

## Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Scan Types In Depth](#-scan-types-in-depth)
- [Timing Profiles](#-timing-profiles)
- [Visualizations](#-visualizations)
- [Export Options](#-export-options)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [API Reference](#-api-reference)
- [Security](#-security)
- [Keyboard Shortcuts](#-keyboard-shortcuts)
- [Technology Stack](#-technology-stack)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Changelog](#-changelog)
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
- **Modern web browser** (Chrome, Firefox, Safari, Edge)

### Installation

```bash
# Clone the repository
git clone https://github.com/aingram702/netscan.net.git
cd netscan.net

# Install dependencies
pip install -r requirements.txt

# Start the server
python server.py
```

Open **http://localhost:5000** in your browser.

### First Scan

1. Enter a target IP or range (e.g., `192.168.1.0/24`)
2. Select a scan type (start with **Quick Scan** for fast results)
3. Choose a timing profile (T3 Normal is the default)
4. Click **Start Scan** or press `Ctrl+Enter`
5. Watch results stream in real-time across the terminal, result cards, and charts
6. Export your findings as JSON, CSV, or PDF

### Target Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.1` | Scan a single host |
| CIDR notation | `10.0.0.0/24` | Scan a subnet (256 addresses) |
| CIDR wide | `172.16.0.0/16` | Scan a large network (samples hosts) |
| IP range | `192.168.1.1-192.168.1.254` | Scan a specific range |

### Custom Ports

Specify exact ports to scan in the custom ports field:

```
22,80,443           # Individual ports
1-1000              # Port range
22,80,443,8000-9000 # Mixed format
```

> Port specifications are capped at 1,000 ports to prevent excessive scan times.

---

## Scan Types In Depth

### Host Discovery

| Scan Type | Command Equivalent | What It Does |
|-----------|-------------------|--------------|
| **Ping Scan** | `nmap -sn` | Discovers live hosts on the network without port scanning. Returns host status, latency, and MAC addresses. Fastest scan type. |

### Port Scanning

| Scan Type | Command Equivalent | What It Does |
|-----------|-------------------|--------------|
| **Quick Scan** | `nmap -F` | Scans the top 100 most common TCP ports. Good balance of speed and coverage for initial reconnaissance. |
| **Full Scan** | `nmap -p-` | Comprehensive scan of all 65,535 TCP ports with service version detection. Thorough but slower. |
| **Stealth Scan** | `nmap -sS` | SYN (half-open) scan that never completes the TCP handshake. Harder to detect in logs. |
| **UDP Scan** | `nmap -sU` | Scans 16 common UDP ports including DNS (53), SNMP (161), NTP (123), DHCP (67/68), and SSDP (1900). |

### Service & OS Detection

| Scan Type | Command Equivalent | What It Does |
|-----------|-------------------|--------------|
| **Service Detection** | `nmap -sV` | Identifies running services and their exact versions (e.g., `OpenSSH 9.3p1`, `nginx 1.24.0`). Covers 16 service families. |
| **OS Detection** | `nmap -O` | Fingerprints the operating system on discovered hosts. Identifies 18 OS variants including Linux, Windows, macOS, FreeBSD, Android, and Cisco IOS. |

### Advanced Scanning

| Scan Type | Command Equivalent | What It Does |
|-----------|-------------------|--------------|
| **Vulnerability Scan** | `nmap --script vuln` | Checks discovered services against a database of 25+ real-world CVEs. Reports severity (critical/high/medium/low) with descriptions. |
| **Aggressive Scan** | `nmap -A` | All-in-one scan combining OS detection, service versions, vulnerability scanning, and traceroute. Most comprehensive option. |

### Vulnerability Database

The scanner checks against 25+ real-world CVEs across severity levels:

<details>
<summary><b>Critical Vulnerabilities (click to expand)</b></summary>

| CVE | Name | Affected Services |
|-----|------|-------------------|
| CVE-2021-44228 | Log4Shell | HTTP, HTTPS, Elasticsearch |
| CVE-2024-3094 | XZ Utils Backdoor | SSH |
| CVE-2019-0708 | BlueKeep | RDP |
| CVE-2022-22965 | Spring4Shell | HTTP, HTTPS |
| CVE-2021-26855 | ProxyLogon | HTTPS (Exchange) |
| CVE-2020-1472 | Zerologon | MSRPC, SMB |
| CVE-2017-0144 | EternalBlue | SMB |
| CVE-2021-34527 | PrintNightmare | SMB, MSRPC |
| CVE-2023-20198 | Cisco IOS XE Web UI | HTTP, HTTPS |
| CVE-2020-14882 | WebLogic RCE | HTTP, HTTPS |
| CVE-2022-26134 | Confluence OGNL Injection | HTTP, HTTPS |
| CVE-2023-46604 | Apache ActiveMQ RCE | HTTP |
| CVE-2024-21887 | Ivanti Connect Secure | HTTPS |
| CVE-2023-48788 | FortiClient EMS SQLi | HTTPS |
| CVE-2023-27997 | FortiGate RCE | HTTPS |
| CVE-2023-23397 | Outlook Elevation | SMTP, IMAP |
| CVE-2020-25213 | WP File Manager RCE | HTTP, HTTPS |
| CVE-2023-22515 | Confluence Broken Access | HTTP, HTTPS |
| CVE-2021-22986 | F5 BIG-IP iControl RCE | HTTPS |

</details>

<details>
<summary><b>High Severity Vulnerabilities (click to expand)</b></summary>

| CVE | Name | Affected Services |
|-----|------|-------------------|
| CVE-2023-44487 | HTTP/2 Rapid Reset | HTTP, HTTPS |
| CVE-2021-41773 | Apache Path Traversal | HTTP |
| CVE-2022-0778 | OpenSSL Infinite Loop | HTTPS, IMAPS, POP3S |
| CVE-2021-3156 | Baron Samedit (Sudo) | SSH |
| CVE-2023-36884 | Office HTML RCE | SMTP |
| CVE-2022-41040 | ProxyNotShell | HTTPS (Exchange) |

</details>

---

## Timing Profiles

Inspired by nmap's `-T` timing templates, these profiles control scan speed and stealth:

| Profile | Init Delay | Per-Host Delay | Use Case |
|---------|-----------|----------------|----------|
| **T1 - Paranoid** | 2.0s | 1.5 - 3.0s | IDS/IPS evasion simulation. Extremely slow to avoid detection. |
| **T2 - Polite** | 1.0s | 0.5 - 1.0s | Low-bandwidth networks. Minimal impact on target systems. |
| **T3 - Normal** | 0.3s | 0.1 - 0.3s | Default. Balanced speed and reliability for most networks. |
| **T4 - Aggressive** | 0.1s | 0.03 - 0.1s | Fast scans on reliable, high-bandwidth local networks. |
| **T5 - Insane** | 0.05s | 0.01 - 0.05s | Maximum speed. May sacrifice accuracy for throughput. |

> **Tip**: Use T4 or T5 for quick demos. Use T1 or T2 to practice patience-based recon techniques.

---

## Visualizations

NetScanner Pro provides 5 interactive visualization tabs powered by Chart.js, updated in real-time as results stream in:

| Tab | Chart Type | What It Shows |
|-----|-----------|---------------|
| **Network Map** | Bubble chart | Each host as a bubble sized by open port count, positioned by latency. Hover for details. |
| **Port Distribution** | Horizontal bar | Most frequently discovered open ports across all scanned hosts (TCP and UDP). |
| **Service Analysis** | Polar area | Breakdown of detected service types (SSH, HTTP, MySQL, etc.) by frequency. |
| **OS Distribution** | Doughnut | Operating system fingerprint distribution across discovered hosts. |
| **Vulnerabilities** | Bar chart | CVE severity breakdown: critical (red), high (orange), medium (yellow), low (blue). |

> Charts update via `requestAnimationFrame` debouncing for smooth performance even during fast scans.

---

## Export Options

| Format | Contents | Notes |
|--------|----------|-------|
| **JSON** | Complete scan data with metadata, timestamps, and all host details | Saved server-side with auto-cleanup (max 100 files) |
| **CSV** | Tabular format with IP, status, hostname, OS, MAC, ports, services, vulns | CSV injection protection (escapes `=+-@` prefixes) |
| **PDF** | Professional report with scan summary, host details, embedded charts, and vulnerability findings | Generated client-side via jsPDF with chart screenshots |

---

## Architecture

```
                         NetScanner Pro Architecture

 ┌─────────────────────────────────────────────────────────────────────┐
 │                        Browser (Client)                            │
 │                                                                    │
 │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
 │  │index.html│  │script.js │  │styles.css│  │ CDN Libraries      │ │
 │  │  UI      │  │  Logic   │  │  Theme   │  │ - Chart.js 4.4.0   │ │
 │  │  Layout  │  │  Charts  │  │  Dark    │  │ - jsPDF 2.5.1      │ │
 │  └──────────┘  │  Export  │  │  Mode    │  └────────────────────┘ │
 │                │  State   │  └──────────┘                         │
 │                └────┬─────┘                                       │
 └─────────────────────┼─────────────────────────────────────────────┘
                       │ fetch (POST)
                       │ NDJSON stream response
                       ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │                     Flask Backend (Python)                         │
 │                                                                    │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
 │  │ /api/scan    │  │ /api/export  │  │ Security Layer           │ │
 │  │  NDJSON      │  │  /json       │  │ - CSP headers            │ │
 │  │  streaming   │  │  /csv        │  │ - Rate limiting          │ │
 │  │  simulation  │  │  /pdf        │  │ - Input sanitization     │ │
 │  ├──────────────┤  ├──────────────┤  │ - Path traversal guard   │ │
 │  │ /api/health  │  │ /api/stats   │  │ - CORS restrictions      │ │
 │  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
 └─────────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Request**: The browser sends a POST to `/api/scan` with target, scan type, timing, and optional custom ports
2. **Streaming**: The Flask backend generates simulated scan data and streams it as NDJSON (newline-delimited JSON) - one JSON object per line
3. **Real-time UI**: As each line arrives, the frontend parses it and updates the terminal output, host result cards, and all 5 chart visualizations
4. **No real scanning**: All network data (IPs, ports, services, OS fingerprints, vulnerabilities, traceroute hops) is randomly generated server-side. No actual network packets are ever sent.

### Key Design Decisions

- **NDJSON over WebSockets**: Simpler to implement, works with standard HTTP, naturally supports streaming via `fetch()` with `ReadableStream`
- **Client-side PDF**: Generated entirely in the browser using jsPDF with embedded chart images - no server-side PDF library needed
- **Vanilla JS**: No framework dependencies - the entire frontend is a single `script.js` file for simplicity
- **Simulated data**: Realistic but safe - uses actual CVE identifiers, real service version strings, and proper IP addressing

---

## Project Structure

```
netscan.net/
├── server.py           # Flask backend - API routes, scan simulation engine,
│                       #   vulnerability database (25+ CVEs), export handlers,
│                       #   security middleware (CSP, rate limiting, sanitization)
├── script.js           # Frontend application - scan control, NDJSON stream
│                       #   parsing, 5 Chart.js visualizations, PDF/CSV/JSON
│                       #   export, DOM sanitization, keyboard shortcuts
├── index.html          # Application shell - scan configuration form,
│                       #   terminal output, visualization tabs, result cards
├── styles.css          # Dark theme with cyan/green accent colors,
│                       #   responsive layout, terminal styling, animations
├── requirements.txt    # Python dependencies (Flask, flask-cors)
├── exports/            # Server-side JSON export storage (auto-cleaned,
│                       #   max 100 files, UUID collision prevention)
└── README.md           # This file
```

---

## API Reference

### `GET /api/health`

Health check endpoint. Returns service status and version.

```json
{
  "status": "ok",
  "service": "NetScanner Pro API",
  "version": "2.0.0",
  "timestamp": "2026-01-15T10:30:00.000000"
}
```

### `POST /api/scan`

Starts a streaming network scan. Rate limited to 10 requests/minute.

**Request body:**
```json
{
  "target": "192.168.1.0/24",
  "scanType": "aggressive",
  "ports": "22,80,443",
  "timing": 4,
  "sourceIP": "10.0.0.1"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | IP address, CIDR range, or IP range |
| `scanType` | string | Yes | One of: `ping`, `quick`, `full`, `stealth`, `service`, `os`, `udp`, `vuln`, `aggressive` |
| `ports` | string | No | Custom port specification (e.g., `22,80,443` or `1-1000`) |
| `timing` | integer | No | Timing profile 1-5 (default: 3) |
| `sourceIP` | string | No | Simulated source IP for display purposes |

**Response:** NDJSON stream (`application/x-ndjson`)

```jsonl
{"type": "log", "level": "INFO", "message": "Initiating AGGRESSIVE scan on 192.168.1.0/24", "color": "cyan"}
{"type": "log", "level": "INFO", "message": "Timing: T4 (Aggressive) | Default port set", "color": "cyan"}
{"type": "log", "level": "INFO", "message": "Scanning 192.168.1.5...", "color": "white"}
{"type": "host", "ip": "192.168.1.5", "status": "up", "latency": "12ms", "mac": "a4:3b:c1:22:f0:9e", "hostname": "web-srv01.local", "os": "Ubuntu 22.04 LTS", "ports": [{"port": 22, "state": "open", "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.3p1"}, {"port": 80, "state": "open", "protocol": "tcp", "service": "http", "version": "nginx 1.24.0"}], "vulnerabilities": [{"cve": "CVE-2021-44228", "name": "Log4Shell", "severity": "critical", "description": "Apache Log4j2 RCE via JNDI lookup injection"}], "traceroute": [{"hop": 1, "ip": "192.168.1.1", "rtt": "1.2ms", "hostname": null}]}
{"type": "log", "level": "SUCCESS", "message": "Scan complete. 12 hosts scanned. 3 vulnerabilities found!", "color": "green"}
```

### `POST /api/export/json`

Export scan results as JSON. Saved server-side with auto-cleanup.

### `POST /api/export/csv`

Export scan results as CSV. Returns file download with CSV injection protection.

### `POST /api/export/pdf`

Returns scan data for client-side PDF generation via jsPDF.

**Export request body (all formats):**
```json
{
  "results": [{ "ip": "...", "status": "up", "ports": [...] }],
  "target": "192.168.1.0/24",
  "scanType": "aggressive"
}
```

### `GET /api/stats`

Returns supported scan types, timing profiles, and port lists.

---

## Security

### Implemented Protections

| Protection | Implementation | Layer |
|-----------|----------------|-------|
| **Path traversal prevention** | Static file serving restricted to allowlisted extensions only (`.html`, `.css`, `.js`, `.png`, etc.) | Server |
| **Input sanitization** | All user inputs stripped of null bytes, control characters, and injection characters (`<>\"';$\&()`) with 255-char limit | Server |
| **XSS prevention** | DOM-based HTML sanitization via `textContent`, CSP headers blocking `unsafe-eval`, no inline scripts | Both |
| **CSS class injection** | Allowlisted values for all dynamic CSS classes (status badges, severity labels, tab IDs) | Client |
| **CSV injection** | Values prefixed with `=`, `+`, `-`, `@` are escaped with a leading single quote on export | Client |
| **Rate limiting** | 10 requests per minute per IP with memory-bounded tracking (max 10,000 IPs) | Server |
| **Request size limits** | Flask-level `MAX_CONTENT_LENGTH` (1MB) - enforced before request body is parsed | Server |
| **Export cleanup** | Old export files automatically pruned when count exceeds 100. UUID suffix prevents filename collisions. | Server |
| **Security headers** | HSTS, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy | Server |
| **Content Security Policy** | Restricts script sources to `self` + CDN domains, blocks `unsafe-eval`, restricts `connect-src` to `self` | Server |
| **CORS restrictions** | Restricted to `localhost` and `127.0.0.1` origins (configurable via `ALLOWED_HOST` env var) | Server |

### Pre-deployment Checklist

- [ ] Generate SRI integrity hashes for CDN scripts:
  ```bash
  curl -s https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js | openssl dgst -sha384 -binary | openssl base64 -A
  curl -s https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js | openssl dgst -sha384 -binary | openssl base64 -A
  ```
- [ ] Replace in-memory rate limiting with Redis or external store for multi-process/multi-server deployments
- [ ] Set `ALLOWED_HOST` environment variable for production domain
- [ ] Configure HTTPS termination via reverse proxy (nginx, Caddy, etc.)
- [ ] Review and tighten CSP `style-src 'unsafe-inline'` if Google Fonts can be self-hosted

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + Enter` | Start scan |
| `Escape` | Stop scan |

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Backend** | Python 3.8+ / Flask | API server, scan simulation, export generation |
| **Frontend** | Vanilla JavaScript (ES6+) | Application logic, stream parsing, DOM manipulation |
| **Styling** | CSS3 with custom properties | Dark theme, responsive layout, animations |
| **Charts** | Chart.js 4.4.0 (CDN) | 5 interactive visualization types |
| **PDF Export** | jsPDF 2.5.1 (CDN) | Client-side PDF report generation |
| **Fonts** | Fira Code (Google Fonts) | Monospace terminal aesthetic |
| **CORS** | flask-cors | Cross-origin request handling |
| **Streaming** | NDJSON over HTTP | Real-time scan result delivery |

---

## Troubleshooting

<details>
<summary><b>Backend won't start</b></summary>

Install dependencies first:
```bash
pip install -r requirements.txt
```

If you see `ModuleNotFoundError`, make sure you're using the right Python environment:
```bash
python3 -m pip install -r requirements.txt
python3 server.py
```
</details>

<details>
<summary><b>Port 5000 already in use</b></summary>

Kill the existing process:
```bash
# Linux/macOS
lsof -ti:5000 | xargs kill -9

# Windows
netstat -ano | findstr :5000
taskkill /PID <pid> /F
```

Or change the port in `server.py` (line 701):
```python
app.run(host='0.0.0.0', port=8080, debug=False)
```
</details>

<details>
<summary><b>No backend connection</b></summary>

Verify the API is running:
```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{"status": "ok", "service": "NetScanner Pro API", "version": "2.0.0"}
```
</details>

<details>
<summary><b>Charts not rendering</b></summary>

1. Open browser developer console (`F12`) and check for JavaScript errors
2. Verify Chart.js loaded: type `Chart` in the console - it should return a function
3. Clear browser cache (`Ctrl+Shift+Delete`)
4. Try a different browser
5. Check if a content blocker is blocking CDN scripts
</details>

<details>
<summary><b>Scan returns no results</b></summary>

1. Check that the target format is valid (e.g., `192.168.1.0/24`)
2. Check the browser console for network errors
3. Verify the backend is running and responding to `/api/health`
4. Try a single IP target first (e.g., `192.168.1.1`)
</details>

---

## Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Make** your changes and test locally
4. **Commit** with clear messages: `git commit -m "Add new scan type for ..."`
5. **Push** to your fork: `git push origin feature/my-feature`
6. **Open** a Pull Request with a description of your changes

### Ideas for Contributions

- Additional scan types (e.g., SCTP scan, IP protocol scan)
- More CVEs in the vulnerability database
- Additional chart visualizations
- Docker containerization
- Automated testing suite
- Accessibility improvements
- Internationalization (i18n) support

---

## Changelog

### v2.0.0 (Current)

- **New scan types**: UDP Scan, Vulnerability Scan, Aggressive Scan (all-in-one)
- **Vulnerability detection**: 25+ real-world CVEs with severity classification
- **Timing profiles**: 5 speed profiles (T1-T5) inspired by nmap
- **Custom ports**: Parse and scan user-specified port ranges
- **Traceroute simulation**: Hop-by-hop path visualization in aggressive mode
- **5 visualization tabs**: Network topology, port distribution, service analysis, OS distribution, vulnerability severity
- **Performance**: `requestAnimationFrame` debounced chart updates
- **Security hardening**: CSP headers, rate limiting, input sanitization, path traversal prevention, CSS class injection prevention, CSV injection protection
- **IP targeting fix**: Correct CIDR/range handling via Python `ipaddress` module
- **Export improvements**: UUID collision prevention, auto-cleanup, size limits

### v1.0.0

- Initial release with basic port scanning simulation
- JSON export
- Single chart visualization

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

**EDUCATIONAL USE ONLY** - Only scan networks you own or have explicit permission to test.

Built with Python, Flask, Chart.js, and a passion for cybersecurity education.

[Report a Bug](https://github.com/aingram702/netscan.net/issues) | [Request a Feature](https://github.com/aingram702/netscan.net/issues)

</div>
