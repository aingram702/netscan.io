# NetScanner Pro

[![Version](https://img.shields.io/badge/version-2.0.0-green)](https://github.com/aingram702/netscan.net)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org/)

A web-based network reconnaissance simulator with real-time visualization. Built for cybersecurity education and authorized penetration testing practice.

> **LEGAL NOTICE**: This is an educational simulation tool. Only scan networks you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## Features

### Scan Types

| Scan Type | Description |
|-----------|-------------|
| Ping Scan | Host discovery - find live hosts on the network |
| Quick Scan | Scan top 100 most common TCP ports |
| Full Scan | Comprehensive scan of all 65,535 TCP ports with service versions |
| Stealth Scan | SYN scan - half-open connections for lower detection |
| Service Detection | Identify running services and their versions |
| OS Detection | Fingerprint operating systems on discovered hosts |
| UDP Scan | Scan common UDP ports (DNS, SNMP, NTP, DHCP, etc.) |
| Vulnerability Scan | Check for known CVEs against discovered services (25+ CVEs) |
| Aggressive Scan | All-in-one: OS detection + service versions + vulnerability scan + traceroute |

### Scan Speed / Timing Profiles

Inspired by nmap's timing templates:

| Profile | Per-Host Delay | Use Case |
|---------|---------------|----------|
| T1 - Paranoid | 1.5-3.0s | IDS evasion simulation |
| T2 - Polite | 0.5-1.0s | Low-bandwidth environments |
| T3 - Normal | 0.1-0.3s | Default balanced speed |
| T4 - Aggressive | 0.03-0.1s | Fast scans on reliable networks |
| T5 - Insane | 0.01-0.05s | Maximum speed |

### Custom Ports

Specify exact ports to scan:
- Single ports: `22,80,443`
- Ranges: `1-1000`
- Mixed: `22,80,443,8000-9000`

### Visualizations (5 tabs)

- **Network Topology** - Bubble chart showing hosts by open port count and latency
- **Port Distribution** - Horizontal bar chart of most frequently open ports (TCP/UDP)
- **Service Analysis** - Polar area chart of detected service types
- **OS Distribution** - Doughnut chart of operating system fingerprints
- **Vulnerability Severity** - Bar chart of CVE severity breakdown (critical/high/medium/low)

### Export Options

- **JSON** - Complete scan data with metadata
- **CSV** - Spreadsheet-compatible format with CSV injection protection
- **PDF** - Professional report with charts, vulnerability findings, and scan metadata

---

## Quick Start

### Prerequisites

- Python 3.8+
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Installation

```bash
git clone https://github.com/aingram702/netscan.net.git
cd netscan.net
pip install -r requirements.txt
python server.py
```

Open `http://localhost:5000` in your browser.

### Usage

1. Enter a target: `192.168.1.1`, `10.0.0.0/24`, or `192.168.1.1-192.168.1.254`
2. Select scan type and timing profile
3. Optionally specify custom ports
4. Click **Start Scan** (or `Ctrl+Enter`)
5. View results in real-time across terminal, results cards, and charts
6. Export results as JSON, CSV, or PDF

---

## Architecture

```
Browser (vanilla JS)              Flask Backend (Python)
┌─────────────────────┐          ┌──────────────────────┐
│  index.html         │  fetch   │  server.py           │
│  script.js          │ ──────── │                      │
│  styles.css         │  NDJSON  │  /api/scan (stream)  │
│                     │ <─────── │  /api/export/*       │
│  Chart.js (CDN)     │          │  /api/health         │
│  jsPDF (CDN)        │          │  /api/stats          │
└─────────────────────┘          └──────────────────────┘
```

- **Streaming**: Scan results are streamed via NDJSON (newline-delimited JSON) so the UI updates in real-time as each host is scanned
- **Simulated**: All scan data is randomly generated server-side - no actual network packets are sent
- **Client-side charts**: Chart.js renders all 5 visualization tabs; updates are debounced via `requestAnimationFrame` for performance
- **Client-side PDF**: jsPDF generates reports entirely in the browser, including embedded chart images

## Project Structure

```
netscan.net/
├── server.py           # Flask backend - API, scan simulation, export
├── script.js           # Frontend logic, charts, export, UI state
├── index.html          # HTML structure
├── styles.css          # Dark theme styling
├── requirements.txt    # Python dependencies (Flask, flask-cors)
├── exports/            # Server-side JSON export storage (auto-cleaned)
└── README.md
```

---

## API Reference

### `GET /api/health`

Returns service status and version.

### `POST /api/scan`

Starts a streaming network scan.

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

**Supported scan types:** `ping`, `quick`, `full`, `stealth`, `service`, `os`, `udp`, `vuln`, `aggressive`

**Response:** NDJSON stream with `log` and `host` objects:
```json
{"type": "log", "level": "INFO", "message": "Initiating AGGRESSIVE scan on 192.168.1.0/24"}
{"type": "host", "ip": "192.168.1.5", "status": "up", "ports": [...], "os": "Ubuntu 22.04 LTS", "vulnerabilities": [...], "traceroute": [...]}
```

### `POST /api/export/json` | `POST /api/export/csv` | `POST /api/export/pdf`

Export scan results. Accepts `{ results: [...], target: "...", scanType: "..." }`.

### `GET /api/stats`

Returns supported scan types, timing profiles, and port lists.

---

## Security

### Implemented Protections

- **Path traversal prevention** - Static file serving restricted to allowed extensions only
- **Input sanitization** - All user inputs stripped of injection characters
- **XSS prevention** - DOM-based HTML sanitization, CSP headers, no `unsafe-eval`
- **CSS class injection prevention** - Allowlisted values for dynamic CSS classes
- **CSV injection protection** - Values prefixed with `=+\-@` are escaped on export
- **Rate limiting** - 10 requests per minute per IP with memory-bounded tracking
- **Request size limits** - Flask-level `MAX_CONTENT_LENGTH` (1MB)
- **Export cleanup** - Old export files automatically pruned beyond limit
- **Security headers** - HSTS, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CSP
- **CORS restrictions** - Restricted to localhost origins
- **Filename collision prevention** - UUID suffix on export files

### Pre-deployment Checklist

- [ ] Generate SRI integrity hashes for CDN scripts (Chart.js, jsPDF)
- [ ] Replace in-memory rate limiting with Redis/external store for multi-process deployments
- [ ] Set `ALLOWED_HOST` environment variable for production domain
- [ ] Configure HTTPS termination (reverse proxy)

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + Enter` | Start Scan |
| `Escape` | Stop Scan |

---

## Troubleshooting

**Backend won't start**: `pip install -r requirements.txt`

**Port 5000 in use**: `lsof -ti:5000 | xargs kill -9` or change port in `server.py`

**No backend connection**: Verify `http://localhost:5000/api/health` returns JSON

**Charts not rendering**: Check browser console for errors, clear cache, try different browser

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**EDUCATIONAL USE ONLY** - Only scan networks you own or have permission to test.
