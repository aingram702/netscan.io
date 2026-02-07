# 📡 NetScanner Pro

[![Version](https://img.shields.io/badge/version-1.0.0-green)](https://github.com/yourusername/netscanner-pro)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://www.python.org/)
[![HTML5](https://img.shields.io/badge/html5-%23E34F26.svg?style=flat&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=flat&logo=javascript&logoColor=%23F7DF1E)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

A powerful, modern web-based network reconnaissance tool with a sleek hacker-inspired UI. Built for educational purposes and authorized penetration testing.

> **⚠️ LEGAL NOTICE**: Only scan networks you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 📑 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Usage Guide](#-usage-guide)
- [Configuration](#%EF%B8%8F-configuration)
- [API Reference](#-api-reference)
- [Security & Legal](#-security--legal)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ⚡ Features

### 🎯 Core Scanning Capabilities

| Scan Type | Description |
|-----------|-------------|
| 🔍 Ping Scan | Host Discovery |
| ⚡ Quick Scan | Top 100 Ports |
| 🔬 Full Scan | All 65,535 Ports |
| 🥷 Stealth Scan | SYN Scan |
| 🔧 Service Detection | Identify running services |
| 🖥️ OS Fingerprinting | Operating system detection |

### 🔄 IP Rotation & Privacy

- **Automatic IP Rotation** - Change source IP at customizable intervals (30s to 5min)
- **Real-time IP Display** - Current source IP shown in header
- **Privacy-First Design** - Configurable rotation settings

### 📊 Advanced Visualization

- **Network Map** - Interactive doughnut chart showing network overview
- **Port Distribution** - Bar chart of most common open ports
- **Service Analysis** - Polar area chart of detected services
- **Real-time Updates** - Charts update as scan progresses

### 📤 Export Options

- **JSON** - Complete scan data with metadata
- **CSV** - Excel-compatible spreadsheet format
- **PDF** - Professional reports with embedded charts

### 💻 User Experience

- Dark hacker theme with Matrix-inspired green/pink aesthetic
- Live terminal output with real-time progress
- Responsive design for desktop, tablet, and mobile
- Keyboard shortcuts (Ctrl+Enter to scan, Escape to stop)

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Modern Web Browser (Chrome, Firefox, Safari, Edge)
- pip (Python package manager)

### Installation

**1. Clone the Repository**

```bash
git clone https://github.com/yourusername/netscanner-pro.git
cd netscanner-pro
```

**2. Install Python Dependencies**

```bash
pip install -r requirements.txt
```

**3. Start the Backend Server**

```bash
python server.py
```

You should see:
```
🚀 NetScanner Pro Backend Starting...
📊 Export & Visualization features enabled
⚠️  EDUCATIONAL USE ONLY - Scan responsibly!
🔒 Security headers and rate limiting enabled
--------------------------------------------------
 * Running on http://127.0.0.1:5000
```

**4. Open the Frontend**

*Option A: Direct File Access*
```bash
# macOS
open index.html

# Windows
start index.html

# Linux
xdg-open index.html
```

*Option B: Local HTTP Server (Recommended)*
```bash
python -m http.server 8000
# Then visit: http://localhost:8000
```

**5. Start Scanning!**
1. Enter a target IP or range (e.g., `192.168.1.0/24`)
2. Select scan type
3. Click **Start Scan**
4. Watch results appear in real-time

---

## 📁 Project Structure

```
netscanner-pro/
├── index.html          # Main frontend interface
├── styles.css          # Dark hacker-themed styling
├── script.js           # Frontend logic & visualizations
├── server.py           # Python Flask backend
├── requirements.txt    # Python dependencies
├── exports/            # Auto-generated directory for exports
└── README.md           # This file
```

---

## 🎮 Usage Guide

### Basic Scan

| Step | Action |
|------|--------|
| **1. Enter Target** | Single IP: `192.168.1.1` • CIDR: `192.168.1.0/24` • Range: `10.0.0.1-10.0.0.255` |
| **2. Select Scan Type** | Choose from 6 scan types based on your needs |
| **3. Configure Options** | Enable Auto-Rotate IP, set interval, add custom ports |
| **4. Start Scanning** | Click 🚀 Start Scan and watch the terminal output |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + Enter` | Start Scan |
| `Escape` | Stop Scan |

### Visualizations

Switch between tabs to view:
- **Network Map** - Overall network status
- **Port Distribution** - Most common open ports
- **Service Analysis** - Services breakdown

### Export Results

After scan completes, export using:
- 📄 **JSON** - Raw data for automation
- 📊 **CSV** - Import into Excel/Google Sheets
- 📕 **PDF** - Professional report with charts

---

## ⚙️ Configuration

### Backend Server Settings

Edit `server.py`:

```python
# Change server port (default: 5000)
app.run(host='127.0.0.1', port=5000, debug=False)
```

### Scan Simulation

Modify scan behavior in `server.py`:

```python
# Adjust host discovery rate (70% hosts up)
is_up = random.random() > 0.3

# Change number of hosts scanned
num_hosts = random.randint(5, 15)
```

### Frontend Customization

Edit `styles.css`:

```css
/* Change color scheme */
--primary-color: #00ff41;    /* Matrix green */
--secondary-color: #ff0080;  /* Cyber pink */
--background: #0a0e27;       /* Dark blue */
```

---

## 🔌 API Reference

### Endpoints

#### `GET /api/health`
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "NetScanner Pro API",
  "version": "1.0.0"
}
```

#### `POST /api/scan`
Start a network scan. Returns NDJSON stream.

**Request:**
```json
{
  "target": "192.168.1.0/24",
  "scanType": "quick",
  "ports": "22,80,443",
  "sourceIP": "192.168.1.100"
}
```

**Response (Stream):**
```json
{"type": "log", "level": "INFO", "message": "Scanning 192.168.1.1..."}
{"type": "host", "ip": "192.168.1.1", "status": "up", "ports": [...]}
```

#### `POST /api/export/json`
Export scan results as JSON.

#### `POST /api/export/csv`
Export scan results as CSV file.

#### `POST /api/export/pdf`
Export scan results as PDF (client-side generation).

#### `GET /api/stats`
Get scan statistics and supported options.

---

## 🔒 Security & Legal

### ⚠️ Important Warnings

> **LEGAL USE ONLY**
> - Only scan networks you own or have explicit written permission to test
> - Unauthorized network scanning is illegal in most jurisdictions
> - Violations may result in criminal prosecution

> **EDUCATIONAL PURPOSE**
> - Designed for cybersecurity education and authorized security testing
> - Use in controlled lab environments
> - Practice on your own networks or authorized testing ranges

### Best Practices

1. **Authorization** - Get written permission, define scope, set time boundaries
2. **Responsible Scanning** - Use appropriate intensity, avoid disrupting production
3. **Data Handling** - Encrypt exports, store securely, delete after use
4. **Compliance** - Follow local laws, organizational policies, privacy requirements

---

## 🐛 Troubleshooting

### Backend Issues

**Problem:** `ModuleNotFoundError: No module named 'flask'`
```bash
pip install -r requirements.txt
```

**Problem:** `Address already in use`
```bash
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9  # macOS/Linux

# Or change port in server.py
app.run(port=5001)
```

### Frontend Issues

**Problem:** Scan not starting / No backend connection
1. Verify backend is running: `http://localhost:5000/api/health`
2. Check browser console for CORS errors
3. Ensure correct API URL in `script.js`

**Problem:** Charts not displaying
1. Check browser console for errors
2. Clear browser cache and reload
3. Try a different browser

### Export Issues

**Problem:** PDF export fails
- Verify jsPDF is loaded (check Network tab)

**Problem:** CSV shows garbled text
- Import into Excel using UTF-8 encoding

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Code Standards
- Follow PEP 8 for Python
- Use ESLint for JavaScript
- Add comments for complex logic
- Update documentation for new features

---

## 📄 License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2025 NetScanner Pro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🙏 Acknowledgments

- [Nmap](https://nmap.org/) - The inspiration for this project
- [Chart.js](https://www.chartjs.org/) - Beautiful data visualizations
- [Flask](https://flask.palletsprojects.com/) - Lightweight Python web framework
- [jsPDF](https://parall.ax/products/jspdf) - Client-side PDF generation
- [Fira Code](https://github.com/tonsky/FiraCode) - Monospace font for terminal aesthetic

---

<div align="center">

**Made with ❤️ for the Cybersecurity Community**

*Remember: With great power comes great responsibility*

</div>
