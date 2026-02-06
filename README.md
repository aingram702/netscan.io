# 📡 NetScanner Pro - Web-Based Network Scanner
<img src="https://img.shields.io/badge/version-1.0.0-green" alt="Version" /> <img src="https://img.shields.io/badge/license-MIT-blue" alt="License" /> <img src="https://img.shields.io/badge/python-3.8+-blue" alt="Python" /> <img src="https://img.shields.io/badge/html5-%23E34F26.svg?&style=flat&logo=html5&logoColor=white" alt="HTML5" /> <img src="https://img.shields.io/badge/javascript-%23323330.svg?&style=flat&logo=javascript&logoColor=%23F7DF1E" alt="JavaScript" />

NetScanner Pro is a powerful, modern web-based network reconnaissance tool with a sleek hacker-inspired UI. Built for educational purposes and authorized penetration testing.
<img src="https://via.placeholder.com/1200x600/0a0e27/00ff41?text=NetScanner+Pro+Dashboard" alt="NetScanner Pro Screenshot" />

## ⚡ Features
🎯 Core Scanning Capabilities

Multiple Scan Types
🔍 Ping Scan (Host Discovery)
⚡ Quick Scan (Top 100 Ports)
🔬 Full Scan (All 65,535 Ports)
🥷 Stealth Scan (SYN Scan)
🔧 Service Detection
🖥️ OS Fingerprinting



## 🔄 IP Rotation & Privacy

Automatic IP Rotation - Change source IP at customizable intervals (30s to 5min)
Real-time IP Display - Current source IP shown in header
Privacy-First Design - Configurable rotation settings

## 📊 Advanced Visualization

Network Map - Interactive doughnut chart showing network overview
Port Distribution - Bar chart of most common open ports
Service Analysis - Polar area chart of detected services
Real-time Updates - Charts update as scan progresses

## 📤 Export Options

JSON Export - Complete scan data with metadata
CSV Export - Excel-compatible spreadsheet format
PDF Reports - Professional reports with embedded charts and statistics

## 💻 User Experience

Dark Hacker Theme - Matrix-inspired green/pink aesthetic
Live Terminal Output - Real-time scan progress
Responsive Design - Works on desktop, tablet, and mobile
Intuitive Controls - Easy-to-use interface for all skill levels


## 🚀 Quick Start
Prerequisites

Python 3.8+
Modern Web Browser (Chrome, Firefox, Safari, Edge)
pip (Python package manager)

Installation

Clone or Download the Repository

git clone https://github.com/yourusername/netscanner-pro.git
cd netscanner-pro

Install Python Dependencies

pip install -r requirements.txt

Start the Backend Server

python server.py
You should see:
🚀 NetScanner Pro Backend Starting...
📊 Export & Visualization features enabled
⚠️  EDUCATIONAL USE ONLY - Scan responsibly!
 * Running on http://127.0.0.1:5000

Open the Frontend

Option A: Direct File Access
# Simply open in browser
open index.html  # macOS
start index.html # Windows
xdg-open index.html # Linux
Option B: Local HTTP Server (Recommended)
# Python 3
python -m http.server 8000

# Then visit: http://localhost:8000

Start Scanning!


Enter a target IP or range (e.g., 192.168.1.0/24)
Select scan type
Click Start Scan
Watch results appear in real-time


## 📁 Project Structure
netscanner-pro/
├── index.html          # Main frontend interface
├── styles.css          # Dark hacker-themed styling
├── script.js           # Frontend logic & visualizations
├── server.py           # Python Flask backend
├── requirements.txt    # Python dependencies
├── exports/            # Auto-generated directory for exports
└── README.md          # This file

🎮 Usage Guide
Basic Scan

Enter Target

Single IP: 192.168.1.1
IP Range: 192.168.1.0/24
Custom Range: 10.0.0.1-10.0.0.255


Select Scan Type

Ping Scan: Quick host discovery
Quick Scan: Scans top 100 common ports
Full Scan: All 65,535 ports (takes longer)
Stealth Scan: SYN scan to avoid detection
Service Detection: Identify running services
OS Detection: Fingerprint operating systems


Configure Options

Enable Auto-Rotate IP for privacy
Set rotation interval (30s - 5min)
Add custom ports (optional)


Start Scanning

Click 🚀 Start Scan
Watch terminal output
View results in real-time



Visualization
Switch between visualization tabs:

Network Map - Overall network status
Port Distribution - Most common open ports
Service Analysis - Services breakdown

Export Results
Click export buttons after scan completes:

📄 JSON - Raw data for automation
📊 CSV - Import into Excel/Google Sheets
📕 PDF - Professional report with charts


## ⚙️ Configuration
Backend Server Settings
Edit server.py:
# Change server port
app.run(debug=True, port=5000)  # Default: 5000

# Adjust CORS settings
CORS(app, origins=['http://localhost:8000'])
Scan Simulation
Modify scan behavior in server.py:
# Adjust host discovery rate
is_up = random.random() > 0.3  # 70% hosts up

# Change number of hosts scanned
num_hosts = random.randint(5, 15)

# Modify port discovery
port_list = random.sample(list(COMMON_PORTS.keys()), random.randint(2, 6))
Frontend Customization
Edit styles.css:
/* Change color scheme */
--primary-color: #00ff41;    /* Matrix green */
--secondary-color: #ff0080;  /* Cyber pink */
--background: #0a0e27;       /* Dark blue */

## 🔌 API Reference
Endpoints
POST /api/scan
Start a network scan
Request Body:
{
  "target": "192.168.1.0/24",
  "scanType": "quick",
  "ports": "22,80,443",
  "sourceIP": "192.168.1.100"
}
Response: Server-Sent Events (SSE) stream
{"type": "log", "level": "INFO", "message": "Scanning 192.168.1.1..."}
{"type": "host", "ip": "192.168.1.1", "status": "up", "ports": [...]}
POST /api/export/json
Export scan results as JSON
Request Body:
{
  "results": [...]
}
Response:
{
  "timestamp": "2025-01-26T10:30:00Z",
  "target": "192.168.1.0/24",
  "results": [...]
}
POST /api/export/csv
Export scan results as CSV
Response: CSV file download
POST /api/export/pdf
Export scan results as PDF
Response: PDF file download
GET /api/stats
Get scan statistics
Response:
{
  "total_hosts": 10,
  "hosts_up": 7,
  "total_ports": 42,
  "top_ports": [...]
}
GET /api/health
Check API health
Response:
{
  "status": "ok",
  "service": "NetScanner Pro API"
}

🛠️ Advanced Features
Real Nmap Integration
To use actual nmap instead of simulation:

Install Nmap

# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html

Modify server.py

import subprocess

def real_nmap_scan(target, scan_type):
    nmap_args = {
        'ping': ['-sn'],
        'quick': ['-F'],
        'full': ['-p-'],
        'stealth': ['-sS'],
        'service': ['-sV'],
        'os': ['-O']
    }
    
    cmd = ['nmap'] + nmap_args.get(scan_type, ['-F']) + [target]
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    for line in process.stdout:
        yield line

Update API endpoint

@app.route('/api/scan/real', methods=['POST'])
def real_scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('scanType', 'quick')
    
    def generate():
        for line in real_nmap_scan(target, scan_type):
            yield f"data: {json.dumps({'type': 'log', 'message': line})}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')
Custom Port Profiles
Add custom scan profiles in server.py:
SCAN_PROFILES = {
    'web': [80, 443, 8080, 8443, 3000, 5000],
    'database': [3306, 5432, 27017, 6379, 1433],
    'common': [21, 22, 23, 25, 53, 80, 110, 143, 443],
    'gaming': [25565, 27015, 7777, 3074, 3478]
}
Webhooks & Notifications
Add Slack/Discord notifications:
import requests

def send_notification(message):
    webhook_url = 'YOUR_WEBHOOK_URL'
    requests.post(webhook_url, json={'text': message})

# Use in scan completion
send_notification(f'Scan complete: {hosts_up} hosts found')

## 🔒 Security & Legal
⚠️ IMPORTANT WARNINGS
LEGAL USE ONLY

Only scan networks you own or have explicit written permission to test
Unauthorized network scanning is illegal in most jurisdictions
Violations may result in criminal prosecution

EDUCATIONAL PURPOSE

This tool is designed for cybersecurity education and authorized security testing
Use in controlled lab environments
Practice on your own networks or authorized testing ranges

ETHICAL GUIDELINES

Always obtain written authorization before scanning
Respect rate limits and network capacity
Document all scanning activities
Follow responsible disclosure practices

Best Practices

Authorization

Get written permission before scanning
Define scope clearly
Set time boundaries


Responsible Scanning

Use appropriate scan intensity
Avoid disrupting production systems
Monitor impact on target networks


Data Handling

Encrypt exported scan results
Store data securely
Delete data after use


Compliance

Follow local laws and regulations
Adhere to organizational policies
Respect privacy requirements




## 🐛 Troubleshooting
Backend Won't Start
Problem: ModuleNotFoundError: No module named 'flask'
Solution:
pip install -r requirements.txt
# or
pip install flask flask-cors reportlab pillow

Problem: Address already in use error
Solution:
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9  # macOS/Linux
netstat -ano | findstr :5000   # Windows (find PID, then kill)

# Or change port in server.py
app.run(debug=True, port=5001)
Frontend Issues
Problem: Scan not starting / No connection to backend
Solution:

Verify backend is running: http://localhost:5000/api/health
Check browser console for CORS errors
Ensure correct API URL in script.js:

const API_BASE = 'http://localhost:5000/api';

Problem: Charts not displaying
Solution:

Check browser console for errors
Verify Chart.js is loaded: Check Network tab
Clear browser cache and reload
Try different browser

Export Problems
Problem: PDF export fails
Solution:
# Reinstall jsPDF
# In browser console:
console.log(window.jspdf); // Should not be undefined

Problem: CSV shows garbled text
Solution:

Open CSV in proper text editor
Import into Excel using UTF-8 encoding
Use "Data > From Text/CSV" in Excel


## 🚧 Roadmap
Planned Features

 Real Nmap Integration - Direct nmap execution
 Network Topology Map - Visual node graph
 Vulnerability Database - CVE integration
 Historical Tracking - Compare scans over time
 Email Reports - Automated report delivery
 WebSocket Streaming - Real-time updates
 Multi-target Scanning - Parallel scans
 Custom Scan Scripts - NSE script integration
 Cloud Deployment - Docker/Kubernetes support
 API Authentication - JWT token system
 User Management - Multi-user support
 Scheduled Scans - Cron-based automation

Upcoming Improvements

Performance optimization for large networks
Mobile app version (React Native)
AI-powered vulnerability detection
Automated remediation suggestions
Integration with SIEM platforms


## 🤝 Contributing
Contributions are welcome! Please follow these guidelines:
How to Contribute

Fork the repository
Create a feature branchgit checkout -b feature/amazing-feature

Commit your changesgit commit -m 'Add amazing feature'

Push to branchgit push origin feature/amazing-feature

Open a Pull Request

Code Standards

Follow PEP 8 for Python code
Use ESLint for JavaScript
Add comments for complex logic
Write descriptive commit messages
Update documentation for new features

Testing
Before submitting:

Test all scan types
Verify export functionality
Check responsive design
Test on multiple browsers


## 📄 License
This project is licensed under the MIT License.
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
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 🙏 Acknowledgments

Nmap - The inspiration for this project
Chart.js - Beautiful data visualizations
Flask - Lightweight Python web framework
Font Awesome - Icon library
Fira Code - Monospace font for terminal aesthetic


## 📞 Support
Get Help

Documentation: Read this README carefully
Issues: GitHub Issues
Discussions: GitHub Discussions
Email: support@netscannerpro.com

Reporting Bugs
When reporting bugs, include:

Detailed description of the issue
Steps to reproduce
Expected vs actual behavior
Browser/OS information
Console error messages
Screenshots if applicable

## 🌟 Show Your Support
If you find this project useful, please consider:

<div align="center">

Made with ❤️ for the Cybersecurity Community
Remember: With great power comes great responsibility
</div>
