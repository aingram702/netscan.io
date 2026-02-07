from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS
import json
import time
import random
import os
from datetime import datetime
from io import BytesIO
import csv

app = Flask(__name__)
CORS(app)

EXPORTS_DIR = 'exports'
os.makedirs(EXPORTS_DIR, exist_ok=True)

# Simulated data
COMMON_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
    3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 6379: 'redis',
    8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb'
}

OS_FINGERPRINTS = [
    'Linux 5.x', 'Windows 10', 'Windows Server 2019', 'macOS 12.x',
    'Ubuntu 20.04', 'CentOS 7', 'FreeBSD 13.x', 'Android 11'
]

HOSTNAMES = [
    'router.local', 'server01.local', 'workstation.local', 'nas.local',
    'printer.local', 'switch.local', 'gateway.local', 'database.local'
]

def generate_random_ip(base='192.168.1'):
    return f"{base}.{random.randint(1, 254)}"

def generate_mac_address():
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])

def simulate_scan(target, scan_type, ports=None, source_ip=None):
    """Simulate network scan and yield results"""
    
    # Send initial log
    yield json.dumps({
        'type': 'log',
        'level': 'INFO',
        'message': f'Initiating {scan_type} scan on {target}',
        'color': 'cyan'
    }) + '\n'
    
    time.sleep(0.5)
    
    # Parse target range
    if '/' in target:
        base_ip = target.split('/')[0].rsplit('.', 1)[0]
        num_hosts = random.randint(5, 15)
    else:
        base_ip = target.rsplit('.', 1)[0]
        num_hosts = 1
    
    # Scan hosts
    for i in range(num_hosts):
        time.sleep(random.uniform(0.3, 0.8))
        
        ip = generate_random_ip(base_ip)
        is_up = random.random() > 0.3  # 70% chance host is up
        
        yield json.dumps({
            'type': 'log',
            'level': 'INFO',
            'message': f'Scanning {ip}...',
            'color': 'white'
        }) + '\n'
        
        host_data = {
            'type': 'host',
            'ip': ip,
            'status': 'up' if is_up else 'down',
            'latency': f'{random.randint(1, 50)}ms' if is_up else None
        }
        
        if is_up:
            # Add hostname (50% chance)
            if random.random() > 0.5:
                host_data['hostname'] = random.choice(HOSTNAMES)
            
            # Add MAC address
            host_data['mac'] = generate_mac_address()
            
            # Add OS detection
            if scan_type in ['os', 'service', 'full']:
                host_data['os'] = random.choice(OS_FINGERPRINTS)
            
            # Add port scan results
            if scan_type != 'ping':
                open_ports = []
                
                if scan_type == 'quick':
                    port_list = random.sample(list(COMMON_PORTS.keys()), random.randint(2, 6))
                elif scan_type == 'full':
                    port_list = random.sample(list(COMMON_PORTS.keys()), random.randint(5, 10))
                else:
                    port_list = random.sample(list(COMMON_PORTS.keys()), random.randint(3, 8))
                
                for port in port_list:
                    port_info = {
                        'port': port,
                        'state': 'open',
                        'service': COMMON_PORTS.get(port, 'unknown')
                    }
                    
                    # Add version info for service scans
                    if scan_type in ['service', 'full']:
                        versions = {
                            'ssh': 'OpenSSH 8.2',
                            'http': 'Apache 2.4.41',
                            'https': 'nginx 1.18.0',
                            'mysql': 'MySQL 8.0.23',
                            'ftp': 'vsftpd 3.0.3'
                        }
                        port_info['version'] = versions.get(port_info['service'], 'N/A')
                    
                    open_ports.append(port_info)
                
                host_data['ports'] = open_ports
        
        yield json.dumps(host_data) + '\n'
    
    # Final summary
    yield json.dumps({
        'type': 'log',
        'level': 'SUCCESS',
        'message': f'Scan complete. Scanned {num_hosts} hosts.',
        'color': 'green'
    }) + '\n'


# Security: Input validation
import re

def validate_target(target):
    """Validate target IP/range format"""
    # Match single IP
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Match CIDR notation
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    # Match IP range
    range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$'
    
    if re.match(ip_pattern, target):
        octets = target.split('.')
        return all(0 <= int(o) <= 255 for o in octets)
    elif re.match(cidr_pattern, target):
        ip, prefix = target.rsplit('/', 1)
        octets = ip.split('.')
        return all(0 <= int(o) <= 255 for o in octets) and 0 <= int(prefix) <= 32
    elif re.match(range_pattern, target):
        return True
    return False


def sanitize_input(text):
    """Sanitize text input to prevent injection attacks"""
    if text is None:
        return ''
    # Remove potentially dangerous characters
    return re.sub(r'[<>"\';`$\\]', '', str(text))


# Rate limiting (simple in-memory implementation)
from functools import wraps
from collections import defaultdict

request_counts = defaultdict(list)
RATE_LIMIT = 10  # requests per minute
RATE_WINDOW = 60  # seconds

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        now = time.time()
        
        # Clean old requests
        request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < RATE_WINDOW]
        
        if len(request_counts[client_ip]) >= RATE_LIMIT:
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
        
        request_counts[client_ip].append(now)
        return f(*args, **kwargs)
    return decorated_function


# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:;"
    return response


# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'NetScanner Pro API',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/scan', methods=['POST'])
@rate_limit
def scan():
    """Start a network scan - returns Server-Sent Events stream"""
    data = request.json
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    target = sanitize_input(data.get('target', ''))
    scan_type = sanitize_input(data.get('scanType', 'quick'))
    ports = sanitize_input(data.get('ports', ''))
    source_ip = sanitize_input(data.get('sourceIP', ''))
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    if not validate_target(target):
        return jsonify({'error': 'Invalid target format. Use IP, CIDR notation, or IP range.'}), 400
    
    valid_scan_types = ['ping', 'quick', 'full', 'stealth', 'service', 'os']
    if scan_type not in valid_scan_types:
        return jsonify({'error': f'Invalid scan type. Must be one of: {", ".join(valid_scan_types)}'}), 400
    
    def generate():
        for result in simulate_scan(target, scan_type, ports, source_ip):
            yield result
    
    return Response(generate(), mimetype='application/x-ndjson')


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get scan statistics"""
    return jsonify({
        'total_scans': 0,
        'active_scans': 0,
        'common_ports': list(COMMON_PORTS.keys()),
        'supported_scan_types': ['ping', 'quick', 'full', 'stealth', 'service', 'os']
    })


@app.route('/api/export/json', methods=['POST'])
@rate_limit
def export_json():
    """Export scan results as JSON"""
    data = request.json
    
    if not data or 'results' not in data:
        return jsonify({'error': 'No results to export'}), 400
    
    export_data = {
        'timestamp': datetime.now().isoformat(),
        'target': sanitize_input(data.get('target', 'N/A')),
        'scanType': sanitize_input(data.get('scanType', 'N/A')),
        'totalHosts': len(data.get('results', [])),
        'results': data.get('results', [])
    }
    
    filename = f"netscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(EXPORTS_DIR, filename)
    
    with open(filepath, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'data': export_data
    })


@app.route('/api/export/csv', methods=['POST'])
@rate_limit
def export_csv():
    """Export scan results as CSV"""
    data = request.json
    
    if not data or 'results' not in data:
        return jsonify({'error': 'No results to export'}), 400
    
    output = BytesIO()
    writer = csv.writer(output, lineterminator='\n')
    
    # Header
    writer.writerow(['IP Address', 'Status', 'Hostname', 'OS', 'MAC', 'Latency', 'Open Ports', 'Services'])
    
    for host in data.get('results', []):
        ports_str = ';'.join([str(p.get('port', '')) for p in host.get('ports', [])])
        services_str = ';'.join([p.get('service', 'unknown') for p in host.get('ports', [])])
        
        writer.writerow([
            host.get('ip', ''),
            host.get('status', ''),
            host.get('hostname', 'N/A'),
            host.get('os', 'N/A'),
            host.get('mac', 'N/A'),
            host.get('latency', 'N/A'),
            ports_str,
            services_str
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue().decode('utf-8'),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=netscan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )


@app.route('/api/export/pdf', methods=['POST'])
@rate_limit
def export_pdf():
    """Export scan results as PDF - Note: Full PDF generation requires frontend jsPDF"""
    data = request.json
    
    if not data or 'results' not in data:
        return jsonify({'error': 'No results to export'}), 400
    
    # For PDF, we return structured data that the frontend can use with jsPDF
    return jsonify({
        'success': True,
        'message': 'PDF generation should be handled client-side with jsPDF',
        'data': {
            'timestamp': datetime.now().isoformat(),
            'target': data.get('target', 'N/A'),
            'scanType': data.get('scanType', 'N/A'),
            'results': data.get('results', [])
        }
    })


if __name__ == '__main__':
    print('🚀 NetScanner Pro Backend Starting...')
    print('📊 Export & Visualization features enabled')
    print('⚠️  EDUCATIONAL USE ONLY - Scan responsibly!')
    print('🔒 Security headers and rate limiting enabled')
    print('-' * 50)
    
    # Set debug=False for production
    app.run(host='127.0.0.1', port=5000, debug=False)
