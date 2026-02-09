from flask import Flask, request, jsonify, Response, send_file, send_from_directory, abort
from flask_cors import CORS
import json
import time
import random
import os
import re
import uuid
import ipaddress
from datetime import datetime
from io import BytesIO
import csv
from functools import wraps
from collections import defaultdict

# Get the directory where server.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app, origins=[
    'http://localhost:5000',
    'http://127.0.0.1:5000',
    f'http://{os.environ.get("ALLOWED_HOST", "localhost")}:5000'
])

# Enforce max request body at Flask level (prevents Content-Length header spoofing)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

# Allowed static file extensions to prevent path traversal to sensitive files
ALLOWED_STATIC_EXTENSIONS = {'.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'}

EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')
os.makedirs(EXPORTS_DIR, exist_ok=True)


# Serve static files (HTML, CSS, JS)
@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    # Prevent path traversal and restrict to allowed file types
    if '..' in filename or filename.startswith('/'):
        abort(403)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_STATIC_EXTENSIONS:
        abort(403)
    return send_from_directory(BASE_DIR, filename)

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

def generate_target_ips(target):
    """Generate the correct list of IPs based on the target specification."""
    if '/' in target:
        # CIDR notation - generate IPs within the actual subnet
        try:
            network = ipaddress.ip_network(target, strict=False)
            num_hosts = random.randint(5, 15)
            # Avoid enumerating huge networks
            if network.num_addresses > 256:
                start = int(network.network_address) + 1
                end = int(network.broadcast_address) - 1
                if end <= start:
                    return [str(network.network_address)]
                ips = set()
                while len(ips) < num_hosts:
                    ips.add(str(ipaddress.ip_address(random.randint(start, end))))
                return list(ips)
            else:
                hosts = list(network.hosts())
                if not hosts:
                    return [str(network.network_address)]
                return [str(ip) for ip in random.sample(hosts, min(num_hosts, len(hosts)))]
        except ValueError:
            return [target]
    elif '-' in target:
        # IP range (e.g., 192.168.1.1-192.168.1.254)
        try:
            start_ip, end_ip = target.split('-')
            start_int = int(ipaddress.ip_address(start_ip.strip()))
            end_int = int(ipaddress.ip_address(end_ip.strip()))
            if start_int > end_int:
                start_int, end_int = end_int, start_int
            range_size = end_int - start_int + 1
            num_hosts = random.randint(3, min(10, range_size))
            ips = set()
            while len(ips) < num_hosts:
                ips.add(str(ipaddress.ip_address(random.randint(start_int, end_int))))
            return list(ips)
        except ValueError:
            return [target]
    else:
        # Single IP - return exactly this IP
        return [target]


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

    # Generate correct IPs for the target
    ips_to_scan = generate_target_ips(target)

    # Scan hosts
    for ip in ips_to_scan:
        time.sleep(random.uniform(0.3, 0.8))

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
        'message': f'Scan complete. Scanned {len(ips_to_scan)} hosts.',
        'color': 'green'
    }) + '\n'


# Security: Input validation
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
        start_ip, end_ip = target.split('-')
        start_octets = start_ip.split('.')
        end_octets = end_ip.split('.')
        return (all(0 <= int(o) <= 255 for o in start_octets) and
                all(0 <= int(o) <= 255 for o in end_octets))
    return False


def sanitize_input(text):
    """Sanitize text input to prevent injection attacks"""
    if text is None:
        return ''
    text = str(text)
    # Strip null bytes
    text = text.replace('\x00', '')
    # Remove potentially dangerous characters for HTML, shell, and SQL contexts
    text = re.sub(r'[<>"\';`$\\&()\x00-\x1f]', '', text)
    # Limit length to prevent abuse
    return text[:255]


# Rate limiting (simple in-memory implementation)
request_counts = defaultdict(list)
RATE_LIMIT = 10  # requests per minute
RATE_WINDOW = 60  # seconds

MAX_TRACKED_IPS = 10000  # Prevent unbounded memory growth

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        now = time.time()

        # Clean old requests for this IP
        request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < RATE_WINDOW]

        # Prune stale IPs to prevent memory leak
        if len(request_counts) > MAX_TRACKED_IPS:
            stale_ips = [ip for ip, times in request_counts.items() if not times]
            for ip in stale_ips:
                del request_counts[ip]

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
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
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

    results = data.get('results', [])
    if not isinstance(results, list) or len(results) > 1000:
        return jsonify({'error': 'Invalid or too many results (max 1000)'}), 400

    export_data = {
        'timestamp': datetime.now().isoformat(),
        'target': sanitize_input(data.get('target', 'N/A')),
        'scanType': sanitize_input(data.get('scanType', 'N/A')),
        'totalHosts': len(results),
        'results': results
    }

    # UUID prevents race condition with concurrent requests
    unique_id = uuid.uuid4().hex[:8]
    filename = f"netscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{unique_id}.json"
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
            'target': sanitize_input(data.get('target', 'N/A')),
            'scanType': sanitize_input(data.get('scanType', 'N/A')),
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
    # Bind to 0.0.0.0 to allow access from network PCs
    app.run(host='0.0.0.0', port=5000, debug=False)
