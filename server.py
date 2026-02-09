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
ALLOWED_STATIC_EXTENSIONS = {
    '.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'
}

EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')
os.makedirs(EXPORTS_DIR, exist_ok=True)
MAX_EXPORT_FILES = 100  # Prevent unbounded disk usage


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


# ── Simulated Data ─────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
    139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'smb',
    993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
    2049: 'nfs', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
    5900: 'vnc', 6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
    9200: 'elasticsearch', 27017: 'mongodb'
}

UDP_PORTS = {
    53: 'dns', 67: 'dhcp-server', 68: 'dhcp-client', 69: 'tftp',
    123: 'ntp', 137: 'netbios-ns', 138: 'netbios-dgm', 161: 'snmp',
    162: 'snmp-trap', 500: 'isakmp', 514: 'syslog', 520: 'rip',
    1194: 'openvpn', 1900: 'ssdp', 4500: 'ipsec-nat-t', 5353: 'mdns'
}

SERVICE_VERSIONS = {
    'ssh': ['OpenSSH 8.2p1', 'OpenSSH 8.9p1', 'OpenSSH 9.3p1', 'Dropbear 2022.83'],
    'http': ['Apache 2.4.41', 'Apache 2.4.57', 'nginx 1.18.0', 'nginx 1.24.0', 'lighttpd 1.4.59'],
    'https': ['nginx 1.18.0', 'nginx 1.24.0', 'Apache 2.4.57', 'IIS 10.0'],
    'mysql': ['MySQL 8.0.23', 'MySQL 8.0.35', 'MariaDB 10.11.4'],
    'ftp': ['vsftpd 3.0.3', 'ProFTPD 1.3.8', 'Pure-FTPd 1.0.51'],
    'smtp': ['Postfix smtpd', 'Microsoft ESMTP', 'Exim 4.96'],
    'rdp': ['Microsoft Terminal Services', 'xrdp 0.9.22'],
    'postgresql': ['PostgreSQL 15.4', 'PostgreSQL 16.1'],
    'redis': ['Redis 7.0.12', 'Redis 7.2.3'],
    'mongodb': ['MongoDB 6.0.11', 'MongoDB 7.0.4'],
    'smb': ['Samba 4.18.6', 'Windows Server 2019 SMB'],
    'dns': ['BIND 9.18.18', 'dnsmasq 2.89', 'Unbound 1.19.0'],
    'snmp': ['net-snmp 5.9.3', 'Cisco IOS SNMP'],
    'elasticsearch': ['Elasticsearch 8.11.1', 'Elasticsearch 7.17.15'],
    'vnc': ['TightVNC 1.3.10', 'RealVNC 6.11.0'],
    'ntp': ['ntpd 4.2.8p17', 'chrony 4.4'],
}

OS_FINGERPRINTS = [
    'Linux 5.x', 'Linux 6.x', 'Windows 10 Build 19045', 'Windows 11 Build 22621',
    'Windows Server 2019', 'Windows Server 2022', 'macOS 13.x Ventura',
    'macOS 14.x Sonoma', 'Ubuntu 22.04 LTS', 'Ubuntu 24.04 LTS',
    'Debian 12', 'CentOS Stream 9', 'RHEL 9', 'FreeBSD 14.0',
    'Android 13', 'Android 14', 'Cisco IOS 17.x', 'pfSense 2.7'
]

HOSTNAMES = [
    'gateway.local', 'router.local', 'firewall.local', 'switch-core.local',
    'dc01.corp.local', 'dc02.corp.local', 'web-srv01.local', 'web-srv02.local',
    'db-primary.local', 'db-replica.local', 'nas01.local', 'backup-srv.local',
    'mail.local', 'vpn.local', 'proxy.local', 'monitoring.local',
    'printer-floor2.local', 'ap-lobby.local', 'cam-entrance.local',
    'workstation-042.local', 'dev-laptop.local', 'kiosk-reception.local'
]

VULNERABILITIES = [
    {'cve': 'CVE-2021-44228', 'name': 'Log4Shell', 'severity': 'critical',
     'services': ['http', 'https', 'http-proxy', 'https-alt', 'elasticsearch'],
     'description': 'Apache Log4j2 RCE via JNDI lookup injection'},
    {'cve': 'CVE-2023-44487', 'name': 'HTTP/2 Rapid Reset', 'severity': 'high',
     'services': ['http', 'https', 'http-proxy', 'https-alt'],
     'description': 'HTTP/2 protocol DDoS amplification vulnerability'},
    {'cve': 'CVE-2024-3094', 'name': 'XZ Utils Backdoor', 'severity': 'critical',
     'services': ['ssh'],
     'description': 'Backdoor in xz/liblzma compromising SSH authentication'},
    {'cve': 'CVE-2019-0708', 'name': 'BlueKeep', 'severity': 'critical',
     'services': ['rdp'],
     'description': 'Windows Remote Desktop Services RCE (wormable)'},
    {'cve': 'CVE-2022-22965', 'name': 'Spring4Shell', 'severity': 'critical',
     'services': ['http', 'https', 'http-proxy'],
     'description': 'Spring Framework RCE via ClassLoader data binding'},
    {'cve': 'CVE-2021-26855', 'name': 'ProxyLogon', 'severity': 'critical',
     'services': ['https'],
     'description': 'Microsoft Exchange Server SSRF leading to RCE'},
    {'cve': 'CVE-2023-27997', 'name': 'FortiGate RCE', 'severity': 'critical',
     'services': ['https'],
     'description': 'Fortinet FortiOS heap-based buffer overflow in SSL VPN'},
    {'cve': 'CVE-2020-1472', 'name': 'Zerologon', 'severity': 'critical',
     'services': ['msrpc', 'smb'],
     'description': 'Netlogon privilege escalation via cryptographic flaw'},
    {'cve': 'CVE-2023-23397', 'name': 'Outlook Elevation', 'severity': 'critical',
     'services': ['smtp', 'imap', 'imaps'],
     'description': 'Microsoft Outlook NTLM relay elevation of privilege'},
    {'cve': 'CVE-2021-41773', 'name': 'Apache Path Traversal', 'severity': 'high',
     'services': ['http', 'http-proxy'],
     'description': 'Apache HTTP Server 2.4.49 path traversal and RCE'},
    {'cve': 'CVE-2022-0778', 'name': 'OpenSSL Infinite Loop', 'severity': 'high',
     'services': ['https', 'imaps', 'pop3s'],
     'description': 'BN_mod_sqrt() infinite loop causing DoS on malformed certs'},
    {'cve': 'CVE-2020-14882', 'name': 'WebLogic RCE', 'severity': 'critical',
     'services': ['http', 'https', 'http-proxy'],
     'description': 'Oracle WebLogic Server admin console unauthenticated RCE'},
    {'cve': 'CVE-2023-46604', 'name': 'Apache ActiveMQ RCE', 'severity': 'critical',
     'services': ['http', 'http-proxy'],
     'description': 'ClassPathXmlApplicationContext RCE in Apache ActiveMQ'},
    {'cve': 'CVE-2021-3156', 'name': 'Baron Samedit', 'severity': 'high',
     'services': ['ssh'],
     'description': 'Sudo heap-based buffer overflow local privilege escalation'},
    {'cve': 'CVE-2017-0144', 'name': 'EternalBlue', 'severity': 'critical',
     'services': ['smb'],
     'description': 'Windows SMBv1 RCE (WannaCry/NotPetya attack vector)'},
    {'cve': 'CVE-2022-26134', 'name': 'Confluence OGNL Injection', 'severity': 'critical',
     'services': ['http', 'https'],
     'description': 'Atlassian Confluence unauthenticated OGNL injection RCE'},
    {'cve': 'CVE-2023-22515', 'name': 'Confluence Broken Access', 'severity': 'critical',
     'services': ['http', 'https'],
     'description': 'Atlassian Confluence privilege escalation to admin'},
    {'cve': 'CVE-2021-22986', 'name': 'F5 BIG-IP iControl RCE', 'severity': 'critical',
     'services': ['https'],
     'description': 'F5 BIG-IP iControl REST unauthenticated RCE'},
    {'cve': 'CVE-2024-21887', 'name': 'Ivanti Connect Secure', 'severity': 'critical',
     'services': ['https'],
     'description': 'Ivanti Connect Secure command injection (chained with SSRF)'},
    {'cve': 'CVE-2023-48788', 'name': 'FortiClient EMS SQLi', 'severity': 'critical',
     'services': ['https'],
     'description': 'Fortinet FortiClient EMS SQL injection to RCE'},
    {'cve': 'CVE-2020-25213', 'name': 'WP File Manager RCE', 'severity': 'critical',
     'services': ['http', 'https'],
     'description': 'WordPress File Manager plugin unauthenticated RCE'},
    {'cve': 'CVE-2023-36884', 'name': 'Office HTML RCE', 'severity': 'high',
     'services': ['smtp'],
     'description': 'Microsoft Office HTML RCE via crafted documents'},
    {'cve': 'CVE-2022-41040', 'name': 'ProxyNotShell', 'severity': 'high',
     'services': ['https'],
     'description': 'Microsoft Exchange Server SSRF (ProxyShell variant)'},
    {'cve': 'CVE-2021-34527', 'name': 'PrintNightmare', 'severity': 'critical',
     'services': ['smb', 'msrpc'],
     'description': 'Windows Print Spooler RCE and privilege escalation'},
    {'cve': 'CVE-2023-20198', 'name': 'Cisco IOS XE Web UI', 'severity': 'critical',
     'services': ['http', 'https'],
     'description': 'Cisco IOS XE Web UI privilege escalation (implant deployment)'},
]

TIMING_PROFILES = {
    1: {'name': 'Paranoid',   'init_delay': 2.0,  'host_delay': (1.5, 3.0)},
    2: {'name': 'Polite',     'init_delay': 1.0,  'host_delay': (0.5, 1.0)},
    3: {'name': 'Normal',     'init_delay': 0.3,  'host_delay': (0.1, 0.3)},
    4: {'name': 'Aggressive', 'init_delay': 0.1,  'host_delay': (0.03, 0.1)},
    5: {'name': 'Insane',     'init_delay': 0.05, 'host_delay': (0.01, 0.05)},
}


# ── Helper Functions ───────────────────────────────────────────────────────

def generate_target_ips(target):
    """Generate the correct list of IPs based on the target specification."""
    if '/' in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            num_hosts = random.randint(5, 15)
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
        return [target]


def generate_mac_address():
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])


def parse_custom_ports(ports_str):
    """Parse custom port specification like '22,80,443' or '1-1000'."""
    if not ports_str:
        return None
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                for p in range(max(1, int(start)), min(65535, int(end)) + 1):
                    ports.add(p)
                    if len(ports) > 1000:
                        return sorted(ports)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports) if ports else None


def get_service_version(service):
    """Get a random realistic version string for a service."""
    versions = SERVICE_VERSIONS.get(service)
    if versions:
        return random.choice(versions)
    return 'N/A'


def find_vulns_for_services(services):
    """Find potential vulnerabilities matching a set of service names."""
    matched = []
    for vuln in VULNERABILITIES:
        if any(s in vuln['services'] for s in services):
            if random.random() < 0.15:  # 15% chance per matching vuln
                matched.append({
                    'cve': vuln['cve'],
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'description': vuln['description']
                })
    return matched


def simulate_traceroute(target_ip):
    """Simulate traceroute hops to a target IP."""
    num_hops = random.randint(4, 12)
    hops = []
    for i in range(1, num_hops + 1):
        if i == 1:
            hop_ip = '192.168.1.1'
        elif i == num_hops:
            hop_ip = target_ip
        else:
            hop_ip = (f'{random.randint(10, 200)}.{random.randint(0, 255)}'
                      f'.{random.randint(0, 255)}.{random.randint(1, 254)}')
        rtt = round(random.uniform(0.5, 5.0) * i, 1)
        lost = random.random() < 0.05  # 5% packet loss
        hops.append({
            'hop': i,
            'ip': '*' if lost else hop_ip,
            'rtt': None if lost else f'{rtt}ms',
            'hostname': None if lost else (
                random.choice([None, f'hop-{i}.isp.net', f'core-{i}.backbone.net'])
            )
        })
    return hops


def cleanup_old_exports():
    """Remove oldest export files if over the limit."""
    try:
        files = sorted(
            [os.path.join(EXPORTS_DIR, f) for f in os.listdir(EXPORTS_DIR)],
            key=os.path.getmtime
        )
        while len(files) > MAX_EXPORT_FILES:
            os.remove(files.pop(0))
    except OSError:
        pass


# ── Scan Simulation ────────────────────────────────────────────────────────

def simulate_scan(target, scan_type, ports=None, source_ip=None, timing=3):
    """Simulate network scan and yield NDJSON results."""
    profile = TIMING_PROFILES.get(timing, TIMING_PROFILES[3])
    custom_ports = parse_custom_ports(ports)

    # Initial log
    yield json.dumps({
        'type': 'log', 'level': 'INFO',
        'message': f'Initiating {scan_type.upper()} scan on {target}',
        'color': 'cyan'
    }) + '\n'

    yield json.dumps({
        'type': 'log', 'level': 'INFO',
        'message': f'Timing: T{timing} ({profile["name"]}) | '
                   f'{"Custom ports: " + ports if custom_ports else "Default port set"}',
        'color': 'cyan'
    }) + '\n'

    time.sleep(profile['init_delay'])

    ips_to_scan = generate_target_ips(target)
    vuln_count = 0

    for ip in ips_to_scan:
        time.sleep(random.uniform(*profile['host_delay']))
        is_up = random.random() > 0.3

        yield json.dumps({
            'type': 'log', 'level': 'INFO',
            'message': f'Scanning {ip}...', 'color': 'white'
        }) + '\n'

        host_data = {
            'type': 'host',
            'ip': ip,
            'status': 'up' if is_up else 'down',
            'latency': f'{random.randint(1, 50)}ms' if is_up else None
        }

        if is_up:
            # Hostname (50% chance)
            if random.random() > 0.5:
                host_data['hostname'] = random.choice(HOSTNAMES)

            # MAC address
            host_data['mac'] = generate_mac_address()

            # OS detection
            if scan_type in ('os', 'service', 'full', 'aggressive', 'vuln'):
                host_data['os'] = random.choice(OS_FINGERPRINTS)

            # Port scanning
            if scan_type != 'ping':
                open_ports = []
                port_source = UDP_PORTS if scan_type == 'udp' else COMMON_PORTS

                if custom_ports:
                    port_list = [p for p in custom_ports
                                 if p in port_source and random.random() > 0.3]
                    if not port_list:
                        port_list = random.sample(
                            list(port_source.keys()),
                            min(random.randint(2, 4), len(port_source))
                        )
                elif scan_type == 'quick':
                    port_list = random.sample(
                        list(port_source.keys()),
                        random.randint(2, 6)
                    )
                elif scan_type in ('full', 'aggressive'):
                    port_list = random.sample(
                        list(port_source.keys()),
                        random.randint(5, min(12, len(port_source)))
                    )
                else:
                    port_list = random.sample(
                        list(port_source.keys()),
                        random.randint(3, 8)
                    )

                for port in sorted(port_list):
                    state = 'open' if random.random() > 0.1 else 'filtered'
                    port_info = {
                        'port': port,
                        'state': state,
                        'protocol': 'udp' if scan_type == 'udp' else 'tcp',
                        'service': port_source.get(port, 'unknown')
                    }

                    if scan_type in ('service', 'full', 'aggressive'):
                        port_info['version'] = get_service_version(port_info['service'])

                    open_ports.append(port_info)

                host_data['ports'] = open_ports

                # Vulnerability scanning
                if scan_type in ('vuln', 'aggressive'):
                    services = {p['service'] for p in open_ports}
                    vulns = find_vulns_for_services(services)
                    if vulns:
                        host_data['vulnerabilities'] = vulns
                        vuln_count += len(vulns)
                        for v in vulns:
                            yield json.dumps({
                                'type': 'log', 'level': 'WARNING',
                                'message': f'[VULN] {ip}: {v["cve"]} - '
                                           f'{v["name"]} ({v["severity"].upper()})',
                                'color': 'red'
                            }) + '\n'

            # Traceroute (aggressive scan only)
            if scan_type == 'aggressive':
                host_data['traceroute'] = simulate_traceroute(ip)
                yield json.dumps({
                    'type': 'log', 'level': 'INFO',
                    'message': f'Traceroute to {ip}: '
                               f'{len(host_data["traceroute"])} hops',
                    'color': 'yellow'
                }) + '\n'

        yield json.dumps(host_data) + '\n'

    # Summary
    summary = f'Scan complete. {len(ips_to_scan)} hosts scanned.'
    if vuln_count > 0:
        summary += f' {vuln_count} vulnerabilities found!'
    yield json.dumps({
        'type': 'log', 'level': 'SUCCESS',
        'message': summary, 'color': 'green'
    }) + '\n'


# ── Security ───────────────────────────────────────────────────────────────

def validate_target(target):
    """Validate target IP/range format."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
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
    """Sanitize text input to prevent injection attacks."""
    if text is None:
        return ''
    text = str(text)
    text = text.replace('\x00', '')
    text = re.sub(r'[<>"\';`$\\&()\x00-\x1f]', '', text)
    return text[:255]


# Rate limiting
request_counts = defaultdict(list)
RATE_LIMIT = 10
RATE_WINDOW = 60
MAX_TRACKED_IPS = 10000

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        now = time.time()
        request_counts[client_ip] = [
            t for t in request_counts[client_ip] if now - t < RATE_WINDOW
        ]
        if len(request_counts) > MAX_TRACKED_IPS:
            stale_ips = [ip for ip, times in request_counts.items() if not times]
            for ip in stale_ips:
                del request_counts[ip]
        if len(request_counts[client_ip]) >= RATE_LIMIT:
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
        request_counts[client_ip].append(now)
        return f(*args, **kwargs)
    return decorated_function


# Security headers
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


# ── API Routes ─────────────────────────────────────────────────────────────

VALID_SCAN_TYPES = ['ping', 'quick', 'full', 'stealth', 'service', 'os',
                    'vuln', 'udp', 'aggressive']

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'service': 'NetScanner Pro API',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/scan', methods=['POST'])
@rate_limit
def scan():
    """Start a network scan - returns NDJSON stream."""
    data = request.json
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    target = sanitize_input(data.get('target', ''))
    scan_type = sanitize_input(data.get('scanType', 'quick'))
    ports = sanitize_input(data.get('ports', ''))
    source_ip = sanitize_input(data.get('sourceIP', ''))
    timing = data.get('timing', 3)

    if not isinstance(timing, int) or timing not in range(1, 6):
        timing = 3

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    if not validate_target(target):
        return jsonify({'error': 'Invalid target format. Use IP, CIDR notation, or IP range.'}), 400

    if scan_type not in VALID_SCAN_TYPES:
        return jsonify({
            'error': f'Invalid scan type. Must be one of: {", ".join(VALID_SCAN_TYPES)}'
        }), 400

    def generate():
        for result in simulate_scan(target, scan_type, ports, source_ip, timing):
            yield result

    return Response(generate(), mimetype='application/x-ndjson')


@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify({
        'total_scans': 0,
        'active_scans': 0,
        'common_ports': list(COMMON_PORTS.keys()),
        'udp_ports': list(UDP_PORTS.keys()),
        'supported_scan_types': VALID_SCAN_TYPES,
        'timing_profiles': {k: v['name'] for k, v in TIMING_PROFILES.items()}
    })


@app.route('/api/export/json', methods=['POST'])
@rate_limit
def export_json():
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

    cleanup_old_exports()
    unique_id = uuid.uuid4().hex[:8]
    filename = f"netscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{unique_id}.json"
    filepath = os.path.join(EXPORTS_DIR, filename)

    with open(filepath, 'w') as f:
        json.dump(export_data, f, indent=2)

    return jsonify({'success': True, 'filename': filename, 'data': export_data})


@app.route('/api/export/csv', methods=['POST'])
@rate_limit
def export_csv():
    data = request.json
    if not data or 'results' not in data:
        return jsonify({'error': 'No results to export'}), 400

    output = BytesIO()
    writer = csv.writer(output, lineterminator='\n')
    writer.writerow([
        'IP Address', 'Status', 'Hostname', 'OS', 'MAC', 'Latency',
        'Open Ports', 'Services', 'Vulnerabilities'
    ])

    for host in data.get('results', []):
        ports_str = ';'.join([str(p.get('port', '')) for p in host.get('ports', [])])
        services_str = ';'.join([p.get('service', 'unknown') for p in host.get('ports', [])])
        vulns_str = ';'.join([v.get('cve', '') for v in host.get('vulnerabilities', [])])

        writer.writerow([
            host.get('ip', ''), host.get('status', ''),
            host.get('hostname', 'N/A'), host.get('os', 'N/A'),
            host.get('mac', 'N/A'), host.get('latency', 'N/A'),
            ports_str, services_str, vulns_str
        ])

    output.seek(0)
    return Response(
        output.getvalue().decode('utf-8'),
        mimetype='text/csv',
        headers={
            'Content-Disposition':
            f'attachment; filename=netscan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    )


@app.route('/api/export/pdf', methods=['POST'])
@rate_limit
def export_pdf():
    data = request.json
    if not data or 'results' not in data:
        return jsonify({'error': 'No results to export'}), 400

    return jsonify({
        'success': True,
        'message': 'PDF generation handled client-side with jsPDF',
        'data': {
            'timestamp': datetime.now().isoformat(),
            'target': sanitize_input(data.get('target', 'N/A')),
            'scanType': sanitize_input(data.get('scanType', 'N/A')),
            'results': data.get('results', [])
        }
    })


if __name__ == '__main__':
    print('NetScanner Pro v2.0 Starting...')
    print('Scan types: ' + ', '.join(VALID_SCAN_TYPES))
    print('EDUCATIONAL USE ONLY - Scan responsibly!')
    print('Security headers and rate limiting enabled')
    print('-' * 50)
    app.run(host='0.0.0.0', port=5000, debug=False)
