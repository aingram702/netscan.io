from flask import Flask, request, jsonify, Response, send_from_directory, abort
from flask_cors import CORS
import json
import time
import os
import re
import uuid
import shutil
import ipaddress
import socket
import nmap
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

# Enforce max request body at Flask level
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB

# Allowed static file extensions to prevent path traversal
ALLOWED_STATIC_EXTENSIONS = {
    '.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'
}

EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')
os.makedirs(EXPORTS_DIR, exist_ok=True)
MAX_EXPORT_FILES = 100


# ── nmap Configuration ────────────────────────────────────────────────────

def check_nmap():
    """Check if nmap is installed and return version info."""
    if shutil.which('nmap') is None:
        return False, None, 'nmap not found'
    try:
        nm = nmap.PortScanner()
        version = nm.nmap_version()
        return True, f'{version[0]}.{version[1]}', 'available'
    except Exception as e:
        return False, None, str(e)


NMAP_AVAILABLE, NMAP_VERSION, NMAP_STATUS = check_nmap()
IS_ROOT = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

# Scan type → nmap arguments
SCAN_ARGUMENTS = {
    'ping':       '-sn',
    'quick':      '-F',
    'full':       '-p 1-65535 -sV',
    'stealth':    '-sS',
    'service':    '-sV',
    'os':         '-O -sV',
    'udp':        '-sU --top-ports 100',
    'vuln':       '-sV --script vuln --script-timeout 60',
    'aggressive': '-A --script-timeout 60',
}

# Scans that require root privileges
PRIVILEGED_SCANS = {'stealth', 'os', 'udp', 'aggressive'}
VALID_SCAN_TYPES = list(SCAN_ARGUMENTS.keys())


def get_local_ip():
    """Get the primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


# ── Static File Serving ───────────────────────────────────────────────────

@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    if '..' in filename or filename.startswith('/'):
        abort(403)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_STATIC_EXTENSIONS:
        abort(403)
    return send_from_directory(BASE_DIR, filename)


# ── Security ──────────────────────────────────────────────────────────────

def sanitize_input(text):
    """Sanitize text input to prevent injection attacks."""
    if text is None:
        return ''
    text = str(text)
    text = text.replace('\x00', '')
    text = re.sub(r'[<>"\';`$\\&()\x00-\x1f]', '', text)
    return text[:255]


def validate_target(target):
    """Validate target IP/CIDR/range/hostname format."""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'

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
    elif re.match(hostname_pattern, target) and len(target) <= 253:
        return True
    return False


def convert_target_for_nmap(target):
    """Convert IP range format to nmap-compatible format."""
    if '-' not in target or '/' in target:
        return target

    parts = target.split('-', 1)
    if len(parts) != 2:
        return target

    try:
        start = ipaddress.ip_address(parts[0].strip())
        end = ipaddress.ip_address(parts[1].strip())
        if int(start) > int(end):
            start, end = end, start

        # Same /24 → use nmap shorthand (192.168.1.1-254)
        start_octets = str(start).split('.')
        end_octets = str(end).split('.')
        if start_octets[:3] == end_octets[:3]:
            return f"{start}-{end_octets[3]}"
        else:
            # Cross-subnet → convert to CIDR blocks
            cidrs = list(ipaddress.summarize_address_range(start, end))
            return ' '.join(str(c) for c in cidrs)
    except (ValueError, TypeError):
        return target


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


# ── nmap Scanning Engine ──────────────────────────────────────────────────

def build_nmap_args(scan_type, timing, ports=None, skip_discovery=False):
    """Build nmap command arguments from scan parameters."""
    args = SCAN_ARGUMENTS.get(scan_type, '-F')
    args += f' -T{timing}'

    if ports and scan_type != 'ping':
        args += f' -p {ports}'

    if skip_discovery and scan_type != 'ping':
        args += ' -Pn'

    args += ' --host-timeout 300s --reason'
    return args


def parse_host_result(nm, host, scan_type):
    """Parse nmap scan results for a single host into frontend-compatible JSON."""
    host_data = {
        'type': 'host',
        'ip': host,
        'status': nm[host].state() if host in nm.all_hosts() else 'down',
    }

    if host_data['status'] != 'up':
        return host_data

    # Hostname
    try:
        hostname = nm[host].hostname()
        if hostname:
            host_data['hostname'] = hostname
    except Exception:
        pass

    # MAC address and vendor
    try:
        addresses = nm[host].get('addresses', {})
        if 'mac' in addresses:
            host_data['mac'] = addresses['mac']
        vendor = nm[host].get('vendor', {})
        if vendor:
            mac = addresses.get('mac', '')
            if mac in vendor:
                host_data['vendor'] = vendor[mac]
    except Exception:
        pass

    # Status reason (e.g., echo-reply, syn-ack)
    try:
        status = nm[host].get('status', {})
        reason = status.get('reason', '')
        if reason:
            host_data['status_reason'] = reason
    except Exception:
        pass

    # OS detection
    try:
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            os_matches = nm[host]['osmatch']
            if os_matches:
                host_data['os'] = os_matches[0]['name']
                host_data['os_accuracy'] = os_matches[0].get('accuracy', '')
                if len(os_matches) > 1:
                    host_data['os_alternatives'] = [
                        {'name': m['name'], 'accuracy': m.get('accuracy', '')}
                        for m in os_matches[1:4]
                    ]
    except Exception:
        pass

    # Ports and vulnerabilities
    ports = []
    vulnerabilities = []

    for proto in ['tcp', 'udp']:
        try:
            if proto in nm[host]:
                for port_num in sorted(nm[host][proto].keys()):
                    port_info = nm[host][proto][port_num]

                    # Build version string
                    version_parts = []
                    if port_info.get('product'):
                        version_parts.append(port_info['product'])
                    if port_info.get('version'):
                        version_parts.append(port_info['version'])
                    if port_info.get('extrainfo'):
                        version_parts.append(f"({port_info['extrainfo']})")

                    port_data = {
                        'port': port_num,
                        'state': port_info.get('state', 'unknown'),
                        'protocol': proto,
                        'service': port_info.get('name', 'unknown'),
                        'version': ' '.join(version_parts) if version_parts else None,
                    }

                    if port_info.get('reason'):
                        port_data['reason'] = port_info['reason']
                    if port_info.get('cpe'):
                        port_data['cpe'] = port_info['cpe']

                    # Script results → vulnerability extraction
                    if 'script' in port_info:
                        for script_name, output in port_info['script'].items():
                            output_str = str(output)
                            cves = list(set(re.findall(r'CVE-\d{4}-\d+', output_str)))

                            if cves:
                                for cve in cves:
                                    cvss_match = re.search(
                                        rf'{re.escape(cve)}\s+(\d+\.?\d*)', output_str
                                    )
                                    score = float(cvss_match.group(1)) if cvss_match else None

                                    if score:
                                        if score >= 9.0:
                                            severity = 'critical'
                                        elif score >= 7.0:
                                            severity = 'high'
                                        elif score >= 4.0:
                                            severity = 'medium'
                                        else:
                                            severity = 'low'
                                    elif 'VULNERABLE' in output_str.upper():
                                        severity = 'critical'
                                    else:
                                        severity = 'high'

                                    vulnerabilities.append({
                                        'cve': cve,
                                        'name': script_name,
                                        'severity': severity,
                                        'port': port_num,
                                        'description': output_str[:500],
                                    })
                            elif 'VULNERABLE' in output_str.upper():
                                vulnerabilities.append({
                                    'cve': script_name,
                                    'name': script_name,
                                    'severity': 'high',
                                    'port': port_num,
                                    'description': output_str[:500],
                                })

                    ports.append(port_data)
        except Exception:
            pass

    if ports:
        host_data['ports'] = ports
    if vulnerabilities:
        host_data['vulnerabilities'] = vulnerabilities

    # Traceroute
    try:
        trace = nm[host].get('trace', None)
        if trace and 'hops' in trace:
            host_data['traceroute'] = [
                {
                    'hop': int(hop.get('ttl', i + 1)),
                    'ip': hop.get('ipaddr', '*'),
                    'rtt': f"{hop.get('rtt', '?')}ms" if hop.get('rtt') else '* * *',
                    'hostname': hop.get('host') if hop.get('host') else None,
                }
                for i, hop in enumerate(trace['hops'])
            ]
    except Exception:
        pass

    return host_data


def nmap_scan(target, scan_type, ports=None, timing=3, skip_discovery=False):
    """Perform real nmap scan and yield NDJSON results."""
    if not NMAP_AVAILABLE:
        yield json.dumps({
            'type': 'log', 'level': 'ERROR',
            'message': 'nmap is not installed. Install with: sudo apt install nmap',
            'color': 'red'
        }) + '\n'
        return

    nm = nmap.PortScanner()

    # Convert target format for nmap compatibility
    nmap_target = convert_target_for_nmap(target)
    scan_args = build_nmap_args(scan_type, timing, ports, skip_discovery)

    # Check privilege requirements and apply fallbacks
    if scan_type in PRIVILEGED_SCANS and not IS_ROOT:
        if scan_type == 'stealth':
            scan_args = scan_args.replace('-sS', '-sT')
            yield json.dumps({
                'type': 'log', 'level': 'WARNING',
                'message': 'SYN stealth scan requires root. Falling back to TCP connect scan (-sT).',
                'color': 'yellow'
            }) + '\n'
        elif scan_type == 'os':
            scan_args = scan_args.replace('-O ', '')
            yield json.dumps({
                'type': 'log', 'level': 'WARNING',
                'message': 'OS detection requires root. Running service detection only.',
                'color': 'yellow'
            }) + '\n'
        elif scan_type == 'udp':
            yield json.dumps({
                'type': 'log', 'level': 'ERROR',
                'message': 'UDP scan requires root privileges. Run: sudo python server.py',
                'color': 'red'
            }) + '\n'
            return
        elif scan_type == 'aggressive':
            scan_args = scan_args.replace('-A', '-sV -sC --traceroute')
            yield json.dumps({
                'type': 'log', 'level': 'WARNING',
                'message': 'Aggressive scan limited without root (no OS detection, no SYN scan).',
                'color': 'yellow'
            }) + '\n'

    yield json.dumps({
        'type': 'log', 'level': 'INFO',
        'message': f'Initiating {scan_type.upper()} scan on {target}',
        'color': 'cyan'
    }) + '\n'

    yield json.dumps({
        'type': 'log', 'level': 'INFO',
        'message': f'nmap {NMAP_VERSION} | Timing: T{timing} | Args: {scan_args}',
        'color': 'cyan'
    }) + '\n'

    try:
        is_range = '/' in target or '-' in target

        if is_range and scan_type != 'ping' and not skip_discovery:
            # Phase 1: Host discovery via ping sweep
            yield json.dumps({
                'type': 'log', 'level': 'INFO',
                'message': 'Phase 1: Host discovery (ping sweep)...',
                'color': 'yellow'
            }) + '\n'

            nm.scan(hosts=nmap_target, arguments=f'-sn -T{timing} --host-timeout 60s')
            live_hosts = [h for h in nm.all_hosts() if nm[h].state() == 'up']

            yield json.dumps({
                'type': 'log', 'level': 'INFO',
                'message': f'Discovered {len(live_hosts)} live host(s)',
                'color': 'green'
            }) + '\n'

            if not live_hosts:
                yield json.dumps({
                    'type': 'log', 'level': 'WARNING',
                    'message': 'No live hosts found. Try enabling "Skip Host Discovery" for hosts that block ping.',
                    'color': 'yellow'
                }) + '\n'
                return

            # Phase 2: Detailed per-host scan
            yield json.dumps({
                'type': 'log', 'level': 'INFO',
                'message': f'Phase 2: {scan_type.upper()} scan on {len(live_hosts)} host(s)...',
                'color': 'yellow'
            }) + '\n'

            vuln_count = 0
            for i, host_ip in enumerate(live_hosts, 1):
                yield json.dumps({
                    'type': 'log', 'level': 'INFO',
                    'message': f'[{i}/{len(live_hosts)}] Scanning {host_ip}...',
                    'color': 'white'
                }) + '\n'

                try:
                    nm.scan(hosts=host_ip, arguments=scan_args)

                    if host_ip in nm.all_hosts():
                        host_data = parse_host_result(nm, host_ip, scan_type)

                        vulns = host_data.get('vulnerabilities', [])
                        vuln_count += len(vulns)
                        for v in vulns:
                            yield json.dumps({
                                'type': 'log', 'level': 'WARNING',
                                'message': f'[VULN] {host_ip}:{v.get("port", "?")} - '
                                           f'{v.get("cve", "unknown")} ({v.get("severity", "?").upper()})',
                                'color': 'red'
                            }) + '\n'

                        yield json.dumps(host_data) + '\n'
                    else:
                        yield json.dumps({
                            'type': 'host', 'ip': host_ip, 'status': 'down'
                        }) + '\n'

                except nmap.PortScannerError as e:
                    yield json.dumps({
                        'type': 'log', 'level': 'ERROR',
                        'message': f'nmap error on {host_ip}: {str(e)[:200]}',
                        'color': 'red'
                    }) + '\n'
                except Exception as e:
                    yield json.dumps({
                        'type': 'log', 'level': 'ERROR',
                        'message': f'Error scanning {host_ip}: {str(e)[:200]}',
                        'color': 'red'
                    }) + '\n'

            elapsed = nm.scanstats().get('elapsed', '?')
            summary = f'Scan complete. {len(live_hosts)} host(s) scanned.'
            if vuln_count > 0:
                summary += f' {vuln_count} vulnerabilities found!'
            summary += f' Duration: {elapsed}s'

        else:
            # Single host, ping scan, or skip-discovery scan
            yield json.dumps({
                'type': 'log', 'level': 'INFO',
                'message': f'Scanning {target}...',
                'color': 'white'
            }) + '\n'

            if scan_type == 'ping':
                nm.scan(hosts=nmap_target, arguments=f'-sn -T{timing} --host-timeout 60s')
            else:
                nm.scan(hosts=nmap_target, arguments=scan_args)

            hosts = nm.all_hosts()
            vuln_count = 0

            for host_ip in hosts:
                host_data = parse_host_result(nm, host_ip, scan_type)

                vulns = host_data.get('vulnerabilities', [])
                vuln_count += len(vulns)
                for v in vulns:
                    yield json.dumps({
                        'type': 'log', 'level': 'WARNING',
                        'message': f'[VULN] {host_ip}:{v.get("port", "?")} - '
                                   f'{v.get("cve", "unknown")} ({v.get("severity", "?").upper()})',
                        'color': 'red'
                    }) + '\n'

                yield json.dumps(host_data) + '\n'

            if not hosts:
                yield json.dumps({
                    'type': 'log', 'level': 'WARNING',
                    'message': f'Host {target} appears to be down or is blocking probes.',
                    'color': 'yellow'
                }) + '\n'

            elapsed = nm.scanstats().get('elapsed', '?')
            summary = f'Scan complete. {len(hosts)} host(s) scanned.'
            if vuln_count > 0:
                summary += f' {vuln_count} vulnerabilities found!'
            summary += f' Duration: {elapsed}s'

        yield json.dumps({
            'type': 'log', 'level': 'SUCCESS',
            'message': summary, 'color': 'green'
        }) + '\n'

    except nmap.PortScannerError as e:
        error_msg = str(e)
        if 'requires root' in error_msg.lower() or 'permission' in error_msg.lower():
            yield json.dumps({
                'type': 'log', 'level': 'ERROR',
                'message': 'Permission denied. This scan type requires root: sudo python server.py',
                'color': 'red'
            }) + '\n'
        else:
            yield json.dumps({
                'type': 'log', 'level': 'ERROR',
                'message': f'nmap error: {error_msg[:300]}',
                'color': 'red'
            }) + '\n'
    except Exception as e:
        yield json.dumps({
            'type': 'log', 'level': 'ERROR',
            'message': f'Scan error: {str(e)[:300]}',
            'color': 'red'
        }) + '\n'


# ── Helper Functions ──────────────────────────────────────────────────────

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


# ── API Routes ────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'service': 'NetScanner Pro API',
        'version': '3.0.0',
        'nmap': {
            'available': NMAP_AVAILABLE,
            'version': NMAP_VERSION,
            'status': NMAP_STATUS
        },
        'privileges': {
            'root': IS_ROOT,
            'note': 'Full scan capabilities' if IS_ROOT else 'Limited (stealth/OS/UDP require root)'
        },
        'source_ip': get_local_ip(),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/scan', methods=['POST'])
@rate_limit
def scan():
    """Start a real nmap scan - returns NDJSON stream."""
    data = request.json
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    target = sanitize_input(data.get('target', ''))
    scan_type = sanitize_input(data.get('scanType', 'quick'))
    ports = sanitize_input(data.get('ports', ''))
    timing = data.get('timing', 3)
    skip_discovery = bool(data.get('skipDiscovery', False))

    if not isinstance(timing, int) or timing not in range(1, 6):
        timing = 3

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    if not validate_target(target):
        return jsonify({'error': 'Invalid target format. Use IP, CIDR, IP range, or hostname.'}), 400

    if scan_type not in VALID_SCAN_TYPES:
        return jsonify({
            'error': f'Invalid scan type. Must be one of: {", ".join(VALID_SCAN_TYPES)}'
        }), 400

    # Validate custom ports format
    if ports and not re.match(r'^[\d,\-\s]+$', ports):
        return jsonify({'error': 'Invalid port format. Use: 22,80,443 or 1-1000'}), 400

    def generate():
        for result in nmap_scan(target, scan_type, ports if ports else None,
                                timing, skip_discovery):
            yield result

    return Response(generate(), mimetype='application/x-ndjson')


@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify({
        'supported_scan_types': VALID_SCAN_TYPES,
        'nmap_available': NMAP_AVAILABLE,
        'nmap_version': NMAP_VERSION,
        'is_root': IS_ROOT,
        'source_ip': get_local_ip(),
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
        'IP Address', 'Status', 'Hostname', 'OS', 'MAC', 'Vendor',
        'Open Ports', 'Services', 'Versions', 'Vulnerabilities'
    ])

    for host in data.get('results', []):
        ports_str = ';'.join([
            str(p.get('port', '')) + '/' + p.get('protocol', 'tcp')
            for p in host.get('ports', [])
        ])
        services_str = ';'.join([p.get('service', 'unknown') for p in host.get('ports', [])])
        versions_str = ';'.join([p.get('version', '') or '' for p in host.get('ports', [])])
        vulns_str = ';'.join([v.get('cve', '') for v in host.get('vulnerabilities', [])])

        writer.writerow([
            host.get('ip', ''), host.get('status', ''),
            host.get('hostname', 'N/A'), host.get('os', 'N/A'),
            host.get('mac', 'N/A'), host.get('vendor', 'N/A'),
            ports_str, services_str, versions_str, vulns_str
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
    print('=' * 60)
    print('  NetScanner Pro v3.0 - Real Network Scanner')
    print('=' * 60)
    print(f'  nmap:       {"v" + NMAP_VERSION if NMAP_AVAILABLE else "NOT INSTALLED"}')
    print(f'  Privileges: {"root (full capabilities)" if IS_ROOT else "unprivileged (limited)"}')
    print(f'  Source IP:  {get_local_ip()}')
    print(f'  Scan types: {", ".join(VALID_SCAN_TYPES)}')
    print('-' * 60)
    if not NMAP_AVAILABLE:
        print('  WARNING: nmap not found! Install: sudo apt install nmap')
    if not IS_ROOT:
        print('  NOTE: Run with sudo for full capabilities')
        print('  Limited without root: stealth, OS, UDP, aggressive')
    print('-' * 60)
    print('  LEGAL: Only scan networks you own or have permission to test')
    print('=' * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
