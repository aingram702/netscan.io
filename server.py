from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import subprocess
import json
import re
import time
import random
from threading import Thread

app = Flask(__name__)
CORS(app)

# Simulated scan data (replace with real nmap in production)
def simulate_scan(target, scan_type, ports, source_ip):
    """
    Simulates network scanning. In production, use actual nmap:
    subprocess.run(['nmap', '-A', target], capture_output=True, text=True)
    
    ⚠️ WARNING: Only use on networks you own or have permission to scan!
    """
    yield json.dumps({
        'type': 'log',
        'level': 'INFO',
        'message': f'Starting {scan_type} scan from {source_ip}...',
        'color': 'cyan'
    }) + '\n'
    
    time.sleep(1)
    
    # Parse target (handle CIDR notation)
    if '/' in target:
        # Simulate subnet scan
        base_ip = target.split('/')[0]
        ip_parts = base_ip.split('.')
        
        for i in range(1, 6):  # Scan 5 hosts for demo
            host_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}"
            
            yield json.dumps({
                'type': 'log',
                'level': 'SCAN',
                'message': f'Scanning host {host_ip}...',
                'color': 'yellow'
            }) + '\n'
            
            time.sleep(0.5)
            
            # Random host up/down
            is_up = random.choice([True, True, False])
            
            if is_up:
                open_ports = []
                
                # Simulate port scanning
                common_ports = [
                    (22, 'ssh'), (80, 'http'), (443, 'https'),
                    (3306, 'mysql'), (5432, 'postgresql'), (8080, 'http-alt')
                ]
                
                for port, service in random.sample(common_ports, random.randint(1, 4)):
                    open_ports.append({'port': port, 'service': service})
                
                yield json.dumps({
                    'type': 'host',
                    'ip': host_ip,
                    'status': 'up',
                    'hostname': f'host-{i}.example.com',
                    'os': random.choice(['Linux 5.x', 'Windows 10', 'macOS']),
                    'ports': open_ports
                }) + '\n'
                
                yield json.dumps({
                    'type': 'log',
                    'level': 'SUCCESS',
                    'message': f'Host {host_ip} is UP - {len(open_ports)} open ports found',
                    'color': 'green'
                }) + '\n'
            else:
                yield json.dumps({
                    'type': 'host',
                    'ip': host_ip,
                    'status': 'down',
                    'ports': []
                }) + '\n'
                
                yield json.dumps({
                    'type': 'log',
                    'level': 'INFO',
                    'message': f'Host {host_ip} is DOWN',
                    'color': 'cyan'
                }) + '\n'
    
    else:
        # Single host scan
        yield json.dumps({
            'type': 'log',
            'level': 'SCAN',
            'message': f'Performing deep scan on {target}...',
            'color': 'yellow'
        }) + '\n'
        
        time.sleep(1)
        
        # Simulate detailed scan
        open_ports = [
            {'port': 22, 'service': 'ssh'},
            {'port': 80, 'service': 'http'},
            {'port': 443, 'service': 'https'},
            {'port': 3306, 'service': 'mysql'}
        ]
        
        yield json.dumps({
            'type': 'host',
            'ip': target,
            'status': 'up',
            'hostname': 'target.example.com',
            'os': 'Linux 5.15.0 (Ubuntu)',
            'ports': open_ports
        }) + '\n'
    
    yield json.dumps({
        'type': 'log',
        'level': 'COMPLETE',
        'message': 'Scan completed successfully',
        'color': 'green'
    }) + '\n'

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('scanType', 'quick')
    ports = data.get('ports')
    source_ip = data.get('sourceIP')
    
    if not target:
        return jsonify({'error': 'Target IP is required'}), 400
    
    # Stream scan results
    return Response(
        simulate_scan(target, scan_type, ports, source_ip),
        mimetype='application/x-ndjson'
    )

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'NetScanner Pro API'})

if __name__ == '__main__':
    print("🚀 NetScanner Pro Backend Starting...")
    print("⚠️  EDUCATIONAL USE ONLY - Scan responsibly!")
    app.run(debug=True, port=5000)
