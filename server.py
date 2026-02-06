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
                    
                
