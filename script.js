// DOM Elements
const startScanBtn = document.getElementById('startScan');
const stopScanBtn = document.getElementById('stopScan');
const clearResultsBtn = document.getElementById('clearResults');
const targetIPInput = document.getElementById('targetIP');
const scanTypeSelect = document.getElementById('scanType');
const portsInput = document.getElementById('ports');
const scanTimingSelect = document.getElementById('scanTiming');
const autoRotateIPCheckbox = document.getElementById('autoRotateIP');
const rotationIntervalSelect = document.getElementById('rotationInterval');
const terminal = document.getElementById('terminal');
const resultsContainer = document.getElementById('resultsContainer');
const currentIPSpan = document.getElementById('currentIP');
const scanStatusSpan = document.getElementById('scanStatus');
const hostsFoundSpan = document.getElementById('hostsFound');

// Export Buttons
const exportJSONBtn = document.getElementById('exportJSON');
const exportCSVBtn = document.getElementById('exportCSV');
const exportPDFBtn = document.getElementById('exportPDF');

// Visualization Elements
const vizTabs = document.querySelectorAll('.viz-tab');
const networkMapCanvas = document.getElementById('networkMap');
const portChartCanvas = document.getElementById('portChart');
const serviceChartCanvas = document.getElementById('serviceChart');
const osChartCanvas = document.getElementById('osChart');
const vulnChartCanvas = document.getElementById('vulnChart');

// State
let isScanning = false;
let scanAbortController = null;
let ipRotationInterval = null;
let scanResults = [];
let networkChart = null;
let portChart = null;
let serviceChart = null;
let osChart = null;
let vulnChart = null;
let vizUpdatePending = false;

// Security: HTML Sanitization to prevent XSS
function sanitizeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Input validation
function validateIPTarget(target) {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    const rangePattern = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;
    return ipPattern.test(target) || cidrPattern.test(target) || rangePattern.test(target);
}

// Show loading state
function setLoadingState(isLoading) {
    const loadingIndicator = document.getElementById('loadingIndicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = isLoading ? 'flex' : 'none';
    }
}

// API Configuration
const API_BASE_URL = `${window.location.protocol}//${window.location.hostname}:5000/api`;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateVisualizations();
});

// Event Listeners
startScanBtn.addEventListener('click', startScan);
stopScanBtn.addEventListener('click', stopScan);
clearResultsBtn.addEventListener('click', clearResults);
exportJSONBtn.addEventListener('click', exportJSON);
exportCSVBtn.addEventListener('click', exportCSV);
exportPDFBtn.addEventListener('click', exportPDF);

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter' && !isScanning) {
        startScan();
    }
    if (e.key === 'Escape' && isScanning) {
        stopScan();
    }
});

// Input validation visual feedback
targetIPInput.addEventListener('input', () => {
    const value = targetIPInput.value.trim();
    if (value && !validateIPTarget(value)) {
        targetIPInput.style.borderColor = '#ff5555';
        targetIPInput.setAttribute('aria-invalid', 'true');
    } else {
        targetIPInput.style.borderColor = '#00ff41';
        targetIPInput.setAttribute('aria-invalid', 'false');
    }
});

// Visualization Tab Switching
const validTabs = ['network', 'ports', 'services', 'os', 'vulns'];
vizTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        if (!validTabs.includes(targetTab)) return;

        vizTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        document.querySelectorAll('.viz-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${targetTab}Tab`).classList.add('active');
    });
});

// Start Scan
async function startScan() {
    const target = targetIPInput.value.trim();
    const scanType = scanTypeSelect.value;
    const ports = portsInput.value.trim();
    const timing = parseInt(scanTimingSelect.value) || 3;

    if (!target) {
        addTerminalLine('ERROR', 'Target IP/Range is required', 'red');
        targetIPInput.focus();
        return;
    }

    if (!validateIPTarget(target)) {
        addTerminalLine('ERROR', 'Invalid target format. Use IP, CIDR, or range format.', 'red');
        targetIPInput.focus();
        return;
    }

    isScanning = true;
    scanAbortController = new AbortController();

    // Update UI
    startScanBtn.disabled = true;
    stopScanBtn.disabled = false;
    scanStatusSpan.textContent = 'SCANNING';
    scanStatusSpan.className = 'status-value status-scanning';
    setLoadingState(true);

    // Clear previous results
    scanResults = [];
    resultsContainer.innerHTML = '';

    // Start IP rotation if enabled
    if (autoRotateIPCheckbox.checked) {
        startIPRotation();
    }

    addTerminalLine('INFO', `Starting ${scanType.toUpperCase()} scan on ${target}`, 'cyan');
    addTerminalLine('INFO', `Source IP: ${currentIPSpan.textContent}`, 'cyan');

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                scanType: scanType,
                ports: ports,
                sourceIP: currentIPSpan.textContent,
                timing: timing
            }),
            signal: scanAbortController.signal
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Server error (${response.status})`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop();
            const completeLines = lines.filter(line => line.trim());

            for (const line of completeLines) {
                try {
                    const data = JSON.parse(line);
                    handleScanData(data);
                } catch (e) {
                    console.error('Error parsing scan data:', e);
                }
            }
        }

        scanStatusSpan.textContent = 'COMPLETE';
        scanStatusSpan.className = 'status-value status-complete';
        addTerminalLine('SUCCESS', 'Scan completed successfully', 'green');
        // Final viz update
        updateVisualizations();

    } catch (error) {
        if (error.name === 'AbortError') {
            addTerminalLine('WARNING', 'Scan stopped by user', 'yellow');
        } else {
            addTerminalLine('ERROR', `Scan failed: ${error.message}`, 'red');
        }
    } finally {
        stopScan();
        setLoadingState(false);
    }
}

// Stop Scan
function stopScan() {
    if (scanAbortController) {
        scanAbortController.abort();
    }
    isScanning = false;
    startScanBtn.disabled = false;
    stopScanBtn.disabled = true;
    setLoadingState(false);

    if (scanStatusSpan.textContent === 'SCANNING') {
        scanStatusSpan.textContent = 'STOPPED';
        scanStatusSpan.className = 'status-value status-idle';
    }
    stopIPRotation();
}

// Handle Scan Data
function handleScanData(data) {
    if (data.type === 'log') {
        addTerminalLine(data.level || 'INFO', data.message, data.color || 'cyan');
    } else if (data.type === 'host') {
        scanResults.push(data);
        displayHostResult(data);
        updateStatistics();
        scheduleVizUpdate();
    }
}

// Debounce visualization updates for speed during rapid scanning
function scheduleVizUpdate() {
    if (!vizUpdatePending) {
        vizUpdatePending = true;
        requestAnimationFrame(() => {
            updateVisualizations();
            vizUpdatePending = false;
        });
    }
}

// Display Host Result
function displayHostResult(host) {
    const noResults = resultsContainer.querySelector('.no-results');
    if (noResults) noResults.remove();

    const hostCard = document.createElement('div');
    hostCard.className = 'host-card';

    const validStatuses = ['up', 'down'];
    const safeStatus = validStatuses.includes(host.status) ? host.status : '';

    let html = `
        <div class="host-header">
            <span class="host-ip">${sanitizeHTML(host.ip)}</span>
            <span class="host-status ${safeStatus}">${sanitizeHTML(host.status?.toUpperCase())}</span>
        </div>
        <div class="host-info">
            ${host.hostname ? `<div class="info-item"><span class="info-label">Hostname</span><span class="info-value">${sanitizeHTML(host.hostname)}</span></div>` : ''}
            ${host.os ? `<div class="info-item"><span class="info-label">Operating System</span><span class="info-value">${sanitizeHTML(host.os)}</span></div>` : ''}
            ${host.mac ? `<div class="info-item"><span class="info-label">MAC Address</span><span class="info-value">${sanitizeHTML(host.mac)}</span></div>` : ''}
            <div class="info-item"><span class="info-label">Response Time</span><span class="info-value">${sanitizeHTML(host.latency) || 'N/A'}</span></div>
        </div>`;

    // Ports table
    if (host.ports && host.ports.length > 0) {
        html += `
        <table class="ports-table">
            <thead><tr>
                <th>Port</th><th>State</th><th>Protocol</th><th>Service</th><th>Version</th>
            </tr></thead>
            <tbody>
                ${host.ports.map(port => `<tr>
                    <td>${sanitizeHTML(String(port.port))}</td>
                    <td><span class="port-state-${port.state === 'open' ? 'open' : 'filtered'}">${sanitizeHTML(port.state)}</span></td>
                    <td>${sanitizeHTML(port.protocol || 'tcp')}</td>
                    <td>${sanitizeHTML(port.service) || 'unknown'}</td>
                    <td>${sanitizeHTML(port.version) || 'N/A'}</td>
                </tr>`).join('')}
            </tbody>
        </table>`;
    }

    // Vulnerabilities
    if (host.vulnerabilities && host.vulnerabilities.length > 0) {
        html += `<div class="vuln-section">
            <h4 class="vuln-header">Vulnerabilities Found (${host.vulnerabilities.length})</h4>
            ${host.vulnerabilities.map(v => {
                const validSeverities = ['critical', 'high', 'medium', 'low'];
                const safeSev = validSeverities.includes(v.severity) ? v.severity : '';
                return `<div class="vuln-item">
                    <span class="vuln-severity ${safeSev}">${sanitizeHTML(v.severity?.toUpperCase())}</span>
                    <span class="vuln-cve">${sanitizeHTML(v.cve)}</span>
                    <span class="vuln-name">${sanitizeHTML(v.name)}</span>
                    <span class="vuln-desc">${sanitizeHTML(v.description)}</span>
                </div>`;
            }).join('')}
        </div>`;
    }

    // Traceroute
    if (host.traceroute && host.traceroute.length > 0) {
        html += `<div class="traceroute-section">
            <h4 class="traceroute-header">Traceroute (${host.traceroute.length} hops)</h4>
            <div class="traceroute-hops">
                ${host.traceroute.map(hop => `<div class="traceroute-hop">
                    <span class="hop-num">${sanitizeHTML(String(hop.hop))}</span>
                    <span class="hop-ip">${sanitizeHTML(hop.ip)}</span>
                    <span class="hop-rtt">${hop.rtt ? sanitizeHTML(hop.rtt) : '* * *'}</span>
                    ${hop.hostname ? `<span class="hop-host">${sanitizeHTML(hop.hostname)}</span>` : ''}
                </div>`).join('')}
            </div>
        </div>`;
    }

    hostCard.innerHTML = html;
    resultsContainer.appendChild(hostCard);
}

// Add Terminal Line
function addTerminalLine(level, message, color = 'cyan') {
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const timestamp = new Date().toLocaleTimeString();
    const allowedColors = ['cyan', 'green', 'yellow', 'red', 'white'];
    const safeColor = allowedColors.includes(color) ? color : 'cyan';

    const promptSpan = document.createElement('span');
    promptSpan.className = 'prompt';
    promptSpan.textContent = `[${level}]`;

    const messageSpan = document.createElement('span');
    messageSpan.className = `text-${safeColor}`;
    messageSpan.textContent = `[${timestamp}] ${message}`;

    line.appendChild(promptSpan);
    line.appendChild(messageSpan);

    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// Clear Terminal
function clearTerminal() {
    terminal.innerHTML = `
        <div class="terminal-line">
            <span class="prompt">[NetScanner]$</span>
            <span class="text-green">System initialized. Ready for reconnaissance...</span>
        </div>
    `;
}

// Clear Results
function clearResults() {
    scanResults = [];
    resultsContainer.innerHTML = `
        <div class="no-results">
            <span class="icon">🔍</span>
            <p>No scan results yet. Start a scan to see data.</p>
        </div>
    `;
    clearTerminal();
    hostsFoundSpan.textContent = '0';

    if (networkChart) networkChart.destroy();
    if (portChart) portChart.destroy();
    if (serviceChart) serviceChart.destroy();
    if (osChart) osChart.destroy();
    if (vulnChart) vulnChart.destroy();

    updateVisualizations();
}

// Update Statistics
function updateStatistics() {
    const hostsUp = scanResults.filter(h => h.status === 'up').length;
    hostsFoundSpan.textContent = hostsUp;
}

// IP Rotation Functions
function startIPRotation() {
    const intervalSeconds = parseInt(rotationIntervalSelect.value);
    rotateIP();
    if (intervalSeconds === 0) {
        addTerminalLine('INFO', 'IP rotation: Every request (random IP per scan)', 'cyan');
        return;
    }
    ipRotationInterval = setInterval(() => rotateIP(), intervalSeconds * 1000);
    addTerminalLine('INFO', `IP rotation enabled (every ${intervalSeconds}s)`, 'cyan');
}

function stopIPRotation() {
    if (ipRotationInterval) {
        clearInterval(ipRotationInterval);
        ipRotationInterval = null;
    }
}

function rotateIP() {
    const newIP = generateRandomIP();
    currentIPSpan.textContent = newIP;
    addTerminalLine('INFO', `IP rotated to ${newIP}`, 'yellow');
}

function generateRandomIP() {
    const classes = [
        () => `${randomInt(1, 126)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`,
        () => `${randomInt(128, 191)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`,
        () => `${randomInt(192, 223)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`
    ];
    return classes[randomInt(0, 2)]();
}

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}


// ── Visualization Functions ─────────────────────────────────────────────

const chartFont = { family: 'Fira Code' };
const chartColors = {
    green: 'rgba(0, 255, 65, 0.8)',
    red: 'rgba(255, 85, 85, 0.8)',
    cyan: 'rgba(0, 255, 255, 0.8)',
    pink: 'rgba(255, 0, 128, 0.8)',
    orange: 'rgba(255, 170, 0, 0.8)',
    purple: 'rgba(128, 0, 255, 0.8)',
    yellow: 'rgba(255, 255, 0, 0.8)',
    blue: 'rgba(0, 128, 255, 0.8)',
};

function updateVisualizations() {
    updateNetworkMap();
    updatePortChart();
    updateServiceChart();
    updateOSChart();
    updateVulnChart();
}

// Network Map - Bubble chart: IPs by open ports and latency
function updateNetworkMap() {
    const ctx = networkMapCanvas.getContext('2d');
    if (networkChart) networkChart.destroy();

    const hostsUp = scanResults.filter(h => h.status === 'up');
    const hostsDown = scanResults.filter(h => h.status === 'down');

    // If no data or only basic stats, show summary doughnut
    if (hostsUp.length === 0 && hostsDown.length === 0) {
        networkChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['No Data'],
                datasets: [{ data: [1], backgroundColor: ['rgba(85,85,85,0.5)'], borderWidth: 0 }]
            },
            options: {
                responsive: true, maintainAspectRatio: true,
                plugins: {
                    legend: { labels: { color: '#00ff41', font: chartFont } },
                    title: { display: true, text: 'Network Overview', color: '#00ff41', font: { ...chartFont, size: 18 } }
                }
            }
        });
        return;
    }

    // Build bubble data: x = index, y = port count, r = latency
    const upData = hostsUp.map((h, i) => ({
        x: i,
        y: h.ports?.length || 0,
        r: Math.max(5, Math.min(25, parseInt(h.latency) || 5)),
        label: h.ip
    }));
    const downData = hostsDown.map((h, i) => ({
        x: hostsUp.length + i,
        y: 0,
        r: 5,
        label: h.ip
    }));

    networkChart = new Chart(ctx, {
        type: 'bubble',
        data: {
            datasets: [
                {
                    label: 'Hosts Up',
                    data: upData,
                    backgroundColor: chartColors.green,
                    borderColor: '#00ff41',
                    borderWidth: 1
                },
                {
                    label: 'Hosts Down',
                    data: downData,
                    backgroundColor: chartColors.red,
                    borderColor: '#ff5555',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true, title: { display: true, text: 'Open Ports', color: '#00ff41', font: chartFont },
                    ticks: { color: '#00ff41', font: chartFont, stepSize: 1 },
                    grid: { color: 'rgba(0,255,65,0.1)' }
                },
                x: {
                    title: { display: true, text: 'Host Index', color: '#00ff41', font: chartFont },
                    ticks: { color: '#00ff41', font: chartFont },
                    grid: { color: 'rgba(0,255,65,0.1)' }
                }
            },
            plugins: {
                legend: { labels: { color: '#00ff41', font: chartFont } },
                title: { display: true, text: 'Network Topology (bubble size = latency)', color: '#00ff41', font: { ...chartFont, size: 16 } },
                tooltip: {
                    callbacks: {
                        label: (ctx) => {
                            const d = ctx.raw;
                            return `${d.label}: ${d.y} ports, ${d.r}ms latency`;
                        }
                    }
                }
            }
        }
    });
}

// Port Distribution Chart
function updatePortChart() {
    const ctx = portChartCanvas.getContext('2d');
    if (portChart) portChart.destroy();

    const portCounts = {};
    scanResults.forEach(host => {
        if (host.ports) {
            host.ports.forEach(port => {
                const key = `${port.port}/${port.protocol || 'tcp'}`;
                portCounts[key] = (portCounts[key] || 0) + 1;
            });
        }
    });

    const sortedPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 15);

    portChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedPorts.map(([port]) => port),
            datasets: [{
                label: 'Occurrences',
                data: sortedPorts.map(([, count]) => count),
                backgroundColor: chartColors.pink,
                borderColor: '#ff0080',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: true, indexAxis: 'y',
            scales: {
                x: { beginAtZero: true, ticks: { color: '#00ff41', font: chartFont }, grid: { color: 'rgba(0,255,65,0.1)' } },
                y: { ticks: { color: '#00ff41', font: chartFont }, grid: { color: 'rgba(0,255,65,0.1)' } }
            },
            plugins: {
                legend: { labels: { color: '#00ff41', font: chartFont } },
                title: { display: true, text: 'Top Open Ports', color: '#00ff41', font: { ...chartFont, size: 18 } }
            }
        }
    });
}

// Service Analysis Chart
function updateServiceChart() {
    const ctx = serviceChartCanvas.getContext('2d');
    if (serviceChart) serviceChart.destroy();

    const serviceCounts = {};
    scanResults.forEach(host => {
        if (host.ports) {
            host.ports.forEach(port => {
                const service = port.service || 'unknown';
                serviceCounts[service] = (serviceCounts[service] || 0) + 1;
            });
        }
    });

    const sortedServices = Object.entries(serviceCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const colors = Object.values(chartColors);

    serviceChart = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: sortedServices.map(([service]) => service.toUpperCase()),
            datasets: [{
                data: sortedServices.map(([, count]) => count),
                backgroundColor: sortedServices.map((_, i) => colors[i % colors.length]),
                borderColor: '#00ff41', borderWidth: 2
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: true,
            plugins: {
                legend: { labels: { color: '#00ff41', font: chartFont } },
                title: { display: true, text: 'Service Distribution', color: '#00ff41', font: { ...chartFont, size: 18 } }
            },
            scales: { r: { ticks: { color: '#00ff41', backdropColor: 'transparent' }, grid: { color: 'rgba(0,255,65,0.2)' } } }
        }
    });
}

// OS Distribution Chart
function updateOSChart() {
    const ctx = osChartCanvas.getContext('2d');
    if (osChart) osChart.destroy();

    const osCounts = {};
    scanResults.forEach(host => {
        if (host.os) {
            osCounts[host.os] = (osCounts[host.os] || 0) + 1;
        }
    });

    const sortedOS = Object.entries(osCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const colors = Object.values(chartColors);

    osChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: sortedOS.length > 0 ? sortedOS.map(([os]) => os) : ['No OS Data'],
            datasets: [{
                data: sortedOS.length > 0 ? sortedOS.map(([, count]) => count) : [1],
                backgroundColor: sortedOS.length > 0
                    ? sortedOS.map((_, i) => colors[i % colors.length])
                    : ['rgba(85,85,85,0.5)'],
                borderColor: '#0a0e27', borderWidth: 3
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: true,
            plugins: {
                legend: { position: 'right', labels: { color: '#00ff41', font: chartFont, padding: 12 } },
                title: { display: true, text: 'OS Distribution', color: '#00ff41', font: { ...chartFont, size: 18 } }
            }
        }
    });
}

// Vulnerability Severity Chart
function updateVulnChart() {
    const ctx = vulnChartCanvas.getContext('2d');
    if (vulnChart) vulnChart.destroy();

    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    scanResults.forEach(host => {
        if (host.vulnerabilities) {
            host.vulnerabilities.forEach(v => {
                if (v.severity in sevCounts) sevCounts[v.severity]++;
            });
        }
    });

    const total = Object.values(sevCounts).reduce((a, b) => a + b, 0);
    const sevColors = {
        critical: 'rgba(220, 38, 38, 0.9)',
        high: 'rgba(255, 85, 85, 0.9)',
        medium: 'rgba(255, 170, 0, 0.9)',
        low: 'rgba(0, 200, 255, 0.9)'
    };

    vulnChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                label: 'Vulnerabilities',
                data: [sevCounts.critical, sevCounts.high, sevCounts.medium, sevCounts.low],
                backgroundColor: Object.values(sevColors),
                borderColor: Object.values(sevColors).map(c => c.replace('0.9', '1')),
                borderWidth: 2,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: true,
            scales: {
                y: { beginAtZero: true, ticks: { color: '#00ff41', font: chartFont, stepSize: 1 }, grid: { color: 'rgba(0,255,65,0.1)' } },
                x: { ticks: { color: '#00ff41', font: chartFont }, grid: { color: 'rgba(0,255,65,0.1)' } }
            },
            plugins: {
                legend: { display: false },
                title: {
                    display: true,
                    text: total > 0 ? `Vulnerability Severity (${total} total)` : 'Vulnerability Severity (run vuln/aggressive scan)',
                    color: total > 0 ? '#ff5555' : '#888',
                    font: { ...chartFont, size: 16 }
                }
            }
        }
    });
}


// ── Export Functions ─────────────────────────────────────────────────────

function exportJSON() {
    if (scanResults.length === 0) {
        addTerminalLine('WARNING', 'No results to export', 'yellow');
        return;
    }

    const exportData = {
        timestamp: new Date().toISOString(),
        target: targetIPInput.value,
        scanType: scanTypeSelect.value,
        totalHosts: scanResults.length,
        hostsUp: scanResults.filter(h => h.status === 'up').length,
        results: scanResults
    };

    const dataStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    downloadFile(blob, `netscan_${Date.now()}.json`);

    addTerminalLine('SUCCESS', 'Results exported to JSON', 'green');
    exportJSONBtn.classList.add('export-success');
    setTimeout(() => exportJSONBtn.classList.remove('export-success'), 500);
}

function sanitizeCSVValue(val) {
    const str = String(val ?? '');
    if (/^[=+\-@\t\r]/.test(str)) {
        return "'" + str;
    }
    return str;
}

function exportCSV() {
    if (scanResults.length === 0) {
        addTerminalLine('WARNING', 'No results to export', 'yellow');
        return;
    }

    let csv = 'IP Address,Status,Hostname,OS,Open Ports,Services,Vulnerabilities\n';

    scanResults.forEach(host => {
        const ports = host.ports ? host.ports.map(p => `${p.port}/${p.protocol || 'tcp'}`).join(';') : '';
        const services = host.ports ? host.ports.map(p => sanitizeCSVValue(p.service)).join(';') : '';
        const vulns = host.vulnerabilities ? host.vulnerabilities.map(v => sanitizeCSVValue(v.cve)).join(';') : '';

        csv += `${sanitizeCSVValue(host.ip)},${sanitizeCSVValue(host.status)},${sanitizeCSVValue(host.hostname || 'N/A')},${sanitizeCSVValue(host.os || 'N/A')},"${sanitizeCSVValue(ports)}","${sanitizeCSVValue(services)}","${sanitizeCSVValue(vulns)}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    downloadFile(blob, `netscan_${Date.now()}.csv`);

    addTerminalLine('SUCCESS', 'Results exported to CSV', 'green');
    exportCSVBtn.classList.add('export-success');
    setTimeout(() => exportCSVBtn.classList.remove('export-success'), 500);
}

async function exportPDF() {
    if (scanResults.length === 0) {
        addTerminalLine('WARNING', 'No results to export', 'yellow');
        return;
    }

    addTerminalLine('INFO', 'Generating PDF report...', 'cyan');

    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF('p', 'mm', 'a4');

    // Title
    pdf.setFontSize(20);
    pdf.setTextColor(0, 100, 0);
    pdf.text('NetScanner Pro - Scan Report', 20, 20);

    // Metadata
    pdf.setFontSize(10);
    pdf.setTextColor(100, 100, 100);
    pdf.text(`Generated: ${new Date().toLocaleString()}`, 20, 30);
    pdf.text(`Target: ${targetIPInput.value}`, 20, 36);
    pdf.text(`Scan Type: ${scanTypeSelect.value.toUpperCase()}`, 20, 42);
    pdf.text(`Timing: T${scanTimingSelect.value}`, 20, 48);

    // Statistics
    pdf.setFontSize(14);
    pdf.setTextColor(0, 0, 0);
    pdf.text('Summary Statistics', 20, 60);

    pdf.setFontSize(10);
    const hostsUp = scanResults.filter(h => h.status === 'up').length;
    const totalPorts = scanResults.reduce((sum, h) => sum + (h.ports?.length || 0), 0);
    const totalVulns = scanResults.reduce((sum, h) => sum + (h.vulnerabilities?.length || 0), 0);

    pdf.text(`Total Hosts Scanned: ${scanResults.length}`, 20, 70);
    pdf.text(`Hosts Up: ${hostsUp}`, 20, 76);
    pdf.text(`Hosts Down: ${scanResults.length - hostsUp}`, 20, 82);
    pdf.text(`Total Open Ports: ${totalPorts}`, 20, 88);
    if (totalVulns > 0) {
        pdf.setTextColor(200, 0, 0);
        pdf.text(`Vulnerabilities Found: ${totalVulns}`, 20, 94);
        pdf.setTextColor(0, 0, 0);
    }

    let yPos = totalVulns > 0 ? 108 : 102;
    pdf.setFontSize(12);
    pdf.text('Scan Results', 20, yPos);
    yPos += 10;

    pdf.setFontSize(8);
    scanResults.forEach((host, index) => {
        if (yPos > 270) { pdf.addPage(); yPos = 20; }

        pdf.setTextColor(0, 0, 0);
        pdf.text(`${index + 1}. ${host.ip} - ${host.status.toUpperCase()}`, 20, yPos);
        yPos += 5;

        if (host.hostname) {
            pdf.setTextColor(100, 100, 100);
            pdf.text(`   Hostname: ${host.hostname}`, 25, yPos); yPos += 5;
        }
        if (host.os) {
            pdf.text(`   OS: ${host.os}`, 25, yPos); yPos += 5;
        }
        if (host.ports && host.ports.length > 0) {
            const portList = host.ports.map(p => `${p.port}/${p.protocol || 'tcp'}(${p.service})`).join(', ');
            const lines = pdf.splitTextToSize(`   Ports: ${portList}`, 170);
            lines.forEach(line => {
                if (yPos > 270) { pdf.addPage(); yPos = 20; }
                pdf.text(line, 25, yPos); yPos += 5;
            });
        }
        if (host.vulnerabilities && host.vulnerabilities.length > 0) {
            pdf.setTextColor(200, 0, 0);
            host.vulnerabilities.forEach(v => {
                if (yPos > 270) { pdf.addPage(); yPos = 20; }
                pdf.text(`   [${v.severity.toUpperCase()}] ${v.cve} - ${v.name}`, 25, yPos); yPos += 5;
            });
            pdf.setTextColor(100, 100, 100);
        }
        yPos += 3;
    });

    // Charts
    try {
        pdf.addPage();
        pdf.setFontSize(14);
        pdf.setTextColor(0, 0, 0);
        pdf.text('Network Visualizations', 20, 20);

        const networkImg = networkMapCanvas.toDataURL('image/png');
        pdf.addImage(networkImg, 'PNG', 20, 30, 170, 85);

        const portImg = portChartCanvas.toDataURL('image/png');
        pdf.addImage(portImg, 'PNG', 20, 130, 170, 85);

        pdf.addPage();
        const serviceImg = serviceChartCanvas.toDataURL('image/png');
        pdf.addImage(serviceImg, 'PNG', 20, 30, 170, 85);

        const osImg = osChartCanvas.toDataURL('image/png');
        pdf.addImage(osImg, 'PNG', 20, 130, 170, 85);

        if (totalVulns > 0) {
            pdf.addPage();
            const vulnImg = vulnChartCanvas.toDataURL('image/png');
            pdf.addImage(vulnImg, 'PNG', 20, 30, 170, 85);
        }
    } catch (error) {
        console.error('Error adding charts to PDF:', error);
    }

    pdf.save(`netscan_${Date.now()}.pdf`);

    addTerminalLine('SUCCESS', 'PDF report generated successfully', 'green');
    exportPDFBtn.classList.add('export-success');
    setTimeout(() => exportPDFBtn.classList.remove('export-success'), 500);
}

function downloadFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
