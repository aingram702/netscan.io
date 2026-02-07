// DOM Elements
const startScanBtn = document.getElementById('startScan');
const stopScanBtn = document.getElementById('stopScan');
const clearResultsBtn = document.getElementById('clearResults');
const targetIPInput = document.getElementById('targetIP');
const scanTypeSelect = document.getElementById('scanType');
const portsInput = document.getElementById('ports');
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

// State
let isScanning = false;
let scanAbortController = null;
let ipRotationInterval = null;
let scanResults = [];
let networkChart = null;
let portChart = null;
let serviceChart = null;

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
const API_BASE_URL = 'http://localhost:5000/api';

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
    // Ctrl+Enter to start scan
    if (e.ctrlKey && e.key === 'Enter' && !isScanning) {
        startScan();
    }
    // Escape to stop scan
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
vizTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;

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

    // Clear previous results
    scanResults = [];
    resultsContainer.innerHTML = '';

    // Start IP rotation if enabled
    if (autoRotateIPCheckbox.checked) {
        startIPRotation();
    }

    // Add scan start message
    addTerminalLine('INFO', `Starting ${scanType.toUpperCase()} scan on ${target}`, 'cyan');
    addTerminalLine('INFO', `Source IP: ${currentIPSpan.textContent}`, 'cyan');

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target: target,
                scanType: scanType,
                ports: ports,
                sourceIP: currentIPSpan.textContent
            }),
            signal: scanAbortController.signal
        });

        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        while (true) {
            const { done, value } = await reader.read();

            if (done) break;

            const chunk = decoder.decode(value);
            const lines = chunk.split('\n').filter(line => line.trim());

            for (const line of lines) {
                try {
                    const data = JSON.parse(line);
                    handleScanData(data);
                } catch (e) {
                    console.error('Error parsing scan data:', e);
                }
            }
        }

        // Scan complete
        scanStatusSpan.textContent = 'COMPLETE';
        scanStatusSpan.className = 'status-value status-complete';
        addTerminalLine('SUCCESS', 'Scan completed successfully', 'green');

    } catch (error) {
        if (error.name === 'AbortError') {
            addTerminalLine('WARNING', 'Scan stopped by user', 'yellow');
        } else {
            addTerminalLine('ERROR', `Scan failed: ${error.message}`, 'red');
        }
    } finally {
        stopScan();
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
        updateVisualizations();
    }
}

// Display Host Result
function displayHostResult(host) {
    // Remove "no results" message if it exists
    const noResults = resultsContainer.querySelector('.no-results');
    if (noResults) {
        noResults.remove();
    }

    const hostCard = document.createElement('div');
    hostCard.className = 'host-card';

    hostCard.innerHTML = `
        <div class="host-header">
            <span class="host-ip">${sanitizeHTML(host.ip)}</span>
            <span class="host-status ${sanitizeHTML(host.status)}">${sanitizeHTML(host.status?.toUpperCase())}</span>
        </div>
        <div class="host-info">
            ${host.hostname ? `
                <div class="info-item">
                    <span class="info-label">Hostname</span>
                    <span class="info-value">${sanitizeHTML(host.hostname)}</span>
                </div>
            ` : ''}
            ${host.os ? `
                <div class="info-item">
                    <span class="info-label">Operating System</span>
                    <span class="info-value">${sanitizeHTML(host.os)}</span>
                </div>
            ` : ''}
            ${host.mac ? `
                <div class="info-item">
                    <span class="info-label">MAC Address</span>
                    <span class="info-value">${sanitizeHTML(host.mac)}</span>
                </div>
            ` : ''}
            <div class="info-item">
                <span class="info-label">Response Time</span>
                <span class="info-value">${sanitizeHTML(host.latency) || 'N/A'}</span>
            </div>
        </div>
        ${host.ports && host.ports.length > 0 ? `
            <table class="ports-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    ${host.ports.map(port => `
                        <tr>
                            <td>${sanitizeHTML(String(port.port))}</td>
                            <td>${sanitizeHTML(port.state)}</td>
                            <td>${sanitizeHTML(port.service) || 'unknown'}</td>
                            <td>${sanitizeHTML(port.version) || 'N/A'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        ` : ''}
    `;

    resultsContainer.appendChild(hostCard);
}

// Add Terminal Line
function addTerminalLine(level, message, color = 'cyan') {
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const timestamp = new Date().toLocaleTimeString();

    line.innerHTML = `
        <span class="prompt">[${level}]</span>
        <span class="text-${color}">[${timestamp}] ${message}</span>
    `;

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

    ipRotationInterval = setInterval(() => {
        rotateIP();
    }, intervalSeconds * 1000);

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
    return `${randomInt(1, 255)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 255)}`;
}

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Visualization Functions
function updateVisualizations() {
    updateNetworkMap();
    updatePortChart();
    updateServiceChart();
}

// Network Map Visualization
function updateNetworkMap() {
    const ctx = networkMapCanvas.getContext('2d');

    if (networkChart) {
        networkChart.destroy();
    }

    const hostsUp = scanResults.filter(h => h.status === 'up');
    const hostsDown = scanResults.filter(h => h.status === 'down');
    const totalPorts = hostsUp.reduce((sum, h) => sum + (h.ports?.length || 0), 0);

    networkChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Hosts Up', 'Hosts Down', 'Total Ports Open'],
            datasets: [{
                data: [hostsUp.length, hostsDown.length, totalPorts],
                backgroundColor: [
                    'rgba(0, 255, 65, 0.8)',
                    'rgba(255, 85, 85, 0.8)',
                    'rgba(0, 255, 255, 0.8)'
                ],
                borderColor: ['#00ff41', '#ff5555', '#00ffff'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#00ff41',
                        font: { family: 'Fira Code', size: 14 }
                    }
                },
                title: {
                    display: true,
                    text: 'Network Overview',
                    color: '#00ff41',
                    font: { family: 'Fira Code', size: 18 }
                }
            }
        }
    });
}

// Port Distribution Chart
function updatePortChart() {
    const ctx = portChartCanvas.getContext('2d');

    if (portChart) {
        portChart.destroy();
    }

    const portCounts = {};
    scanResults.forEach(host => {
        if (host.ports) {
            host.ports.forEach(port => {
                portCounts[port.port] = (portCounts[port.port] || 0) + 1;
            });
        }
    });

    const sortedPorts = Object.entries(portCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    portChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedPorts.map(([port]) => `Port ${port}`),
            datasets: [{
                label: 'Occurrences',
                data: sortedPorts.map(([, count]) => count),
                backgroundColor: 'rgba(255, 0, 128, 0.8)',
                borderColor: '#ff0080',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#00ff41',
                        font: { family: 'Fira Code' }
                    },
                    grid: { color: 'rgba(0, 255, 65, 0.1)' }
                },
                x: {
                    ticks: {
                        color: '#00ff41',
                        font: { family: 'Fira Code' }
                    },
                    grid: { color: 'rgba(0, 255, 65, 0.1)' }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#00ff41',
                        font: { family: 'Fira Code' }
                    }
                },
                title: {
                    display: true,
                    text: 'Top 10 Open Ports',
                    color: '#00ff41',
                    font: { family: 'Fira Code', size: 18 }
                }
            }
        }
    });
}

// Service Analysis Chart
function updateServiceChart() {
    const ctx = serviceChartCanvas.getContext('2d');

    if (serviceChart) {
        serviceChart.destroy();
    }

    const serviceCounts = {};
    scanResults.forEach(host => {
        if (host.ports) {
            host.ports.forEach(port => {
                const service = port.service || 'unknown';
                serviceCounts[service] = (serviceCounts[service] || 0) + 1;
            });
        }
    });

    const sortedServices = Object.entries(serviceCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);

    serviceChart = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: sortedServices.map(([service]) => service.toUpperCase()),
            datasets: [{
                data: sortedServices.map(([, count]) => count),
                backgroundColor: [
                    'rgba(0, 255, 65, 0.7)',
                    'rgba(255, 0, 128, 0.7)',
                    'rgba(0, 255, 255, 0.7)',
                    'rgba(255, 170, 0, 0.7)',
                    'rgba(128, 0, 255, 0.7)',
                    'rgba(255, 255, 0, 0.7)',
                    'rgba(0, 128, 255, 0.7)',
                    'rgba(255, 128, 0, 0.7)'
                ],
                borderColor: '#00ff41',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#00ff41',
                        font: { family: 'Fira Code' }
                    }
                },
                title: {
                    display: true,
                    text: 'Service Distribution',
                    color: '#00ff41',
                    font: { family: 'Fira Code', size: 18 }
                }
            },
            scales: {
                r: {
                    ticks: {
                        color: '#00ff41',
                        backdropColor: 'transparent'
                    },
                    grid: { color: 'rgba(0, 255, 65, 0.2)' }
                }
            }
        }
    });
}

// Export Functions
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

function exportCSV() {
    if (scanResults.length === 0) {
        addTerminalLine('WARNING', 'No results to export', 'yellow');
        return;
    }

    let csv = 'IP Address,Status,Hostname,OS,Open Ports,Services\n';

    scanResults.forEach(host => {
        const ports = host.ports ? host.ports.map(p => p.port).join(';') : '';
        const services = host.ports ? host.ports.map(p => p.service).join(';') : '';

        csv += `${host.ip},${host.status},${host.hostname || 'N/A'},${host.os || 'N/A'},"${ports}","${services}"\n`;
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

    // Statistics
    pdf.setFontSize(14);
    pdf.setTextColor(0, 0, 0);
    pdf.text('Summary Statistics', 20, 55);

    pdf.setFontSize(10);
    const hostsUp = scanResults.filter(h => h.status === 'up').length;
    const totalPorts = scanResults.reduce((sum, h) => sum + (h.ports?.length || 0), 0);

    pdf.text(`Total Hosts Scanned: ${scanResults.length}`, 20, 65);
    pdf.text(`Hosts Up: ${hostsUp}`, 20, 71);
    pdf.text(`Hosts Down: ${scanResults.length - hostsUp}`, 20, 77);
    pdf.text(`Total Open Ports: ${totalPorts}`, 20, 83);

    // Results Table
    let yPos = 95;
    pdf.setFontSize(12);
    pdf.text('Scan Results', 20, yPos);
    yPos += 10;

    pdf.setFontSize(8);
    scanResults.forEach((host, index) => {
        if (yPos > 270) {
            pdf.addPage();
            yPos = 20;
        }

        pdf.setTextColor(0, 0, 0);
        pdf.text(`${index + 1}. ${host.ip} - ${host.status.toUpperCase()}`, 20, yPos);
        yPos += 5;

        if (host.hostname) {
            pdf.setTextColor(100, 100, 100);
            pdf.text(`   Hostname: ${host.hostname}`, 25, yPos);
            yPos += 5;
        }

        if (host.os) {
            pdf.text(`   OS: ${host.os}`, 25, yPos);
            yPos += 5;
        }

        if (host.ports && host.ports.length > 0) {
            const portList = host.ports.map(p => `${p.port}(${p.service})`).join(', ');
            const lines = pdf.splitTextToSize(`   Open Ports: ${portList}`, 170);
            lines.forEach(line => {
                if (yPos > 270) {
                    pdf.addPage();
                    yPos = 20;
                }
                pdf.text(line, 25, yPos);
                yPos += 5;
            });
        }

        yPos += 3;
    });

    // Add Charts
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
