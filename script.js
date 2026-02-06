// DOM Elements (add to existing)
const exportJSONBtn = document.getElementById('exportJSON');
const exportCSVBtn = document.getElementById('exportCSV');
const exportPDFBtn = document.getElementById('exportPDF');
const hostsFoundSpan = document.getElementById('hostsFound');

// Visualization Elements
const vizTabs = document.querySelectorAll('.viz-tab');
const networkMapCanvas = document.getElementById('networkMap');
const portChartCanvas = document.getElementById('portChart');
const serviceChartCanvas = document.getElementById('serviceChart');

// State (add to existing)
let scanResults = [];
let networkChart = null;
let portChart = null;
let serviceChart = null;

// ... (previous code remains the same) ...

// Modified handleScanData function
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

// Update Statistics
function updateStatistics() {
    const hostsUp = scanResults.filter(h => h.status === 'up').length;
    hostsFoundSpan.textContent = hostsUp;
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
    
    networkChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Hosts Up', 'Hosts Down', 'Total Ports Open'],
            datasets: [{
                data: [
                    hostsUp.length,
                    hostsDown.length,
                    hostsUp.reduce((sum, h) => sum + (h.ports?.length || 0), 0)
                ],
                backgroundColor: [
                    'rgba(0, 255, 65, 0.8)',
                    'rgba(255, 85, 85, 0.8)',
                    'rgba(0, 255, 255, 0.8)'
                ],
                borderColor: [
                    '#00ff41',
                    '#ff5555',
                    '#00ffff'
                ],
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
                        font: {
                            family: 'Fira Code',
                            size: 14
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Network Overview',
                    color: '#00ff41',
                    font: {
                        family: 'Fira Code',
                        size: 18
                    }
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
    
    // Count port occurrences
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
                    grid: {
                        color: 'rgba(0, 255, 65, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#00ff41',
                        font: { family: 'Fira Code' }
                    },
                    grid: {
                        color: 'rgba(0, 255, 65, 0.1)'
                    }
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
                    font: {
                        family: 'Fira Code',
                        size: 18
                    }
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
    
    // Count service occurrences
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
                    font: {
                        family: 'Fira Code',
                        size: 18
                    }
                }
            },
            scales: {
                r: {
                    ticks: {
                        color: '#00ff41',
                        backdropColor: 'transparent'
                    },
                    grid: {
                        color: 'rgba(0, 255, 65, 0.2)'
                    }
                }
            }
        }
    });
}

// Tab Switching
vizTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        
        // Update tab buttons
        vizTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Update panels
        document.querySelectorAll('.viz-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${targetTab}Tab`).classList.add('active');
    });
});

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
    pdf.setTextColor(0, 255, 65);
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
            pdf.text(`   Open Ports: ${host.ports.map(p => `${p.port}(${p.service})`).join(', ')}`, 25, yPos);
            yPos += 5;
        }
        
        yPos += 3;
    });
    
    // Add Charts as Images
    try {
        pdf.addPage();
        pdf.setFontSize(14);
        pdf.text('Network Visualizations', 20, 20);
        
        // Capture network chart
        const networkImg = await captureChart(networkMapCanvas);
        if (networkImg) {
            pdf.addImage(networkImg, 'PNG', 20, 30, 170, 85);
        }
        
        // Capture port chart
        const portImg = await captureChart(portChartCanvas);
        if (portImg) {
            pdf.addImage(portImg, 'PNG', 20, 130, 170, 85);
        }
        
        // New page for service chart
        pdf.addPage();
        const serviceImg = await captureChart(serviceChartCanvas);
        if (serviceImg) {
            pdf.addImage(serviceImg, 'PNG', 20, 30, 170, 85);
        }
    } catch (error) {
        console.error('Error adding charts to PDF:', error);
    }
    
    // Save PDF
    pdf.save(`netscan_${Date.now()}.pdf`);
    
    addTerminalLine('SUCCESS', 'PDF report generated successfully', 'green');
    exportPDFBtn.classList.add('export-success');
    setTimeout(() => exportPDFBtn.classList.remove('export-success'), 500);
}

// Helper function to capture chart as image
function captureChart(canvas) {
    return new Promise((resolve) => {
        try {
            const img = canvas.toDataURL('image/png');
            resolve(img);
        } catch (error) {
            resolve(null);
        }
    });
}

// Download file helper
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

// Modified clearResults to reset visualizations
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
    
    // Clear charts
    if (networkChart) networkChart.destroy();
    if (portChart) portChart.destroy();
    if (serviceChart) serviceChart.destroy();
}

// Event Listeners (add to existing)
exportJSONBtn.addEventListener('click', exportJSON);
exportCSVBtn.addEventListener('click', exportCSV);
exportPDFBtn.addEventListener('click', exportPDF);

// Initialize visualizations on load
document.addEventListener('DOMContentLoaded', () => {
    updateVisualizations();
});
