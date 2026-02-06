// DOM Elements
const targetIPInput = document.getElementById('targetIP');
const scanTypeSelect = document.getElementById('scanType');
const portsInput = document.getElementById('ports');
const autoRotateIPCheckbox = document.getElementById('autoRotateIP');
const rotationIntervalSelect = document.getElementById('rotationInterval');
const startScanBtn = document.getElementById('startScan');
const stopScanBtn = document.getElementById('stopScan');
const clearResultsBtn = document.getElementById('clearResults');
const terminal = document.getElementById('terminal');
const resultsContainer = document.getElementById('resultsContainer');
const currentIPSpan = document.getElementById('currentIP');
const scanStatusSpan = document.getElementById('scanStatus');

// State
let isScanning = false;
let rotationInterval = null;
let scanAbortController = null;

// IP Rotation
function generateRandomIP() {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function rotateIP() {
    const newIP = generateRandomIP();
    currentIPSpan.textContent = newIP;
    addTerminalLine('INFO', `IP rotated to ${newIP}`, 'cyan');
}

function startIPRotation() {
    if (autoRotateIPCheckbox.checked) {
        const interval = parseInt(rotationIntervalSelect.value) * 1000;
        rotationInterval = setInterval(rotateIP, interval);
        addTerminalLine('SUCCESS', `IP rotation enabled (every ${rotationIntervalSelect.value}s)`, 'green');
    }
}

function stopIPRotation() {
    if (rotationInterval) {
        clearInterval(rotationInterval);
        rotationInterval = null;
        addTerminalLine('INFO', 'IP rotation stopped', 'cyan');
    }
}

// Terminal Functions
function addTerminalLine(type, message, colorClass = 'green') {
    const line = document.createElement('div');
    line.className = 'terminal-line';
    
    const timestamp = new Date().toLocaleTimeString();
    line.innerHTML = `
        <span class="prompt">[${type}]</span>
        <span class="text-${colorClass}">[${timestamp}] ${message}</span>
    `;
    
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal() {
    terminal.innerHTML = `
        <div class="terminal-line">
            <span class="prompt">[NetScanner]$</span> 
            <span class="text-green">Terminal cleared. Ready for new scan...</span>
        </div>
    `;
}

// Scan Functions
async function startScan() {
    if (isScanning) return;
    
    const target = targetIPInput.value.trim();
    const scanType = scanTypeSelect.value;
    const ports = portsInput.value.trim();
    
    if (!target) {
        addTerminalLine('ERROR', 'Please enter a target IP or range', 'red');
        return;
    }
    
    isScanning = true;
    scanAbortController = new AbortController();
    
    // Update UI
    startScanBtn.disabled = true;
    stopScanBtn.disabled = false;
    scanStatusSpan.textContent = 'SCANNING';
    scanStatusSpan.className = 'status-value status-scanning';
    
    // Start IP rotation
    startIPRotation();
    
    // Add terminal output
    addTerminalLine('START', `Initiating ${scanType} scan on ${target}...`, 'green');
    addTerminalLine('INFO', `Source IP: ${currentIPSpan.textContent}`, 'cyan');
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target,
                scanType,
                ports: ports || null,
                sourceIP: currentIPSpan.textContent
            }),
            signal: scanAbortController.signal
        });
        
        if (!response.ok) {
            throw new Error(`Scan failed: ${response.statusText}`);
        }
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            const chunk = decoder.decode(value);
            const lines = chunk.split('\n').filter(l => l.trim());
            
            for (const line of lines) {
                try {
                    const data = JSON.parse(line);
                    handleScanData(data);
                } catch (e) {
                    // Not JSON, treat as plain text
                    addTerminalLine('OUTPUT', line, 'cyan');
                }
            }
        }
        
        addTerminalLine('COMPLETE', 'Scan completed successfully', 'green');
        scanStatusSpan.textContent = 'COMPLETE';
        scanStatusSpan.className = 'status-value status-complete';
        
    } catch (error) {
        if (error.name === 'AbortError') {
            addTerminalLine('STOPPED', 'Scan stopped by user', 'yellow');
        } else {
            addTerminalLine('ERROR', error.message, 'red');
        }
    } finally {
        stopScan();
    }
}

function stopScan() {
    if (scanAbortController) {
        scanAbortController.abort();
        scanAbortController = null;
    }
    
    isScanning = false;
    startScanBtn.disabled = false;
    stopScanBtn.disabled = true;
    scanStatusSpan.textContent = 'IDLE';
    scanStatusSpan.className = 'status-value status-idle';
    
    stopIPRotation();
}

function handleScanData(data) {
    if (data.type === 'log') {
        addTerminalLine(data.level || 'INFO', data.message, data.color || 'cyan');
    } else if (data.type === 'host') {
        displayHostResult(data);
    }
}

function displayHostResult(hostData) {
    // Remove "no results" message
    const noResults = resultsContainer.querySelector('.no-results');
    if (noResults) noResults.remove();
    
    const hostCard = document.createElement('div');
    hostCard.className = 'host-card';
    
    let portsHTML = '';
    if (hostData.ports && hostData.ports.length > 0) {
        portsHTML = `
            <div class="ports-grid">
                ${hostData.ports.map(port => `
                    <div class="port-item">
                        <span class="port-number">${port.port}</span>
                        <span class="port-service">${port.service || 'unknown'}</span>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    hostCard.innerHTML = `
        <div class="host-header">
            <span class="host-ip">${hostData.ip}</span>
            <span class="host-status status-${hostData.status}">${hostData.status.toUpperCase()}</span>
        </div>
        ${hostData.hostname ? `<div><strong>Hostname:</strong> ${hostData.hostname}</div>` : ''}
        ${hostData.os ? `<div><strong>OS:</strong> ${hostData.os}</div>` : ''}
        ${portsHTML}
    `;
    
    resultsContainer.appendChild(hostCard);
}

function clearResults() {
    resultsContainer.innerHTML = `
        <div class="no-results">
            <span class="icon">🔍</span>
            <p>No scan results yet. Start a scan to see data.</p>
        </div>
    `;
    clearTerminal();
}

// Event Listeners
startScanBtn.addEventListener('click', startScan);
stopScanBtn.addEventListener('click', stopScan);
clearResultsBtn.addEventListener('click', clearResults);

// Initialize
rotateIP();
