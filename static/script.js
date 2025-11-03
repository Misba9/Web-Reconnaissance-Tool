// Global variables
let taskId = null;
let statusCheckInterval = null;
let timerInterval = null;
let startTime = null;

// DOM Elements
const scanForm = document.getElementById('scanForm');
const scanBtn = document.getElementById('scanBtn');
const statusSection = document.getElementById('statusSection');
const resultsSection = document.getElementById('resultsSection');
const statusText = document.getElementById('statusText');
const progressFill = document.getElementById('progressFill');
const timer = document.getElementById('timer');
const resultTargetUrl = document.getElementById('resultTargetUrl');
const resultElapsedTime = document.getElementById('resultElapsedTime');
const downloadTxtBtn = document.getElementById('downloadTxtBtn');
const downloadJsonBtn = document.getElementById('downloadJsonBtn');
const downloadPdfBtn = document.getElementById('downloadPdfBtn');

// Summary elements
const summaryTarget = document.getElementById('summaryTarget');
const summaryIp = document.getElementById('summaryIp');
const summaryTime = document.getElementById('summaryTime');
const summaryPath = document.getElementById('summaryPath');

// Module elements
const headersModule = document.getElementById('headersModule');
const sslModule = document.getElementById('sslModule');
const whoisModule = document.getElementById('whoisModule');
const crawlerModule = document.getElementById('crawlerModule');
const dnsModule = document.getElementById('dnsModule');
const subdomainsModule = document.getElementById('subdomainsModule');
const directoryModule = document.getElementById('directoryModule');
const waybackModule = document.getElementById('waybackModule');
const portscanModule = document.getElementById('portscanModule');

// Content elements
const headersGrid = document.getElementById('headersGrid');
const sslDetails = document.getElementById('sslDetails');
const whoisContent = document.getElementById('whoisContent');
const crawlerContent = document.getElementById('crawlerContent');
const dnsContent = document.getElementById('dnsContent');
const subdomainsContent = document.getElementById('subdomainsContent');
const directoryContent = document.getElementById('directoryContent');
const waybackContent = document.getElementById('waybackContent');
const portscanContent = document.getElementById('portscanContent');

// Raw output
const rawOutput = document.getElementById('rawOutput');

// Form submission handler
scanForm.addEventListener('submit', function (e) {
    e.preventDefault();

    const targetUrl = document.getElementById('target_url').value;
    if (!targetUrl) {
        alert('Please enter a target URL');
        return;
    }

    // Disable button and show loading
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

    // Reset UI
    hideResults();
    showStatus('Initializing scan...');

    // Submit scan request
    const formData = new FormData(scanForm);

    fetch('/scan', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }

            taskId = data.task_id;
            startTime = new Date();
            startTimer();
            startStatusCheck();
        })
        .catch(error => {
            showError('Error starting scan: ' + error.message);
            resetForm();
        });
});

// Start checking status every 50 seconds
function startStatusCheck() {
    statusCheckInterval = setInterval(checkStatus, 50000); // 50 seconds
}

// Check scan status
function checkStatus() {
    if (!taskId) return;

    fetch(`/status/${taskId}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'running') {
                showStatus('Scan in progress...');
                updateProgress(50); // Set progress to 50% while running
            } else if (data.status === 'completed') {
                clearInterval(statusCheckInterval);
                clearInterval(timerInterval);
                showStatus('Scan completed successfully!');
                updateProgress(100);
                showResults(data);
            } else if (data.status === 'error') {
                clearInterval(statusCheckInterval);
                clearInterval(timerInterval);
                showError('Scan failed: ' + (data.error || 'Unknown error'));
                resetForm();
            }
        })
        .catch(error => {
            console.error('Error checking status:', error);
        });
}

// Show status section
function showStatus(message) {
    statusSection.style.display = 'block';
    resultsSection.style.display = 'none';
    statusText.textContent = message;
}

// Show error message
function showError(message) {
    statusSection.style.display = 'block';
    statusText.textContent = message;
    statusText.style.color = '#f72585'; // Danger color
    progressFill.style.backgroundColor = '#f72585';
}

// Update progress bar
function updateProgress(percent) {
    progressFill.style.width = percent + '%';
}

// Start timer - update every 5 seconds instead of every second to reduce flickering
function startTimer() {
    timerInterval = setInterval(() => {
        const elapsed = new Date() - startTime;
        const seconds = Math.floor(elapsed / 1000) % 60;
        const minutes = Math.floor(elapsed / (1000 * 60)) % 60;
        const hours = Math.floor(elapsed / (1000 * 60 * 60));

        timer.textContent = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }, 5000); // Update every 5 seconds instead of every second
}

// Show results section
function showResults(data) {
    // Get structured results
    fetch(`/results_json/${taskId}`)
        .then(response => response.json())
        .then(jsonData => {
            // Update summary
            resultTargetUrl.textContent = data.target_url || 'Unknown target';
            summaryTarget.textContent = jsonData.target || data.target_url || 'Unknown target';
            summaryIp.textContent = jsonData.ip_address || 'Not available';
            summaryTime.textContent = jsonData.scan_time || 'Not available';
            summaryPath.textContent = jsonData.exported_path || 'Not available';

            // Format elapsed time
            const elapsedSeconds = Math.floor(data.elapsed_time);
            const minutes = Math.floor(elapsedSeconds / 60);
            const seconds = elapsedSeconds % 60;
            resultElapsedTime.textContent = `Completed in ${minutes}m ${seconds}s`;

            // Display modules
            displayModuleResults(jsonData);

            // Show results section
            statusSection.style.display = 'none';
            resultsSection.style.display = 'block';

            // Reset form
            resetForm();
        })
        .catch(error => {
            // Fallback to raw output if JSON parsing fails
            fetch(`/results/${taskId}`)
                .then(response => response.text())
                .then(content => {
                    rawOutput.textContent = content;
                    document.querySelector('.raw-output').style.display = 'block';

                    resultTargetUrl.textContent = data.target_url || 'Unknown target';

                    // Format elapsed time
                    const elapsedSeconds = Math.floor(data.elapsed_time);
                    const minutes = Math.floor(elapsedSeconds / 60);
                    const seconds = elapsedSeconds % 60;
                    resultElapsedTime.textContent = `Completed in ${minutes}m ${seconds}s`;

                    // Show results section
                    statusSection.style.display = 'none';
                    resultsSection.style.display = 'block';

                    // Reset form
                    resetForm();
                })
                .catch(error2 => {
                    showError('Error fetching results: ' + error.message);
                    resetForm();
                });
        });
}

// Display module results
function displayModuleResults(data) {
    // Hide all modules first
    headersModule.style.display = 'none';
    sslModule.style.display = 'none';
    whoisModule.style.display = 'none';
    crawlerModule.style.display = 'none';
    dnsModule.style.display = 'none';
    subdomainsModule.style.display = 'none';
    directoryModule.style.display = 'none';
    waybackModule.style.display = 'none';
    portscanModule.style.display = 'none';

    // Display enhanced results if available
    if (data.headers_info) {
        displayHeadersInfo(data.headers_info);
        headersModule.style.display = 'block';
    }

    if (data.ssl_details) {
        displaySSLInfo(data.ssl_details);
        sslModule.style.display = 'block';
    }

    // Display regular module content
    if (data.modules && Object.keys(data.modules).length > 0) {
        for (const [module, content] of Object.entries(data.modules)) {
            if (content && content.length > 0) {
                displayModuleContent(module, content);
            }
        }
    } else if (data.raw_output) {
        // Show raw output if no modules found
        rawOutput.textContent = data.raw_output;
        document.querySelector('.raw-output').style.display = 'block';
    }
}

// Display headers information in a grid
function displayHeadersInfo(headers) {
    headersGrid.innerHTML = '';

    // Create header items for important headers
    const importantHeaders = [
        'Date', 'Server', 'Last-Modified', 'Content-Type',
        'Content-Length', 'Cache-Control', 'Expires', 'ETag',
        'X-Powered-By', 'X-Frame-Options', 'X-XSS-Protection'
    ];

    // Display important headers first
    importantHeaders.forEach(headerName => {
        if (headers[headerName]) {
            const headerItem = document.createElement('div');
            headerItem.className = 'header-item';
            headerItem.innerHTML = `
                <div class="header-key">${headerName}</div>
                <div class="header-value">${headers[headerName]}</div>
            `;
            headersGrid.appendChild(headerItem);
        }
    });

    // Display other headers
    for (const [key, value] of Object.entries(headers)) {
        if (!importantHeaders.includes(key)) {
            const headerItem = document.createElement('div');
            headerItem.className = 'header-item';
            headerItem.innerHTML = `
                <div class="header-key">${key}</div>
                <div class="header-value">${value}</div>
            `;
            headersGrid.appendChild(headerItem);
        }
    }
}

// Display SSL information in sections
function displaySSLInfo(sslInfo) {
    sslDetails.innerHTML = '';

    // Protocol
    if (sslInfo.protocol) {
        const protocolSection = document.createElement('div');
        protocolSection.className = 'ssl-section';
        protocolSection.innerHTML = `
            <h4>Protocol</h4>
            <div class="ssl-simple">${sslInfo.protocol}</div>
        `;
        sslDetails.appendChild(protocolSection);
    }

    // Version
    if (sslInfo.version) {
        const versionSection = document.createElement('div');
        versionSection.className = 'ssl-section';
        versionSection.innerHTML = `
            <h4>Version</h4>
            <div class="ssl-simple">${sslInfo.version}</div>
        `;
        sslDetails.appendChild(versionSection);
    }

    // Serial Number
    if (sslInfo.serialNumber) {
        const serialSection = document.createElement('div');
        serialSection.className = 'ssl-section';
        serialSection.innerHTML = `
            <h4>Serial Number</h4>
            <div class="ssl-simple">${sslInfo.serialNumber}</div>
        `;
        sslDetails.appendChild(serialSection);
    }

    // Validity Period
    if (sslInfo.notBefore || sslInfo.notAfter) {
        const validitySection = document.createElement('div');
        validitySection.className = 'ssl-section';
        validitySection.innerHTML = `
            <h4>Validity Period</h4>
            <div class="ssl-simple">From: ${sslInfo.notBefore || 'N/A'}</div>
            <div class="ssl-simple">To: ${sslInfo.notAfter || 'N/A'}</div>
        `;
        sslDetails.appendChild(validitySection);
    }

    // Cipher
    if (sslInfo.cipher && sslInfo.cipher.length > 0) {
        const cipherSection = document.createElement('div');
        cipherSection.className = 'ssl-section';
        cipherSection.innerHTML = `
            <h4>Cipher Information</h4>
            <ul class="ssl-list">
                ${sslInfo.cipher.map(item => `<li>${item}</li>`).join('')}
            </ul>
        `;
        sslDetails.appendChild(cipherSection);
    }

    // Subject
    if (sslInfo.subject && sslInfo.subject.length > 0) {
        const subjectSection = document.createElement('div');
        subjectSection.className = 'ssl-section';
        subjectSection.innerHTML = `
            <h4>Subject</h4>
            <ul class="ssl-list">
                ${sslInfo.subject.map(item => `<li>${item}</li>`).join('')}
            </ul>
        `;
        sslDetails.appendChild(subjectSection);
    }

    // Issuer
    if (sslInfo.issuer && sslInfo.issuer.length > 0) {
        const issuerSection = document.createElement('div');
        issuerSection.className = 'ssl-section';
        issuerSection.innerHTML = `
            <h4>Issuer</h4>
            <ul class="ssl-list">
                ${sslInfo.issuer.map(item => `<li>${item}</li>`).join('')}
            </ul>
        `;
        sslDetails.appendChild(issuerSection);
    }

    // Subject Alternative Names
    if (sslInfo.subjectAltName && sslInfo.subjectAltName.length > 0) {
        const sanSection = document.createElement('div');
        sanSection.className = 'ssl-section';
        sanSection.innerHTML = `
            <h4>Subject Alternative Names</h4>
            <ul class="ssl-list">
                ${sslInfo.subjectAltName.map(item => `<li>${item}</li>`).join('')}
            </ul>
        `;
        sslDetails.appendChild(sanSection);
    }
}

// Display content for a specific module
function displayModuleContent(moduleName, content) {
    let moduleElement, contentElement;

    switch (moduleName) {
        case 'headers':
            // Skip if we already displayed enhanced headers
            if (headersModule.style.display === 'block') return;
            moduleElement = headersModule;
            contentElement = headersGrid;
            break;
        case 'ssl_info':
            // Skip if we already displayed enhanced SSL info
            if (sslModule.style.display === 'block') return;
            moduleElement = sslModule;
            contentElement = sslDetails;
            break;
        case 'whois':
            moduleElement = whoisModule;
            contentElement = whoisContent;
            break;
        case 'crawler':
            moduleElement = crawlerModule;
            contentElement = crawlerContent;
            break;
        case 'dns':
            moduleElement = dnsModule;
            contentElement = dnsContent;
            break;
        case 'subdomains':
            moduleElement = subdomainsModule;
            contentElement = subdomainsContent;
            break;
        case 'directory':
            moduleElement = directoryModule;
            contentElement = directoryContent;
            break;
        case 'wayback':
            moduleElement = waybackModule;
            contentElement = waybackContent;
            break;
        case 'portscan':
            moduleElement = portscanModule;
            contentElement = portscanContent;
            break;
        default:
            return;
    }

    // Clear previous content
    contentElement.innerHTML = '';

    // Process content based on format
    if (Array.isArray(content)) {
        // For headers and other key-value pairs
        const list = document.createElement('ul');
        list.style.listStyleType = 'none';
        list.style.paddingLeft = '0';

        content.forEach(line => {
            const item = document.createElement('li');
            item.style.padding = '8px 0';
            item.style.borderBottom = '1px solid #e9ecef';

            // Check if it's a key-value pair
            if (line.includes(':')) {
                const parts = line.split(':', 2);
                const key = parts[0].trim();
                const value = parts[1].trim();

                item.innerHTML = `<div style="display: flex; flex-wrap: wrap;">
                    <span style="font-weight: 600; min-width: 200px; color: #4361ee;">${key}:</span>
                    <span style="flex: 1; word-break: break-word;">${value}</span>
                </div>`;
            } else {
                // Handle hierarchical data (lines with └╴)
                if (line.includes('└╴')) {
                    const parts = line.split('└╴');
                    const indent = parts[0].replace(/\s/g, '').length; // Count non-space characters for indentation
                    const value = parts[1].trim();

                    item.innerHTML = `<div style="display: flex; align-items: center;">
                        <span style="margin-left: ${indent * 20}px"></span>
                        <span style="margin-left: 10px;">${value}</span>
                    </div>`;
                } else {
                    // Regular line
                    item.textContent = line;
                }
            }

            list.appendChild(item);
        });

        // Remove last border
        if (list.lastChild) {
            list.lastChild.style.borderBottom = 'none';
        }

        contentElement.appendChild(list);
    } else {
        // For plain text content
        contentElement.textContent = content;
    }

    // Show the module
    moduleElement.style.display = 'block';
}

// Hide results section
function hideResults() {
    resultsSection.style.display = 'none';
}

// Reset form
function resetForm() {
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<i class="fas fa-bolt"></i> Run Reconnaissance';
}

// Download handlers
downloadTxtBtn.addEventListener('click', function () {
    if (taskId) {
        window.location.href = `/download/${taskId}`;
    }
});

downloadJsonBtn.addEventListener('click', function () {
    if (taskId) {
        window.location.href = `/download_json/${taskId}`;
    }
});

downloadPdfBtn.addEventListener('click', function () {
    if (taskId) {
        window.location.href = `/download_pdf/${taskId}`;
    }
});

// Full scan checkbox handler
document.getElementById('full_scan').addEventListener('change', function () {
    const isChecked = this.checked;
    const checkboxes = document.querySelectorAll('.option input[type="checkbox"]:not(#full_scan)');

    checkboxes.forEach(checkbox => {
        checkbox.disabled = isChecked;
        if (isChecked) {
            checkbox.parentElement.style.opacity = '0.5';
        } else {
            checkbox.parentElement.style.opacity = '1';
        }
    });
});