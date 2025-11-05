const configMetadata = {
    manual_mode: {
        label: "Manual Mode",
        description: "Hold Ragnar in manual control. Disable this to let the orchestrator continuously discover devices, run actions, and launch vulnerability scans automatically."
    },
    debug_mode: {
        label: "Debug Mode",
        description: "Enable verbose debug logging for deeper troubleshooting output."
    },
    scan_vuln_running: {
        label: "Automatic Vulnerability Scans",
        description: "Allow the orchestrator to launch vulnerability scans on discovered hosts based on the configured interval."
    },
    retry_success_actions: {
        label: "Retry Successful Actions",
        description: "Re-run actions that previously succeeded after the success retry delay to keep intelligence fresh."
    },
    retry_failed_actions: {
        label: "Retry Failed Actions",
        description: "Retry actions that failed after waiting the failed retry delay."
    },
    blacklistcheck: {
        label: "Honor Scan Blacklists",
        description: "Skip hosts or MAC addresses that appear in the scan blacklist lists when running automated actions."
    },
    displaying_csv: {
        label: "Display Scan CSV",
        description: "Push the most recent scan CSV results to the e-paper display after each network sweep."
    },
    log_debug: {
        label: "Log Debug Messages",
        description: "Include debug-level entries in Ragnar logs."
    },
    log_info: {
        label: "Log Info Messages",
        description: "Include informational entries in Ragnar logs."
    },
    log_warning: {
        label: "Log Warning Messages",
        description: "Include warning-level entries in Ragnar logs."
    },
    log_error: {
        label: "Log Error Messages",
        description: "Include error-level entries in Ragnar logs."
    },
    log_critical: {
        label: "Log Critical Messages",
        description: "Include critical-level entries in Ragnar logs."
    },
    terminal_log_level: {
        label: "Terminal Log Level",
        description: "Control which log levels appear in the dashboard terminal. Options: 'all' (show everything), 'info' (info, warnings, and errors only), 'error' (errors only).",
        type: "select",
        options: ["all", "info", "error"]
    },
    startup_delay: {
        label: "Startup Delay (s)",
        description: "Seconds to wait after boot before the orchestrator begins automated activity."
    },
    web_delay: {
        label: "Web Update Delay (s)",
        description: "Seconds between refreshes of the web dashboards and API responses."
    },
    screen_delay: {
        label: "Screen Update Delay (s)",
        description: "Seconds between e-paper display refreshes."
    },
    comment_delaymin: {
        label: "Comment Delay Min (s)",
        description: "Minimum number of seconds between on-screen comment rotations."
    },
    comment_delaymax: {
        label: "Comment Delay Max (s)",
        description: "Maximum number of seconds between on-screen comment rotations."
    },
    livestatus_delay: {
        label: "Live Status Delay (s)",
        description: "Seconds between updates to the live status CSV that feeds dashboards."
    },
    image_display_delaymin: {
        label: "Image Display Min (s)",
        description: "Minimum time an image remains on the e-paper display."
    },
    image_display_delaymax: {
        label: "Image Display Max (s)",
        description: "Maximum time an image remains on the e-paper display."
    },
    scan_interval: {
        label: "Scan Interval (s)",
        description: "Seconds between full network discovery scans."
    },
    scan_vuln_interval: {
        label: "Vulnerability Scan Interval (s)",
        description: "Seconds between automated vulnerability scan cycles when enabled."
    },
    failed_retry_delay: {
        label: "Failed Retry Delay (s)",
        description: "Seconds to wait before retrying an action that previously failed."
    },
    success_retry_delay: {
        label: "Success Retry Delay (s)",
        description: "Seconds to wait before repeating an action that previously succeeded."
    },
    ref_width: {
        label: "Reference Width",
        description: "Reference pixel width used to scale drawings for the e-paper display."
    },
    ref_height: {
        label: "Reference Height",
        description: "Reference pixel height used to scale drawings for the e-paper display."
    },
    epd_type: {
        label: "EPD Type",
        description: "Model identifier for the connected Waveshare e-paper display."
    },
    portlist: {
        label: "Additional Ports",
        description: "Comma separated list of extra ports to check on every host in addition to the sequential range."
    },
    mac_scan_blacklist: {
        label: "MAC Scan Blacklist",
        description: "Comma separated MAC addresses Ragnar should ignore during scans and automated actions."
    },
    ip_scan_blacklist: {
        label: "IP Scan Blacklist",
        description: "Comma separated IP addresses Ragnar should ignore during scans and automated actions."
    },
    steal_file_names: {
        label: "Target File Names",
        description: "Comma separated file name fragments that trigger file collection when encountered."
    },
    steal_file_extensions: {
        label: "Target File Extensions",
        description: "Comma separated file extensions that Ragnar should collect when found."
    },
    nmap_scan_aggressivity: {
        label: "Nmap Aggressiveness",
        description: "Timing template flag passed to nmap (for example -T2). Adjust to trade accuracy for speed."
    },
    portstart: {
        label: "Port Range Start",
        description: "First port in the sequential range scanned on every host."
    },
    portend: {
        label: "Port Range End",
        description: "Last port in the sequential range scanned on every host."
    },
    timewait_smb: {
        label: "SMB Retry Wait (s)",
        description: "Seconds to wait before retrying SMB actions against a host."
    },
    timewait_ssh: {
        label: "SSH Retry Wait (s)",
        description: "Seconds to wait before retrying SSH actions against a host."
    },
    timewait_telnet: {
        label: "Telnet Retry Wait (s)",
        description: "Seconds to wait before retrying Telnet actions against a host."
    },
    timewait_ftp: {
        label: "FTP Retry Wait (s)",
        description: "Seconds to wait before retrying FTP actions against a host."
    },
    timewait_sql: {
        label: "SQL Retry Wait (s)",
        description: "Seconds to wait before retrying SQL actions against a host."
    },
    timewait_rdp: {
        label: "RDP Retry Wait (s)",
        description: "Seconds to wait before retrying RDP actions against a host."
    },
    wifi_known_networks: {
        label: "Known Wi-Fi Networks",
        description: "Comma separated list of SSIDs Ragnar should automatically join when detected."
    },
    wifi_ap_ssid: {
        label: "AP SSID",
        description: "Network name broadcast when Ragnar creates its own access point."
    },
    wifi_ap_password: {
        label: "AP Password",
        description: "Password clients must use to join Ragnar's access point."
    },
    wifi_connection_timeout: {
        label: "Wi-Fi Connection Timeout (s)",
        description: "Seconds to wait for each Wi-Fi connection attempt before considering it failed."
    },
    wifi_max_attempts: {
        label: "Wi-Fi Max Attempts",
        description: "Number of Wi-Fi connection retries before giving up or falling back to AP mode."
    },
    wifi_scan_interval: {
        label: "Wi-Fi Scan Interval (s)",
        description: "Seconds between wireless network scans performed by the Wi-Fi manager."
    },
    wifi_monitor_enabled: {
        label: "Wi-Fi Monitor",
        description: "Keep the Wi-Fi manager running so connectivity issues are detected quickly."
    },
    wifi_auto_ap_fallback: {
        label: "Auto AP Fallback",
        description: "Automatically enable Ragnar's access point if normal Wi-Fi connectivity cannot be restored."
    },
    wifi_ap_timeout: {
        label: "AP Timeout (s)",
        description: "Maximum duration before an active Ragnar access point session shuts down automatically."
    },
    wifi_ap_idle_timeout: {
        label: "AP Idle Timeout (s)",
        description: "Seconds of inactivity allowed before shutting down the Ragnar access point."
    },
    wifi_reconnect_interval: {
        label: "Wi-Fi Reconnect Interval (s)",
        description: "Seconds between Wi-Fi reconnect attempts when the device is offline."
    },
    wifi_ap_cycle_enabled: {
        label: "AP Smart Cycling",
        description: "Periodically cycle the access point when active to limit exposure."
    },
    wifi_initial_connection_timeout: {
        label: "Initial Wi-Fi Timeout (s)",
        description: "Timeout for the very first Wi-Fi connection attempt during boot."
    },
    network_device_retention_days: {
        label: "Device Retention (days)",
        description: "Number of days to keep inactive devices in the network database before pruning them."
    },
    network_resolution_timeout: {
        label: "Resolution Timeout (s)",
        description: "Seconds to wait before re-resolving details for the same device."
    },
    network_confirmation_scans: {
        label: "Confirmation Scans",
        description: "Number of extra scans required to confirm a detected network change."
    },
    network_change_grace: {
        label: "Change Grace Period (s)",
        description: "Grace period after detecting a network change before automation responds."
    },
    network_intelligence_enabled: {
        label: "Network Intelligence",
        description: "Enable the network intelligence engine that tracks devices and their state changes."
    },
    network_auto_resolution: {
        label: "Automatic Resolution",
        description: "Automatically resolve and enrich newly discovered or changed devices."
    }
};

function getConfigLabel(key) {
    if (configMetadata[key] && configMetadata[key].label) {
        return configMetadata[key].label;
    }
    return key
        .replace(/__+/g, ' ')
        .replace(/_/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .replace(/\b\w/g, (char) => char.toUpperCase());
}

function getConfigDescription(key) {
    if (configMetadata[key] && configMetadata[key].description) {
        return configMetadata[key].description;
    }
    return "No additional information available for this setting.";
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function createInfoIconMarkup(key) {
    const description = escapeHtml(getConfigDescription(key));
    return `<span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>`;
}

function safeValue(value) {
    if (value === null || value === undefined) {
        return '';
    }
    return escapeHtml(value);
}

function generateConfigForm(config) {
    const formElement = document.querySelector(".config-form");
    formElement.innerHTML = ''; // Clear the form
    
    const leftColumn = document.createElement('div');
    leftColumn.classList.add('left-column');
    
    const rightColumn = document.createElement('div');
    rightColumn.classList.add('right-column');
    
    for (const [key, value] of Object.entries(config)) {
        if (key.startsWith("__title_")) {
            const title = escapeHtml(value);
            rightColumn.innerHTML += `<div class="section-title"><b>${title}</b></div>`;
        } else if (typeof value === "boolean") {
            const checked = value ? "checked" : "";
            const labelText = escapeHtml(getConfigLabel(key));
            const infoIcon = createInfoIconMarkup(key);
            leftColumn.innerHTML += `
                <div class="label-switch">
                    <label class="switch">
                        <input type="checkbox" id="${key}" name="${key}" ${checked}>
                        <span class="slider round"></span>
                    </label>
                    <div class="label-text">
                        <label for="${key}">${labelText}</label>
                        ${infoIcon}
                    </div>
                </div>
            `;
        } else if (configMetadata[key] && configMetadata[key].type === "select") {
            // Handle dropdown/select fields
            const labelText = escapeHtml(getConfigLabel(key));
            const infoIcon = createInfoIconMarkup(key);
            const options = configMetadata[key].options || [];
            const optionsHtml = options.map(opt => 
                `<option value="${escapeHtml(opt)}" ${opt === value ? 'selected' : ''}>${escapeHtml(opt)}</option>`
            ).join('');
            rightColumn.innerHTML += `
                <div class="section-item">
                    <div class="label-with-info">
                        <label for="${key}">${labelText}:</label>
                        ${infoIcon}
                    </div>
                    <select id="${key}" name="${key}" style="width: 100%; padding: 8px; border: 1px solid #555; background-color: #2a2a2a; color: #fff; border-radius: 4px;">
                        ${optionsHtml}
                    </select>
                </div>
            `;
        } else if (Array.isArray(value)) {
            const listValue = safeValue(value.join(','));
            const labelText = escapeHtml(getConfigLabel(key));
            const infoIcon = createInfoIconMarkup(key);
            rightColumn.innerHTML += `
                <div class="section-item">
                    <div class="label-with-info">
                        <label for="${key}">${labelText}:</label>
                        ${infoIcon}
                    </div>
                    <input type="text" id="${key}" name="${key}" value="${listValue}">
                </div>
            `;
        } else if (!isNaN(value) && !key.toLowerCase().includes("ip") && !key.toLowerCase().includes("mac")) {
            const numericValue = safeValue(value);
            const labelText = escapeHtml(getConfigLabel(key));
            const infoIcon = createInfoIconMarkup(key);
            rightColumn.innerHTML += `
                <div class="section-item">
                    <div class="label-with-info">
                        <label for="${key}">${labelText}:</label>
                        ${infoIcon}
                    </div>
                    <input type="number" id="${key}" name="${key}" value="${numericValue}">
                </div>
            `;
        } else {
            const textValue = safeValue(value);
            const labelText = escapeHtml(getConfigLabel(key));
            const infoIcon = createInfoIconMarkup(key);
            rightColumn.innerHTML += `
                <div class="section-item">
                    <div class="label-with-info">
                        <label for="${key}">${labelText}:</label>
                        ${infoIcon}
                    </div>
                    <input type="text" id="${key}" name="${key}" value="${textValue}">
                </div>
            `;
        }
    }
    
    formElement.appendChild(leftColumn);
    formElement.appendChild(rightColumn);
    
    // Add a spacer div at the end for better scrolling experience
    formElement.innerHTML += '<div style="height: 50px;"></div>';
    }
    
    
    function saveConfig() {
        console.log("Saving configuration...");
        const formElement = document.querySelector(".config-form");
    
        if (!formElement) {
            console.error("Form element not found.");
            return;
        }
    
        const formData = new FormData(formElement);
        const formDataObj = {};
        // Each of these fields contains an array of data.  Lets track these so we can ensure the format remains an array for the underlying structure.
        const arrayFields = [
            "portlist",
            "mac_scan_blacklist",
            "ip_scan_blacklist",
            "steal_file_names",
            "steal_file_extensions",
            "wifi_known_networks",
        ];

        formData.forEach((value, key) => {
            // Check if the input from the user contains a `,` character or is a known array field
            if (value.includes(',') || arrayFields.includes(key)) {
                formDataObj[key] = value.split(',').map(item => {
                    const trimmedItem = item.trim();
                    return isNaN(trimmedItem) || trimmedItem == "" ? trimmedItem : parseFloat(trimmedItem);
                });
            } else {
                formDataObj[key] = value === 'on' ? true : (isNaN(value) ? value : parseFloat(value));
            }
        });
    
        formElement.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
            if (!formData.has(checkbox.name)) {
                formDataObj[checkbox.name] = false;
            }
        });
    
        console.log("Form data:", formDataObj);
    
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/save_config", true);
        xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
        xhr.onreadystatechange = function () {
            if (xhr.readyState == 4) {
                console.log("Response status: " + xhr.status);
                if (xhr.status == 200) {
                    loadConfig();
                } else {
                    console.error("Failed to save configuration");
                    alert("Failed to save configuration");
                }
            }
        };
        xhr.send(JSON.stringify(formDataObj));
    }
    
    function restoreDefault() {
        fetch('/restore_default_config').then(response => response.json()).then(data => {
            generateConfigForm(data);
        });
    }
    
    function loadConfig() {
        fetch('/load_config').then(response => response.json()).then(data => {
            generateConfigForm(data);
        });
    }
    
    function toggleWifiPanel() {
        let wifiPanel = document.getElementById('wifi-panel');
        if (wifiPanel.style.display === 'block') {
            clearInterval(wifiIntervalId);
            wifiPanel.style.display = 'none';
        } else {
            scanWifi(true); // Pass true to start the update interval
        }
    }
    
    function closeWifiPanel() {
        clearInterval(wifiIntervalId);
        let wifiPanel = document.getElementById('wifi-panel');
        wifiPanel.style.display = 'none';
    }
    
    
    let wifiIntervalId;
    
    function scanWifi(update = false) {
        fetch('/scan_wifi')
            .then(response => response.json())
            .then(data => {
                console.log("Current SSID:", data.current_ssid); // Debugging
                let wifiPanel = document.getElementById('wifi-panel');
                let wifiList = document.getElementById('wifi-list');
                wifiList.innerHTML = '';
                data.networks.forEach(network => {
                    let li = document.createElement('li');
                    li.innerText = network;
                    li.setAttribute('data-ssid', network);
                    li.onclick = () => connectWifi(network);
                    if (network === data.current_ssid) {
                        li.classList.add('current-wifi'); // Apply the class if it's the current SSID
                        li.innerText += " ✅"; // Add the checkmark icon
                    }
                    wifiList.appendChild(li);
                });
                if (data.networks.length > 0) {
                    wifiPanel.style.display = 'block';
                    if (update) {
                        clearInterval(wifiIntervalId);
                        wifiIntervalId = setInterval(() => scanWifi(true), 5000);
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
    }
    
    
    
    function connectWifi(ssid) {
        let password = prompt("Enter the password for " + ssid);
        if (password) {
            fetch('/connect_wifi', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ ssid: ssid, password: password }),
            })
            .then(response => response.json())
            .then(data => alert(data.message))
            .catch(error => alert('Error: ' + error));
        }
    }

    function startAPMode() {
        // Confirm the action since it will disconnect current Wi-Fi
        if (confirm('Start AP Mode?\n\nThis will:\n• Disconnect from current Wi-Fi\n• Start "Ragnar" access point\n• Enable 3-minute smart cycling\n• Allow Wi-Fi configuration via AP\n\nContinue?')) {
            // Show a loading message
            showWifiStatus('Starting AP Mode...', 'connecting');
            
            const button = event.target.closest('button');
            const img = button.querySelector('img');
            
            // Temporarily change button appearance
            img.style.opacity = '0.5';
            button.title = 'Starting AP Mode...';
            
            fetch('/api/wifi/ap/enable', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showWifiStatus(
                        `AP Mode Active: "${data.ap_config.ssid}" | ${data.ap_config.timeout}s timeout | Smart cycling enabled`,
                        'ap-mode'
                    );
                    
                    // Auto-hide the success message after 10 seconds
                    setTimeout(() => {
                        hideWifiStatus();
                    }, 10000);
                } else {
                    showWifiStatus('Failed to start AP Mode: ' + data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error starting AP mode:', error);
                showWifiStatus('Error starting AP Mode: ' + error, 'error');
            })
            .finally(() => {
                // Restore button appearance
                img.style.opacity = '1';
                button.title = 'Start AP Mode';
            });
        }
    }

    function showWifiStatus(message, type = '') {
        const statusBar = document.getElementById('wifi-status');
        const statusText = document.getElementById('wifi-status-text');
        
        statusText.textContent = message;
        statusBar.className = 'wifi-status-bar ' + type;
        statusBar.style.display = 'flex';
    }

    function hideWifiStatus() {
        const statusBar = document.getElementById('wifi-status');
        statusBar.style.display = 'none';
    }

    // Check Wi-Fi status on page load
    document.addEventListener('DOMContentLoaded', function() {
        checkWifiStatus();
    });

    function checkWifiStatus() {
        fetch('/api/wifi/status')
            .then(response => response.json())
            .then(data => {
                if (data.ap_mode_active) {
                    showWifiStatus(
                        `AP Mode Active: "${data.ap_ssid || 'Ragnar'}" | Connect to configure Wi-Fi`,
                        'ap-mode'
                    );
                } else if (data.wifi_connected) {
                    showWifiStatus(
                        `Connected to: ${data.current_ssid || 'Wi-Fi Network'}`,
                        ''
                    );
                    // Auto-hide connected status after 5 seconds
                    setTimeout(() => {
                        hideWifiStatus();
                    }, 5000);
                }
            })
            .catch(error => {
                console.log('Wi-Fi status check failed:', error);
            });
    }
    
    
        
    
    function adjustFormPadding() {
        const toolbarHeight = document.querySelector('.toolbar').offsetHeight;
        const formElement = document.querySelector('.config-form');
        formElement.style.paddingBottom = toolbarHeight + 'px';
    }
    
    window.addEventListener('load', () => {
        adjustFormPadding();
    });
    window.addEventListener('resize', () => {
        adjustFormPadding();
    }); // Adjust size on window resize
    
    document.addEventListener("DOMContentLoaded", function() {
        loadConfig();
    
    });

    let fontSize = 12;

    // Adjust font size based on device type
    if (/Mobi|Android/i.test(navigator.userAgent)) {
        fontSize = 7; // size for mobile devices
    }
    
    function adjustConfigFontSize(change) {
        fontSize += change;
        
        // Retrieve all elements with the class 'section-item'
        var sectionItems = document.getElementsByClassName('section-item');
        
        // Loop through each element and apply the style
        for (var i = 0; i < sectionItems.length; i++) {
            // Apply the style to the section element
            sectionItems[i].style.fontSize = fontSize + 'px';
            
            // Retrieve all inputs inside this section element
            var inputs = sectionItems[i].getElementsByTagName('input');
            
            // Loop through each input and apply the style
            for (var j = 0; j < inputs.length; j++) {
                inputs[j].style.fontSize = fontSize + 'px';
            }
            
            // Retrieve all elements with the class 'switch' inside this section element
            var switches = sectionItems[i].getElementsByClassName('switch');
            
            // Loop through each switch and apply the style
            for (var k = 0; k < switches.length; k++) {
                switches[k].style.fontSize = fontSize + 'px';
            }
    
            // Retrieve all elements with the class 'slider round' inside this section element
            var sliders = sectionItems[i].getElementsByClassName('slider round');
            
            // Loop through each slider and apply the style
            for (var l = 0; l < sliders.length; l++) {
                sliders[l].style.width = fontSize * 2 + 'px';  // Adjust width based on fontSize
                sliders[l].style.height = fontSize + 'px';  // Adjust height based on fontSize
                sliders[l].style.borderRadius = fontSize / 2 + 'px';  // Adjust border-radius based on fontSize
            }
        }
    
        // Retrieve all elements with the class 'section-title'
        var sectionTitles = document.getElementsByClassName('section-title');
        
        // Loop through each element and apply the style
        for (var i = 0; i < sectionTitles.length; i++) {
            sectionTitles[i].style.fontSize = fontSize + 'px';
        }
    
        // Retrieve all elements with the class 'label-switch'
        var labelSwitches = document.getElementsByClassName('label-switch');
        
        // Loop through each element and apply the style
        for (var i = 0; i < labelSwitches.length; i++) {
            labelSwitches[i].style.fontSize = fontSize + 'px';
        }
        
        // Apply the style to the element with the class 'config-form'
        document.querySelector('.config-form').style.fontSize = fontSize + 'px';
    }
    

    

function toggleConfigToolbar() {
    const mainToolbar = document.querySelector('.toolbar');
    const toggleButton = document.getElementById('toggle-toolbar')
    const toggleIcon = document.getElementById('toggle-icon');
    if (mainToolbar.classList.contains('hidden')) {
        mainToolbar.classList.remove('hidden');
        toggleIcon.src = '/web/images/hide.png';
        toggleButton.setAttribute('data-open', 'false');
    } else {
        mainToolbar.classList.add('hidden');
        toggleIcon.src = '/web/images/reveal.png';
        toggleButton.setAttribute('data-open', 'true');

    }
}
