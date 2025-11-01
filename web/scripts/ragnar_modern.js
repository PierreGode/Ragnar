// Ragnar_modern.js - Enhanced Modern JavaScript for Ragnar web interface

let socket;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
let currentTab = 'dashboard';
let autoRefreshIntervals = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    initializeTabs();
    initializeMobileMenu();
    loadInitialData();
    setupAutoRefresh();
    setupEpaperAutoRefresh();
    setupEventListeners();
});

// ============================================================================
// WEBSOCKET CONNECTION
// ============================================================================

function initializeSocket() {
    socket = io({
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: MAX_RECONNECT_ATTEMPTS
    });

    socket.on('connect', function() {
        console.log('Connected to Ragnar server');
        updateConnectionStatus(true);
        reconnectAttempts = 0;
        addConsoleMessage('Connected to Ragnar server', 'success');
        
        // Request initial data
        socket.emit('request_status');
        socket.emit('request_logs');
    });

    socket.on('disconnect', function() {
        console.log('Disconnected from Ragnar server');
        updateConnectionStatus(false);
        addConsoleMessage('Disconnected from server', 'error');
    });

    socket.on('status_update', function(data) {
        updateDashboardStatus(data);
    });

    socket.on('log_update', function(logs) {
        updateConsole(logs);
    });

    socket.on('network_update', function(data) {
        if (currentTab === 'network') {
            displayNetworkTable(data);
        }
    });

    socket.on('credentials_update', function(data) {
        if (currentTab === 'credentials') {
            displayCredentialsTable(data);
        }
    });

    socket.on('loot_update', function(data) {
        if (currentTab === 'loot') {
            displayLootTable(data);
        }
    });

    socket.on('config_updated', function(config) {
        addConsoleMessage('Configuration updated successfully', 'info');
        if (currentTab === 'config') {
            displayConfigForm(config);
        }
    });

    socket.on('connect_error', function(error) {
        reconnectAttempts++;
        console.error('Connection error:', error);
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            addConsoleMessage('Failed to connect to server after multiple attempts', 'error');
        }
    });
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
        if (connected) {
            statusEl.innerHTML = `
                <span class="w-2 h-2 bg-green-500 rounded-full pulse-glow"></span>
                <span class="text-xs text-gray-400">Connected</span>
            `;
        } else {
            statusEl.innerHTML = `
                <span class="w-2 h-2 bg-red-500 rounded-full"></span>
                <span class="text-xs text-gray-400">Disconnected</span>
            `;
        }
    }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // Tab navigation
    document.querySelectorAll('[data-tab]').forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            showTab(tabName);
        });
    });

    // Refresh buttons
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('refresh-btn')) {
            refreshCurrentTab();
        }
    });

    // Clear console button
    const clearBtn = document.getElementById('clear-console');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearConsole);
    }
}

// ============================================================================
// TAB MANAGEMENT
// ============================================================================

function initializeTabs() {
    // Set dashboard as active by default
    showTab('dashboard');
}

function showTab(tabName) {
    // Store current tab
    currentTab = tabName;
    
    // Clear system monitoring interval when leaving system tab
    if (systemMonitoringInterval && tabName !== 'system') {
        clearInterval(systemMonitoringInterval);
        systemMonitoringInterval = null;
    }
    
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.add('hidden');
    });
    
    // Remove active class from all nav buttons
    document.querySelectorAll('.nav-btn, [data-tab]').forEach(btn => {
        btn.classList.remove('bg-Ragnar-600');
        btn.classList.add('text-gray-300', 'hover:text-white', 'hover:bg-gray-700');
    });
    
    // Show selected tab
    const selectedTab = document.getElementById(`${tabName}-tab`);
    if (selectedTab) {
        selectedTab.classList.remove('hidden');
    }
    
    // Add active class to selected nav button
    const selectedBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (selectedBtn) {
        selectedBtn.classList.add('bg-Ragnar-600');
        selectedBtn.classList.remove('text-gray-300', 'hover:text-white', 'hover:bg-gray-700');
    }
    
    // Load tab-specific data
    loadTabData(tabName);
    
    // Close mobile menu
    const mobileMenu = document.getElementById('mobile-menu');
    if (mobileMenu) {
        mobileMenu.classList.add('hidden');
    }
}

function refreshCurrentTab() {
    loadTabData(currentTab);
    addConsoleMessage(`Refreshed ${currentTab} data`, 'info');
}

function setupAutoRefresh() {
    // Set up auto-refresh for different tabs
    autoRefreshIntervals.network = setInterval(() => {
        if (currentTab === 'network' && socket && socket.connected) {
            socket.emit('request_network');
        }
    }, 10000); // Every 10 seconds

    autoRefreshIntervals.credentials = setInterval(() => {
        if (currentTab === 'credentials' && socket && socket.connected) {
            socket.emit('request_credentials');
        }
    }, 15000); // Every 15 seconds

    autoRefreshIntervals.loot = setInterval(() => {
        if (currentTab === 'loot' && socket && socket.connected) {
            socket.emit('request_loot');
        }
    }, 20000); // Every 20 seconds
    
    // Set up console log refreshing (fallback when WebSocket is not working)
    autoRefreshIntervals.console = setInterval(() => {
        if (currentTab === 'dashboard') {
            loadConsoleLogs();
        }
    }, 5000); // Every 5 seconds when on dashboard
    
    // Set up periodic update checking
    autoRefreshIntervals.updates = setInterval(() => {
        checkForUpdatesQuiet();
    }, 300000); // Every 5 minutes
    
    // Initial update check after page load
    setTimeout(() => {
        checkForUpdatesQuiet();
    }, 5000); // Check 5 seconds after page load
}

function initializeMobileMenu() {
    const menuBtn = document.getElementById('mobile-menu-btn');
    const mobileMenu = document.getElementById('mobile-menu');
    
    if (menuBtn && mobileMenu) {
        menuBtn.addEventListener('click', () => {
            mobileMenu.classList.toggle('hidden');
        });
    }
}

// ============================================================================
// DATA LOADING
// ============================================================================

async function loadInitialData() {
    try {
        // Load status
        const status = await fetchAPI('/api/status');
        if (status) {
            updateDashboardStatus(status);
        }
        
        // Load initial console logs
        await loadConsoleLogs();
        
        // Load initial Wi-Fi status
        await refreshWifiStatus();
        
        // Add welcome message to console
        addConsoleMessage('Ragnar Modern Web Interface Initialized', 'success');
        addConsoleMessage('Dashboard loaded successfully', 'info');
        
    } catch (error) {
        console.error('Error loading initial data:', error);
        addConsoleMessage('Error loading initial data', 'error');
    }
}

async function loadTabData(tabName) {
    switch(tabName) {
        case 'dashboard':
            await loadDashboardData();
            await loadConsoleLogs();
            break;
        case 'network':
            await loadNetworkData();
            break;
        case 'credentials':
            await loadCredentialsData();
            break;
        case 'loot':
            await loadLootData();
            break;
        case 'files':
            await loadFilesData();
            break;
        case 'images':
            await loadImagesData();
            break;
        case 'system':
            loadSystemData();
            break;
        case 'netkb':
            loadNetkbData();
            break;
        case 'epaper':
            await loadEpaperDisplay();
            break;
        case 'config':
            await loadConfigData();
            await refreshWifiStatus();
            break;
    }
}

async function loadDashboardData() {
    try {
        const data = await fetchAPI('/api/dashboard/stats');
        updateDashboardStats(data);
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

function updateDashboardStats(stats) {
    updateElement('target-count', stats.target_count || 0);
    updateElement('port-count', stats.port_count || 0);
    updateElement('vuln-count', stats.vulnerability_count || 0);
    updateElement('cred-count', stats.credential_count || 0);
}

async function loadNetworkData() {
    try {
        const data = await fetchAPI('/api/network');
        displayNetworkTable(data);
    } catch (error) {
        console.error('Error loading network data:', error);
    }
}

async function loadCredentialsData() {
    try {
        const data = await fetchAPI('/api/credentials');
        displayCredentialsTable(data);
    } catch (error) {
        console.error('Error loading credentials:', error);
    }
}

async function loadLootData() {
    try {
        const data = await fetchAPI('/api/loot');
        displayLootTable(data);
    } catch (error) {
        console.error('Error loading loot data:', error);
    }
}

async function loadConfigData() {
    try {
        const config = await fetchAPI('/api/config');
        displayConfigForm(config);
        
        // Also check for updates when loading config tab
        checkForUpdates();
    } catch (error) {
        console.error('Error loading config:', error);
    }
}

async function loadFilesData() {
    try {
        displayDirectoryTree();
        loadFiles('/');
    } catch (error) {
        console.error('Error loading files data:', error);
    }
}

// ============================================================================
// SYSTEM MANAGEMENT FUNCTIONS
// ============================================================================

async function checkForUpdates() {
    try {
        updateElement('update-status', 'Checking...');
        updateElement('update-info', 'Checking for updates...');
        addConsoleMessage('Checking for system updates...', 'info');
        
        const data = await fetchAPI('/api/system/check-updates');
        
        // Debug logging
        console.log('Update check response:', data);
        addConsoleMessage(`Debug: Repo path: ${data.repo_path}`, 'info');
        addConsoleMessage(`Debug: Current commit: ${data.current_commit}`, 'info');
        addConsoleMessage(`Debug: Latest commit: ${data.latest_commit}`, 'info');
        addConsoleMessage(`Debug: Commits behind: ${data.commits_behind}`, 'info');
        
        if (data.updates_available && data.commits_behind > 0) {
            updateElement('update-status', 'Update Available');
            document.getElementById('update-status').className = 'text-sm px-2 py-1 rounded bg-orange-700 text-orange-300';
            updateElement('update-info', `${data.commits_behind} commits behind. Latest: ${data.latest_commit || 'Unknown'}`);
            
            // Enable update button
            const updateBtn = document.getElementById('update-btn');
            updateBtn.disabled = false;
            updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
            
            addConsoleMessage(`Update available: ${data.commits_behind} commits behind`, 'warning');
        } else {
            updateElement('update-status', 'Up to Date');
            document.getElementById('update-status').className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
            updateElement('update-info', 'System is up to date');
            
            // Disable update button
            const updateBtn = document.getElementById('update-btn');
            updateBtn.disabled = true;
            updateBtn.className = 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-not-allowed';
            
            addConsoleMessage('System is up to date', 'success');
        }
        
    } catch (error) {
        console.error('Error checking for updates:', error);
        updateElement('update-status', 'Error');
        document.getElementById('update-status').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        
        // Check if it's a git safe directory error
        if (error.message && error.message.includes('safe.directory')) {
            updateElement('update-info', 'Git safe directory issue detected');
            addConsoleMessage('Git safe directory error detected. Click the Fix Git button.', 'error');
            
            // Show fix git button
            const updateBtn = document.getElementById('update-btn');
            updateBtn.textContent = 'Fix Git Config';
            updateBtn.disabled = false;
            updateBtn.className = 'w-full bg-yellow-600 hover:bg-yellow-700 text-white py-2 px-4 rounded transition-colors';
            updateBtn.onclick = fixGitConfig;
        } else {
            updateElement('update-info', 'Failed to check for updates');
            addConsoleMessage(`Failed to check for updates: ${error.message}`, 'error');
        }
    }
}

async function fixGitConfig() {
    try {
        updateElement('update-btn-text', 'Fixing...');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = true;
        
        addConsoleMessage('Fixing git configuration...', 'info');
        
        const result = await postAPI('/api/system/fix-git', {});
        
        if (result.success) {
            addConsoleMessage('Git configuration fixed successfully', 'success');
            
            // Reset button and retry update check
            updateBtn.textContent = 'Update System';
            updateBtn.onclick = performUpdate;
            
            // Retry update check
            setTimeout(() => {
                checkForUpdates();
            }, 1000);
        } else {
            addConsoleMessage(`Failed to fix git configuration: ${result.error}`, 'error');
            updateBtn.disabled = false;
            updateElement('update-btn-text', 'Fix Git Config');
        }
        
    } catch (error) {
        console.error('Error fixing git config:', error);
        addConsoleMessage('Failed to fix git configuration', 'error');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = false;
        updateElement('update-btn-text', 'Fix Git Config');
    }
}

async function performUpdate() {
    if (!confirm('This will update the system and restart the service. Continue?')) {
        return;
    }
    
    try {
        updateElement('update-btn-text', 'Updating...');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = true;
        updateBtn.className = 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-not-allowed';
        
        addConsoleMessage('Starting system update...', 'info');
        
        const data = await postAPI('/api/system/update', {});
        
        if (data.success) {
            addConsoleMessage('Update completed successfully', 'success');
            addConsoleMessage('System will restart automatically...', 'info');
            updateElement('update-info', 'Update completed. System restarting...');
            
            // Check for updates again after a delay
            setTimeout(() => {
                checkForUpdates();
            }, 30000); // Check again in 30 seconds
        } else {
            addConsoleMessage(`Update failed: ${data.error || 'Unknown error'}`, 'error');
            updateElement('update-btn-text', 'Update System');
            updateBtn.disabled = false;
            updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
        }
        
    } catch (error) {
        console.error('Error performing update:', error);
        addConsoleMessage('Update failed due to network error', 'error');
        updateElement('update-btn-text', 'Update System');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = false;
        updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
    }
}

async function checkForUpdatesQuiet() {
    try {
        const data = await fetchAPI('/api/system/check-updates');
        
        if (data.updates_available && data.commits_behind > 0) {
            // Show update notification in console if not on config tab
            if (currentTab !== 'config') {
                addConsoleMessage(`🔄 System update available: ${data.commits_behind} commits behind`, 'warning');
            }
            
            // Add visual indicator to config tab
            const configTabBtn = document.querySelector('[data-tab="config"]');
            if (configTabBtn && !configTabBtn.querySelector('.update-indicator')) {
                const indicator = document.createElement('span');
                indicator.className = 'update-indicator absolute -top-1 -right-1 w-3 h-3 bg-orange-500 rounded-full pulse-glow';
                configTabBtn.style.position = 'relative';
                configTabBtn.appendChild(indicator);
            }
        } else {
            // Remove update indicator if up to date
            const configTabBtn = document.querySelector('[data-tab="config"]');
            const indicator = configTabBtn?.querySelector('.update-indicator');
            if (indicator) {
                indicator.remove();
            }
        }
        
    } catch (error) {
        // Silently fail for background checks
        console.debug('Background update check failed:', error);
    }
}

async function restartService() {
    if (!confirm('This will restart the Ragnar service. The web interface may be temporarily unavailable. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Restarting Ragnar service...', 'info');
        updateElement('service-status', 'Restarting...');
        document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-yellow-700 text-yellow-300';
        
        const data = await postAPI('/api/system/restart-service', {});
        
        if (data.success) {
            addConsoleMessage('Service restart initiated', 'success');
            addConsoleMessage('Service will be back online shortly...', 'info');
            
            // Update status after delay
            setTimeout(() => {
                updateElement('service-status', 'Running');
                document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
                addConsoleMessage('Service restart completed', 'success');
            }, 10000); // 10 seconds delay
        } else {
            addConsoleMessage(`Service restart failed: ${data.error || 'Unknown error'}`, 'error');
            updateElement('service-status', 'Error');
            document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        }
        
    } catch (error) {
        console.error('Error restarting service:', error);
        addConsoleMessage('Failed to restart service', 'error');
        updateElement('service-status', 'Error');
        document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
    }
}

async function rebootSystem() {
    if (!confirm('This will reboot the entire system. The device will be offline for several minutes. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Initiating system reboot...', 'warning');
        
        const data = await postAPI('/api/system/reboot', {});
        
        if (data.success) {
            addConsoleMessage('System reboot initiated', 'success');
            addConsoleMessage('Device will be offline for several minutes...', 'warning');
            
            // Update connection status
            updateConnectionStatus(false);
        } else {
            addConsoleMessage(`Reboot failed: ${data.error || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error rebooting system:', error);
        addConsoleMessage('Failed to initiate system reboot', 'error');
    }
}

// ============================================================================
// WI-FI MANAGEMENT FUNCTIONS
// ============================================================================

async function startAPMode() {
    if (!confirm('Start AP Mode?\n\nThis will:\n• Disconnect from current Wi-Fi\n• Start "Ragnar" access point\n• Enable 3-minute smart cycling\n• Allow Wi-Fi configuration via AP\n\nContinue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Starting AP Mode...', 'info');
        updateWifiStatus('Starting AP Mode...', 'connecting');
        
        const data = await postAPI('/api/wifi/ap/enable', {});
        
        if (data.success) {
            addConsoleMessage(`AP Mode started: ${data.ap_config.ssid}`, 'success');
            updateWifiStatus(
                `AP Mode Active: "${data.ap_config.ssid}" | ${data.ap_config.timeout}s timeout | Smart cycling enabled`,
                'ap-mode'
            );
            
            // Auto-refresh Wi-Fi status
            setTimeout(refreshWifiStatus, 2000);
        } else {
            addConsoleMessage(`Failed to start AP Mode: ${data.message}`, 'error');
            updateWifiStatus(`Failed to start AP Mode: ${data.message}`, 'error');
        }
        
    } catch (error) {
        console.error('Error starting AP mode:', error);
        addConsoleMessage('Error starting AP Mode', 'error');
        updateWifiStatus('Error starting AP Mode', 'error');
    }
}

async function refreshWifiStatus() {
    try {
        const data = await fetchAPI('/api/wifi/status');
        
        if (data.ap_mode_active) {
            updateWifiStatus(
                `AP Mode Active: "${data.ap_ssid || 'Ragnar'}" | Connect to configure Wi-Fi`,
                'ap-mode'
            );
            updateElement('wifi-status-indicator', 'AP Mode');
            document.getElementById('wifi-status-indicator').className = 'text-sm px-2 py-1 rounded bg-orange-700 text-orange-300';
        } else if (data.wifi_connected) {
            updateWifiStatus(`Connected to: ${data.current_ssid || 'Wi-Fi Network'}`, 'connected');
            updateElement('wifi-status-indicator', 'Connected');
            document.getElementById('wifi-status-indicator').className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
        } else {
            updateWifiStatus('Wi-Fi disconnected', 'disconnected');
            updateElement('wifi-status-indicator', 'Disconnected');
            document.getElementById('wifi-status-indicator').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        }
        
        updateElement('wifi-info', data.wifi_connected ? 
            `Connected to: ${data.current_ssid || 'Unknown'}` : 
            'No Wi-Fi connection');
            
    } catch (error) {
        console.error('Error refreshing Wi-Fi status:', error);
        updateWifiStatus('Error checking Wi-Fi status', 'error');
        updateElement('wifi-status-indicator', 'Error');
        document.getElementById('wifi-status-indicator').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
    }
}

function updateWifiStatus(message, type = '') {
    // This function can be enhanced to show status messages in a notification area
    // For now, we'll use console messages and update the UI elements
    addConsoleMessage(message, type === 'error' ? 'error' : type === 'ap-mode' ? 'warning' : 'info');
}

async function loadConsoleLogs() {
    try {
        const data = await fetchAPI('/api/logs');
        if (data && data.logs) {
            updateConsole(data.logs);
        }
    } catch (error) {
        console.error('Error loading console logs:', error);
        // Add fallback console messages if log loading fails
        addConsoleMessage('Unable to load historical logs from server', 'warning');
        addConsoleMessage('Console will show new messages as they occur', 'info');
    }
}

// ============================================================================
// MANUAL MODE FUNCTIONS
// ============================================================================

async function loadManualModeData() {
    try {
        // Store current selections before reloading
        const currentIp = document.getElementById('manual-ip-dropdown')?.value || '';
        const currentPort = document.getElementById('manual-port-dropdown')?.value || '';
        const currentAction = document.getElementById('manual-action-dropdown')?.value || '';
        
        const data = await fetchAPI('/api/manual/targets');
        
        // Populate IP dropdown
        const ipDropdown = document.getElementById('manual-ip-dropdown');
        if (ipDropdown) {
            ipDropdown.innerHTML = '<option value="">Select IP</option>';
            if (data.targets && data.targets.length > 0) {
                data.targets.forEach(target => {
                    const option = document.createElement('option');
                    option.value = target.ip;
                    option.textContent = `${target.ip} (${target.hostname})`;
                    if (target.ip === currentIp) {
                        option.selected = true;
                    }
                    ipDropdown.appendChild(option);
                });
            }
        }
        
        // Populate vulnerability scan IP dropdown
        const vulnIpDropdown = document.getElementById('vuln-ip-dropdown');
        if (vulnIpDropdown) {
            vulnIpDropdown.innerHTML = '<option value="">Select IP</option>';
            if (data.targets && data.targets.length > 0) {
                data.targets.forEach(target => {
                    const option = document.createElement('option');
                    option.value = target.ip;
                    option.textContent = `${target.ip} (${target.hostname})`;
                    vulnIpDropdown.appendChild(option);
                });
            }
        }
        
        // Populate action dropdown with available attack types
        const actionDropdown = document.getElementById('manual-action-dropdown');
        if (actionDropdown) {
            actionDropdown.innerHTML = '<option value="">Select Action</option>';
            const actions = ['ssh', 'ftp', 'telnet', 'smb', 'rdp', 'sql'];
            actions.forEach(action => {
                const option = document.createElement('option');
                option.value = action;
                option.textContent = action.toUpperCase() + ' Brute Force';
                if (action === currentAction) {
                    option.selected = true;
                }
                actionDropdown.appendChild(option);
            });
        }
        
        // Store targets data for updateManualPorts function
        window.manualTargetsData = data.targets || [];
        
        // Restore port selection if IP was selected
        if (currentIp) {
            updateManualPorts();
            // Restore port selection after ports are populated
            setTimeout(() => {
                const portDropdown = document.getElementById('manual-port-dropdown');
                if (portDropdown && currentPort) {
                    portDropdown.value = currentPort;
                }
            }, 50);
        }
        
    } catch (error) {
        console.error('Error loading manual mode data:', error);
        addConsoleMessage('Failed to load manual mode data', 'error');
    }
}

function updateManualPorts() {
    const ipDropdown = document.getElementById('manual-ip-dropdown');
    const portDropdown = document.getElementById('manual-port-dropdown');
    
    if (!ipDropdown || !portDropdown) return;
    
    const selectedIp = ipDropdown.value;
    portDropdown.innerHTML = '<option value="">Select Port</option>';
    
    if (selectedIp && window.manualTargetsData) {
        // Find the target with the selected IP
        const target = window.manualTargetsData.find(t => t.ip === selectedIp);
        if (target && target.ports) {
            target.ports.forEach(port => {
                const option = document.createElement('option');
                option.value = port;
                option.textContent = port;
                portDropdown.appendChild(option);
            });
        }
    }
}

async function executeManualAttack() {
    const ip = document.getElementById('manual-ip-dropdown')?.value;
    const port = document.getElementById('manual-port-dropdown')?.value;
    const action = document.getElementById('manual-action-dropdown')?.value;
    
    if (!ip || !port || !action) {
        addConsoleMessage('Please select IP, Port, and Action for manual attack', 'error');
        return;
    }
    
    try {
        addConsoleMessage(`Executing manual attack: ${action} on ${ip}:${port}`, 'info');
        
        const data = await postAPI('/api/manual/execute-attack', {
            ip: ip,
            port: port,
            action: action
        });
        
        if (data.success) {
            addConsoleMessage(`Manual attack executed successfully: ${data.message}`, 'success');
        } else {
            addConsoleMessage(`Manual attack failed: ${data.message || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error executing manual attack:', error);
        addConsoleMessage('Failed to execute manual attack due to network error', 'error');
    }
}

async function startOrchestrator() {
    try {
        addConsoleMessage('Starting automatic mode...', 'info');
        
        const data = await postAPI('/api/manual/orchestrator/start', {});
        
        if (data.success) {
            addConsoleMessage('Automatic mode started successfully', 'success');
            updateElement('ragnar-mode', 'Auto');
            document.getElementById('ragnar-mode').className = 'text-green-400 font-semibold';
            
            // Hide manual controls
            const manualControls = document.getElementById('manual-controls');
            if (manualControls) {
                manualControls.classList.add('hidden');
            }
        } else {
            addConsoleMessage(`Failed to start automatic mode: ${data.message || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error starting orchestrator:', error);
        addConsoleMessage('Failed to start automatic mode', 'error');
    }
}

async function stopOrchestrator() {
    try {
        addConsoleMessage('Stopping automatic mode...', 'info');
        
        const data = await postAPI('/api/manual/orchestrator/stop', {});
        
        if (data.success) {
            addConsoleMessage('Automatic mode stopped - Manual mode activated', 'warning');
            updateElement('ragnar-mode', 'Manual');
            document.getElementById('ragnar-mode').className = 'text-orange-400 font-semibold';
            
            // Show manual controls
            const manualControls = document.getElementById('manual-controls');
            if (manualControls) {
                manualControls.classList.remove('hidden');
                // Load manual mode data
                loadManualModeData();
            }
        } else {
            addConsoleMessage(`Failed to stop automatic mode: ${data.message || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error stopping orchestrator:', error);
        addConsoleMessage('Failed to stop automatic mode', 'error');
    }
}

async function triggerNetworkScan() {
    try {
        addConsoleMessage('Triggering network scan...', 'info');
        
        const data = await postAPI('/api/manual/scan/network', {});
        
        if (data.success) {
            addConsoleMessage('Network scan triggered successfully', 'success');
        } else {
            addConsoleMessage(`Failed to trigger network scan: ${data.message || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error triggering network scan:', error);
        addConsoleMessage('Failed to trigger network scan', 'error');
    }
}

async function triggerVulnScan() {
    try {
        const vulnIpDropdown = document.getElementById('vuln-ip-dropdown');
        const selectedIp = vulnIpDropdown ? vulnIpDropdown.value : '';
        
        if (!selectedIp) {
            addConsoleMessage('Please select an IP address for vulnerability scan', 'error');
            return;
        }
        
        addConsoleMessage(`Triggering vulnerability scan for ${selectedIp}...`, 'info');
        
        const data = await postAPI('/api/manual/scan/vulnerability', { ip: selectedIp });
        
        if (data.success) {
            addConsoleMessage('Vulnerability scan triggered successfully', 'success');
        } else {
            addConsoleMessage(`Failed to trigger vulnerability scan: ${data.message || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error triggering vulnerability scan:', error);
        addConsoleMessage('Failed to trigger vulnerability scan', 'error');
    }
}

// ============================================================================
// API HELPERS
// ============================================================================

async function fetchAPI(endpoint) {
    try {
        const response = await fetch(endpoint);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Error fetching ${endpoint}:`, error);
        throw error;
    }
}

async function postAPI(endpoint, data) {
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Error posting to ${endpoint}:`, error);
        throw error;
    }
}

// ============================================================================
// DASHBOARD UPDATES
// ============================================================================

async function refreshDashboard() {
    try {
        const data = await fetchAPI('/api/status');
        updateDashboardStatus(data);
    } catch (error) {
        console.error('Error refreshing dashboard:', error);
    }
}

function updateDashboardStatus(data) {
    // If the WebSocket data has zero counts, fetch from our dashboard API instead
    if ((data.target_count || 0) === 0 && (data.port_count || 0) === 0 && 
        (data.vulnerability_count || 0) === 0 && (data.credential_count || 0) === 0) {
        
        // Fetch proper dashboard stats
        fetchAPI('/api/dashboard/stats')
            .then(stats => {
                updateElement('target-count', stats.target_count || 0);
                updateElement('port-count', stats.port_count || 0);
                updateElement('vuln-count', stats.vulnerability_count || 0);
                updateElement('cred-count', stats.credential_count || 0);
            })
            .catch(() => {
                // Fallback to WebSocket data if API fails
                updateElement('target-count', data.target_count || 0);
                updateElement('port-count', data.port_count || 0);
                updateElement('vuln-count', data.vulnerability_count || 0);
                updateElement('cred-count', data.credential_count || 0);
            });
    } else {
        // Use WebSocket data if it has non-zero values
        updateElement('target-count', data.target_count || 0);
        updateElement('port-count', data.port_count || 0);
        updateElement('vuln-count', data.vulnerability_count || 0);
        updateElement('cred-count', data.credential_count || 0);
    }
    
    // Update status - use the actual e-paper display text
    updateElement('ragnar-status', data.ragnar_status || 'IDLE');
    updateElement('ragnar-says', (data.ragnar_status2 || data.ragnar_status || 'Awakening...'));
    
    // Update mode and handle manual controls
    const isManualMode = data.manual_mode;
    updateElement('Ragnar-mode', isManualMode ? 'Manual' : 'Auto');
    
    // Update mode styling
    const modeElement = document.getElementById('Ragnar-mode');
    if (modeElement) {
        if (isManualMode) {
            modeElement.className = 'text-orange-400 font-semibold';
        } else {
            modeElement.className = 'text-green-400 font-semibold';
        }
    }
    
    // Show/hide manual controls based on mode
    const manualControls = document.getElementById('manual-controls');
    if (manualControls) {
        if (isManualMode) {
            const wasHidden = manualControls.classList.contains('hidden');
            manualControls.classList.remove('hidden');
            // Only load manual mode data when first showing controls, not on every status update
            if (wasHidden) {
                loadManualModeData();
            }
        } else {
            manualControls.classList.add('hidden');
        }
    }
    
    // Update connectivity status
    updateConnectivityIndicator('wifi-status', data.wifi_connected);
    updateConnectivityIndicator('bluetooth-status', data.bluetooth_active);
    updateConnectivityIndicator('usb-status', data.usb_active);
    updateConnectivityIndicator('pan-status', data.pan_connected);
}

function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function updateConnectivityIndicator(id, active) {
    const element = document.getElementById(id);
    if (element) {
        if (active) {
            element.className = 'w-3 h-3 bg-green-500 rounded-full pulse-glow';
        } else {
            element.className = 'w-3 h-3 bg-gray-600 rounded-full';
        }
    }
}

// ============================================================================
// CONSOLE
// ============================================================================

let consoleBuffer = [];
const MAX_CONSOLE_LINES = 200;

function addConsoleMessage(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const colors = {
        'success': 'text-green-400',
        'error': 'text-red-400',
        'warning': 'text-yellow-400',
        'info': 'text-blue-400'
    };
    
    const colorClass = colors[type] || colors['info'];
    const logEntry = {
        timestamp,
        message,
        type,
        colorClass
    };
    
    consoleBuffer.push(logEntry);
    
    // Keep only the last MAX_CONSOLE_LINES
    if (consoleBuffer.length > MAX_CONSOLE_LINES) {
        consoleBuffer = consoleBuffer.slice(-MAX_CONSOLE_LINES);
    }
    
    updateConsoleDisplay();
}

function updateConsole(logs) {
    if (!logs || !Array.isArray(logs)) {
        // If no logs available, add informational messages
        if (consoleBuffer.length === 0) {
            addConsoleMessage('No historical logs available', 'warning');
            addConsoleMessage('New activity will appear here as it occurs', 'info');
        }
        return;
    }
    
    // If logs are empty array, provide user feedback
    if (logs.length === 0) {
        if (consoleBuffer.length === 0) {
            addConsoleMessage('No recent activity logged', 'info');
            addConsoleMessage('Waiting for new events...', 'info');
        }
        return;
    }
    
    // Clear existing buffer and add new logs
    consoleBuffer = [];
    
    logs.forEach(log => {
        // Skip empty lines
        if (!log.trim()) return;
        
        let type = 'info';
        if (log.includes('ERROR') || log.includes('Error') || log.includes('error')) type = 'error';
        else if (log.includes('WARN') || log.includes('Warning') || log.includes('warning')) type = 'warning';
        else if (log.includes('INFO') || log.includes('Info')) type = 'info';
        else if (log.includes('DEBUG') || log.includes('Debug')) type = 'info';
        else if (log.includes('SUCCESS') || log.includes('Success')) type = 'success';
        
        const timestamp = new Date().toLocaleTimeString();
        const colors = {
            'success': 'text-green-400',
            'error': 'text-red-400',
            'warning': 'text-yellow-400',
            'info': 'text-gray-300'
        };
        
        consoleBuffer.push({
            timestamp,
            message: log.trim(),
            type,
            colorClass: colors[type]
        });
    });
    
    updateConsoleDisplay();
}

function updateConsoleDisplay() {
    const console = document.getElementById('console-output');
    if (!console) return;
    
    console.innerHTML = consoleBuffer.map(entry => 
        `<div class="${entry.colorClass}">[${entry.timestamp}] ${escapeHtml(entry.message)}</div>`
    ).join('');
    
    // Auto-scroll to bottom
    console.scrollTop = console.scrollHeight;
}

function clearConsole() {
    consoleBuffer = [];
    const console = document.getElementById('console-output');
    if (console) {
        console.innerHTML = '<div class="text-green-400">Console cleared</div>';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// TABLE DISPLAYS
// ============================================================================

function displayNetworkTable(data) {
    const container = document.getElementById('network-table');
    if (!container) return;
    
    if (!data || data.length === 0) {
        container.innerHTML = '<p class="text-gray-400">No network data available</p>';
        return;
    }
    
    let html = `
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-700">
                <thead class="bg-gray-800">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">IP Address</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Hostname</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">MAC Address</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Open Ports</th>
                    </tr>
                </thead>
                <tbody class="bg-gray-900 divide-y divide-gray-700">
    `;
    
    data.forEach(item => {
        const status = item.Alive === '1' ? 'Online' : 'Offline';
        const statusColor = item.Alive === '1' ? 'text-green-400' : 'text-gray-400';
        const ports = item.Ports ? item.Ports.split(';').filter(p => p.trim()).join(', ') : 'None';
        
        html += `
            <tr class="hover:bg-gray-800 transition-colors">
                <td class="px-6 py-4 whitespace-nowrap text-sm text-white">${item.IPs || 'N/A'}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">${item.Hostname || '-'}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-mono">${item['MAC Address'] || '-'}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm ${statusColor}">${status}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">${ports}</td>
            </tr>
        `;
    });
    
    html += '</tbody></table></div>';
    container.innerHTML = html;
}

function displayCredentialsTable(data) {
    const container = document.getElementById('credentials-table');
    if (!container) return;
    
    if (!data || Object.keys(data).length === 0) {
        container.innerHTML = '<p class="text-gray-400">No credentials discovered yet</p>';
        return;
    }
    
    let html = '<div class="space-y-6">';
    
    Object.entries(data).forEach(([service, creds]) => {
        if (creds && creds.length > 0) {
            html += `
                <div class="bg-gray-800 rounded-lg p-4">
                    <h3 class="text-lg font-semibold text-Ragnar-400 mb-3">${service.toUpperCase()} (${creds.length})</h3>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-700">
                            <thead>
                                <tr>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Target</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Username</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Password</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-700">
            `;
            
            creds.forEach(cred => {
                html += `
                    <tr class="hover:bg-gray-700 transition-colors">
                        <td class="px-4 py-2 text-sm text-white">${cred.ip || 'N/A'}</td>
                        <td class="px-4 py-2 text-sm text-green-400 font-mono">${cred.username || 'N/A'}</td>
                        <td class="px-4 py-2 text-sm text-yellow-400 font-mono">${cred.password || 'N/A'}</td>
                    </tr>
                `;
            });
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }
    });
    
    html += '</div>';
    
    if (html === '<div class="space-y-6"></div>') {
        container.innerHTML = '<p class="text-gray-400">No credentials discovered yet</p>';
    } else {
        container.innerHTML = html;
    }
}

function displayLootTable(data) {
    const container = document.getElementById('loot-table');
    if (!container) return;
    
    if (!data || data.length === 0) {
        container.innerHTML = '<p class="text-gray-400">No loot data available</p>';
        return;
    }
    
    let html = `<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">`;
    
    data.forEach(item => {
        html += `
            <div class="bg-gray-800 rounded-lg p-4 hover:bg-gray-700 transition-colors">
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-lg font-semibold text-Ragnar-400 truncate" title="${item.filename || 'Unknown File'}">${item.filename || 'Unknown File'}</h3>
                    <span class="text-xs text-gray-400 ml-2">${item.size || 'N/A'}</span>
                </div>
                <div class="space-y-2 text-sm text-gray-300">
                    <p><span class="text-gray-400">Source:</span> ${item.source || 'Unknown'}</p>
                    <p><span class="text-gray-400">Timestamp:</span> ${item.timestamp || 'Unknown'}</p>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

function displayConfigForm(config) {
    const container = document.getElementById('config-form');
    
    let html = '<div class="space-y-6"><form id="config-update-form">';
    
    // Group config by sections
    const sections = {
        'General': ['manual_mode', 'websrv', 'debug_mode', 'web_increment', 'blacklistcheck'],
        'Timing': ['startup_delay', 'web_delay', 'screen_delay', 'scan_interval'],
        'Display': ['epd_type', 'ref_width', 'ref_height']
    };
    
    for (const [sectionName, keys] of Object.entries(sections)) {
        html += `
            <div class="bg-slate-800 bg-opacity-50 rounded-lg p-4">
                <h3 class="text-lg font-bold mb-4 text-Ragnar-400">${sectionName}</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        `;
        
        keys.forEach(key => {
            if (config.hasOwnProperty(key)) {
                const value = config[key];
                const type = typeof value === 'boolean' ? 'checkbox' : 'text';
                
                if (type === 'checkbox') {
                    html += `
                        <label class="flex items-center space-x-3 p-3 rounded-lg hover:bg-slate-700 hover:bg-opacity-50 transition-colors cursor-pointer">
                            <input type="checkbox" name="${key}" ${value ? 'checked' : ''} 
                                   class="w-5 h-5 rounded bg-slate-700 border-slate-600 text-Ragnar-500 focus:ring-Ragnar-500">
                            <span>${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
                        </label>
                    `;
                } else {
                    html += `
                        <div class="space-y-2">
                            <label class="block text-sm text-gray-400">
                                ${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </label>
                            <input type="${type}" name="${key}" value="${value}"
                                   class="w-full px-4 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-Ragnar-500 focus:ring-1 focus:ring-Ragnar-500">
                        </div>
                    `;
                }
            }
        });
        
        html += '</div></div>';
    }
    
    html += `
        <button type="submit" class="w-full bg-Ragnar-600 hover:bg-Ragnar-700 text-white font-bold py-3 px-6 rounded-lg transition-colors">
            Save Configuration
        </button>
    </form></div>`;
    
    container.innerHTML = html;
    
    // Add form submit handler
    document.getElementById('config-update-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig(e.target);
    });
}

async function saveConfig(form) {
    const formData = new FormData(form);
    const config = {};
    
    // First, get all checkboxes and set them to false by default
    const checkboxes = form.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        config[checkbox.name] = false;
    });
    
    // Then get all form values, including checked checkboxes
    for (const [key, value] of formData.entries()) {
        const input = form.elements[key];
        if (input.type === 'checkbox') {
            config[key] = input.checked;
        } else if (!isNaN(value) && value !== '') {
            config[key] = Number(value);
        } else {
            config[key] = value;
        }
    }
    
    // Handle unchecked checkboxes explicitly
    checkboxes.forEach(checkbox => {
        config[checkbox.name] = checkbox.checked;
    });
    
    console.log('Saving config:', config); // Debug logging
    
    try {
        const result = await postAPI('/api/config', config);
        addConsoleMessage('Configuration saved successfully', 'success');
        
        // If manual_mode was changed, refresh the dashboard to update UI
        if (config.hasOwnProperty('manual_mode')) {
            setTimeout(() => {
                refreshDashboard();
            }, 500);
        }
        
    } catch (error) {
        console.error('Config save error:', error);
        addConsoleMessage('Failed to save configuration', 'error');
    }
}

// E-Paper Display Functions
async function loadEpaperDisplay() {
    try {
        const data = await fetchAPI('/api/epaper-display');
        
        // Update status text
        updateElement('epaper-status-1', data.status_text || 'Unknown');
        updateElement('epaper-status-2', data.status_text2 || 'Unknown');
        
        // Update timestamp
        if (data.timestamp) {
            const date = new Date(data.timestamp * 1000);
            updateElement('epaper-timestamp', date.toLocaleString());
        }
        
        // Update display image
        const imgElement = document.getElementById('epaper-display-image');
        const loadingElement = document.getElementById('epaper-loading');
        const connectionElement = document.getElementById('epaper-connection');
        
        if (data.image) {
            imgElement.src = data.image;
            imgElement.style.display = 'block';
            loadingElement.style.display = 'none';
            
            // Update resolution info
            if (data.width && data.height) {
                updateElement('epaper-resolution', `${data.width} x ${data.height}`);
            }
            
            // Update connection status
            connectionElement.textContent = 'Live';
            connectionElement.className = 'text-green-400 font-medium';
        } else {
            imgElement.style.display = 'none';
            loadingElement.style.display = 'flex';
            loadingElement.innerHTML = `
                <div class="text-center text-gray-600">
                    <svg class="h-8 w-8 mx-auto mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <p>${data.message || 'No display image available'}</p>
                </div>
            `;
            
            // Update connection status
            connectionElement.textContent = 'Offline';
            connectionElement.className = 'text-red-400 font-medium';
        }
        
    } catch (error) {
        console.error('Error loading e-paper display:', error);
        addConsoleMessage('Failed to load e-paper display', 'error');
        
        // Update connection status
        const connectionElement = document.getElementById('epaper-connection');
        connectionElement.textContent = 'Error';
        connectionElement.className = 'text-red-400 font-medium';
    }
}

function refreshEpaperDisplay() {
    addConsoleMessage('Refreshing e-paper display...', 'info');
    loadEpaperDisplay();
}

// E-Paper display size toggle functionality
let epaperSizeMode = 'large'; // default to large size
function toggleEpaperSize() {
    const imgElement = document.getElementById('epaper-display-image');
    
    if (epaperSizeMode === 'large') {
        // Switch to extra large
        imgElement.style.maxHeight = '1200px';
        imgElement.style.minHeight = '600px';
        epaperSizeMode = 'xlarge';
        addConsoleMessage('E-paper display size: Extra Large', 'info');
    } else if (epaperSizeMode === 'xlarge') {
        // Switch to medium
        imgElement.style.maxHeight = '600px';
        imgElement.style.minHeight = '300px';
        epaperSizeMode = 'medium';
        addConsoleMessage('E-paper display size: Medium', 'info');
    } else {
        // Switch back to large
        imgElement.style.maxHeight = '800px';
        imgElement.style.minHeight = '400px';
        epaperSizeMode = 'large';
        addConsoleMessage('E-paper display size: Large', 'info');
    }
}

// Add e-paper display to auto-refresh
function setupEpaperAutoRefresh() {
    setInterval(() => {
        if (currentTab === 'epaper') {
            loadEpaperDisplay();
        }
    }, 5000); // Refresh every 5 seconds when on e-paper tab
}

// ============================================================================
// FILE MANAGEMENT FUNCTIONS
// ============================================================================

let currentDirectory = '/';
let fileOperationInProgress = false;

function loadFiles(path = '/') {
    if (fileOperationInProgress) return;
    
    fetch(`/api/files/list?path=${encodeURIComponent(path)}`)
        .then(response => response.json())
        .then(files => {
            displayFiles(files, path);
            updateCurrentPath(path);
        })
        .catch(error => {
            console.error('Error loading files:', error);
            showFileError('Failed to load files: ' + error.message);
        });
}

function displayFiles(files, path) {
    const fileList = document.getElementById('file-list');
    currentDirectory = path;
    
    if (!fileList) return;
    
    if (files.length === 0) {
        fileList.innerHTML = '<p class="text-gray-400 p-4">No files found in this directory</p>';
        return;
    }
    
    let html = '<div class="space-y-2">';
    
    // Add back button if not in root
    if (path !== '/') {
        const parentPath = path.split('/').slice(0, -1).join('/') || '/';
        html += `
            <div class="flex items-center p-3 hover:bg-slate-700 rounded-lg cursor-pointer transition-colors" onclick="loadFiles('${parentPath}')">
                <svg class="w-5 h-5 mr-3 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                </svg>
                <span class="text-blue-400">.. (Parent Directory)</span>
            </div>
        `;
    }
    
    // Sort files - directories first, then by name
    files.sort((a, b) => {
        if (a.is_directory && !b.is_directory) return -1;
        if (!a.is_directory && b.is_directory) return 1;
        return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    });
    
    files.forEach(file => {
        const icon = file.is_directory ? 
            `<svg class="w-5 h-5 mr-3 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-5l-2-2H5a2 2 0 00-2 2z"></path>
            </svg>` :
            `<svg class="w-5 h-5 mr-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
            </svg>`;
        
        const size = file.is_directory ? '' : formatBytes(file.size);
        const date = file.modified ? new Date(file.modified * 1000).toLocaleDateString() : '';
        
        html += `
            <div class="flex items-center justify-between p-3 hover:bg-slate-700 rounded-lg transition-colors">
                <div class="flex items-center cursor-pointer flex-1" onclick="${file.is_directory ? `loadFiles('${file.path}')` : ''}">
                    ${icon}
                    <div class="flex-1">
                        <div class="font-medium">${file.name}</div>
                        ${!file.is_directory && size ? `<div class="text-sm text-gray-400">${size} • ${date}</div>` : ''}
                    </div>
                </div>
                ${!file.is_directory ? `
                    <div class="flex space-x-2">
                        <button onclick="downloadFile('${file.path}')" class="p-2 text-blue-400 hover:bg-slate-600 rounded" title="Download">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-4-4m4 4l4-4m6 4H6"></path>
                            </svg>
                        </button>
                        <button onclick="deleteFile('${file.path}')" class="p-2 text-red-400 hover:bg-slate-600 rounded" title="Delete">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                            </svg>
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    });
    
    html += '</div>';
    fileList.innerHTML = html;
}

function displayDirectoryTree() {
    const treeContainer = document.getElementById('directory-tree');
    if (!treeContainer) return;
    
    const directories = [
        { name: 'Data Stolen', path: '/data_stolen', icon: '🗃️' },
        { name: 'Scan Results', path: '/scan_results', icon: '📊' },
        { name: 'Cracked Passwords', path: '/crackedpwd', icon: '🔓' },
        { name: 'Vulnerabilities', path: '/vulnerabilities', icon: '⚠️' },
        { name: 'Logs', path: '/logs', icon: '📋' },
        { name: 'Backups', path: '/backups', icon: '💾' },
        { name: 'Uploads', path: '/uploads', icon: '📤' }
    ];
    
    let html = '<div class="space-y-1">';
    directories.forEach(dir => {
        html += `
            <div class="flex items-center p-3 hover:bg-slate-700 rounded-lg cursor-pointer transition-colors" onclick="loadFiles('${dir.path}')">
                <span class="mr-3">${dir.icon}</span>
                <span>${dir.name}</span>
            </div>
        `;
    });
    html += '</div>';
    
    treeContainer.innerHTML = html;
}

function updateCurrentPath(path) {
    const pathElement = document.getElementById('current-path');
    if (pathElement) {
        pathElement.textContent = path;
    }
}

function downloadFile(filePath) {
    if (fileOperationInProgress) return;
    
    const downloadUrl = `/api/files/download?path=${encodeURIComponent(filePath)}`;
    
    // Create a temporary link to trigger download
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = '';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showFileSuccess(`Downloading ${filePath.split('/').pop()}`);
}

function deleteFile(filePath) {
    if (fileOperationInProgress) return;
    
    const fileName = filePath.split('/').pop();
    showFileConfirmModal(
        'Delete File',
        `Are you sure you want to delete "${fileName}"? This action cannot be undone.`,
        () => {
            fileOperationInProgress = true;
            fetch('/api/files/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ path: filePath })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showFileSuccess(`Deleted ${fileName}`);
                    refreshFiles();
                } else {
                    showFileError(`Failed to delete file: ${data.error}`);
                }
            })
            .catch(error => {
                showFileError(`Error deleting file: ${error.message}`);
            })
            .finally(() => {
                fileOperationInProgress = false;
                closeFileModal();
            });
        }
    );
}

function uploadFile() {
    // Create file input
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    
    input.onchange = function(event) {
        const files = event.target.files;
        if (files.length === 0) return;
        
        const formData = new FormData();
        
        // Add all selected files
        for (let file of files) {
            formData.append('file', file);
        }
        
        // Set upload path (default to uploads)
        formData.append('path', '/uploads');
        
        fileOperationInProgress = true;
        showFileLoading('Uploading files...');
        
        fetch('/api/files/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showFileSuccess(`Uploaded ${files.length} file(s)`);
                refreshFiles();
            } else {
                showFileError(`Upload failed: ${data.error}`);
            }
        })
        .catch(error => {
            showFileError(`Upload error: ${error.message}`);
        })
        .finally(() => {
            fileOperationInProgress = false;
        });
    };
    
    input.click();
}

function clearFiles() {
    showFileConfirmModal(
        'Clear Files',
        `
        <div class="space-y-3">
            <p>Choose the type of file clearing:</p>
            <div class="space-y-2">
                <label class="flex items-center">
                    <input type="radio" name="clearType" value="light" checked class="mr-2">
                    <span>Light Clear (logs, temporary files only)</span>
                </label>
                <label class="flex items-center">
                    <input type="radio" name="clearType" value="full" class="mr-2">
                    <span>Full Clear (all data including configs)</span>
                </label>
            </div>
        </div>
        `,
        () => {
            const selectedType = document.querySelector('input[name="clearType"]:checked')?.value || 'light';
            
            fileOperationInProgress = true;
            showFileLoading('Clearing files...');
            
            fetch('/api/files/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ type: selectedType })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showFileSuccess(data.message);
                    refreshFiles();
                } else {
                    showFileError(`Clear failed: ${data.error}`);
                }
            })
            .catch(error => {
                showFileError(`Clear error: ${error.message}`);
            })
            .finally(() => {
                fileOperationInProgress = false;
                closeFileModal();
            });
        }
    );
}

function refreshFiles() {
    displayDirectoryTree();
    loadFiles(currentDirectory);
}

function showFileSuccess(message) {
    showNotification(message, 'success');
}

function showFileError(message) {
    showNotification(message, 'error');
}

function showFileLoading(message) {
    showNotification(message, 'info');
}

function showFileConfirmModal(title, content, onConfirm) {
    const modal = document.getElementById('file-operations-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const confirmBtn = document.getElementById('modal-confirm');
    
    if (!modal || !modalTitle || !modalContent || !confirmBtn) return;
    
    modalTitle.textContent = title;
    modalContent.innerHTML = content;
    
    // Remove existing listeners
    const newConfirmBtn = confirmBtn.cloneNode(true);
    confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
    
    // Add new listener
    newConfirmBtn.addEventListener('click', onConfirm);
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeFileModal() {
    const modal = document.getElementById('file-operations-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg max-w-sm transform translate-x-full transition-transform duration-300 ${
        type === 'success' ? 'bg-green-600' : 
        type === 'error' ? 'bg-red-600' : 
        'bg-blue-600'
    } text-white`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// ============================================================================
// IMAGE GALLERY FUNCTIONS
// ============================================================================

let currentImageFilter = 'all';
let allImages = [];

function loadImagesData() {
    fetch('/api/images/list')
        .then(response => response.json())
        .then(images => {
            allImages = images;
            displayImages(images);
        })
        .catch(error => {
            console.error('Error loading images:', error);
            showImageError('Failed to load images: ' + error.message);
        });
}

function displayImages(images) {
    const imageGrid = document.getElementById('image-grid');
    if (!imageGrid) return;
    
    if (images.length === 0) {
        imageGrid.innerHTML = '<p class="text-gray-400 col-span-full text-center py-8">No images found</p>';
        return;
    }
    
    let html = '';
    images.forEach(image => {
        const date = new Date(image.modified * 1000).toLocaleDateString();
        const size = formatBytes(image.size);
        
        html += `
            <div class="image-item bg-slate-800 rounded-lg overflow-hidden hover:scale-105 transition-transform cursor-pointer"
                 data-category="${image.category}" onclick="showImageDetail('${image.path}')">
                <div class="aspect-square relative">
                    <img src="${image.url}" alt="${image.filename}" 
                         class="w-full h-full object-cover" 
                         onerror="this.src='/web/images/no-image.png'">
                    <div class="absolute top-2 right-2">
                        <span class="bg-black bg-opacity-70 text-white text-xs px-2 py-1 rounded">
                            ${image.category.replace('_', ' ')}
                        </span>
                    </div>
                </div>
                <div class="p-3">
                    <h4 class="font-medium text-sm truncate" title="${image.filename}">${image.filename}</h4>
                    <p class="text-xs text-gray-400">${size} • ${date}</p>
                </div>
            </div>
        `;
    });
    
    imageGrid.innerHTML = html;
}

function filterImages(category) {
    currentImageFilter = category;
    
    // Update filter button states
    document.querySelectorAll('.image-filter-btn').forEach(btn => {
        if (btn.dataset.filter === category) {
            btn.classList.remove('bg-gray-600');
            btn.classList.add('bg-Ragnar-600');
        } else {
            btn.classList.remove('bg-Ragnar-600');
            btn.classList.add('bg-gray-600');
        }
    });
    
    // Filter and display images
    const filteredImages = category === 'all' ? 
        allImages : 
        allImages.filter(img => img.category === category);
    
    displayImages(filteredImages);
}

function showImageDetail(imagePath) {
    // Get image info
    fetch(`/api/images/info?path=${encodeURIComponent(imagePath)}`)
        .then(response => response.json())
        .then(info => {
            const modal = document.getElementById('image-detail-modal');
            const title = document.getElementById('image-detail-title');
            const img = document.getElementById('image-detail-img');
            const infoDiv = document.getElementById('image-detail-info');
            const downloadBtn = document.getElementById('download-image-btn');
            const deleteBtn = document.getElementById('delete-image-btn');
            
            if (!modal || !title || !img || !infoDiv || !downloadBtn || !deleteBtn) return;
            
            title.textContent = info.filename;
            img.src = `/api/images/serve?path=${encodeURIComponent(imagePath)}`;
            img.alt = info.filename;
            
            infoDiv.innerHTML = `
                <div class="grid grid-cols-2 gap-2">
                    <span class="text-gray-400">Filename:</span>
                    <span>${info.filename}</span>
                    
                    <span class="text-gray-400">Size:</span>
                    <span>${info.size_formatted}</span>
                    
                    <span class="text-gray-400">Modified:</span>
                    <span>${info.modified_formatted}</span>
                    
                    ${info.width && info.height ? `
                        <span class="text-gray-400">Dimensions:</span>
                        <span>${info.width} × ${info.height}</span>
                    ` : ''}
                    
                    ${info.format ? `
                        <span class="text-gray-400">Format:</span>
                        <span>${info.format}</span>
                    ` : ''}
                </div>
            `;
            
            // Set up download button
            downloadBtn.onclick = () => downloadImage(imagePath);
            
            // Set up delete button
            deleteBtn.onclick = () => deleteImage(imagePath);
            
            modal.classList.remove('hidden');
            modal.classList.add('flex');
        })
        .catch(error => {
            console.error('Error getting image info:', error);
            showImageError('Failed to load image details');
        });
}

function closeImageModal() {
    const modal = document.getElementById('image-detail-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

function downloadImage(imagePath) {
    const downloadUrl = `/api/images/serve?path=${encodeURIComponent(imagePath)}`;
    
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = '';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showImageSuccess('Download started');
}

function deleteImage(imagePath) {
    if (!confirm('Are you sure you want to delete this image? This action cannot be undone.')) {
        return;
    }
    
    fetch('/api/images/delete', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ path: imagePath })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showImageSuccess('Image deleted successfully');
            closeImageModal();
            refreshImages();
        } else {
            showImageError(`Failed to delete image: ${data.error}`);
        }
    })
    .catch(error => {
        showImageError(`Error deleting image: ${error.message}`);
    });
}

function captureScreenshot() {
    showImageLoading('Capturing screenshot...');
    
    fetch('/api/images/capture', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showImageSuccess('Screenshot captured successfully');
            refreshImages();
        } else {
            showImageError(`Failed to capture screenshot: ${data.error}`);
        }
    })
    .catch(error => {
        showImageError(`Error capturing screenshot: ${error.message}`);
    });
}

function refreshImages() {
    loadImagesData();
}

function showImageSuccess(message) {
    showNotification(message, 'success');
}

function showImageError(message) {
    showNotification(message, 'error');
}

function showImageLoading(message) {
    showNotification(message, 'info');
}

// ============================================================================
// SYSTEM MONITORING FUNCTIONS
// ============================================================================

let systemMonitoringInterval;
let currentProcessSort = 'cpu';

function loadSystemData() {
    fetchSystemStatus();
    fetchNetworkStats();
    
    // Auto-refresh every 5 seconds when on system tab
    if (systemMonitoringInterval) {
        clearInterval(systemMonitoringInterval);
    }
    
    systemMonitoringInterval = setInterval(() => {
        if (currentTab === 'system') {
            fetchSystemStatus();
            fetchNetworkStats();
        }
    }, 5000);
}

function fetchSystemStatus() {
    fetch('/api/system/status')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showSystemError('Failed to load system status: ' + data.error);
                return;
            }
            updateSystemOverview(data);
            updateProcessList(data.processes);
            updateNetworkInterfaces(data.network_interfaces);
            updateTemperatureDisplay(data.temperatures);
        })
        .catch(error => {
            console.error('Error fetching system status:', error);
            showSystemError('Failed to load system status');
        });
}

function fetchNetworkStats() {
    fetch('/api/system/network-stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Network stats error:', data.error);
                return;
            }
            updateNetworkStats(data);
        })
        .catch(error => {
            console.error('Error fetching network stats:', error);
        });
}

function updateSystemOverview(data) {
    // CPU
    const cpuUsage = document.getElementById('cpu-usage');
    const cpuDetails = document.getElementById('cpu-details');
    const cpuProgress = document.getElementById('cpu-progress');
    
    if (cpuUsage) cpuUsage.textContent = `${data.cpu.percent}%`;
    if (cpuDetails) cpuDetails.textContent = `${data.cpu.count} cores`;
    if (cpuProgress) cpuProgress.style.width = `${data.cpu.percent}%`;
    
    // Memory
    const memoryUsage = document.getElementById('memory-usage');
    const memoryDetails = document.getElementById('memory-details');
    const memoryProgress = document.getElementById('memory-progress');
    
    if (memoryUsage) memoryUsage.textContent = `${data.memory.percent}%`;
    if (memoryDetails) memoryDetails.textContent = `${data.memory.used_formatted} / ${data.memory.total_formatted}`;
    if (memoryProgress) memoryProgress.style.width = `${data.memory.percent}%`;
    
    // Disk
    const diskUsage = document.getElementById('disk-usage');
    const diskDetails = document.getElementById('disk-details');
    const diskProgress = document.getElementById('disk-progress');
    
    if (diskUsage) diskUsage.textContent = `${data.disk.percent}%`;
    if (diskDetails) diskDetails.textContent = `${data.disk.used_formatted} / ${data.disk.total_formatted}`;
    if (diskProgress) diskProgress.style.width = `${data.disk.percent}%`;
    
    // Uptime
    const uptimeDisplay = document.getElementById('uptime-display');
    if (uptimeDisplay) uptimeDisplay.textContent = data.uptime.formatted;
}

function updateProcessList(processes) {
    const processList = document.getElementById('process-list');
    if (!processList) return;
    
    if (processes.length === 0) {
        processList.innerHTML = '<p class="text-gray-400 text-center py-4">No process data available</p>';
        return;
    }
    
    let html = '';
    processes.slice(0, 10).forEach(proc => {
        const cpuPercent = (proc.cpu_percent || 0).toFixed(1);
        const memoryPercent = (proc.memory_percent || 0).toFixed(1);
        
        html += `
            <div class="flex items-center justify-between p-2 bg-slate-800 rounded text-sm">
                <div class="flex-1 truncate">
                    <span class="font-medium">${proc.name}</span>
                    <span class="text-gray-400 ml-2">PID: ${proc.pid}</span>
                </div>
                <div class="flex space-x-3 text-xs">
                    <span class="text-blue-400">${cpuPercent}% CPU</span>
                    <span class="text-green-400">${memoryPercent}% MEM</span>
                </div>
            </div>
        `;
    });
    
    processList.innerHTML = html;
}

function updateNetworkInterfaces(interfaces) {
    const networkInterfaces = document.getElementById('network-interfaces');
    if (!networkInterfaces) return;
    
    if (interfaces.length === 0) {
        networkInterfaces.innerHTML = '<p class="text-gray-400 text-center py-4">No network interfaces found</p>';
        return;
    }
    
    let html = '';
    interfaces.forEach(iface => {
        const statusColor = iface.is_up ? 'text-green-400' : 'text-red-400';
        const statusText = iface.is_up ? 'UP' : 'DOWN';
        
        html += `
            <div class="border border-gray-700 rounded p-3">
                <div class="flex items-center justify-between mb-2">
                    <span class="font-medium">${iface.name}</span>
                    <span class="${statusColor} text-xs">${statusText}</span>
                </div>
                <div class="text-xs text-gray-400 space-y-1">
                    ${iface.speed > 0 ? `<div>Speed: ${iface.speed} Mbps</div>` : ''}
                    ${iface.addresses.map(addr => 
                        `<div>${addr.address} (${addr.family})</div>`
                    ).join('')}
                </div>
            </div>
        `;
    });
    
    networkInterfaces.innerHTML = html;
}

function updateNetworkStats(data) {
    const networkStats = document.getElementById('network-stats');
    if (!networkStats) return;
    
    let html = '';
    
    // Connection summary
    html += `
        <div class="bg-slate-800 rounded p-3">
            <h4 class="font-medium mb-2">Connections</h4>
            <div class="text-2xl font-bold text-blue-400">${data.total_connections}</div>
            <div class="text-xs text-gray-400">Total active</div>
        </div>
    `;
    
    // Interface statistics
    Object.entries(data.interfaces).slice(0, 4).forEach(([name, stats]) => {
        html += `
            <div class="bg-slate-800 rounded p-3">
                <h4 class="font-medium mb-2">${name}</h4>
                <div class="text-xs space-y-1">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Sent:</span>
                        <span class="text-green-400">${stats.bytes_sent_formatted}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Received:</span>
                        <span class="text-blue-400">${stats.bytes_recv_formatted}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Packets:</span>
                        <span>${stats.packets_sent + stats.packets_recv}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    networkStats.innerHTML = html;
}

function updateTemperatureDisplay(temperatures) {
    const tempSection = document.getElementById('temperature-section');
    const tempDisplay = document.getElementById('temperature-display');
    
    if (!tempSection || !tempDisplay) return;
    
    if (Object.keys(temperatures).length === 0) {
        tempSection.classList.add('hidden');
        return;
    }
    
    tempSection.classList.remove('hidden');
    
    let html = '';
    Object.entries(temperatures).forEach(([sensor, temp]) => {
        const tempColor = temp > 70 ? 'text-red-400' : temp > 50 ? 'text-yellow-400' : 'text-green-400';
        
        html += `
            <div class="bg-slate-800 rounded p-3">
                <h4 class="font-medium mb-1 text-sm">${sensor}</h4>
                <div class="text-xl font-bold ${tempColor}">${temp.toFixed(1)}°C</div>
            </div>
        `;
    });
    
    tempDisplay.innerHTML = html;
}

function sortProcesses(sortBy) {
    currentProcessSort = sortBy;
    
    // Update button states
    document.querySelectorAll('.process-sort-btn').forEach(btn => {
        if (btn.dataset.sort === sortBy) {
            btn.classList.remove('bg-gray-600');
            btn.classList.add('bg-Ragnar-600');
        } else {
            btn.classList.remove('bg-Ragnar-600');
            btn.classList.add('bg-gray-600');
        }
    });
    
    // Fetch processes with new sort order
    fetch(`/api/system/processes?sort=${sortBy}`)
        .then(response => response.json())
        .then(processes => {
            updateProcessList(processes);
        })
        .catch(error => {
            console.error('Error sorting processes:', error);
        });
}

function refreshSystemStatus() {
    fetchSystemStatus();
    fetchNetworkStats();
    showSystemSuccess('System status refreshed');
}

function showSystemSuccess(message) {
    showNotification(message, 'success');
}

function showSystemError(message) {
    showNotification(message, 'error');
}

// ============================================================================
// NETKB (Network Knowledge Base) FUNCTIONS
// ============================================================================

let currentNetkbFilter = 'all';
let netkbData = [];

function loadNetkbData() {
    fetchNetkbData();
}

function fetchNetkbData() {
    fetch('/api/netkb/data')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showNetkbError('Failed to load NetKB data: ' + data.error);
                return;
            }
            netkbData = data.entries || [];
            updateNetkbStatistics(data.statistics || {});
            displayNetkbData(netkbData);
        })
        .catch(error => {
            console.error('Error fetching NetKB data:', error);
            showNetkbError('Failed to load NetKB data');
        });
}

function updateNetkbStatistics(stats) {
    const totalEntries = document.getElementById('netkb-total-entries');
    const vulnerabilities = document.getElementById('netkb-vulnerabilities');
    const services = document.getElementById('netkb-services');
    const hosts = document.getElementById('netkb-hosts');
    
    if (totalEntries) totalEntries.textContent = stats.total_entries || 0;
    if (vulnerabilities) vulnerabilities.textContent = stats.vulnerabilities || 0;
    if (services) services.textContent = stats.services || 0;
    if (hosts) hosts.textContent = stats.unique_hosts || 0;
}

function displayNetkbData(entries) {
    const tableBody = document.getElementById('netkb-table-body');
    if (!tableBody) return;
    
    if (entries.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center text-gray-400 py-8">No NetKB entries found</td></tr>';
        return;
    }
    
    let html = '';
    entries.forEach(entry => {
        const severityColor = getSeverityColor(entry.severity);
        const typeIcon = getTypeIcon(entry.type);
        const discoveredDate = new Date(entry.discovered * 1000).toLocaleDateString();
        
        html += `
            <tr class="border-b border-gray-800 hover:bg-slate-800 cursor-pointer" onclick="showNetkbEntryDetail('${entry.id}')">
                <td class="p-3">
                    <span class="inline-flex items-center">
                        ${typeIcon}
                        <span class="ml-2 capitalize">${entry.type}</span>
                    </span>
                </td>
                <td class="p-3 font-mono text-sm">${entry.host}</td>
                <td class="p-3 font-mono text-sm">${entry.port || '-'}</td>
                <td class="p-3">
                    <span class="font-medium">${entry.service || entry.description}</span>
                    <div class="text-xs text-gray-400 mt-1">${entry.description}</div>
                </td>
                <td class="p-3">
                    <span class="px-2 py-1 rounded text-xs font-medium ${severityColor}">
                        ${entry.severity}
                    </span>
                </td>
                <td class="p-3 text-sm text-gray-400">${discoveredDate}</td>
                <td class="p-3">
                    <div class="flex space-x-2">
                        <button onclick="event.stopPropagation(); showNetkbEntryDetail('${entry.id}')" 
                                class="text-blue-400 hover:text-blue-300 text-xs">
                            View
                        </button>
                        ${entry.type === 'vulnerability' ? 
                            `<button onclick="event.stopPropagation(); researchVulnerability('${entry.cve || entry.id}')" 
                                     class="text-orange-400 hover:text-orange-300 text-xs">
                                Research
                            </button>` : ''
                        }
                    </div>
                </td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
}

function getSeverityColor(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'bg-red-900 text-red-200';
        case 'high': return 'bg-red-800 text-red-100';
        case 'medium': return 'bg-yellow-800 text-yellow-100';
        case 'low': return 'bg-blue-800 text-blue-100';
        case 'info': return 'bg-gray-700 text-gray-200';
        default: return 'bg-gray-600 text-gray-200';
    }
}

function getTypeIcon(type) {
    switch (type.toLowerCase()) {
        case 'vulnerability':
            return '<svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>';
        case 'service':
            return '<svg class="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>';
        case 'host':
            return '<svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path></svg>';
        case 'exploit':
            return '<svg class="w-4 h-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>';
        default:
            return '<svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
    }
}

function filterNetkbData(filterType) {
    currentNetkbFilter = filterType;
    
    // Update button states
    document.querySelectorAll('.netkb-filter-btn').forEach(btn => {
        if (btn.dataset.filter === filterType) {
            btn.classList.remove('bg-gray-600');
            btn.classList.add('bg-Ragnar-600');
        } else {
            btn.classList.remove('bg-Ragnar-600');
            btn.classList.add('bg-gray-600');
        }
    });
    
    // Filter and display data
    let filteredData = netkbData;
    if (filterType !== 'all') {
        filteredData = netkbData.filter(entry => entry.type === filterType);
    }
    
    displayNetkbData(filteredData);
}

function searchNetkbData(searchTerm) {
    const filtered = netkbData.filter(entry => {
        const searchLower = searchTerm.toLowerCase();
        return entry.host.toLowerCase().includes(searchLower) ||
               entry.service.toLowerCase().includes(searchLower) ||
               entry.description.toLowerCase().includes(searchLower) ||
               entry.type.toLowerCase().includes(searchLower);
    });
    
    displayNetkbData(filtered);
}

function clearNetkbSearch() {
    const searchInput = document.getElementById('netkb-search');
    if (searchInput) {
        searchInput.value = '';
        filterNetkbData(currentNetkbFilter);
    }
}

function showNetkbEntryDetail(entryId) {
    const entry = netkbData.find(e => e.id === entryId);
    if (!entry) return;
    
    const modal = document.getElementById('netkb-detail-modal');
    const title = document.getElementById('netkb-detail-title');
    const content = document.getElementById('netkb-detail-content');
    
    if (!modal || !title || !content) return;
    
    title.textContent = `${entry.type.toUpperCase()}: ${entry.host}`;
    
    const discoveredDate = new Date(entry.discovered * 1000).toLocaleString();
    const severityColor = getSeverityColor(entry.severity);
    
    content.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="space-y-3">
                <div>
                    <label class="text-sm text-gray-400">Host/Target</label>
                    <div class="font-mono text-lg">${entry.host}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Service/Port</label>
                    <div class="font-mono">${entry.port || 'N/A'} ${entry.service ? '(' + entry.service + ')' : ''}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Type</label>
                    <div class="capitalize">${entry.type}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Severity</label>
                    <div><span class="px-2 py-1 rounded text-sm ${severityColor}">${entry.severity}</span></div>
                </div>
            </div>
            <div class="space-y-3">
                <div>
                    <label class="text-sm text-gray-400">Description</label>
                    <div class="text-sm">${entry.description}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Source</label>
                    <div class="text-sm">${entry.source}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Discovered</label>
                    <div class="text-sm">${discoveredDate}</div>
                </div>
                ${entry.cve ? `
                <div>
                    <label class="text-sm text-gray-400">CVE</label>
                    <div class="font-mono text-sm">${entry.cve}</div>
                </div>
                ` : ''}
            </div>
        </div>
        
        <div class="mt-6 p-4 bg-slate-800 rounded-lg">
            <h4 class="font-medium mb-2">Recommendations</h4>
            <ul class="text-sm text-gray-300 space-y-1">
                <li>• Monitor this ${entry.type} regularly for changes</li>
                <li>• Consider implementing additional security measures</li>
                <li>• Review access controls and firewall rules</li>
                ${entry.type === 'vulnerability' ? '<li>• Apply security patches if available</li>' : ''}
                ${entry.type === 'service' ? '<li>• Ensure service is properly configured and updated</li>' : ''}
            </ul>
        </div>
    `;
    
    // Show/hide exploit button based on entry type
    const exploitBtn = document.getElementById('netkb-exploit-btn');
    if (exploitBtn) {
        if (entry.type === 'vulnerability') {
            exploitBtn.classList.remove('hidden');
            exploitBtn.onclick = () => exploitVulnerability(entry);
        } else {
            exploitBtn.classList.add('hidden');
        }
    }
    
    // Update research button
    const researchBtn = document.getElementById('netkb-research-btn');
    if (researchBtn) {
        researchBtn.onclick = () => researchEntry(entry);
    }
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeNetkbModal() {
    const modal = document.getElementById('netkb-detail-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

function refreshNetkbData() {
    fetchNetkbData();
    showNetkbSuccess('NetKB data refreshed');
}

function exportNetkbData() {
    const format = prompt('Export format (json/csv):', 'json');
    if (format && (format === 'json' || format === 'csv')) {
        window.open(`/api/netkb/export?format=${format}`, '_blank');
        showNetkbSuccess(`NetKB data exported as ${format.toUpperCase()}`);
    }
}

function exportNetkbEntry() {
    // Export the currently viewed entry
    showNetkbInfo('Individual entry export feature coming soon');
}

function researchEntry(entry) {
    let searchUrl = 'https://www.google.com/search?q=';
    let searchTerm = '';
    
    if (entry.cve) {
        searchTerm = entry.cve;
    } else if (entry.service) {
        searchTerm = `${entry.service} vulnerability exploit`;
    } else {
        searchTerm = `${entry.host} ${entry.description}`;
    }
    
    window.open(searchUrl + encodeURIComponent(searchTerm), '_blank');
    showNetkbInfo(`Researching: ${searchTerm}`);
}

function researchVulnerability(cveOrId) {
    let searchUrl = 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=';
    window.open(searchUrl + encodeURIComponent(cveOrId), '_blank');
    showNetkbInfo(`Researching vulnerability: ${cveOrId}`);
}

function exploitVulnerability(entry) {
    const confirmMsg = `Are you sure you want to attempt exploitation of ${entry.cve || entry.description} on ${entry.host}?`;
    if (confirm(confirmMsg)) {
        showNetkbInfo('Exploitation feature not yet implemented - this would trigger automated exploit attempts');
        // TODO: Implement actual exploitation logic
    }
}

function showNetkbSuccess(message) {
    showNotification(message, 'success');
}

function showNetkbError(message) {
    showNotification(message, 'error');
}

function showNetkbInfo(message) {
    showNotification(message, 'info');
}

// ============================================================================
// GLOBAL FUNCTION EXPORTS (for HTML onclick handlers)
// ============================================================================

// Make functions available globally for HTML onclick handlers
window.loadConsoleLogs = loadConsoleLogs;
window.clearConsole = clearConsole;
window.refreshEpaperDisplay = refreshEpaperDisplay;
window.toggleEpaperSize = toggleEpaperSize;
window.checkForUpdates = checkForUpdates;
window.checkForUpdatesQuiet = checkForUpdatesQuiet;
window.performUpdate = performUpdate;
window.restartService = restartService;
window.rebootSystem = rebootSystem;
window.startAPMode = startAPMode;
window.refreshWifiStatus = refreshWifiStatus;
window.updateManualPorts = updateManualPorts;
window.executeManualAttack = executeManualAttack;
window.startOrchestrator = startOrchestrator;
window.stopOrchestrator = stopOrchestrator;
window.triggerNetworkScan = triggerNetworkScan;
window.triggerVulnScan = triggerVulnScan;
window.refreshDashboard = refreshDashboard;

// File Management Functions
window.loadFiles = loadFiles;
window.downloadFile = downloadFile;
window.deleteFile = deleteFile;
window.uploadFile = uploadFile;
window.clearFiles = clearFiles;
window.refreshFiles = refreshFiles;
window.closeFileModal = closeFileModal;

// Image Management Functions
window.loadImagesData = loadImagesData;
window.filterImages = filterImages;
window.showImageDetail = showImageDetail;
window.closeImageModal = closeImageModal;
window.downloadImage = downloadImage;
window.deleteImage = deleteImage;
window.captureScreenshot = captureScreenshot;
window.refreshImages = refreshImages;

// System Monitoring Functions
window.loadSystemData = loadSystemData;
window.sortProcesses = sortProcesses;
window.refreshSystemStatus = refreshSystemStatus;

// Dashboard Functions
window.loadDashboardData = loadDashboardData;
window.updateDashboardStats = updateDashboardStats;

// NetKB Functions
window.loadNetkbData = loadNetkbData;
window.refreshNetkbData = refreshNetkbData;
window.filterNetkbData = filterNetkbData;
window.searchNetkbData = searchNetkbData;
window.clearNetkbSearch = clearNetkbSearch;
window.showNetkbEntryDetail = showNetkbEntryDetail;
window.closeNetkbModal = closeNetkbModal;
window.exportNetkbData = exportNetkbData;
window.exportNetkbEntry = exportNetkbEntry;
window.researchEntry = researchEntry;
window.researchVulnerability = researchVulnerability;
window.exploitVulnerability = exploitVulnerability;
