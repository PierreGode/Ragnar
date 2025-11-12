// Ragnar_modern.js - Enhanced Modern JavaScript for Ragnar web interface

let socket;
let reconnectAttempts = 0;
const RECONNECT_WARNING_THRESHOLD = 5;
const RECONNECT_DELAY_MAX = 15000;
let currentTab = 'dashboard';
let autoRefreshIntervals = {};

// Configuration metadata for tooltips
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
        label: "Vulnerability Scanning",
        description: "Enable automatic vulnerability scans on discovered hosts based on the configured interval."
    },
    scan_vuln_no_ports: {
        label: "Scan Hosts Without Ports",
        description: "When enabled, vulnerability scans will scan the top 50 common ports on hosts where no ports were discovered. When disabled, only hosts with discovered ports will be scanned."
    },
    enable_attacks: {
        label: "Enable Attacks",
        description: "Allow Ragnar to perform automated attacks (SSH, FTP, SMB, SQL, etc.) on discovered targets. Disable to only scan without attacking."
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
    return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function getConfigDescription(key) {
    if (configMetadata[key] && configMetadata[key].description) {
        return configMetadata[key].description;
    }
    return "No additional information available for this setting.";
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

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
        reconnectionDelayMax: RECONNECT_DELAY_MAX
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
        // Ensure the client continues to retry if Socket.IO gives up internally
        setTimeout(() => {
            if (socket && socket.disconnected) {
                console.log('Attempting manual socket reconnection');
                socket.connect();
            }
        }, 2000);
    });

    socket.on('status_update', function(data) {
        updateDashboardStatus(data);
    });

    socket.on('log_update', function(logs) {
        updateConsole(logs);
    });

    socket.on('network_update', function(data) {
        if (currentTab === 'network') {
            // Only refresh the stable data when we get background updates
            // This prevents the twitching by not processing conflicting data sources
            loadStableNetworkData();
        }
    });

    socket.on('credentials_update', function(data) {
        if (currentTab === 'discovered') {
            displayCredentialsTable(data);
        }
    });

    socket.on('loot_update', function(data) {
        if (currentTab === 'discovered') {
            displayLootTable(data);
        }
    });

    socket.on('config_updated', function(config) {
        addConsoleMessage('Configuration updated successfully', 'info');
        if (currentTab === 'config') {
            displayConfigForm(config);
        }
    });

    // Real-time scanning WebSocket handlers
    socket.on('scan_started', function(data) {
        handleScanStarted(data);
    });

    socket.on('scan_progress', function(data) {
        handleScanProgress(data);
    });

    socket.on('scan_host_update', function(data) {
        handleScanHostUpdate(data);
    });

    socket.on('scan_completed', function(data) {
        handleScanCompleted(data);
    });

    socket.on('scan_error', function(data) {
        handleScanError(data);
    });

    socket.on('deep_scan_update', function(data) {
        handleDeepScanUpdate(data);
    });

    socket.on('connect_error', function(error) {
        reconnectAttempts++;
        console.error('Connection error:', error);
        if (reconnectAttempts === RECONNECT_WARNING_THRESHOLD) {
            addConsoleMessage('Reconnecting to server… still attempting to reach backend', 'warning');
        } else if (reconnectAttempts > RECONNECT_WARNING_THRESHOLD && reconnectAttempts % RECONNECT_WARNING_THRESHOLD === 0) {
            addConsoleMessage(`Still reconnecting (attempt ${reconnectAttempts}). Will keep trying until successful.`, 'warning');
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

    // Remove network scan button listeners to prevent conflicts
    // Network tab now just displays stable data from background scanning
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

    autoRefreshIntervals.connect = setInterval(() => {
        if (currentTab === 'connect') {
            refreshWifiStatus();
            refreshBluetoothStatus();
        }
    }, 15000); // Every 15 seconds

    autoRefreshIntervals.discovered = setInterval(() => {
        if (currentTab === 'discovered' && socket && socket.connected) {
            socket.emit('request_credentials');
            socket.emit('request_loot');
            loadAttackLogs(); // Also refresh attack logs
        }
    }, 20000); // Every 20 seconds
    
    // Set up console log refreshing (fallback when WebSocket is not working)
    autoRefreshIntervals.console = setInterval(() => {
        if (currentTab === 'dashboard') {
            loadConsoleLogs();
        }
    }, 5000); // Every 5 seconds when on dashboard
    
    // Set up dashboard stats auto-refresh
    autoRefreshIntervals.dashboard = setInterval(() => {
        if (currentTab === 'dashboard') {
            loadDashboardData();
        }
    }, 15000); // Every 15 seconds when on dashboard
    
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
        
        // Load dashboard statistics
        await loadDashboardData();
        
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
            await Promise.all([
                loadDashboardData(),
                loadConsoleLogs()
            ]);
            break;
        case 'network':
            await loadNetworkData();
            break;
        case 'connect':
            await loadConnectData();
            break;
        case 'discovered':
            await Promise.all([
                loadCredentialsData(),
                loadLootData(),
                loadAttackLogs()
            ]);
            break;
        case 'threat-intel':
            await loadThreatIntelData();
            break;
        case 'files':
            await Promise.all([
                loadFilesData(),
                loadImagesData()
            ]);
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

function toNumber(value, fallback = 0) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallback;
}

function formatRelativeTime(seconds) {
    if (!Number.isFinite(seconds)) {
        return null;
    }

    let remaining = Math.max(0, Math.floor(seconds));
    const units = [
        { label: 'd', value: 86400 },
        { label: 'h', value: 3600 },
        { label: 'm', value: 60 },
        { label: 's', value: 1 }
    ];

    const parts = [];
    for (const unit of units) {
        if (remaining >= unit.value || (unit.label === 's' && parts.length === 0)) {
            const amount = Math.floor(remaining / unit.value);
            if (amount > 0 || unit.label === 's') {
                parts.push(`${amount}${unit.label}`);
            }
            remaining -= amount * unit.value;
        }
        if (parts.length >= 2) {
            break;
        }
    }

    return parts.length > 0 ? parts.join(' ') : '0s';
}

function buildLastSyncDisplay(stats) {
    if (!stats) {
        return 'Sync pending…';
    }

    const ageSeconds = toNumber(stats.last_sync_age_seconds, NaN);
    const hasAge = Number.isFinite(ageSeconds);
    const relative = hasAge ? `${formatRelativeTime(ageSeconds)} ago` : '';

    let timestampSource = stats.last_sync_iso ?? stats.last_sync_time ?? stats.last_sync_timestamp;
    let isoValue = null;

    if (typeof timestampSource === 'number') {
        isoValue = new Date(timestampSource * 1000).toISOString();
    } else if (typeof timestampSource === 'string' && timestampSource) {
        isoValue = timestampSource;
    }

    let absolute = '';
    if (isoValue) {
        const parsed = new Date(isoValue);
        if (!Number.isNaN(parsed.getTime())) {
            absolute = parsed.toLocaleString();
        }
    }

    if (relative && absolute) {
        return `${relative} (${absolute})`;
    }

    if (relative) {
        return relative;
    }

    if (absolute) {
        return absolute;
    }

    return 'Sync pending…';
}

function updateDashboardStats(stats) {
    if (!stats || typeof stats !== 'object') {
        return;
    }

    const activeTargets = toNumber(stats.active_target_count ?? stats.target_count, 0);
    const inactiveTargets = toNumber(stats.inactive_target_count ?? stats.offline_target_count, 0);
    const totalTargets = toNumber(stats.total_target_count ?? activeTargets + inactiveTargets, activeTargets + inactiveTargets);

    const newTargetList = Array.isArray(stats.new_target_ips) ? stats.new_target_ips :
        (Array.isArray(stats.new_targets) ? stats.new_targets : []);
    const lostTargetList = Array.isArray(stats.lost_target_ips) ? stats.lost_target_ips :
        (Array.isArray(stats.lost_targets) ? stats.lost_targets : []);

    const newTargets = toNumber(stats.new_target_count ?? stats.new_targets ?? newTargetList.length, newTargetList.length);
    const lostTargets = toNumber(stats.lost_target_count ?? stats.lost_targets ?? lostTargetList.length, lostTargetList.length);

    const portCount = toNumber(stats.port_count ?? stats.open_port_count, 0);
    const vulnCount = toNumber(stats.vulnerability_count ?? stats.vuln_count, 0);
    const vulnerableHostsCount = toNumber(stats.vulnerable_hosts_count ?? stats.vulnerable_host_count ?? 0, 0);
    const credCount = toNumber(stats.credential_count ?? stats.cred_count, 0);
    const level = toNumber(stats.level ?? stats.levelnbr, 0);
    const points = toNumber(stats.points ?? stats.coins, 0);

    updateElement('target-count', activeTargets);
    updateElement('target-total-count', totalTargets);
    updateElement('target-inactive-count', inactiveTargets);
    updateElement('target-new-count', newTargets);
    updateElement('target-lost-count', lostTargets);

    const newCountElement = document.getElementById('target-new-count');
    if (newCountElement) {
        newCountElement.title = newTargetList.length > 0 ? newTargetList.join(', ') : 'No recent additions';
    }

    const lostCountElement = document.getElementById('target-lost-count');
    if (lostCountElement) {
        lostCountElement.title = lostTargetList.length > 0 ? lostTargetList.join(', ') : 'No recent drops';
    }

    updateElement('port-count', portCount);
    updateElement('vuln-count', vulnCount);
    updateElement('dashboard-vulnerable-hosts-count', vulnerableHostsCount);
    updateElement('cred-count', credCount);
    updateElement('level-count', level);
    updateElement('points-count', points);

    const activeSummary = totalTargets > 0 ? `${activeTargets}/${totalTargets} active` : `${activeTargets} active`;
    const newSummary = newTargets > 0 ? `${newTargets} new` : 'No new targets';
    const lostSummary = lostTargets > 0 ? `${lostTargets} lost` : 'No targets lost';

    updateElement('active-target-summary', activeSummary);
    updateElement('new-target-summary', newSummary);
    updateElement('lost-target-summary', lostSummary);
    updateElement('last-sync-display', buildLastSyncDisplay(stats));
}

async function loadNetworkData() {
    try {
        // Use the new stable network data endpoint
        await loadStableNetworkData();
    } catch (error) {
        console.error('Error loading network data:', error);
        addConsoleMessage('Failed to load network data', 'error');
    }
}

// ============================================================================
// STABLE NETWORK DATA FUNCTIONS
// ============================================================================

async function loadStableNetworkData() {
    try {
        const data = await fetchAPI('/api/network/stable');
        
        if (data.success) {
            displayStableNetworkTable(data);
            addConsoleMessage(`Network data loaded: ${data.count} hosts`, 'info');
        } else {
            addConsoleMessage(`Failed to load network data: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error loading stable network data:', error);
        addConsoleMessage(`Network data error: ${error.message}`, 'error');
    }
}

function displayStableNetworkTable(data) {
    const tableBody = document.getElementById('network-hosts-table');
    const hostCountSpan = document.getElementById('host-count');
    
    if (!tableBody) return;
    
    // Save all existing deep scan button states before clearing table
    const existingRows = tableBody.querySelectorAll('tr[data-ip]');
    existingRows.forEach(row => {
        const ip = row.getAttribute('data-ip');
        if (ip) {
            saveDeepScanButtonState(ip);
        }
    });
    
    tableBody.innerHTML = '';
    
    if (!data.hosts || data.hosts.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-8 text-gray-400">
                    No hosts discovered yet. Network scanning is running in the background.
                </td>
            </tr>
        `;
        if (hostCountSpan) hostCountSpan.textContent = '0 hosts';
        return;
    }
    
    data.hosts.forEach((host, index) => {
        // DEBUG: Log first few host objects to see structure
        if (index < 5) {
            console.log(`🔍 Host ${index}:`, host);
            console.log(`   IP field:`, host.ip, typeof host.ip);
            console.log(`   All fields:`, Object.keys(host));
        }
        
        const row = document.createElement('tr');
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        
        // Status indicator
        const statusIcon = host.status === 'up' ? 
            '<span class="flex items-center"><div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>Online</span>' :
            '<span class="flex items-center"><div class="w-2 h-2 bg-gray-500 rounded-full mr-2"></div>Unknown</span>';
        
        // Format MAC address
        let macDisplay = host.mac === 'Unknown' ? 
            '<span class="text-gray-500">Unknown</span>' : 
            `<span class="font-mono text-xs">${host.mac}</span>`;
        
        // Format ports
        let portsDisplay = host.ports === 'Unknown' || host.ports === 'Scanning...' ? 
            '<span class="text-gray-500">Unknown</span>' : 
            `<span class="text-xs">${host.ports}</span>`;
        
        // Format vulnerabilities
        let vulnDisplay = host.vulnerabilities === '0' ? 
            '<span class="text-gray-500">None</span>' : 
            `<span class="text-orange-400">${host.vulnerabilities}</span>`;
        
        // Format last scan
        let lastScanDisplay = host.last_scan === 'Never' || host.last_scan === 'Unknown' ? 
            '<span class="text-gray-500">Never</span>' : 
            `<span class="text-xs">${formatTimeAgo(host.last_scan)}</span>`;
        
        row.innerHTML = `
            <td class="py-3 px-4">${statusIcon}</td>
            <td class="py-3 px-4 font-mono text-sm">${host.ip}</td>
            <td class="py-3 px-4">${host.hostname === 'Unknown' ? '<span class="text-gray-500">Unknown</span>' : host.hostname}</td>
            <td class="py-3 px-4">${macDisplay}</td>
            <td class="py-3 px-4">${portsDisplay}</td>
            <td class="py-3 px-4">${vulnDisplay}</td>
            <td class="py-3 px-4">${lastScanDisplay}</td>
            <td class="py-3 px-4">
                <button onclick="triggerDeepScan('${host.ip}')" 
                        id="deep-scan-btn-${host.ip.replace(/\./g, '-')}"
                        data-scan-status="idle"
                        class="deep-scan-button bg-purple-600 hover:bg-purple-700 text-white text-xs px-3 py-1 rounded transition-all duration-300"
                        title="Scan all 65535 ports with TCP connect (-sT). IP: ${host.ip}">
                    Deep Scan
                </button>
            </td>
        `;
        
        // Set data-ip attribute for state management
        row.setAttribute('data-ip', host.ip);
        
        tableBody.appendChild(row);
        
        // Restore deep scan button state after adding to DOM
        restoreDeepScanButtonState(host.ip);
    });
    
    // Update host count
    if (hostCountSpan) {
        hostCountSpan.textContent = `${data.hosts.length} hosts`;
    }
    
    // Cleanup old button states for removed hosts
    cleanupOldDeepScanStates();
}

function formatTimeAgo(timeString) {
    try {
        if (!timeString || timeString === 'Never' || timeString === 'Unknown') {
            return 'Never';
        }
        
        // If it's already a relative time string, return as is
        if (timeString.includes('ago') || timeString.includes('Recently')) {
            return timeString;
        }
        
        const date = new Date(timeString);
        if (isNaN(date.getTime())) {
            return timeString; // Return original if can't parse
        }
        
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return date.toLocaleDateString();
    } catch (error) {
        return timeString;
    }
}

// Real-time scanning variables
let currentScanState = {
    isScanning: false,
    totalHosts: 0,
    scannedHosts: 0,
    currentTarget: '',
    startTime: null
};

// Deep scan button state management
let deepScanButtonStates = new Map(); // Map<IP, {status, text, classes, disabled}>

function saveDeepScanButtonState(ip) {
    const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
    const button = document.getElementById(buttonId);
    
    if (button) {
        const state = {
            status: button.dataset.scanStatus || 'idle',
            text: button.textContent,
            classes: button.className,
            disabled: button.disabled,
            title: button.title
        };
        deepScanButtonStates.set(ip, state);
        console.log(`💾 Saved deep scan button state for ${ip}:`, state);
    }
}

function restoreDeepScanButtonState(ip) {
    const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
    const button = document.getElementById(buttonId);
    const state = deepScanButtonStates.get(ip);
    
    if (button && state) {
        button.textContent = state.text;
        button.className = state.classes;
        button.disabled = state.disabled;
        button.title = state.title;
        button.dataset.scanStatus = state.status;
        console.log(`🔄 Restored deep scan button state for ${ip}:`, state);
    } else if (button && !state) {
        console.log(`⚠️ No saved state found for ${ip}, keeping default button state`);
    }
}

function clearDeepScanButtonState(ip) {
    if (deepScanButtonStates.has(ip)) {
        deepScanButtonStates.delete(ip);
        console.log(`🗑️ Cleared deep scan button state for ${ip}`);
    }
}

function cleanupOldDeepScanStates() {
    // Remove states for IPs that no longer have buttons in the DOM
    let cleanedCount = 0;
    for (const [ip] of deepScanButtonStates) {
        const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
        if (!document.getElementById(buttonId)) {
            deepScanButtonStates.delete(ip);
            cleanedCount++;
        }
    }
    if (cleanedCount > 0) {
        console.log(`🧹 Cleaned up ${cleanedCount} old deep scan button states`);
    }
}

// Real-time scanning control functions
async function startRealtimeScan() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    try {
        startBtn.disabled = true;
        startBtn.innerHTML = '⏳ Starting...';
        
        const response = await fetch('/api/scan/start-realtime', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        if (response.ok) {
            currentScanState.isScanning = true;
            currentScanState.startTime = new Date();
            stopBtn.disabled = false;
            startBtn.innerHTML = '⏳ Scanning...';
            
            // Show progress section
            document.getElementById('scan-progress').classList.remove('hidden');
            
            addConsoleMessage('Real-time network scan started', 'info');
        } else {
            throw new Error('Failed to start scan');
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        addConsoleMessage('Failed to start network scan: ' + error.message, 'error');
        resetScanButtons();
    }
}

async function stopRealtimeScan() {
    const stopBtn = document.getElementById('stop-network-scan');
    
    try {
        stopBtn.disabled = true;
        stopBtn.innerHTML = '⏳ Stopping...';
        
        // Emit stop scan event via WebSocket
        socket.emit('stop_scan');
        
        addConsoleMessage('Stopping network scan...', 'info');
    } catch (error) {
        console.error('Error stopping scan:', error);
        addConsoleMessage('Failed to stop network scan: ' + error.message, 'error');
        stopBtn.disabled = false;
        stopBtn.innerHTML = '⏹️ Stop Scan';
    }
}

function resetScanButtons() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    startBtn.disabled = false;
    startBtn.innerHTML = '<span class="group-disabled:hidden">🔍</span> Start Full Scan';
    stopBtn.disabled = true;
    stopBtn.innerHTML = '⏹️ Stop Scan';
    
    currentScanState.isScanning = false;
    document.getElementById('scan-progress').classList.add('hidden');
}

// WebSocket event handlers for real-time scanning
function handleScanStarted(data) {
    currentScanState.totalHosts = data.total_hosts || 0;
    currentScanState.scannedHosts = 0;
    
    updateScanProgress();
    addConsoleMessage(`Started scanning ${currentScanState.totalHosts} hosts`, 'info');
}

function handleScanProgress(data) {
    currentScanState.scannedHosts = data.completed || 0;
    currentScanState.currentTarget = data.current_target || '';
    
    updateScanProgress();
}

function handleScanHostUpdate(data) {
    if (!data) {
        return;
    }

    const eventType = data.type || data.event || 'host_update';

    if (eventType === 'sep_scan_output') {
        if (data.message) {
            const prefix = data.ip ? `[sep-scan ${data.ip}]` : '[sep-scan]';
            addConsoleMessage(`${prefix} ${data.message}`, 'info');
        }
        return;
    }

    if (eventType === 'sep_scan_error') {
        const prefix = data.ip ? `sep-scan error for ${data.ip}` : 'sep-scan error';
        addConsoleMessage(`${prefix}: ${data.message || 'Unknown error'}`, 'error');
        return;
    }

    if (eventType === 'sep_scan_completed') {
        const ipLabel = data.ip || 'target';
        const statusLabel = data.status === 'success' ? 'successfully' : 'with issues';
        const level = data.status === 'success' ? 'success' : 'warning';
        addConsoleMessage(`sep-scan completed for ${ipLabel} ${statusLabel}`, level);

        if (currentTab === 'network') {
            loadNetworkData();
        }
        return;
    }

    // Update the network table with new host data
    if (eventType === 'host_updated' || data.ip || data.IPs) {
        if (currentTab === 'network') {
            updateHostInTable(data);
        }

        // Update threat intelligence and NetKB if vulnerabilities found
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            if (currentTab === 'threat-intel') {
                loadThreatIntelData();
            }
            if (currentTab === 'netkb') {
                loadNetkbData();
            }
        }
        return;
    }
}

function handleScanCompleted(data) {
    addConsoleMessage(`Network scan completed. Found ${data.hosts_discovered || 0} hosts, ${data.vulnerabilities_found || 0} vulnerabilities`, 'success');
    resetScanButtons();
    
    // Refresh all relevant tabs
    if (currentTab === 'network') {
        loadNetworkData();
    }
}

function handleScanError(data) {
    addConsoleMessage(`Scan error: ${data.error}`, 'error');
    resetScanButtons();
}

// ============================================================================
// DEEP SCAN FUNCTIONS
// ============================================================================

// TEST FUNCTION - Direct deep scan test
function testDeepScan() {
    console.log('🧪 Testing deep scan with hardcoded IP...');
    triggerDeepScan('192.168.1.211');
}

async function triggerDeepScan(ip) {
    try {
        // EXPLICIT DEBUG: Log what we received
        console.log('🔍 triggerDeepScan CALLED');
        console.log('   Received IP parameter:', ip);
        console.log('   IP type:', typeof ip);
        console.log('   IP length:', ip ? ip.length : 'null/undefined');
        
        if (!ip) {
            console.error('❌ IP parameter is empty in triggerDeepScan!');
            addConsoleMessage('Error: No IP address provided for deep scan', 'error');
            return;
        }
        
        // Update button immediately to show scan is starting
        const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
        const button = document.getElementById(buttonId);
        if (button) {
            button.classList.remove('bg-purple-600', 'hover:bg-purple-700');
            button.classList.add('bg-blue-600', 'cursor-wait');
            button.disabled = true;
            button.textContent = 'Initiating...';
            button.dataset.scanStatus = 'initiating';
            // Save the updated state
            saveDeepScanButtonState(ip);
        }
        
        addConsoleMessage(`Starting deep scan on ${ip}...`, 'info');
        
        console.log('📤 Sending POST request to /api/scan/deep');
        console.log('   Request body:', JSON.stringify({ ip: ip }));
        
        const response = await fetch('/api/scan/deep', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip: ip })
        });
        
        console.log('📥 Response received, status:', response.status);
        
        const data = await response.json();
        console.log('📋 Response data:', data);
        
        if (data.status === 'success') {
            addConsoleMessage(`Deep scan initiated for ${ip} - scanning all 65535 ports`, 'success');
        } else {
            addConsoleMessage(`Failed to start deep scan: ${data.message}`, 'error');
            // Reset button on failure
            if (button) {
                button.classList.remove('bg-blue-600', 'cursor-wait');
                button.classList.add('bg-purple-600', 'hover:bg-purple-700');
                button.disabled = false;
                button.textContent = 'Deep Scan';
                button.dataset.scanStatus = 'idle';
                clearDeepScanButtonState(ip);
            }
        }
    } catch (error) {
        console.error('Error triggering deep scan:', error);
        addConsoleMessage(`Error starting deep scan: ${error.message}`, 'error');
        
        // Reset button on error
        const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
        const button = document.getElementById(buttonId);
        if (button) {
            button.classList.remove('bg-blue-600', 'cursor-wait');
            button.classList.add('bg-purple-600', 'hover:bg-purple-700');
            button.disabled = false;
            button.textContent = 'Deep Scan';
            button.dataset.scanStatus = 'idle';
            clearDeepScanButtonState(ip);
        }
    }
}

function handleDeepScanUpdate(data) {
    const { type, ip, message } = data;
    
    // Get the button for this IP
    const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
    const button = document.getElementById(buttonId);
    
    switch (type) {
        case 'deep_scan_started':
            addConsoleMessage(`🔍 ${message}`, 'info');
            if (button) {
                button.classList.remove('bg-purple-600', 'hover:bg-purple-700');
                button.classList.add('bg-blue-600', 'cursor-wait');
                button.disabled = true;
                button.textContent = 'Scan started';
                button.dataset.scanStatus = 'scanning';
                // Save the updated state
                saveDeepScanButtonState(ip);
            }
            break;
        
        case 'deep_scan_progress':
            // Update button with short progress messages
            if (button) {
                const event = data.event;
                if (event === 'scanning') {
                    button.textContent = 'Scanning...';
                } else if (event === 'hostname') {
                    // Extract short hostname (max 20 chars already in message)
                    button.textContent = message;
                } else if (event === 'port_found') {
                    const port = data.port;
                    const service = data.service;
                    button.textContent = `Port ${port} found`;
                }
                button.dataset.scanStatus = 'scanning';
                // Save the updated state
                saveDeepScanButtonState(ip);
            }
            break;
            
        case 'deep_scan_completed':
            const portCount = data.open_ports ? data.open_ports.length : 0;
            const duration = data.scan_duration ? data.scan_duration.toFixed(2) : 'unknown';
            addConsoleMessage(`✅ Deep scan of ${ip} complete: ${portCount} ports found in ${duration}s`, 'success');
            
            // Show detailed port information
            if (data.open_ports && data.open_ports.length > 0) {
                const portList = data.open_ports.slice(0, 10).join(', ');
                const moreText = data.open_ports.length > 10 ? ` (+${data.open_ports.length - 10} more)` : '';
                addConsoleMessage(`   Open ports: ${portList}${moreText}`, 'info');
            }
            
            // Update button to show completion
            if (button) {
                button.classList.remove('bg-blue-600', 'cursor-wait');
                button.classList.add('bg-green-600');
                button.textContent = `✅ ${portCount} ports`;
                button.disabled = true;
                button.dataset.scanStatus = 'completed';
                // Save the updated state
                saveDeepScanButtonState(ip);
                
                // Reset button after 3 seconds
                setTimeout(() => {
                    if (document.getElementById(buttonId)) {
                        button.classList.remove('bg-green-600');
                        button.classList.add('bg-purple-600', 'hover:bg-purple-700');
                        button.textContent = 'Deep Scan';
                        button.disabled = false;
                        button.dataset.scanStatus = 'idle';
                        // Clear the saved state since it's back to default
                        clearDeepScanButtonState(ip);
                    }
                }, 3000);
            }
            
            // Refresh network table to show updated port information
            if (currentTab === 'network') {
                loadNetworkData();
            }
            break;
            
        case 'deep_scan_error':
            addConsoleMessage(`❌ Deep scan error for ${ip}: ${message}`, 'error');
            
            // Update button to show error
            if (button) {
                button.classList.remove('bg-blue-600', 'cursor-wait');
                button.classList.add('bg-red-600');
                button.textContent = '❌ Error';
                button.disabled = true;
                button.dataset.scanStatus = 'error';
                // Save the updated state
                saveDeepScanButtonState(ip);
                
                // Reset button after 3 seconds
                setTimeout(() => {
                    if (document.getElementById(buttonId)) {
                        button.classList.remove('bg-red-600');
                        button.classList.add('bg-purple-600', 'hover:bg-purple-700');
                        button.textContent = 'Deep Scan';
                        button.disabled = false;
                        button.dataset.scanStatus = 'idle';
                        // Clear the saved state since it's back to default
                        clearDeepScanButtonState(ip);
                    }
                }, 3000);
            }
            break;
            
        default:
            addConsoleMessage(`Deep scan update: ${message}`, 'info');
    }
}

// ============================================================================
// ENHANCED NETWORK SCANNING WITH ARP/NMAP
// ============================================================================

// Network scanning variables for enhanced scanning
let enhancedNetworkScanInterval = null;
let isEnhancedRealTimeScanning = false;

async function startEnhancedRealTimeScan() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    if (!startBtn || !stopBtn) return;
    
    try {
        addConsoleMessage('Starting enhanced real-time network scanning (ARP + Nmap)...', 'info');
        startBtn.disabled = true;
        stopBtn.disabled = false;
        isEnhancedRealTimeScanning = true;
        
        // Show progress section
        document.getElementById('scan-progress').classList.remove('hidden');
        
        // Start immediate scan
        await performCombinedNetworkScan();
        
        // Set up interval for continuous scanning
        enhancedNetworkScanInterval = setInterval(async () => {
            if (isEnhancedRealTimeScanning) {
                await performCombinedNetworkScan();
            }
        }, 15000); // Scan every 15 seconds (ARP background scanning is every 10 seconds)
        
        addConsoleMessage('Enhanced real-time network scanning started', 'info');
        
    } catch (error) {
        console.error('Error starting enhanced real-time scan:', error);
        addConsoleMessage('Failed to start network scan: ' + error.message, 'error');
        resetEnhancedScanButtons();
    }
}

async function stopEnhancedRealTimeScan() {
    const stopBtn = document.getElementById('stop-network-scan');
    const startBtn = document.getElementById('start-network-scan');
    
    if (enhancedNetworkScanInterval) {
        clearInterval(enhancedNetworkScanInterval);
        enhancedNetworkScanInterval = null;
    }
    
    isEnhancedRealTimeScanning = false;
    
    if (stopBtn && startBtn) {
        addConsoleMessage('Stopping enhanced network scan...', 'info');
        resetEnhancedScanButtons();
    }
}

function resetEnhancedScanButtons() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    if (startBtn && stopBtn) {
        startBtn.disabled = false;
        stopBtn.disabled = true;
        isEnhancedRealTimeScanning = false;
        document.getElementById('scan-progress').classList.add('hidden');
    }
}

async function performCombinedNetworkScan() {
    try {
        const data = await fetchAPI('/api/scan/combined-network');
        
        if (data.success) {
            updateNetworkTableWithScanData(data);
            addConsoleMessage(`Network scan found ${data.count} hosts (ARP: ${data.arp_count}, Nmap: ${data.nmap_count})`, 'success');
        } else {
            addConsoleMessage(`Network scan failed: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error performing network scan:', error);
        addConsoleMessage(`Network scan error: ${error.message}`, 'error');
    }
}

function updateNetworkTableWithScanData(data) {
    const tableBody = document.getElementById('network-hosts-table');
    const hostCountSpan = document.getElementById('host-count');
    
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (!data.hosts || Object.keys(data.hosts).length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-8 text-gray-400">
                    No hosts discovered. Check network connectivity and try again.
                </td>
            </tr>
        `;
        if (hostCountSpan) hostCountSpan.textContent = '0 hosts';
        return;
    }
    
    // Convert hosts object to array for easier processing
    const hostArray = Object.values(data.hosts);
    
    hostArray.forEach(host => {
        const row = document.createElement('tr');
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        
        // Determine status indicator
        const statusIcon = host.status === 'up' ? 
            '<span class="flex items-center"><div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>Online</span>' :
            '<span class="flex items-center"><div class="w-2 h-2 bg-red-500 rounded-full mr-2"></div>Offline</span>';
        
        // Format MAC address with vendor info
        let macDisplay = host.mac || 'Unknown';
        if (host.vendor) {
            macDisplay += `<br><span class="text-xs text-gray-400">${host.vendor}</span>`;
        }
        
        // Get source indicator
        const sourceIcon = {
            'arp': '<span class="text-xs px-2 py-1 bg-blue-600 rounded">ARP</span>',
            'nmap': '<span class="text-xs px-2 py-1 bg-purple-600 rounded">NMAP</span>',
            'arp+nmap': '<span class="text-xs px-2 py-1 bg-green-600 rounded">ARP+NMAP</span>'
        }[host.source] || '';
        
        row.innerHTML = `
            <td class="py-3 px-4">${statusIcon}</td>
            <td class="py-3 px-4 font-mono text-sm">${host.ip}</td>
            <td class="py-3 px-4">${host.hostname || 'Unknown'}</td>
            <td class="py-3 px-4 font-mono text-xs">${macDisplay}</td>
            <td class="py-3 px-4">
                <span class="text-xs px-2 py-1 bg-gray-600 rounded">Scanning...</span>
            </td>
            <td class="py-3 px-4">
                <span class="text-xs px-2 py-1 bg-gray-600 rounded">Checking...</span>
            </td>
            <td class="py-3 px-4 text-sm text-gray-400">${new Date().toLocaleTimeString()}</td>
            <td class="py-3 px-4">
                <div class="flex space-x-2">
                    ${sourceIcon}
                    <button onclick="scanSingleHostEnhanced('${host.ip}')" 
                            class="text-xs px-2 py-1 bg-Ragnar-600 hover:bg-Ragnar-700 rounded transition-colors">
                        Scan
                    </button>
                </div>
            </td>
        `;
        
        tableBody.appendChild(row);
    });
    
    // Update host count
    if (hostCountSpan) {
        hostCountSpan.textContent = `${hostArray.length} hosts`;
    }
}

async function scanSingleHostEnhanced(ip) {
    try {
        addConsoleMessage(`Scanning host ${ip}...`, 'info');
        
        const data = await postAPI('/api/scan/host', { 
            ip: ip,
            scan_type: 'full'
        });
        
        if (data.success) {
            addConsoleMessage(`Host ${ip} scan completed`, 'success');
            // Refresh the network table to show updated data
            await performCombinedNetworkScan();
        } else {
            addConsoleMessage(`Host ${ip} scan failed: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error scanning host:', error);
        addConsoleMessage(`Host scan error: ${error.message}`, 'error');
    }
}

function updateScanProgress() {
    const progressText = document.getElementById('scan-progress-text');
    const progressBar = document.getElementById('scan-progress-bar');
    const currentTarget = document.getElementById('current-scan-target');

    const percentage = currentScanState.totalHosts > 0 ?
        (currentScanState.scannedHosts / currentScanState.totalHosts) * 100 : 0;

    if (progressText) {
        progressText.textContent = `${currentScanState.scannedHosts}/${currentScanState.totalHosts} hosts`;
    }

    if (progressBar) {
        progressBar.style.width = `${percentage}%`;
    }

    if (currentTarget) {
        currentTarget.textContent = currentScanState.currentTarget ?
            `Currently scanning: ${currentScanState.currentTarget}` : '';
    }
}

function escapeSelector(value) {
    if (window.CSS && typeof CSS.escape === 'function') {
        return CSS.escape(value);
    }
    return value.replace(/([ #;?%&,.+*~\':"!^$\[\]()=>|\/])/g, '\\$1');
}

function parseCompactTimestamp(value) {
    if (!value) {
        return null;
    }
    const digits = value.replace(/[^0-9]/g, '');
    if (digits.length < 8) {
        return null;
    }

    const year = Number(digits.slice(0, 4));
    const month = Number(digits.slice(4, 6)) - 1;
    const day = Number(digits.slice(6, 8));
    const hour = digits.length >= 10 ? Number(digits.slice(8, 10)) : 0;
    const minute = digits.length >= 12 ? Number(digits.slice(10, 12)) : 0;
    const second = digits.length >= 14 ? Number(digits.slice(12, 14)) : 0;

    const date = new Date(year, month, day, hour, minute, second);
    return Number.isNaN(date.getTime()) ? null : date;
}

function buildLastScanInfo(rawStatus, isoTimestamp) {
    const info = {
        label: 'Never',
        className: 'text-gray-400',
        timestampText: '',
        tooltip: '',
        rawStatus: rawStatus || '',
        rawTimestamp: isoTimestamp || ''
    };

    let statusPart = (rawStatus || '').toString().trim();
    let timestamp = null;

    if (statusPart.includes('_')) {
        const parts = statusPart.split('_');
        statusPart = parts[0];
        const timestampCandidate = parts.slice(1).join('_');
        timestamp = parseCompactTimestamp(timestampCandidate);
    }

    if (!timestamp && isoTimestamp) {
        const parsed = new Date(isoTimestamp);
        if (!Number.isNaN(parsed.getTime())) {
            timestamp = parsed;
        }
    }

    if (!timestamp && rawStatus) {
        const digits = rawStatus.replace(/[^0-9]/g, '');
        if (digits.length >= 8) {
            const parsedDigits = parseCompactTimestamp(digits);
            if (parsedDigits) {
                timestamp = parsedDigits;
            }
        }
    }

    const lowerStatus = statusPart.toLowerCase();
    if (!statusPart) {
        if (timestamp) {
            info.label = 'Completed';
            info.className = 'text-blue-400';
        } else {
            info.label = 'Never';
            info.className = 'text-gray-400';
        }
    } else if (lowerStatus.startsWith('success')) {
        info.label = 'Success';
        info.className = 'text-green-400';
    } else if (lowerStatus.startsWith('failed')) {
        info.label = 'Failed';
        info.className = 'text-red-400';
    } else if (['running', 'scanning', 'pending', 'inprogress', 'in_progress'].includes(lowerStatus)) {
        info.label = statusPart.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        info.className = 'text-yellow-400';
    } else {
        info.label = statusPart.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        info.className = 'text-slate-300';
    }

    if (timestamp) {
        info.timestampText = timestamp.toLocaleString();
    }

    const tooltipParts = [];
    if (info.rawStatus) {
        tooltipParts.push(`Status: ${info.rawStatus}`);
    }
    if (info.timestampText) {
        tooltipParts.push(`Completed: ${info.timestampText}`);
    }
    if (info.rawTimestamp && !info.timestampText) {
        tooltipParts.push(`Reported: ${info.rawTimestamp}`);
    }
    info.tooltip = tooltipParts.join('\n');

    return info;
}

function normalizeHostRecord(hostData) {
    if (!hostData) {
        return null;
    }

    const ip = hostData.IPs || hostData.ip || hostData.address || hostData.target || '';
    if (!ip) {
        return null;
    }

    const hostname = hostData.Hostnames || hostData.Hostname || hostData.hostname || hostData.name || '';
    const mac = hostData['MAC Address'] || hostData.MAC || hostData.mac || '';

    const aliveValue = hostData.Alive ?? hostData.alive ?? hostData.Status ?? hostData.status ?? '';
    const aliveString = aliveValue === undefined || aliveValue === null ? '' : String(aliveValue).trim();
    const aliveLower = aliveString.toLowerCase();
    const isActive = ['1', 'true', 'online', 'up', 'active', 'success'].includes(aliveLower);
    const isInactive = ['0', 'false', 'offline', 'down', 'inactive', 'failed'].includes(aliveLower);

    let statusText = 'Unknown';
    if (isActive) {
        statusText = 'Active';
    } else if (isInactive) {
        statusText = 'Inactive';
    } else if (aliveString) {
        statusText = aliveString.charAt(0).toUpperCase() + aliveString.slice(1);
    }

    const statusClass = isActive ? 'text-green-400' : (isInactive ? 'text-red-400' : 'text-yellow-400');

    const rawPorts = hostData.Ports ?? hostData.ports ?? hostData.port_list ?? hostData.open_ports;
    let ports = [];
    if (Array.isArray(rawPorts)) {
        ports = rawPorts.map(port => String(port).trim()).filter(Boolean);
    } else if (typeof rawPorts === 'string') {
        ports = rawPorts.split(/[,;\s]+/).map(port => port.trim()).filter(Boolean);
    } else if (rawPorts) {
        ports = [String(rawPorts).trim()];
    }

    const vulnObjects = Array.isArray(hostData.vulnerabilities) ? hostData.vulnerabilities : [];
    const normalizedVulnObjects = vulnObjects.map(vuln => {
        if (typeof vuln === 'string') {
            return vuln;
        }
        if (vuln && typeof vuln === 'object') {
            return vuln.vulnerability || vuln.raw_output || vuln.description || vuln.id || '';
        }
        return '';
    }).filter(Boolean);

    let vulnSummary = hostData['Nmap Vulnerabilities'] || hostData['nmap_vulnerabilities'] || hostData.vulnerability_summary || '';
    if (!vulnSummary && typeof hostData.NmapVulnerabilities === 'string') {
        vulnSummary = hostData.NmapVulnerabilities;
    }
    const summaryEntries = (typeof vulnSummary === 'string' && vulnSummary.trim())
        ? vulnSummary.split(';').map(entry => entry.trim()).filter(Boolean)
        : [];

    const combinedVulns = [...normalizedVulnObjects, ...summaryEntries];
    const uniqueVulns = [];
    const seenVulns = new Set();
    combinedVulns.forEach(entry => {
        const key = entry.toLowerCase();
        if (!seenVulns.has(key)) {
            seenVulns.add(key);
            uniqueVulns.push(entry);
        }
    });

    const rawScanStatus = hostData['NmapVulnScanner'] || hostData['nmap_vuln_scanner'] || hostData.scan_status || '';
    const lastScanIso = hostData.last_scan || hostData.LastScan || hostData.last_vuln_scan || '';
    const lastScan = buildLastScanInfo(rawScanStatus, lastScanIso);

    return {
        ip: String(ip).trim(),
        hostname: hostname || '',
        mac: mac || '',
        ports,
        statusText,
        statusClass,
        vulnerabilityCount: uniqueVulns.length,
        vulnerabilityPreview: uniqueVulns.slice(0, 2).join('; '),
        vulnerabilityFull: uniqueVulns.join('; '),
        lastScan,
        raw: hostData
    };
}

function formatPortsCell(ports) {
    if (!ports || ports.length === 0) {
        return '<span class="text-gray-400">None</span>';
    }
    const displayPorts = ports.slice(0, 5);
    const displayText = escapeHtml(displayPorts.join(', '));
    const ellipsis = ports.length > 5 ? '…' : '';
    const tooltip = escapeHtml(ports.join(', '));
    return `<span title="${tooltip}">${displayText}${ellipsis}</span>`;
}

function formatVulnerabilityCell(normalized) {
    if (!normalized || normalized.vulnerabilityCount === 0) {
        return '<span class="text-gray-400">None</span>';
    }

    const countText = `${normalized.vulnerabilityCount} ${normalized.vulnerabilityCount === 1 ? 'issue' : 'issues'}`;
    const tooltipSource = normalized.vulnerabilityFull || normalized.vulnerabilityPreview || countText;
    const tooltip = escapeHtml(tooltipSource);
    const preview = normalized.vulnerabilityPreview
        ? `<div class="text-xs text-slate-300 truncate max-w-xs" title="${tooltip}">${escapeHtml(normalized.vulnerabilityPreview)}</div>`
        : '';

    return `<span class="text-red-400 font-medium" title="${tooltip}">${countText}</span>${preview}`;
}

function formatLastScanCell(info) {
    if (!info) {
        return '<span class="text-gray-400">Never</span>';
    }

    const tooltip = info.tooltip ? ` title="${escapeHtml(info.tooltip)}"` : '';
    const timestampLine = info.timestampText
        ? `<div class="text-xs text-gray-400">${escapeHtml(info.timestampText)}</div>`
        : '';

    return `<div${tooltip}><span class="${info.className}">${escapeHtml(info.label)}</span>${timestampLine}</div>`;
}

function renderHostRow(normalized) {
    const hostname = normalized.hostname ? escapeHtml(normalized.hostname) : 'Unknown';
    const mac = normalized.mac ? escapeHtml(normalized.mac) : 'Unknown';
    const ip = escapeHtml(normalized.ip);

    return `
        <td class="py-3 px-4">
            <span class="px-2 py-1 rounded text-xs ${normalized.statusClass}">${escapeHtml(normalized.statusText)}</span>
        </td>
        <td class="py-3 px-4 font-mono">${ip}</td>
        <td class="py-3 px-4">${hostname || 'Unknown'}</td>
        <td class="py-3 px-4 font-mono text-sm">${mac || 'Unknown'}</td>
        <td class="py-3 px-4 text-sm">${formatPortsCell(normalized.ports)}</td>
        <td class="py-3 px-4 text-sm">${formatVulnerabilityCell(normalized)}</td>
        <td class="py-3 px-4 text-sm">${formatLastScanCell(normalized.lastScan)}</td>
        <td class="py-3 px-4">
            <button onclick="triggerDeepScan('${normalized.ip}')" 
                    id="deep-scan-btn-${normalized.ip.replace(/\./g, '-')}"
                    data-scan-status="idle"
                    class="deep-scan-button bg-purple-600 hover:bg-purple-700 text-white text-xs px-3 py-1 rounded transition-all duration-300"
                    title="Scan all 65535 ports with TCP connect (-sT). IP: ${normalized.ip}">
                Deep Scan
            </button>
        </td>
    `;
}

function updateHostCountDisplay() {
    const tableBody = document.getElementById('network-hosts-table');
    const hostCount = document.getElementById('host-count');
    if (!tableBody || !hostCount) {
        return;
    }

    const totalHosts = tableBody.querySelectorAll('tr[data-ip]').length;
    hostCount.textContent = `${totalHosts} host${totalHosts !== 1 ? 's' : ''}`;
}

function updateHostInTable(hostData) {
    const tableBody = document.getElementById('network-hosts-table');
    if (!tableBody) {
        return;
    }

    const normalized = normalizeHostRecord(hostData);
    if (!normalized) {
        return;
    }

    const noDataRow = tableBody.querySelector('td[colspan="8"]');
    if (noDataRow) {
        noDataRow.parentElement.remove();
    }

    const selector = `tr[data-ip="${escapeSelector(normalized.ip)}"]`;
    let row = tableBody.querySelector(selector);
    
    // Save deep scan button state before updating row
    if (row) {
        saveDeepScanButtonState(normalized.ip);
    }
    
    if (!row) {
        row = document.createElement('tr');
        row.setAttribute('data-ip', normalized.ip);
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        tableBody.appendChild(row);
    }

    row.innerHTML = renderHostRow(normalized);
    
    // Restore deep scan button state after updating row
    restoreDeepScanButtonState(normalized.ip);
    
    updateHostCountDisplay();
}

async function scanSingleHost(ip) {
    try {
        const response = await fetch('/api/scan/host', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip: ip })
        });
        
        if (response.ok) {
            addConsoleMessage(`Started scan of ${ip}`, 'info');
        } else {
            throw new Error('Failed to start host scan');
        }
    } catch (error) {
        console.error('Error scanning host:', error);
        addConsoleMessage(`Failed to scan ${ip}: ${error.message}`, 'error');
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

// Attack Logs Functions
let currentAttackFilter = 'all';
let attackLogsCache = null;
let attackLogsETag = null;
let attackLogsInFlight = null;

async function loadAttackLogs(options = {}) {
    const { force = false } = options;

    if (attackLogsInFlight) {
        return attackLogsInFlight;
    }

    const headers = {};
    if (!force && attackLogsETag) {
        headers['If-None-Match'] = attackLogsETag;
    }

    if (!attackLogsCache) {
        document.getElementById('attack-logs-container').innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-8 h-8 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                <p>Loading attack logs...</p>
            </div>
        `;
    }

    attackLogsInFlight = (async () => {
        try {
            const response = await fetch('/api/attack?limit=200&days=7', { headers });

            if (response.status === 304) {
                console.debug('Attack logs unchanged; skipping DOM update');
                return attackLogsCache;
            }

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            attackLogsCache = data;
            attackLogsETag = response.headers.get('ETag') || attackLogsETag;
            displayAttackLogs(data);
            return data;
        } catch (error) {
            console.error('Error loading attack logs:', error);

            if (!attackLogsCache) {
                document.getElementById('attack-logs-container').innerHTML = `
                    <div class="text-center text-red-400 py-8">
                        <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <p>Error loading attack logs</p>
                        <p class="text-sm text-gray-500 mt-2">${error.message}</p>
                    </div>
                `;
            }

            return attackLogsCache;
        } finally {
            attackLogsInFlight = null;
        }
    })();

    return attackLogsInFlight;
}

function filterAttackLogs(status) {
    currentAttackFilter = status;
    
    // Update filter button styles
    document.querySelectorAll('.attack-filter-btn').forEach(btn => {
        if (btn.getAttribute('data-filter') === status) {
            btn.classList.add('ring-2', 'ring-white');
        } else {
            btn.classList.remove('ring-2', 'ring-white');
        }
    });
    
    // Re-display with filter
    if (attackLogsCache) {
        displayAttackLogs(attackLogsCache);
    }
}

async function refreshAttackLogs() {
    await loadAttackLogs({ force: true });
}

function displayAttackLogs(data) {
    if (!data || !data.attack_logs) {
        document.getElementById('attack-logs-container').innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <p>No attack logs found</p>
            </div>
        `;
        return;
    }
    
    // Update statistics
    document.getElementById('attack-stat-total').textContent = data.total_count || 0;
    document.getElementById('attack-stat-success').textContent = data.success_count || 0;
    document.getElementById('attack-stat-failed').textContent = data.failed_count || 0;
    
    // Calculate timeout count
    const timeoutCount = data.attack_logs.filter(log => log.status === 'timeout').length;
    document.getElementById('attack-stat-timeout').textContent = timeoutCount;
    
    // Filter logs based on current filter
    let logs = data.attack_logs;
    if (currentAttackFilter !== 'all') {
        logs = logs.filter(log => log.status === currentAttackFilter);
    }
    
    if (logs.length === 0) {
        document.getElementById('attack-logs-container').innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                </svg>
                <p>No ${currentAttackFilter === 'all' ? '' : currentAttackFilter} attacks found</p>
            </div>
        `;
        return;
    }
    
    // Group logs by IP address
    const logsByIP = {};
    logs.forEach(log => {
        const ip = log.target_ip || 'Unknown';
        if (!logsByIP[ip]) {
            logsByIP[ip] = [];
        }
        logsByIP[ip].push(log);
    });
    
    // Sort IPs
    const sortedIPs = Object.keys(logsByIP).sort();
    
    // Build HTML
    let html = '<div class="space-y-4">';
    
    sortedIPs.forEach(ip => {
        const hostLogs = logsByIP[ip];
        const successCount = hostLogs.filter(l => l.status === 'success').length;
        const failedCount = hostLogs.filter(l => l.status === 'failed').length;
        const timeoutCount = hostLogs.filter(l => l.status === 'timeout').length;
        
        html += `
            <div class="bg-slate-800 bg-opacity-50 rounded-lg border border-slate-700 overflow-hidden">
                <div class="px-4 py-3 bg-slate-900 bg-opacity-50 flex items-center justify-between cursor-pointer hover:bg-opacity-70 transition-colors" onclick="toggleAttackHost('${ip}')">
                    <div class="flex items-center space-x-3">
                        <svg class="w-5 h-5 text-Ragnar-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path>
                        </svg>
                        <span class="font-semibold text-lg">${ip}</span>
                        <span class="text-sm text-gray-400">(${hostLogs.length} attacks)</span>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-sm text-green-400">✓ ${successCount}</span>
                        <span class="text-sm text-red-400">✗ ${failedCount}</span>
                        <span class="text-sm text-yellow-400">⏱ ${timeoutCount}</span>
                        <svg id="attack-chevron-${ip.replace(/\./g, '-')}" class="w-5 h-5 text-gray-400 transform transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                        </svg>
                    </div>
                </div>
                <div id="attack-host-${ip.replace(/\./g, '-')}" class="hidden px-4 py-3 space-y-2">
        `;
        
        // Sort logs by timestamp (most recent first)
        hostLogs.sort((a, b) => {
            return new Date(b.timestamp) - new Date(a.timestamp);
        });
        
        hostLogs.forEach(log => {
            const statusColors = {
                'success': 'bg-green-900 bg-opacity-30 border-green-500',
                'failed': 'bg-red-900 bg-opacity-30 border-red-500',
                'timeout': 'bg-yellow-900 bg-opacity-30 border-yellow-500'
            };
            
            const statusIcons = {
                'success': '✓',
                'failed': '✗',
                'timeout': '⏱'
            };
            
            const statusTextColors = {
                'success': 'text-green-400',
                'failed': 'text-red-400',
                'timeout': 'text-yellow-400'
            };
            
            const colorClass = statusColors[log.status] || 'bg-gray-900 bg-opacity-30 border-gray-500';
            const icon = statusIcons[log.status] || '•';
            const textColor = statusTextColors[log.status] || 'text-gray-400';
            
            html += `
                <div class="border-l-4 ${colorClass} p-3 rounded-r-lg">
                    <div class="flex items-start justify-between">
                        <div class="flex-1">
                            <div class="flex items-center space-x-2 mb-1">
                                <span class="font-semibold ${textColor}">${icon} ${log.attack_type}</span>
                                ${log.target_port ? `<span class="text-xs text-gray-400">Port ${log.target_port}</span>` : ''}
                                <span class="text-xs text-gray-500">${log.timestamp}</span>
                            </div>
                            ${log.message ? `<p class="text-sm text-gray-300 mb-2">${escapeHtml(log.message)}</p>` : ''}
                            ${Object.keys(log.details || {}).length > 0 ? `
                                <div class="text-xs space-y-1 mt-2">
                                    ${Object.entries(log.details).map(([key, value]) => `
                                        <div class="flex items-center space-x-2">
                                            <span class="text-gray-500">${key}:</span>
                                            <span class="text-gray-300 font-mono">${escapeHtml(String(value))}</span>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    
    document.getElementById('attack-logs-container').innerHTML = html;
}

function toggleAttackHost(ip) {
    const containerId = `attack-host-${ip.replace(/\./g, '-')}`;
    const chevronId = `attack-chevron-${ip.replace(/\./g, '-')}`;
    const container = document.getElementById(containerId);
    const chevron = document.getElementById(chevronId);
    
    if (container.classList.contains('hidden')) {
        container.classList.remove('hidden');
        chevron.classList.add('rotate-180');
    } else {
        container.classList.add('hidden');
        chevron.classList.remove('rotate-180');
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function loadConfigData() {
    try {
        const config = await fetchAPI('/api/config');
        displayConfigForm(config);
        
        // Load hardware profiles
        await loadHardwareProfiles();
        
        // Display current profile if set
        displayCurrentProfile(config);
        
        // Update vulnerability count in data management card
        updateVulnerabilityCount();
        
        // Also check for updates when loading config tab
        checkForUpdates();
    } catch (error) {
        console.error('Error loading config:', error);
    }
}

async function loadConnectData() {
    try {
        // Load Wi-Fi interfaces first so dropdowns are populated before status updates
        await loadWifiInterfaces();

        // Refresh Wi-Fi and Bluetooth status in parallel to shorten the loading time
        console.log('Loading connect tab, refreshing connectivity status...');
        await Promise.all([
            refreshWifiStatus(),
            refreshBluetoothStatus()
        ]);
    } catch (error) {
        console.error('Error loading connect data:', error);
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
// HARDWARE PROFILE MANAGEMENT FUNCTIONS
// ============================================================================

async function loadHardwareProfiles() {
    try {
        const profiles = await fetchAPI('/api/config/hardware-profiles');
        const select = document.getElementById('hardware-profile-select');
        const applyBtn = document.getElementById('apply-profile-btn');
        
        if (!select) return;
        
        // Clear existing options
        select.innerHTML = '<option value="">Select a hardware profile...</option>';
        
        // Store profiles data for later use
        window.hardwareProfiles = profiles;
        
        // Populate dropdown options
        for (const [profileId, profile] of Object.entries(profiles)) {
            const option = document.createElement('option');
            option.value = profileId;
            option.textContent = `${profile.name} (${profile.ram}MB RAM)`;
            select.appendChild(option);
        }
        
        // Add change event listener to show profile details
        select.addEventListener('change', function() {
            const selectedProfileId = this.value;
            const applyBtn = document.getElementById('apply-profile-btn');
            
            if (selectedProfileId && profiles[selectedProfileId]) {
                showProfileDetails(profiles[selectedProfileId]);
                applyBtn.disabled = false;
            } else {
                hideProfileDetails();
                applyBtn.disabled = true;
            }
        });
        
    } catch (error) {
        console.error('Error loading hardware profiles:', error);
        addConsoleMessage('Failed to load hardware profiles', 'error');
        
        const select = document.getElementById('hardware-profile-select');
        if (select) {
            select.innerHTML = '<option value="">Error loading profiles</option>';
        }
    }
}

function showProfileDetails(profile) {
    const detailsDiv = document.getElementById('profile-details');
    if (!detailsDiv) return;
    
    document.getElementById('profile-description').textContent = profile.description || 'No description available';
    document.getElementById('profile-ram').textContent = `${profile.ram}MB`;
    document.getElementById('profile-threads').textContent = profile.settings.scanner_max_threads || 'N/A';
    document.getElementById('profile-concurrent').textContent = profile.settings.orchestrator_max_concurrent || 'N/A';
    document.getElementById('profile-speed').textContent = profile.settings.nmap_scan_aggressivity || 'N/A';
    
    detailsDiv.classList.remove('hidden');
}

function hideProfileDetails() {
    const detailsDiv = document.getElementById('profile-details');
    if (detailsDiv) {
        detailsDiv.classList.add('hidden');
    }
}

async function applySelectedProfile() {
    const select = document.getElementById('hardware-profile-select');
    const selectedProfileId = select.value;
    
    if (!selectedProfileId) {
        addConsoleMessage('Please select a hardware profile first', 'warning');
        return;
    }
    
    await confirmApplyProfile(selectedProfileId, window.hardwareProfiles[selectedProfileId]);
}

async function detectAndApplyHardware() {
    try {
        addConsoleMessage('Detecting hardware...', 'info');
        const infoDiv = document.getElementById('hardware-detection-info');
        infoDiv.innerHTML = '<span class="text-Ragnar-400">🔍 Detecting hardware...</span>';
        
        const hardware = await fetchAPI('/api/config/detect-hardware');
        
        // Display detection results
        infoDiv.innerHTML = `
            <div class="space-y-2">
                <div class="flex justify-between">
                    <span class="text-gray-400">Detected Model:</span>
                    <span class="text-white font-semibold">${hardware.model}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-gray-400">Total RAM:</span>
                    <span class="text-white font-semibold">${hardware.ram_gb} GB (${hardware.ram_mb} MB)</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-gray-400">CPU Cores:</span>
                    <span class="text-white font-semibold">${hardware.cpu_count}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-gray-400">Recommended Profile:</span>
                    <span class="text-Ragnar-400 font-semibold">${hardware.recommended_profile}</span>
                </div>
            </div>
        `;
        
        addConsoleMessage(`Detected: ${hardware.model} with ${hardware.ram_gb}GB RAM`, 'success');
        
        // Auto-apply the recommended profile
        if (hardware.recommended_profile) {
            addConsoleMessage(`Applying recommended profile: ${hardware.recommended_profile}`, 'info');
            await applyHardwareProfile(hardware.recommended_profile);
        }
        
    } catch (error) {
        console.error('Error detecting hardware:', error);
        addConsoleMessage('Failed to detect hardware', 'error');
        document.getElementById('hardware-detection-info').innerHTML = 
            '<span class="text-red-400">❌ Failed to detect hardware. Try manual selection.</span>';
    }
}

async function confirmApplyProfile(profileId, profile) {
    if (confirm(`Apply profile "${profile.name}"?\n\n${profile.description}\n\nThis will update system resource settings and requires a service restart to take full effect.`)) {
        await applyHardwareProfile(profileId);
    }
}

async function applyHardwareProfile(profileId) {
    try {
        addConsoleMessage(`Applying hardware profile: ${profileId}...`, 'info');
        
        const result = await postAPI('/api/config/apply-profile', { profile_id: profileId });
        
        if (result.success) {
            addConsoleMessage(`✅ Profile applied: ${result.profile.name}`, 'success');
            addConsoleMessage('⚠️ Service restart required for changes to take effect', 'warning');
            
            // Update current profile display
            displayCurrentProfile({
                hardware_profile: profileId,
                hardware_profile_name: result.profile.name,
                hardware_profile_applied: result.profile.hardware_profile_applied || new Date().toISOString()
            });
            
            // Show restart prompt
            if (confirm('Hardware profile applied successfully!\n\nRestart the Ragnar service now to apply changes?')) {
                await restartService();
            }
        } else {
            addConsoleMessage('❌ Failed to apply profile', 'error');
        }
        
    } catch (error) {
        console.error('Error applying hardware profile:', error);
        addConsoleMessage(`Failed to apply hardware profile: ${error.message}`, 'error');
    }
}

function displayCurrentProfile(config) {
    const statusDiv = document.getElementById('current-profile-status');
    const nameSpan = document.getElementById('current-profile-name');
    const appliedSpan = document.getElementById('current-profile-applied');
    
    if (config.hardware_profile && config.hardware_profile_name) {
        statusDiv.classList.remove('hidden');
        nameSpan.textContent = config.hardware_profile_name;
        
        if (config.hardware_profile_applied) {
            const appliedDate = new Date(config.hardware_profile_applied);
            appliedSpan.textContent = `Applied: ${appliedDate.toLocaleString()}`;
        } else {
            appliedSpan.textContent = 'Applied recently';
        }
    } else {
        statusDiv.classList.add('hidden');
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
        updateElement('update-btn-text', 'Update now');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = true;
        updateBtn.className = 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-not-allowed';
        
        addConsoleMessage('Starting system update...', 'info');
        
        const data = await postAPI('/api/system/update', {});
        
        if (data.success) {
            addConsoleMessage('Update completed successfully', 'success');
            addConsoleMessage('System will restart automatically...', 'info');
            updateElement('update-info', 'Update completed. System restarting...');
            
            // Wait for service restart and verify it's back up
            setTimeout(async () => {
                await verifyServiceRestart();
            }, 10000); // Start checking after 10 seconds
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

async function verifyServiceRestart() {
    let attempts = 0;
    const maxAttempts = 12; // Try for up to 2 minutes (12 attempts * 10 seconds)
    
    addConsoleMessage('Verifying service is back online...', 'info');
    updateElement('update-info', 'Verifying service restart...');
    
    const checkService = async () => {
        attempts++;
        
        try {
            // Try to fetch the stats endpoint as a health check
            const response = await fetch('/api/stats', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000
            });
            
            if (response.ok) {
                // Service is back up
                addConsoleMessage('✅ Service verified online after update', 'success');
                updateElement('update-info', 'Update completed successfully. Service is online.');
                
                // Reset the update button
                const updateBtn = document.getElementById('update-btn');
                updateElement('update-btn-text', 'Update System');
                updateBtn.disabled = false;
                updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
                
                // Check for updates to refresh status
                setTimeout(() => {
                    checkForUpdates();
                }, 5000);
                
                return; // Success, exit the checking loop
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            console.log(`Service check attempt ${attempts}/${maxAttempts} failed:`, error.message);
            
            if (attempts >= maxAttempts) {
                // Max attempts reached, service might not have restarted properly
                addConsoleMessage('⚠️ Service restart verification timeout. Manual check may be needed.', 'warning');
                updateElement('update-info', 'Update completed, but service verification timed out.');
                
                // Reset the update button
                const updateBtn = document.getElementById('update-btn');
                updateElement('update-btn-text', 'Update System');
                updateBtn.disabled = false;
                updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
                
                return; // Exit the checking loop
            }
            
            // Continue checking
            addConsoleMessage(`Service check ${attempts}/${maxAttempts} - waiting for restart...`, 'info');
            setTimeout(checkService, 10000); // Check again in 10 seconds
        }
    };
    
    // Start the checking process after 10s
    checkService();
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
// DATA MANAGEMENT FUNCTIONS
// ============================================================================

async function resetVulnerabilities() {
    if (!confirm('⚠️ Reset All Vulnerabilities?\n\nThis will permanently delete:\n• All discovered vulnerabilities\n• Vulnerability scan results\n• Network intelligence vulnerability data\n\nThis action cannot be undone. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Resetting vulnerabilities...', 'warning');
        
        const data = await postAPI('/api/data/reset-vulnerabilities', {});
        
        if (data.success) {
            addConsoleMessage(`Vulnerabilities reset: ${data.deleted_count || 0} entries removed`, 'success');
            
            // Update vulnerability count display
            updateElement('vuln-count', '0');
            updateElement('vulnerability-count', '0');
            
            // Refresh current tab if we're on network or discovered tabs
            if (currentTab === 'network' || currentTab === 'discovered' || currentTab === 'threat-intel') {
                setTimeout(() => {
                    refreshCurrentTab();
                }, 500);
            }
        } else {
            addConsoleMessage(`Reset failed: ${data.error || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error resetting vulnerabilities:', error);
        addConsoleMessage('Failed to reset vulnerabilities', 'error');
    }
}

async function resetThreatIntelligence() {
    if (!confirm('⚠️ Reset Threat Intelligence?\n\nThis will permanently delete:\n• All threat intelligence findings\n• Enriched threat data\n• Threat cache\n\nThis action cannot be undone. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Resetting threat intelligence...', 'warning');
        
        const data = await postAPI('/api/data/reset-threat-intel', {});
        
        if (data.success) {
            addConsoleMessage('Threat intelligence data reset successfully', 'success');
            
            // Refresh threat intel tab if active
            if (currentTab === 'threat-intel') {
                setTimeout(() => {
                    refreshCurrentTab();
                }, 500);
            }
        } else {
            addConsoleMessage(`Reset failed: ${data.error || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error resetting threat intelligence:', error);
        addConsoleMessage('Failed to reset threat intelligence', 'error');
    }
}

// Update vulnerability count in config tab
async function updateVulnerabilityCount() {
    try {
        const stats = await fetchAPI('/api/stats');
        const count = stats.vulnerability_count || 0;
        updateElement('vuln-count', count.toString());
    } catch (error) {
        console.error('Error updating vulnerability count:', error);
        updateElement('vuln-count', '?');
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
        console.log('Wi-Fi status data received:', data);
        
        const statusIndicator = document.getElementById('wifi-status-indicator');
        const wifiInfo = document.getElementById('wifi-info');
        
        if (!statusIndicator || !wifiInfo) {
            console.error('Wi-Fi status elements not found in DOM');
            console.log('Looking for elements: wifi-status-indicator and wifi-info');
            return;
        }
        
        console.log('Wi-Fi status elements found, updating...');
        
        if (data.ap_mode_active) {
            const apMessage = `AP Mode Active: "${data.ap_ssid || 'Ragnar'}" | Connect to configure Wi-Fi`;
            console.log('Setting AP mode status:', apMessage);
            updateWifiStatus(apMessage, 'ap-mode');
            statusIndicator.textContent = 'AP Mode';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-orange-700 text-orange-300';
            wifiInfo.textContent = apMessage;
        } else if (data.wifi_connected) {
            const ssid = data.current_ssid || 'Unknown Network';
            const connectedMessage = `Connected to: ${ssid}`;
            console.log('Setting connected status:', connectedMessage);
            updateWifiStatus(connectedMessage, 'connected');
            statusIndicator.textContent = 'Connected';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
            wifiInfo.textContent = connectedMessage;
        } else {
            console.log('Setting disconnected status');
            updateWifiStatus('Wi-Fi disconnected', 'disconnected');
            statusIndicator.textContent = 'Disconnected';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
            wifiInfo.textContent = 'No Wi-Fi connection';
        }
        
        console.log('Wi-Fi status updated successfully');
            
    } catch (error) {
        console.error('Error refreshing Wi-Fi status:', error);
        updateWifiStatus('Error checking Wi-Fi status', 'error');
        
        const statusIndicator = document.getElementById('wifi-status-indicator');
        const wifiInfo = document.getElementById('wifi-info');
        
        if (statusIndicator) {
            statusIndicator.textContent = 'Error';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        }
        if (wifiInfo) {
            wifiInfo.textContent = 'Error checking Wi-Fi status';
        }
    }
}

function updateWifiStatus(message, type = '') {
    // This function can be enhanced to show status messages in a notification area
    // For now, we'll use console messages and update the UI elements
    addConsoleMessage(message, type === 'error' ? 'error' : type === 'ap-mode' ? 'warning' : 'info');
}

// ============================================================================
// WI-FI MANAGEMENT FUNCTIONS
// ============================================================================

let currentWifiNetworks = [];
let selectedWifiNetwork = null;

async function loadWifiInterfaces() {
    try {
        const data = await fetchAPI('/api/wifi/interfaces');
        const interfaceSelect = document.getElementById('wifi-interface-select');
        
        if (!interfaceSelect) return;
        
        if (data.success && data.interfaces && data.interfaces.length > 0) {
            interfaceSelect.innerHTML = '';
            data.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface.name;
                option.textContent = `${iface.name}${iface.is_default ? ' (default)' : ''} - ${iface.state}`;
                if (iface.is_default) {
                    option.selected = true;
                }
                interfaceSelect.appendChild(option);
            });
            console.log('Loaded Wi-Fi interfaces:', data.interfaces);
        } else {
            interfaceSelect.innerHTML = '<option value="wlan0">wlan0 (default)</option>';
        }
    } catch (error) {
        console.error('Error loading Wi-Fi interfaces:', error);
        const interfaceSelect = document.getElementById('wifi-interface-select');
        if (interfaceSelect) {
            interfaceSelect.innerHTML = '<option value="wlan0">wlan0 (default)</option>';
        }
    }
}

async function scanWifiNetworks() {
    const scanBtn = document.getElementById('scan-wifi-btn');
    const networksList = document.getElementById('wifi-networks-list');
    
    if (!networksList) return;
    
    try {
        // Disable button and show scanning message
        if (scanBtn) {
            scanBtn.disabled = true;
            scanBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-1 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Scanning...
            `;
        }
        
        networksList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-8 h-8 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                <p>Scanning for Wi-Fi networks...</p>
            </div>
        `;
        
        // Trigger scan
        await postAPI('/api/wifi/scan', {});
        
        // Wait a bit for scan to complete
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Get networks
        const data = await fetchAPI('/api/wifi/networks');
        
        console.log('Wi-Fi networks data:', data);
        
        // Display networks
        displayWifiNetworks(data);
        
    } catch (error) {
        console.error('Error scanning Wi-Fi networks:', error);
        networksList.innerHTML = `
            <div class="text-center text-red-400 py-8">
                <p>Error scanning for networks</p>
                <p class="text-sm mt-2">${error.message}</p>
            </div>
        `;
    } finally {
        // Re-enable button
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                </svg>
                Scan Networks
            `;
        }
    }
}

function displayWifiNetworks(data) {
    const networksList = document.getElementById('wifi-networks-list');
    if (!networksList) return;
    
    let networks = [];
    let knownNetworks = [];
    
    // Extract networks from response
    if (data.available) {
        networks = data.available;
    } else if (data.networks) {
        networks = data.networks;
    }
    
    // Extract known networks
    if (data.known) {
        knownNetworks = data.known.map(n => n.ssid || n);
    }
    
    console.log('Displaying networks:', networks);
    console.log('Known networks:', knownNetworks);
    
    if (!networks || networks.length === 0) {
        networksList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <p>No Wi-Fi networks found</p>
                <p class="text-sm mt-2">Try scanning again or check your Wi-Fi interface</p>
            </div>
        `;
        return;
    }
    
    // Sort networks by signal strength
    networks.sort((a, b) => (b.signal || 0) - (a.signal || 0));
    
    // Store for later use
    currentWifiNetworks = networks;
    
    // Build network list HTML
    networksList.innerHTML = networks.map(network => {
        const ssid = network.ssid || network.SSID || 'Unknown Network';
        const signal = network.signal || 0;
        const isSecure = network.security !== 'open' && network.security !== 'Open';
        const isKnown = knownNetworks.includes(ssid);
        const isCurrent = network.in_use || false;
        
        // Determine signal icon
        let signalIcon = '';
        if (signal >= 70) {
            signalIcon = `<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"></path>
            </svg>`;
        } else if (signal >= 50) {
            signalIcon = `<svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7z"></path>
            </svg>`;
        } else {
            signalIcon = `<svg class="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5z"></path>
            </svg>`;
        }
        
        // Security icon
        const securityIcon = isSecure ? `
            <svg class="w-4 h-4 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"></path>
            </svg>
        ` : '';
        
        // Badge for known/current network
        let badge = '';
        if (isCurrent) {
            badge = '<span class="text-xs px-2 py-1 rounded bg-green-600 text-white ml-2">Connected</span>';
        } else if (isKnown) {
            badge = '<span class="text-xs px-2 py-1 rounded bg-blue-600 text-white ml-2">Saved</span>';
        }
        
        return `
            <div class="bg-slate-800 rounded-lg p-3 hover:bg-slate-700 transition-colors cursor-pointer"
                 onclick="openWifiConnectModal('${ssid.replace(/'/g, "\\'")}', ${isKnown})">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-3 flex-1">
                        ${signalIcon}
                        <div class="flex-1">
                            <div class="flex items-center">
                                <span class="font-medium">${ssid}</span>
                                ${badge}
                            </div>
                            <div class="text-xs text-gray-400 mt-1">
                                ${isSecure ? 'Secured' : 'Open'} • Signal: ${signal}%
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2">
                        ${securityIcon}
                        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function openWifiConnectModal(ssid, isKnown) {
    const modal = document.getElementById('wifi-connect-modal');
    const ssidInput = document.getElementById('wifi-connect-ssid');
    const passwordSection = document.getElementById('wifi-password-section');
    const passwordInput = document.getElementById('wifi-connect-password');
    const statusDiv = document.getElementById('wifi-connect-status');
    
    if (!modal || !ssidInput) return;
    
    // Store selected network
    selectedWifiNetwork = { ssid, isKnown };
    
    // Set SSID
    ssidInput.value = ssid;
    
    // Clear password
    if (passwordInput) {
        passwordInput.value = '';
    }
    
    // Hide/show password section based on whether network is known
    if (passwordSection) {
        if (isKnown) {
            passwordSection.style.display = 'none';
        } else {
            passwordSection.style.display = 'block';
        }
    }
    
    // Hide status
    if (statusDiv) {
        statusDiv.classList.add('hidden');
    }
    
    // Show modal
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeWifiConnectModal() {
    const modal = document.getElementById('wifi-connect-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
    selectedWifiNetwork = null;
}

function togglePasswordVisibility() {
    const passwordInput = document.getElementById('wifi-connect-password');
    const eyeIcon = document.getElementById('password-eye-icon');
    
    if (!passwordInput) return;
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        if (eyeIcon) {
            eyeIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"></path>
            `;
        }
    } else {
        passwordInput.type = 'password';
        if (eyeIcon) {
            eyeIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
            `;
        }
    }
}

async function connectToWifiNetwork() {
    if (!selectedWifiNetwork) return;
    
    const passwordInput = document.getElementById('wifi-connect-password');
    const saveCheckbox = document.getElementById('wifi-save-network');
    const statusDiv = document.getElementById('wifi-connect-status');
    const submitBtn = document.getElementById('wifi-connect-submit-btn');
    
    const ssid = selectedWifiNetwork.ssid;
    const isKnown = selectedWifiNetwork.isKnown;
    const password = isKnown ? null : (passwordInput ? passwordInput.value : '');
    const saveNetwork = saveCheckbox ? saveCheckbox.checked : true;
    
    // Validate password for new networks
    if (!isKnown && !password) {
        if (statusDiv) {
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = '<div class="bg-red-600 rounded p-3 text-sm">Please enter a password</div>';
        }
        return;
    }
    
    try {
        // Disable submit button
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Connecting...
            `;
        }
        
        // Show connecting status
        if (statusDiv) {
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = `
                <div class="bg-blue-600 rounded p-3 text-sm">
                    <svg class="w-4 h-4 inline mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                    </svg>
                    Connecting to ${ssid}...
                </div>
            `;
        }
        
        // Connect to network
        const data = await postAPI('/api/wifi/connect', {
            ssid: ssid,
            password: password,
            save: saveNetwork
        });
        
        if (data.success) {
            // Success
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-green-600 rounded p-3 text-sm">
                        <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                        </svg>
                        ${data.message || 'Connected successfully!'}
                    </div>
                `;
            }
            
            addConsoleMessage(`Connected to Wi-Fi: ${ssid}`, 'success');
            
            // Close modal after 2 seconds
            setTimeout(() => {
                closeWifiConnectModal();
                refreshWifiStatus();
            }, 2000);
            
        } else {
            // Failed
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-red-600 rounded p-3 text-sm">
                        <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                        ${data.message || 'Connection failed'}
                    </div>
                `;
            }
            
            addConsoleMessage(`Failed to connect to Wi-Fi: ${ssid}`, 'error');
            
            // If this was a known network, show password field for retry
            if (isKnown && passwordSection) {
                passwordSection.style.display = 'block';
                if (passwordInput) {
                    passwordInput.value = '';
                    passwordInput.placeholder = 'Stored password failed - enter correct password';
                }
                // Update the network state so next attempt uses the password
                if (selectedWifiNetwork) {
                    selectedWifiNetwork.isKnown = false;
                }
            }
        }
        
    } catch (error) {
        console.error('Error connecting to Wi-Fi:', error);
        
        if (statusDiv) {
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = `
                <div class="bg-red-600 rounded p-3 text-sm">
                    Error: ${error.message}
                </div>
            `;
        }
        
        addConsoleMessage(`Error connecting to Wi-Fi: ${error.message}`, 'error');
        
        // Show password field on connection error for known networks
        if (isKnown && passwordSection) {
            passwordSection.style.display = 'block';
            if (passwordInput) {
                passwordInput.value = '';
                passwordInput.placeholder = 'Connection error - please enter password';
            }
            // Update the network state
            if (selectedWifiNetwork) {
                selectedWifiNetwork.isKnown = false;
            }
        }
        
    } finally {
        // Re-enable submit button
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Connect';
        }
    }
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
// BLUETOOTH MANAGEMENT FUNCTIONS
// ============================================================================

// Global variables for Bluetooth
let currentBluetoothDevices = [];
let isBluetoothScanning = false;
let bluetoothScanInterval = null;

async function refreshBluetoothStatus() {
    try {
        const data = await fetchAPI('/api/bluetooth/status');
        updateBluetoothStatus(data);
    } catch (error) {
        console.error('Error refreshing Bluetooth status:', error);
        updateBluetoothStatus({
            enabled: false,
            discoverable: false,
            error: 'Failed to get Bluetooth status'
        });
    }
}

function updateBluetoothStatus(data) {
    const statusIndicator = document.getElementById('bluetooth-status-indicator');
    const infoDiv = document.getElementById('bluetooth-info');
    const powerBtn = document.getElementById('bluetooth-power-btn');
    const powerText = document.getElementById('bluetooth-power-text');
    const discoverableBtn = document.getElementById('bluetooth-discoverable-btn');
    const discoverableText = document.getElementById('bluetooth-discoverable-text');
    
    if (!statusIndicator || !infoDiv || !powerBtn || !powerText) return;
    
    if (data.error) {
        statusIndicator.className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        statusIndicator.textContent = 'Error';
        infoDiv.textContent = data.error;
        powerText.textContent = 'Enable Bluetooth';
        if (discoverableText) discoverableText.textContent = 'Make Discoverable';
        return;
    }
    
    if (data.enabled) {
        statusIndicator.className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
        statusIndicator.textContent = 'Enabled';
        powerText.textContent = 'Disable Bluetooth';
        powerBtn.className = 'w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition-colors';
        
        let infoText = 'Bluetooth is enabled';
        if (data.address) {
            infoText += ` | Address: ${data.address}`;
        }
        if (data.name) {
            infoText += ` | Name: ${data.name}`;
        }
        infoDiv.textContent = infoText;
        
        if (discoverableBtn && discoverableText) {
            if (data.discoverable) {
                discoverableText.textContent = 'Hide Device';
                discoverableBtn.className = 'w-full bg-orange-600 hover:bg-orange-700 text-white py-2 px-4 rounded transition-colors';
            } else {
                discoverableText.textContent = 'Make Discoverable';
                discoverableBtn.className = 'w-full bg-cyan-600 hover:bg-cyan-700 text-white py-2 px-4 rounded transition-colors';
            }
            discoverableBtn.disabled = false;
        }
    } else {
        statusIndicator.className = 'text-sm px-2 py-1 rounded bg-gray-700 text-gray-300';
        statusIndicator.textContent = 'Disabled';
        infoDiv.textContent = 'Bluetooth is disabled';
        powerText.textContent = 'Enable Bluetooth';
        powerBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
        
        if (discoverableBtn && discoverableText) {
            discoverableText.textContent = 'Make Discoverable';
            discoverableBtn.className = 'w-full bg-gray-600 hover:bg-gray-700 text-white py-2 px-4 rounded transition-colors';
            discoverableBtn.disabled = true;
        }
    }
}

async function toggleBluetoothPower() {
    const powerBtn = document.getElementById('bluetooth-power-btn');
    const powerText = document.getElementById('bluetooth-power-text');
    
    if (!powerBtn || !powerText) return;
    
    const originalText = powerText.textContent;
    powerText.textContent = 'Processing...';
    powerBtn.disabled = true;
    
    try {
        const isEnabled = originalText === 'Disable Bluetooth';
        const endpoint = isEnabled ? '/api/bluetooth/disable' : '/api/bluetooth/enable';
        
        const response = await fetchAPI(endpoint, {
            method: 'POST'
        });
        
        if (response.success) {
            addConsoleMessage(`Bluetooth ${isEnabled ? 'disabled' : 'enabled'} successfully`, 'success');
            setTimeout(refreshBluetoothStatus, 1000);
        } else {
            throw new Error(response.error || 'Failed to toggle Bluetooth');
        }
    } catch (error) {
        console.error('Error toggling Bluetooth power:', error);
        addConsoleMessage(`Error toggling Bluetooth: ${error.message}`, 'error');
        powerText.textContent = originalText;
    } finally {
        powerBtn.disabled = false;
        if (powerText.textContent === 'Processing...') {
            powerText.textContent = originalText;
        }
    }
}

async function toggleBluetoothDiscoverable() {
    const discoverableBtn = document.getElementById('bluetooth-discoverable-btn');
    const discoverableText = document.getElementById('bluetooth-discoverable-text');
    
    if (!discoverableBtn || !discoverableText) return;
    
    const originalText = discoverableText.textContent;
    discoverableText.textContent = 'Processing...';
    discoverableBtn.disabled = true;
    
    try {
        const isDiscoverable = originalText === 'Hide Device';
        const endpoint = isDiscoverable ? '/api/bluetooth/discoverable/off' : '/api/bluetooth/discoverable/on';
        
        const response = await fetchAPI(endpoint, {
            method: 'POST'
        });
        
        if (response.success) {
            addConsoleMessage(`Bluetooth ${isDiscoverable ? 'hidden' : 'made discoverable'}`, 'success');
            setTimeout(refreshBluetoothStatus, 1000);
        } else {
            throw new Error(response.error || 'Failed to toggle discoverable mode');
        }
    } catch (error) {
        console.error('Error toggling Bluetooth discoverable:', error);
        addConsoleMessage(`Error toggling discoverable mode: ${error.message}`, 'error');
        discoverableText.textContent = originalText;
    } finally {
        discoverableBtn.disabled = false;
        if (discoverableText.textContent === 'Processing...') {
            discoverableText.textContent = originalText;
        }
    }
}

async function startBluetoothScan() {
    const scanBtn = document.getElementById('bluetooth-scan-btn');
    const scanText = document.getElementById('bluetooth-scan-text');
    const scanStatus = document.getElementById('bluetooth-scan-status');
    
    if (!scanBtn || !scanText || !scanStatus) return;
    
    if (isBluetoothScanning) {
        stopBluetoothScan();
        return;
    }
    
    isBluetoothScanning = true;
    scanText.textContent = 'Stop Scan';
    scanBtn.className = 'w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition-colors mb-2';
    scanStatus.className = 'text-sm px-2 py-1 rounded bg-blue-700 text-blue-300';
    scanStatus.textContent = 'Scanning...';
    
    try {
        const response = await fetchAPI('/api/bluetooth/scan/start', {
            method: 'POST'
        });
        
        if (response.success) {
            addConsoleMessage('Started Bluetooth device scan', 'info');
            
            // Start periodic refresh to get discovered devices
            bluetoothScanInterval = setInterval(async () => {
                try {
                    const devices = await fetchAPI('/api/bluetooth/devices');
                    displayBluetoothDevices(devices.devices || []);
                } catch (error) {
                    console.error('Error getting Bluetooth devices:', error);
                }
            }, 2000);
            
        } else {
            throw new Error(response.error || 'Failed to start Bluetooth scan');
        }
    } catch (error) {
        console.error('Error starting Bluetooth scan:', error);
        addConsoleMessage(`Error starting Bluetooth scan: ${error.message}`, 'error');
        stopBluetoothScan();
    }
}

function stopBluetoothScan() {
    const scanBtn = document.getElementById('bluetooth-scan-btn');
    const scanText = document.getElementById('bluetooth-scan-text');
    const scanStatus = document.getElementById('bluetooth-scan-status');
    
    isBluetoothScanning = false;
    
    if (bluetoothScanInterval) {
        clearInterval(bluetoothScanInterval);
        bluetoothScanInterval = null;
    }
    
    if (scanBtn && scanText && scanStatus) {
        scanText.textContent = 'Start Scan';
        scanBtn.className = 'w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2 px-4 rounded transition-colors mb-2';
        scanStatus.className = 'text-sm px-2 py-1 rounded bg-gray-700 text-gray-300';
        scanStatus.textContent = 'Ready';
    }
    
    // Stop the scan on the server
    fetchAPI('/api/bluetooth/scan/stop', {
        method: 'POST'
    }).catch(error => {
        console.error('Error stopping Bluetooth scan:', error);
    });
    
    addConsoleMessage('Stopped Bluetooth device scan', 'info');
}

function displayBluetoothDevices(devices) {
    const devicesList = document.getElementById('bluetooth-devices-list');
    if (!devicesList) return;
    
    currentBluetoothDevices = devices;
    
    if (!devices || devices.length === 0) {
        devicesList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                ${isBluetoothScanning ? 'Scanning for devices...' : 'No devices found. Start a scan to discover nearby devices.'}
            </div>
        `;
        return;
    }
    
    devicesList.innerHTML = devices.map(device => `
        <div class="glass rounded-lg p-3 hover:bg-slate-700 transition-colors cursor-pointer"
             onclick="showBluetoothDeviceDetails('${device.address}')">
            <div class="flex items-center justify-between">
                <div class="flex-1">
                    <div class="font-medium text-white">
                        ${escapeHtml(device.name || 'Unknown Device')}
                    </div>
                    <div class="text-sm text-gray-400">
                        ${device.address} ${device.rssi ? `• ${device.rssi} dBm` : ''}
                    </div>
                    ${device.device_class ? `
                        <div class="text-xs text-gray-500 mt-1">
                            ${escapeHtml(device.device_class)}
                        </div>
                    ` : ''}
                </div>
                <div class="flex items-center space-x-2">
                    ${device.rssi ? `
                        <div class="text-xs px-2 py-1 rounded ${getRSSIClass(device.rssi)}">
                            ${device.rssi} dBm
                        </div>
                    ` : ''}
                    ${device.paired ? `
                        <div class="text-xs px-2 py-1 rounded bg-green-700 text-green-300">
                            Paired
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `).join('');
}

function getRSSIClass(rssi) {
    if (rssi >= -40) return 'bg-green-700 text-green-300';
    if (rssi >= -60) return 'bg-yellow-700 text-yellow-300';
    if (rssi >= -80) return 'bg-orange-700 text-orange-300';
    return 'bg-red-700 text-red-300';
}

function showBluetoothDeviceDetails(address) {
    const device = currentBluetoothDevices.find(d => d.address === address);
    if (!device) return;
    
    const modal = document.getElementById('bluetooth-device-modal');
    const nameInput = document.getElementById('bt-device-name');
    const macInput = document.getElementById('bt-device-mac');
    const rssiInput = document.getElementById('bt-device-rssi');
    const classInput = document.getElementById('bt-device-class');
    const servicesDiv = document.getElementById('bt-device-services');
    const pairBtn = document.getElementById('bt-pair-btn');
    
    if (!modal || !nameInput || !macInput) return;
    
    nameInput.value = device.name || 'Unknown Device';
    macInput.value = device.address;
    if (rssiInput) rssiInput.value = device.rssi ? `${device.rssi} dBm` : 'Unknown';
    if (classInput) classInput.value = device.device_class || 'Unknown';
    
    if (servicesDiv) {
        if (device.services && device.services.length > 0) {
            servicesDiv.innerHTML = device.services.map(service => `
                <div class="mb-1 text-sm">${escapeHtml(service)}</div>
            `).join('');
        } else {
            servicesDiv.innerHTML = '<div class="text-gray-400">No services detected</div>';
        }
    }
    
    if (pairBtn) {
        if (device.paired) {
            pairBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
                </svg>
                Unpair Device
            `;
            pairBtn.className = 'bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition-colors';
        } else {
            pairBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
                </svg>
                Pair Device
            `;
            pairBtn.className = 'bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
        }
        pairBtn.setAttribute('data-device-address', device.address);
    }
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeBluetoothDeviceModal() {
    const modal = document.getElementById('bluetooth-device-modal');
    const statusDiv = document.getElementById('bt-device-status');
    
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
    
    if (statusDiv) {
        statusDiv.classList.add('hidden');
        statusDiv.innerHTML = '';
    }
}

async function pairBluetoothDevice() {
    const pairBtn = document.getElementById('bt-pair-btn');
    const statusDiv = document.getElementById('bt-device-status');
    
    if (!pairBtn) return;
    
    const address = pairBtn.getAttribute('data-device-address');
    if (!address) return;
    
    const device = currentBluetoothDevices.find(d => d.address === address);
    if (!device) return;
    
    const originalHTML = pairBtn.innerHTML;
    pairBtn.innerHTML = 'Processing...';
    pairBtn.disabled = true;
    
    if (statusDiv) {
        statusDiv.classList.remove('hidden');
        statusDiv.innerHTML = `
            <div class="bg-blue-600 rounded p-3 text-sm">
                ${device.paired ? 'Unpairing' : 'Pairing'} device ${device.name || address}...
            </div>
        `;
    }
    
    try {
        const endpoint = device.paired ? '/api/bluetooth/unpair' : '/api/bluetooth/pair';
        const response = await fetchAPI(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                address: address
            })
        });
        
        if (response.success) {
            const action = device.paired ? 'unpaired' : 'paired';
            addConsoleMessage(`Device ${device.name || address} ${action} successfully`, 'success');
            
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-green-600 rounded p-3 text-sm">
                        Device ${action} successfully
                    </div>
                `;
            }
            
            // Refresh the device list
            setTimeout(() => {
                if (isBluetoothScanning) {
                    fetchAPI('/api/bluetooth/devices').then(data => {
                        displayBluetoothDevices(data.devices || []);
                    }).catch(error => {
                        console.error('Error refreshing devices:', error);
                    });
                }
                closeBluetoothDeviceModal();
            }, 2000);
            
        } else {
            throw new Error(response.error || `Failed to ${device.paired ? 'unpair' : 'pair'} device`);
        }
    } catch (error) {
        console.error('Error pairing/unpairing device:', error);
        addConsoleMessage(`Error: ${error.message}`, 'error');
        
        if (statusDiv) {
            statusDiv.innerHTML = `
                <div class="bg-red-600 rounded p-3 text-sm">
                    Error: ${error.message}
                </div>
            `;
        }
    } finally {
        pairBtn.disabled = false;
        if (pairBtn.innerHTML === 'Processing...') {
            pairBtn.innerHTML = originalHTML;
        }
    }
}

async function enumerateBluetoothServices() {
    const enumerateBtn = document.getElementById('bt-enumerate-btn');
    const statusDiv = document.getElementById('bt-device-status');
    const servicesDiv = document.getElementById('bt-device-services');
    
    if (!enumerateBtn) return;
    
    const address = document.getElementById('bt-pair-btn')?.getAttribute('data-device-address');
    if (!address) return;
    
    const device = currentBluetoothDevices.find(d => d.address === address);
    if (!device) return;
    
    const originalHTML = enumerateBtn.innerHTML;
    enumerateBtn.innerHTML = 'Enumerating...';
    enumerateBtn.disabled = true;
    
    if (statusDiv) {
        statusDiv.classList.remove('hidden');
        statusDiv.innerHTML = `
            <div class="bg-blue-600 rounded p-3 text-sm">
                Enumerating services for ${device.name || address}...
            </div>
        `;
    }
    
    try {
        const response = await fetchAPI('/api/bluetooth/enumerate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                address: address
            })
        });
        
        if (response.success && response.services) {
            addConsoleMessage(`Found ${response.services.length} services on ${device.name || address}`, 'success');
            
            if (servicesDiv) {
                if (response.services.length > 0) {
                    servicesDiv.innerHTML = response.services.map(service => `
                        <div class="mb-2 p-2 bg-slate-800 rounded text-sm">
                            <div class="font-medium">${escapeHtml(service.name || 'Unknown Service')}</div>
                            <div class="text-gray-400 text-xs">${service.uuid}</div>
                            ${service.description ? `<div class="text-gray-500 text-xs mt-1">${escapeHtml(service.description)}</div>` : ''}
                        </div>
                    `).join('');
                } else {
                    servicesDiv.innerHTML = '<div class="text-gray-400">No services found</div>';
                }
            }
            
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-green-600 rounded p-3 text-sm">
                        Found ${response.services.length} services
                    </div>
                `;
            }
            
        } else {
            throw new Error(response.error || 'Failed to enumerate services');
        }
    } catch (error) {
        console.error('Error enumerating services:', error);
        addConsoleMessage(`Error enumerating services: ${error.message}`, 'error');
        
        if (statusDiv) {
            statusDiv.innerHTML = `
                <div class="bg-red-600 rounded p-3 text-sm">
                    Error: ${error.message}
                </div>
            `;
        }
    } finally {
        enumerateBtn.disabled = false;
        if (enumerateBtn.innerHTML === 'Enumerating...') {
            enumerateBtn.innerHTML = originalHTML;
        }
    }
}

function clearBluetoothDevices() {
    const devicesList = document.getElementById('bluetooth-devices-list');
    if (devicesList) {
        devicesList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                Start a Bluetooth scan to discover nearby devices
            </div>
        `;
    }
    currentBluetoothDevices = [];
    addConsoleMessage('Cleared Bluetooth device list', 'info');
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
        const currentVulnIp = document.getElementById('vuln-ip-dropdown')?.value || 'all';
        
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
            vulnIpDropdown.innerHTML = '';

            const allOption = document.createElement('option');
            allOption.value = 'all';
            allOption.textContent = 'All Targets';
            if (currentVulnIp === 'all' || !currentVulnIp) {
                allOption.selected = true;
            }
            vulnIpDropdown.appendChild(allOption);

            if (data.targets && data.targets.length > 0) {
                data.targets.forEach(target => {
                    const option = document.createElement('option');
                    option.value = target.ip;
                    option.textContent = `${target.ip} (${target.hostname})`;
                    if (target.ip === currentVulnIp) {
                        option.selected = true;
                    }
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
        const selectedIp = vulnIpDropdown ? vulnIpDropdown.value : 'all';
        const isAllTargets = !selectedIp || selectedIp === 'all';
        const scanLabel = isAllTargets ? 'all targets' : selectedIp;

        addConsoleMessage(`Triggering vulnerability scan for ${scanLabel}...`, 'info');

        const data = await postAPI('/api/manual/scan/vulnerability', { ip: isAllTargets ? 'all' : selectedIp });
        
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

async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, options);
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
                updateDashboardStats(stats);
            })
            .catch(() => {
                // Fallback to WebSocket data if API fails
                updateDashboardStats(data);
            });
    } else {
        // Use WebSocket data if it has non-zero values
        updateDashboardStats(data);
    }

    // Update status - use the actual e-paper display text
    updateElement('Ragnar-status', data.ragnar_status || 'IDLE');
    updateElement('Ragnar-says', (data.ragnar_says || 'Hacking away...'));
    
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
    
    // Update connectivity status with WiFi SSID
    updateConnectivityIndicator('wifi-status', data.wifi_connected, data.current_ssid, data.ap_mode_active);
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

function updateConnectivityIndicator(id, active, ssid = null, apMode = false) {
    const element = document.getElementById(id);
    if (element) {
        if (active) {
            element.className = 'w-3 h-3 bg-green-500 rounded-full pulse-glow';
        } else {
            element.className = 'w-3 h-3 bg-gray-600 rounded-full';
        }
    }
    
    // Update WiFi SSID display if this is the WiFi indicator
    if (id === 'wifi-status') {
        const ssidDisplay = document.getElementById('wifi-ssid-display');
        if (ssidDisplay) {
            if (apMode) {
                ssidDisplay.textContent = ssid ? `AP Mode: ${ssid}` : 'AP Mode';
                ssidDisplay.className = 'text-xs text-blue-400 truncate';
            } else if (active && ssid) {
                ssidDisplay.textContent = ssid;
                ssidDisplay.className = 'text-xs text-gray-400 truncate';
            } else {
                ssidDisplay.textContent = 'Not connected';
                ssidDisplay.className = 'text-xs text-gray-500 truncate';
            }
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
    const tableBody = document.getElementById('network-hosts-table');
    if (!container || !tableBody) {
        return;
    }

    // Save all existing deep scan button states before clearing table
    const existingRows = tableBody.querySelectorAll('tr[data-ip]');
    existingRows.forEach(row => {
        const ip = row.getAttribute('data-ip');
        if (ip) {
            saveDeepScanButtonState(ip);
        }
    });

    tableBody.innerHTML = '';

    const entries = Array.isArray(data) ? data : (data && Array.isArray(data.hosts) ? data.hosts : []);

    if (!entries || entries.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-8 text-gray-400">
                    No network data available. Start a scan to discover hosts.
                </td>
            </tr>
        `;
        updateHostCountDisplay();
        return;
    }

    entries.forEach(item => {
        const normalized = normalizeHostRecord(item);
        if (!normalized) {
            return;
        }

        const row = document.createElement('tr');
        row.setAttribute('data-ip', normalized.ip);
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        row.innerHTML = renderHostRow(normalized);
        tableBody.appendChild(row);
        
        // Restore deep scan button state after adding to DOM
        restoreDeepScanButtonState(normalized.ip);
    });

    updateHostCountDisplay();
    
    // Cleanup old button states for removed hosts
    cleanupOldDeepScanStates();
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
        'General': ['manual_mode', 'debug_mode', 'scan_vuln_running', 'scan_vuln_no_ports', 'enable_attacks', 'blacklistcheck'],
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
            // Check if config has the key, or provide defaults for known boolean settings
            const knownBooleans = ['manual_mode', 'debug_mode', 'scan_vuln_running', 'scan_vuln_no_ports', 'enable_attacks', 'blacklistcheck'];
            let value = config[key];
            
            // If key is missing and it's a known boolean, default to true (except manual_mode)
            if (!config.hasOwnProperty(key) && knownBooleans.includes(key)) {
                value = (key === 'manual_mode') ? false : true;
            }
            
            if (config.hasOwnProperty(key) || knownBooleans.includes(key)) {
                const type = typeof value === 'boolean' ? 'checkbox' : 'text';
                const label = getConfigLabel(key);
                const description = escapeHtml(getConfigDescription(key));
                
                if (type === 'checkbox') {
                    // Determine if this checkbox should be disabled based on dependencies
                    const disabledAttr = (key === 'scan_vuln_no_ports' && !config.scan_vuln_running) ? 'disabled' : '';
                    const disabledClass = disabledAttr ? 'opacity-50 cursor-not-allowed' : '';
                    
                    html += `
                        <label class="flex items-center space-x-3 p-3 rounded-lg hover:bg-slate-700 hover:bg-opacity-50 transition-colors cursor-pointer ${disabledClass}">
                            <input type="checkbox" name="${key}" ${value ? 'checked' : ''} ${disabledAttr}
                                   class="w-5 h-5 rounded bg-slate-700 border-slate-600 text-Ragnar-500 focus:ring-Ragnar-500"
                                   ${key === 'scan_vuln_running' ? 'onchange="handleVulnScanToggle(this)"' : ''}>
                            <span class="flex items-center gap-2">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </span>
                        </label>
                    `;
                } else {
                    html += `
                        <div class="space-y-2">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
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

// Handle vulnerability scanning checkbox toggle to enable/disable dependent options
function handleVulnScanToggle(checkbox) {
    const scanVulnNoPortsCheckbox = document.querySelector('input[name="scan_vuln_no_ports"]');
    const scanVulnNoPortsLabel = scanVulnNoPortsCheckbox ? scanVulnNoPortsCheckbox.closest('label') : null;
    
    if (scanVulnNoPortsCheckbox) {
        scanVulnNoPortsCheckbox.disabled = !checkbox.checked;
        
        if (scanVulnNoPortsLabel) {
            if (checkbox.checked) {
                scanVulnNoPortsLabel.classList.remove('opacity-50', 'cursor-not-allowed');
            } else {
                scanVulnNoPortsLabel.classList.add('opacity-50', 'cursor-not-allowed');
            }
        }
    }
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

// Wi-Fi Management Functions
window.loadWifiInterfaces = loadWifiInterfaces;
window.scanWifiNetworks = scanWifiNetworks;
window.openWifiConnectModal = openWifiConnectModal;
window.closeWifiConnectModal = closeWifiConnectModal;
window.togglePasswordVisibility = togglePasswordVisibility;
window.connectToWifiNetwork = connectToWifiNetwork;

// Bluetooth Management Functions
window.refreshBluetoothStatus = refreshBluetoothStatus;
window.toggleBluetoothPower = toggleBluetoothPower;
window.toggleBluetoothDiscoverable = toggleBluetoothDiscoverable;
window.startBluetoothScan = startBluetoothScan;
window.showBluetoothDeviceDetails = showBluetoothDeviceDetails;
window.closeBluetoothDeviceModal = closeBluetoothDeviceModal;
window.pairBluetoothDevice = pairBluetoothDevice;
window.enumerateBluetoothServices = enumerateBluetoothServices;
window.clearBluetoothDevices = clearBluetoothDevices;

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

// Deep Scan Functions
window.triggerDeepScan = triggerDeepScan;
window.testDeepScan = testDeepScan;

// Debug Functions
window.debugDeepScanStates = function() {
    console.log('Current deep scan button states:', Object.fromEntries(deepScanButtonStates));
};

// Threat Intelligence Functions
window.loadThreatIntelData = loadThreatIntelData;
window.refreshThreatIntel = refreshThreatIntel;
window.enrichTarget = enrichTarget;
window.updateThreatIntelStats = updateThreatIntelStats;
window.toggleHostDetails = toggleHostDetails;
window.showVulnerabilityDetails = showVulnerabilityDetails;
window.closeVulnerabilityModal = closeVulnerabilityModal;

// ===========================================
// THREAT INTELLIGENCE FUNCTIONS
// ===========================================

// Load threat intelligence data when tab is shown
async function loadThreatIntelData() {
    // Only load threat intel data if we're on the threat-intel tab
    if (currentTab !== 'threat-intel') {
        return;
    }
    
    try {
        // Load grouped vulnerabilities
        const response = await fetch('/api/vulnerabilities/grouped');
        if (response.ok) {
            const data = await response.json();
            displayGroupedVulnerabilities(data);
        } else {
            // Fallback to regular vulnerabilities endpoint
            const fallbackResponse = await fetch('/api/vulnerabilities');
            if (fallbackResponse.ok) {
                const vulnData = await fallbackResponse.json();
                displayFallbackVulnerabilities(vulnData);
            }
        }

    } catch (error) {
        console.error('Error loading vulnerability data:', error);
        document.getElementById('grouped-vulnerabilities-container').innerHTML = `
            <div class="glass rounded-lg p-6 text-center">
                <p class="text-red-400">Error loading vulnerabilities</p>
                <p class="text-slate-400 text-sm mt-2">${error.message}</p>
            </div>
        `;
    }
}

// Display grouped vulnerabilities by host
function displayGroupedVulnerabilities(data) {
    const container = document.getElementById('grouped-vulnerabilities-container');
    
    // Update summary cards
    const threatIntelVulnerableHosts = document.getElementById('threat-intel-vulnerable-hosts-count');
    if (threatIntelVulnerableHosts) {
        threatIntelVulnerableHosts.textContent = data.total_hosts || 0;
    }
    document.getElementById('total-vulnerabilities-count').textContent = data.total_vulnerabilities || 0;
    
    // Calculate severity totals
    let criticalTotal = 0, highTotal = 0;
    if (data.grouped_vulnerabilities) {
        data.grouped_vulnerabilities.forEach(host => {
            criticalTotal += host.severity_counts.critical || 0;
            highTotal += host.severity_counts.high || 0;
        });
    }
    document.getElementById('critical-vuln-count').textContent = criticalTotal;
    document.getElementById('high-vuln-count').textContent = highTotal;
    
    if (!data.grouped_vulnerabilities || data.grouped_vulnerabilities.length === 0) {
        container.innerHTML = `
            <div class="glass rounded-lg p-6 text-center">
                <svg class="w-16 h-16 mx-auto mb-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <h3 class="text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
                <p class="text-slate-400">All discovered hosts appear to be secure!</p>
            </div>
        `;
        return;
    }
    
    // Build HTML for each host group
    let html = '';
    data.grouped_vulnerabilities.forEach((hostData, index) => {
        const severityCounts = hostData.severity_counts;
        const vulnCount = hostData.total_vulnerabilities;
        
        // Determine risk level color
        let riskColor = 'blue';
        let riskLabel = 'Low Risk';
        if (severityCounts.critical > 0) {
            riskColor = 'red';
            riskLabel = 'Critical Risk';
        } else if (severityCounts.high > 5) {
            riskColor = 'orange';
            riskLabel = 'High Risk';
        } else if (severityCounts.high > 0) {
            riskColor = 'yellow';
            riskLabel = 'Medium Risk';
        }
        
        html += `
            <div class="glass rounded-lg p-6">
                <!-- Host Header -->
                <div class="flex items-center justify-between mb-4 pb-4 border-b border-slate-700">
                    <div class="flex items-center space-x-4">
                        <div class="bg-${riskColor}-500/20 p-3 rounded-lg">
                            <svg class="w-8 h-8 text-${riskColor}-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path>
                            </svg>
                        </div>
                        <div>
                            <h3 class="text-2xl font-bold text-white">${hostData.ip}</h3>
                            <p class="text-sm text-slate-400">
                                <span class="bg-${riskColor}-500/20 text-${riskColor}-300 px-2 py-1 rounded text-xs font-semibold">${riskLabel}</span>
                                <span class="ml-2">${vulnCount} Vulnerabilities Found</span>
                            </p>
                        </div>
                    </div>
                    <button onclick="toggleHostDetails('host-${index}')" class="bg-Ragnar-600 hover:bg-Ragnar-700 text-white px-4 py-2 rounded-lg transition-colors">
                        <span id="host-${index}-toggle">Show Details</span>
                    </button>
                </div>
                
                <!-- Quick Stats -->
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-red-400 text-2xl font-bold">${severityCounts.critical || 0}</div>
                        <div class="text-xs text-slate-400">Critical</div>
                    </div>
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-orange-400 text-2xl font-bold">${severityCounts.high || 0}</div>
                        <div class="text-xs text-slate-400">High</div>
                    </div>
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-yellow-400 text-2xl font-bold">${severityCounts.medium || 0}</div>
                        <div class="text-xs text-slate-400">Medium</div>
                    </div>
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-blue-400 text-2xl font-bold">${severityCounts.low || 0}</div>
                        <div class="text-xs text-slate-400">Low</div>
                    </div>
                </div>
                
                <!-- Affected Services -->
                <div class="mb-4">
                    <div class="text-sm text-slate-400 mb-2">Affected Services</div>
                    <div class="flex flex-wrap gap-2">
                        ${hostData.affected_services.map(service => 
                            `<span class="bg-slate-700 px-3 py-1 rounded-full text-sm">${service}</span>`
                        ).join('')}
                    </div>
                    <div class="text-sm text-slate-400 mt-2">
                        Ports: ${hostData.affected_ports.join(', ')}
                    </div>
                </div>
                
                <!-- Detailed Vulnerabilities (Initially Hidden) -->
                <div id="host-${index}-details" class="hidden mt-4">
                    <div class="border-t border-slate-700 pt-4">
                        <h4 class="text-lg font-semibold mb-3 text-white">All Vulnerabilities (${vulnCount})</h4>
                        <div class="space-y-2 max-h-96 overflow-y-auto scrollbar-thin">
                            ${hostData.vulnerabilities.map(vuln => {
                                const severityColors = {
                                    'critical': 'red',
                                    'high': 'orange',
                                    'medium': 'yellow',
                                    'low': 'blue'
                                };
                                const color = severityColors[vuln.severity] || 'gray';
                                const vulnText = vuln.vulnerability.length > 100 ? 
                                    vuln.vulnerability.substring(0, 100) + '...' : 
                                    vuln.vulnerability;
                                
                                return `
                                    <div class="bg-slate-800/30 rounded p-3 hover:bg-slate-800/50 transition-colors">
                                        <div class="flex items-start justify-between">
                                            <div class="flex-1">
                                                <div class="flex items-center space-x-2 mb-1">
                                                    <span class="bg-${color}-500/20 text-${color}-300 px-2 py-0.5 rounded text-xs font-semibold uppercase">${vuln.severity}</span>
                                                    <span class="text-slate-400 text-xs">${vuln.service}:${vuln.port}</span>
                                                </div>
                                                <div class="text-sm text-white font-mono">${vulnText}</div>
                                            </div>
                                            <button onclick='showVulnerabilityDetails(${JSON.stringify(vuln).replace(/'/g, "\\'")})' 
                                                    class="ml-2 text-Ragnar-400 hover:text-Ragnar-300 text-xs">
                                                Details
                                            </button>
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Toggle host details visibility
function toggleHostDetails(hostId) {
    const detailsDiv = document.getElementById(`${hostId}-details`);
    const toggleBtn = document.getElementById(`${hostId}-toggle`);
    
    if (detailsDiv.classList.contains('hidden')) {
        detailsDiv.classList.remove('hidden');
        toggleBtn.textContent = 'Hide Details';
    } else {
        detailsDiv.classList.add('hidden');
        toggleBtn.textContent = 'Show Details';
    }
}

// Show vulnerability details modal
function showVulnerabilityDetails(vuln) {
    const modal = document.getElementById('vulnerability-detail-modal');
    const content = document.getElementById('vuln-detail-content');
    
    const severityColors = {
        'critical': 'text-red-400',
        'high': 'text-orange-400',
        'medium': 'text-yellow-400',
        'low': 'text-blue-400'
    };
    
    // Extract CVE IDs from vulnerability text and create links
    function formatVulnerabilityWithLinks(vulnText) {
        // Match CVE patterns (CVE-YYYY-NNNNN)
        const cvePattern = /(CVE-\d{4}-\d{4,7})/gi;
        const cves = vulnText.match(cvePattern);
        
        if (!cves || cves.length === 0) {
            return `<div class="text-white font-mono text-sm break-all">${vulnText}</div>`;
        }
        
        // Create links section
        let linksHtml = '<div class="mt-3 pt-3 border-t border-slate-700">';
        linksHtml += '<div class="text-sm text-slate-400 mb-2">CVE References:</div>';
        linksHtml += '<div class="flex flex-wrap gap-2">';
        
        const uniqueCVEs = [...new Set(cves)]; // Remove duplicates
        uniqueCVEs.forEach(cve => {
            const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cve}`;
            const mitreUrl = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`;
            
            linksHtml += `
                <div class="bg-slate-700/50 rounded px-3 py-2 flex items-center space-x-2">
                    <span class="text-Ragnar-400 font-mono text-sm">${cve}</span>
                    <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" 
                       class="text-blue-400 hover:text-blue-300 transition-colors" 
                       title="View on NIST NVD">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                  d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                        </svg>
                    </a>
                    <a href="${mitreUrl}" target="_blank" rel="noopener noreferrer" 
                       class="text-green-400 hover:text-green-300 transition-colors" 
                       title="View on MITRE">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                    </a>
                </div>
            `;
        });
        
        linksHtml += '</div></div>';
        
        return `<div class="text-white font-mono text-sm break-all">${vulnText}</div>${linksHtml}`;
    }
    
    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Severity</div>
                <div class="${severityColors[vuln.severity]} text-2xl font-bold uppercase">${vuln.severity}</div>
            </div>
            
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Vulnerability</div>
                ${formatVulnerabilityWithLinks(vuln.vulnerability)}
            </div>
            
            <div class="grid grid-cols-2 gap-4">
                <div class="bg-slate-800/50 rounded-lg p-4">
                    <div class="text-sm text-slate-400 mb-1">Service</div>
                    <div class="text-white">${vuln.service}</div>
                </div>
                <div class="bg-slate-800/50 rounded-lg p-4">
                    <div class="text-sm text-slate-400 mb-1">Port</div>
                    <div class="text-white">${vuln.port}</div>
                </div>
            </div>
            
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Discovered</div>
                <div class="text-white">${new Date(vuln.discovered).toLocaleString()}</div>
            </div>
            
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Status</div>
                <div class="text-white capitalize">${vuln.status}</div>
            </div>
        </div>
    `;
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

// Close vulnerability modal
function closeVulnerabilityModal() {
    const modal = document.getElementById('vulnerability-detail-modal');
    modal.classList.add('hidden');
    modal.classList.remove('flex');
}

// Fallback display for regular vulnerabilities
function displayFallbackVulnerabilities(data) {
    // Group vulnerabilities by IP manually if grouped endpoint not available
    const grouped = {};
    if (data.vulnerabilities) {
        data.vulnerabilities.forEach(vuln => {
            if (!grouped[vuln.host]) {
                grouped[vuln.host] = {
                    ip: vuln.host,
                    total_vulnerabilities: 0,
                    severity_counts: { critical: 0, high: 0, medium: 0, low: 0 },
                    affected_ports: new Set(),
                    affected_services: new Set(),
                    vulnerabilities: []
                };
            }
            grouped[vuln.host].total_vulnerabilities++;
            grouped[vuln.host].severity_counts[vuln.severity]++;
            grouped[vuln.host].affected_ports.add(vuln.port);
            grouped[vuln.host].affected_services.add(vuln.service);
            grouped[vuln.host].vulnerabilities.push(vuln);
        });
    }
    
    // Convert to array and format
    const groupedArray = Object.values(grouped).map(host => ({
        ...host,
        affected_ports: Array.from(host.affected_ports),
        affected_services: Array.from(host.affected_services)
    }));
    
    displayGroupedVulnerabilities({
        total_hosts: groupedArray.length,
        total_vulnerabilities: data.vulnerabilities?.length || 0,
        grouped_vulnerabilities: groupedArray
    });
}

// Trigger manual vulnerability scan
async function triggerManualVulnScan() {
    try {
        addConsoleMessage('Starting vulnerability scan on all discovered hosts...', 'info');
        const response = await fetchAPI('/api/threat-intelligence/trigger-vuln-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: 'all'
            })
        });
        
        if (response.action === 'vulnerability_scan_triggered') {
            addConsoleMessage(`✅ ${response.message}`, 'success');
            addConsoleMessage(`📋 Scanning ${response.discovered_hosts} discovered hosts`, 'info');
            
            // Show detailed next steps
            if (response.next_steps) {
                response.next_steps.forEach(step => {
                    addConsoleMessage(`   • ${step}`, 'info');
                });
            }
            
            showNotification(`Vulnerability scan started on ${response.discovered_hosts} hosts. Check back in a few minutes!`, 'success');
            
            // Refresh threat intel data in 30 seconds to check for results
            setTimeout(() => {
                if (currentTab === 'threat-intel') {
                    loadThreatIntelData();
                    addConsoleMessage('🔄 Checking for new threat intelligence findings...', 'info');
                }
            }, 30000);
            
            // And again in 2 minutes
            setTimeout(() => {
                if (currentTab === 'threat-intel') {
                    loadThreatIntelData();
                    addConsoleMessage('🔍 Final check for vulnerability scan results...', 'info');
                }
            }, 120000);
        } else {
            addConsoleMessage('❌ Failed to start vulnerability scan', 'error');
            showNotification('Failed to start vulnerability scan', 'error');
        }
    } catch (error) {
        console.error('Error triggering vulnerability scan:', error);
        addConsoleMessage('❌ Error starting vulnerability scan: ' + error.message, 'error');
        showNotification('Error starting vulnerability scan', 'error');
    }
}

// Refresh threat intelligence data
function refreshThreatIntel() {
    showNotification('Refreshing threat intelligence...', 'info');
    if (currentTab === 'threat-intel') {
        loadThreatIntelData();
    }
}

// Update threat intelligence statistics
function updateThreatIntelStats(data) {
    // Update summary cards
    document.getElementById('threat-sources-count').textContent = data.active_sources || 0;
    document.getElementById('enriched-findings-count').textContent = data.enriched_findings_count || 0;
    document.getElementById('high-risk-count').textContent = data.high_risk_count || 0;
    document.getElementById('active-campaigns-count').textContent = data.active_campaigns || 0;

    // Update risk distribution
    const riskDistribution = data.risk_distribution || {};
    document.getElementById('critical-risk-count').textContent = riskDistribution.critical || 0;
    document.getElementById('high-risk-detail-count').textContent = riskDistribution.high || 0;
    document.getElementById('medium-risk-count').textContent = riskDistribution.medium || 0;
    document.getElementById('low-risk-count').textContent = riskDistribution.low || 0;

    // Update source status indicators
    const sources = data.source_status || {};
    updateSourceStatus('cisa-status', sources.cisa_kev || false);
    updateSourceStatus('nvd-status', sources.nvd_cve || false);
    updateSourceStatus('otx-status', sources.alienvault_otx || false);
    updateSourceStatus('mitre-status', sources.mitre_attack || false);

    updateTopThreatsList(data.top_threats || [], data.last_update || data.last_intelligence_update || null);
}

// Update source status indicator
function updateSourceStatus(elementId, isActive) {
    const element = document.getElementById(elementId);
    if (element) {
        element.className = `w-3 h-3 rounded-full ${isActive ? 'bg-green-400' : 'bg-red-400'}`;
    }
}

// Update enriched findings table
function updateEnrichedFindingsTable(findings) {
    const tableBody = document.getElementById('enriched-findings-table');

    if (!findings || findings.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-12 text-slate-400">
                    <div class="space-y-4">
                        <div class="text-xl">🛡️ No Threat Intelligence Findings</div>
                        <div class="text-sm max-w-md mx-auto space-y-2">
                            <p>Threat intelligence enrichment requires vulnerability discoveries first.</p>
                            <p class="text-cyan-400">📋 Steps to generate threat intelligence:</p>
                            <ol class="text-left text-xs space-y-1 mt-2">
                                <li>1. Wait for network discovery to complete (${document.getElementById('target-count')?.textContent || '0'} hosts found)</li>
                                <li>2. Run vulnerability scans on discovered hosts</li>
                                <li>3. Threat intelligence will enrich discovered vulnerabilities</li>
                            </ol>
                            <div class="mt-4">
                                <button onclick="triggerManualVulnScan()" class="bg-cyan-600 hover:bg-cyan-700 px-4 py-2 rounded text-sm transition-colors">
                                    🚀 Start Vulnerability Scan
                                </button>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = findings.map(finding => `
        <tr class="border-b border-slate-700 hover:bg-slate-700/50">
            <td class="py-3 px-4 text-white font-mono">${escapeHtml(finding.target)}</td>
            <td class="py-3 px-4">
                <span class="px-2 py-1 rounded text-xs font-medium ${getRiskScoreClass(finding.risk_score)}">
                    ${finding.risk_score}/100
                </span>
            </td>
            <td class="py-3 px-4 text-slate-300 max-w-xs truncate" title="${escapeHtml(finding.threat_context || 'N/A')}">
                ${escapeHtml(finding.threat_context || 'N/A')}
            </td>
            <td class="py-3 px-4 text-slate-300">${escapeHtml(finding.attribution || 'Unknown')}</td>
            <td class="py-3 px-4 text-slate-400">${formatTimestamp(finding.last_updated)}</td>
            <td class="py-3 px-4">
                <button onclick="downloadThreatReport('${finding.target}')" 
                        class="text-blue-400 hover:text-blue-300 text-sm">
                    Report
                </button>
            </td>
        </tr>
    `).join('');
}

// Update top threats list
function updateTopThreatsList(threats, lastUpdated) {
    const listElement = document.getElementById('top-threats-list');
    const updatedElement = document.getElementById('top-threats-updated');

    if (!listElement) {
        return;
    }

    if (updatedElement) {
        updatedElement.textContent = `Last updated: ${lastUpdated ? formatTimestamp(lastUpdated) : 'N/A'}`;
    }

    if (!threats || threats.length === 0) {
        listElement.innerHTML = `
            <li class="text-slate-400 text-center py-4">
                <div class="space-y-2">
                    <div>🛡️ No active threats detected</div>
                    <div class="text-xs">Threat intelligence will appear here when vulnerabilities are discovered and enriched</div>
                </div>
            </li>
        `;
        return;
    }

    listElement.innerHTML = threats.slice(0, 5).map(threat => `
        <li class="bg-slate-800/60 rounded-lg p-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div class="space-y-1">
                <p class="text-white font-semibold">${escapeHtml(threat.target || 'Unknown Target')}</p>
                <p class="text-slate-400 text-sm">${escapeHtml(threat.summary || 'No summary available')}</p>
                <div class="text-xs text-slate-500 space-x-3">
                    <span>Last Seen: ${formatTimestamp(threat.last_seen)}</span>
                    ${threat.attribution ? `<span>Attributed to: ${escapeHtml(threat.attribution)}</span>` : ''}
                </div>
            </div>
            <span class="self-start sm:self-center px-2 py-1 rounded text-xs font-semibold ${getRiskScoreClass(threat.risk_score)}">
                ${threat.risk_score}/100
            </span>
        </li>
    `).join('');
}

// Get risk score CSS class
function getRiskScoreClass(score) {
    if (score >= 90) return 'bg-red-600 text-white';
    if (score >= 70) return 'bg-orange-600 text-white';
    if (score >= 50) return 'bg-yellow-600 text-black';
    return 'bg-green-600 text-white';
}

// Manual target enrichment
async function enrichTarget() {
    const targetInput = document.getElementById('enrichment-target');
    const target = targetInput.value.trim();
    
    if (!target) {
        showNotification('Please enter a target (IP, domain, or hash)', 'error');
        return;
    }

    try {
        showNotification(`Enriching target: ${target}...`, 'info');
        
        const response = await fetch('/api/threat-intelligence/enrich-target', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        });

        if (response.ok) {
            const result = await response.json();
            showNotification(`Target enriched successfully. Risk score: ${result.risk_score}/100`, 'success');
            targetInput.value = '';
            if (currentTab === 'threat-intel') {
                loadThreatIntelData(); // Refresh the data
            }
        } else {
            const error = await response.json();
            showNotification(`Enrichment failed: ${error.error}`, 'error');
        }
    } catch (error) {
        console.error('Error enriching target:', error);
        showNotification('Error enriching target', 'error');
    }
}

// Download threat intelligence report
async function downloadThreatReport(target) {
    try {
        showNotification(`Analyzing ${target} for threat intelligence...`, 'info');
        
        const response = await fetch('/api/threat-intelligence/download-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            
            // Generate filename with current date
            const now = new Date();
            const dateStr = now.toISOString().slice(0, 19).replace(/:/g, '-');
            a.download = `Threat_Intelligence_Report_${target.replace(/[^a-zA-Z0-9.-]/g, '_')}_${dateStr}.txt`;
            
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showNotification(`Threat intelligence report downloaded for ${target}`, 'success');
        } else {
            const error = await response.json();
            if (error.target_type === 'no_findings') {
                showNotification(`No vulnerability findings detected for ${target} - run network scans first to discover vulnerabilities for threat intelligence enrichment`, 'warning');
            } else {
                showNotification(`Failed to generate report: ${error.error}`, 'error');
            }
        }
    } catch (error) {
        console.error('Error downloading threat report:', error);
        showNotification('Error downloading threat intelligence report', 'error');
    }
}

// Format timestamp for display
function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (error) {
        return 'Invalid date';
    }
}

// HTML escape utility
function escapeHtml(text) {
    if (typeof text !== 'string') return text;
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}