#!/bin/bash

# ragnar Web Interface Fix and Test Script
# This script fixes all issues with the modern web interface and ensures it works properly

echo "🔧 ragnar Web Interface - Complete Fix & Test"
echo "=============================================="

# Function to check if service is running
check_service() {
    if systemctl is-active --quiet ragnar; then
        echo "✅ ragnar service is running"
        return 0
    else
        echo "❌ ragnar service is not running"
        return 1
    fi
}

# Function to check if modern interface is working
test_modern_interface() {
    local host="localhost"
    local port="8000"
    
    echo "🧪 Testing modern web interface..."
    
    # Test main page
    if curl -s -f "http://${host}:${port}/" > /dev/null; then
        echo "✅ Main page accessible"
    else
        echo "❌ Main page not accessible"
        return 1
    fi
    
    # Test API endpoints
    endpoints=("/api/status" "/api/config" "/api/network" "/api/credentials" "/api/loot")
    
    for endpoint in "${endpoints[@]}"; do
        if curl -s -f "http://${host}:${port}${endpoint}" > /dev/null; then
            echo "✅ API endpoint ${endpoint} working"
        else
            echo "❌ API endpoint ${endpoint} failed"
        fi
    done
    
    # Test static files
    static_files=("/web/scripts/ragnar_modern.js" "/web/images/favicon.ico")
    
    for file in "${static_files[@]}"; do
        if curl -s -f "http://${host}:${port}${file}" > /dev/null; then
            echo "✅ Static file ${file} accessible"
        else
            echo "❌ Static file ${file} not accessible"
        fi
    done
}

# Function to fix file permissions
fix_permissions() {
    echo "🔐 Fixing file permissions..."
    
    # Make scripts executable
    chmod +x /home/ragnar/ragnar/*.sh
    
    # Fix web directory permissions
    chmod -R 644 /home/ragnar/ragnar/web/
    chmod 755 /home/ragnar/ragnar/web/
    find /home/ragnar/ragnar/web/ -type d -exec chmod 755 {} \;
    
    # Fix Python file permissions
    chmod 644 /home/ragnar/ragnar/*.py
    chmod 644 /home/ragnar/ragnar/web/scripts/*.js
    
    echo "✅ File permissions fixed"
}

# Function to validate required files
validate_files() {
    echo "📁 Validating required files..."
    
    required_files=(
        "/home/ragnar/ragnar/webapp_modern.py"
        "/home/ragnar/ragnar/web/index_modern.html"
        "/home/ragnar/ragnar/web/scripts/ragnar_modern.js"
        "/home/ragnar/ragnar/config/actions.json"
    )
    
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            echo "✅ $file exists"
        else
            echo "❌ $file missing"
            return 1
        fi
    done
}

# Function to check ragnar.py configuration
check_ragnar_config() {
    echo "⚙️ Checking ragnar.py configuration..."
    
    local ragnar_file="/home/ragnar/ragnar/ragnar.py"
    
    if grep -q "from webapp_modern import run_server" "$ragnar_file"; then
        echo "✅ ragnar.py configured for modern webapp"
    else
        echo "🔄 Configuring ragnar.py for modern webapp..."
        
        # Create backup
        cp "$ragnar_file" "${ragnar_file}.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Update imports and threading
        sed -i 's/from webapp import web_thread/from webapp_modern import run_server/' "$ragnar_file"
        sed -i 's/web_thread = threading.Thread(target=web_thread)/web_thread = threading.Thread(target=run_server)/' "$ragnar_file"
        
        echo "✅ ragnar.py updated for modern webapp"
    fi
}

# Function to test API responses
test_api_responses() {
    echo "🌐 Testing API responses..."
    
    local host="localhost"
    local port="8000"
    
    # Test status endpoint
    local status_response=$(curl -s "http://${host}:${port}/api/status")
    if echo "$status_response" | jq . > /dev/null 2>&1; then
        echo "✅ Status API returns valid JSON"
    else
        echo "❌ Status API response invalid"
    fi
    
    # Test config endpoint
    local config_response=$(curl -s "http://${host}:${port}/api/config")
    if echo "$config_response" | jq . > /dev/null 2>&1; then
        echo "✅ Config API returns valid JSON"
    else
        echo "❌ Config API response invalid"
    fi
}

# Function to show final status
show_final_status() {
    echo ""
    echo "🎯 Final Status Report"
    echo "====================="
    
    if check_service; then
        echo "✅ Service Status: RUNNING"
        
        local ip=$(hostname -I | awk '{print $1}')
        echo "🌐 Web Interface: http://${ip}:8000"
        echo "🌐 Local Access: http://localhost:8000"
        
        # Show last few log entries
        echo ""
        echo "📋 Recent Logs:"
        sudo journalctl -u ragnar --no-pager -n 5
        
    else
        echo "❌ Service Status: NOT RUNNING"
        echo "To start: sudo systemctl start ragnar"
    fi
}

# Main execution
echo "Starting comprehensive fix and test..."
echo ""

# Step 1: Validate files
if ! validate_files; then
    echo "❌ Required files missing. Please check installation."
    exit 1
fi

# Step 2: Fix permissions
fix_permissions

# Step 3: Check and fix ragnar.py configuration
check_ragnar_config

# Step 4: Restart service to apply changes
echo "🔄 Restarting ragnar service..."
sudo systemctl restart ragnar

# Wait for service to start
echo "⏳ Waiting for service to start..."
sleep 5

# Step 5: Check service status
if check_service; then
    echo "✅ Service restarted successfully"
    
    # Wait a bit more for web server to initialize
    sleep 3
    
    # Step 6: Test modern interface
    test_modern_interface
    
    # Step 7: Test API responses (if jq is available)
    if command -v jq > /dev/null; then
        test_api_responses
    else
        echo "ℹ️ jq not installed, skipping detailed API tests"
    fi
    
else
    echo "❌ Service failed to start. Check logs:"
    sudo journalctl -u ragnar --no-pager -n 10
fi

# Step 8: Show final status
show_final_status

echo ""
echo "🏁 Fix and test complete!"
echo ""
echo "If everything is working:"
echo "- Dashboard: Real-time status updates"
echo "- Network: Live scan results"
echo "- Credentials: Discovered login pairs" 
echo "- Loot: Stolen data files"
echo "- Config: Live configuration editing"
echo ""
echo "Use 'sudo journalctl -u ragnar -f' to monitor logs in real-time"
