#!/bin/bash
# Deploy Lightweight Mode - Immediate Memory Reduction for Pi Zero W2
# This script applies emergency memory optimizations

set -e

echo "=========================================="
echo "  Ragnar Lightweight Mode Deployment"
echo "  Pi Zero W2 Memory Optimization"
echo "=========================================="
echo ""

# Check if running on Pi
if [ ! -f /proc/device-tree/model ]; then
    echo "Warning: Not running on Raspberry Pi"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Find Ragnar directory
RAGNAR_DIR="/home/pi/Ragnar"
if [ ! -d "$RAGNAR_DIR" ]; then
    RAGNAR_DIR="$(pwd)"
fi

echo "Ragnar directory: $RAGNAR_DIR"
echo ""

# Backup current config
echo "1. Backing up current configuration..."
if [ -f "$RAGNAR_DIR/config/shared_config.json" ]; then
    cp "$RAGNAR_DIR/config/shared_config.json" "$RAGNAR_DIR/config/shared_config.backup.$(date +%Y%m%d_%H%M%S).json"
    echo "   ✓ Backup created"
else
    echo "   ! No existing config found"
fi

# Apply lightweight config
echo ""
echo "2. Applying lightweight configuration..."
if [ -f "$RAGNAR_DIR/config/shared_config_lightweight.json" ]; then
    cp "$RAGNAR_DIR/config/shared_config_lightweight.json" "$RAGNAR_DIR/config/shared_config.json"
    echo "   ✓ Lightweight config applied"
else
    echo "   ✗ Lightweight config not found!"
    echo "   Creating minimal config..."
    cat > "$RAGNAR_DIR/config/shared_config.json" << 'EOF'
{
  "ai_enabled": false,
  "ai_target_evaluation_enabled": false,
  "websrv": false,
  "displaying_csv": false,
  "enable_attacks": true,
  "scan_vuln_running": true,
  "scan_interval": 300,
  "scan_vuln_interval": 1800
}
EOF
    echo "   ✓ Minimal config created"
fi

# Show current memory
echo ""
echo "3. Current memory status:"
free -h | head -2
echo ""

# Restart service
echo "4. Restarting Ragnar service..."
if systemctl is-active --quiet ragnar; then
    sudo systemctl restart ragnar
    echo "   ✓ Service restarted"
else
    echo "   ! Service not running, starting..."
    sudo systemctl start ragnar
fi

# Wait for startup
echo ""
echo "5. Waiting for service to stabilize (30 seconds)..."
sleep 30

# Check new memory usage
echo ""
echo "6. New memory status:"
free -h | head -2
echo ""

# Show Ragnar process
echo "7. Ragnar process memory:"
ps aux | grep -E "python.*[Rr]agnar" | grep -v grep | awk '{printf "   PID: %s, MEM: %s%%, CMD: %s\n", $2, $4, $11}'
echo ""

# Service status
echo "8. Service status:"
systemctl status ragnar --no-pager -l | head -15
echo ""

echo "=========================================="
echo "  Lightweight Mode Deployment Complete"
echo "=========================================="
echo ""
echo "Disabled features to save memory:"
echo "  - AI/GPT features (~60-80MB saved)"
echo "  - Web server (~40-50MB saved)"
echo "  - Display updates (~20-30MB saved)"
echo ""
echo "Expected memory reduction: 120-160MB"
echo "Target: 40-50% idle (was 70%)"
echo ""
echo "To monitor: ./monitor_memory.sh"
echo "To restore: cp config/shared_config.backup.*.json config/shared_config.json"
echo ""
