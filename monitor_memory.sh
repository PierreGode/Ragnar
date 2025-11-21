#!/bin/bash
# Ragnar Memory Monitor - Watch for OOM kills and memory usage
# Usage: ./monitor_memory.sh

echo "=========================================="
echo "  Ragnar Memory Monitoring Tool"
echo "  Pi Zero W2 OOM Kill Prevention"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Warning: Not running as root. Some checks may be limited.${NC}"
    echo ""
fi

# Function to check memory percentage
check_memory() {
    mem_percent=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100)}')
    mem_mb=$(free -m | grep Mem | awk '{print $3 "/" $2 " MB"}')
    
    if [ "$mem_percent" -gt 85 ]; then
        echo -e "${RED}🚨 CRITICAL: Memory at ${mem_percent}% (${mem_mb})${NC}"
    elif [ "$mem_percent" -gt 70 ]; then
        echo -e "${YELLOW}⚠️  WARNING: Memory at ${mem_percent}% (${mem_mb})${NC}"
    else
        echo -e "${GREEN}✅ OK: Memory at ${mem_percent}% (${mem_mb})${NC}"
    fi
}

# Function to check for recent OOM kills
check_oom_kills() {
    echo ""
    echo "Checking for OOM kills in last 24 hours..."
    oom_count=$(journalctl --since "24 hours ago" 2>/dev/null | grep -c "killed process" || echo "0")
    # Remove any whitespace/newlines that might cause integer comparison issues
    oom_count=$(echo "$oom_count" | tr -d '[:space:]')
    
    if [ "$oom_count" -gt 0 ] 2>/dev/null; then
        echo -e "${RED}💥 Found ${oom_count} OOM kill(s) in last 24h${NC}"
        echo "Recent OOM kills:"
        journalctl --since "24 hours ago" 2>/dev/null | grep "killed process" | tail -5
    else
        echo -e "${GREEN}✅ No OOM kills in last 24 hours${NC}"
    fi
}

# Function to check Ragnar service status
check_service() {
    echo ""
    echo "Ragnar Service Status:"
    if systemctl is-active --quiet ragnar; then
        uptime=$(systemctl show ragnar -p ActiveEnterTimestamp --value)
        echo -e "${GREEN}✅ Running since: $uptime${NC}"
    else
        echo -e "${RED}❌ Ragnar service is NOT running${NC}"
        echo "Last failure reason:"
        systemctl status ragnar | tail -10
    fi
}

# Function to check recent systemd kills
check_systemd_kills() {
    echo ""
    echo "Checking for systemd SIGKILL signals..."
    sigkill_count=$(journalctl -u ragnar --since "24 hours ago" | grep -c "code=killed, status=9" 2>/dev/null || echo "0")
    
    if [ "$sigkill_count" -gt 0 ]; then
        echo -e "${RED}💥 Found ${sigkill_count} SIGKILL(s) by systemd in last 24h${NC}"
        echo "Recent kills:"
        journalctl -u ragnar --since "24 hours ago" | grep "code=killed, status=9" | tail -5
    else
        echo -e "${GREEN}✅ No systemd kills in last 24 hours${NC}"
    fi
}

# Function to show current Ragnar processes
check_ragnar_processes() {
    echo ""
    echo "Ragnar Process Memory Usage:"
    ps aux | grep -E "python.*[Rr]agnar|[Rr]agnar.py" | grep -v grep | awk '{printf "  PID %-6s MEM %5s%%  CMD: %s\n", $2, $4, $11}'
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}⚠️  No Ragnar processes found${NC}"
    fi
}

# Main monitoring loop
echo "Starting continuous monitoring (Ctrl+C to stop)..."
echo ""

counter=0
while true; do
    clear
    echo "=========================================="
    echo "  Ragnar Memory Monitor - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
    
    # Memory status
    check_memory
    
    # Process info
    check_ragnar_processes
    
    # Every 10th iteration (30 seconds), check for kills
    if [ $((counter % 10)) -eq 0 ]; then
        check_oom_kills
        check_systemd_kills
        check_service
    fi
    
    echo ""
    echo "----------------------------------------"
    echo "Refreshing in 3 seconds... (Ctrl+C to stop)"
    echo "For detailed logs: journalctl -u ragnar -f"
    
    counter=$((counter + 1))
    sleep 3
done
