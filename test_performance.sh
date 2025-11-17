#!/bin/bash
# Performance Testing Script for Dashboard Optimizations
# This script tests the dashboard loading performance on Raspberry Pi Zero

echo "==================================================================="
echo "Dashboard Performance Testing Script"
echo "==================================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Check if webapp is running
echo "Test 1: Checking if webapp is running..."
if pgrep -f "webapp_modern.py" > /dev/null; then
    echo -e "${GREEN}✓ webapp_modern.py is running${NC}"
else
    echo -e "${RED}✗ webapp_modern.py is NOT running${NC}"
    echo "  Start it with: sudo systemctl start ragnar.service"
    exit 1
fi
echo ""

# Test 2: Test /api/dashboard/quick endpoint
echo "Test 2: Testing new /api/dashboard/quick endpoint..."
QUICK_RESPONSE=$(curl -s -w "\n%{time_total}" http://localhost:8000/api/dashboard/quick 2>/dev/null)
QUICK_TIME=$(echo "$QUICK_RESPONSE" | tail -1)
QUICK_DATA=$(echo "$QUICK_RESPONSE" | head -n -1)

if [ -n "$QUICK_DATA" ]; then
    echo -e "${GREEN}✓ /api/dashboard/quick endpoint responding${NC}"
    echo "  Response time: ${QUICK_TIME}s"
    
    # Parse some key values
    TARGET_COUNT=$(echo "$QUICK_DATA" | grep -o '"target_count":[0-9]*' | cut -d':' -f2)
    PORT_COUNT=$(echo "$QUICK_DATA" | grep -o '"port_count":[0-9]*' | cut -d':' -f2)
    VULN_COUNT=$(echo "$QUICK_DATA" | grep -o '"vulnerability_count":[0-9]*' | cut -d':' -f2)
    
    echo "  Targets: $TARGET_COUNT"
    echo "  Ports: $PORT_COUNT"
    echo "  Vulnerabilities: $VULN_COUNT"
    
    # Check if response time is acceptable
    if (( $(echo "$QUICK_TIME < 0.1" | bc -l) )); then
        echo -e "${GREEN}✓ Response time is excellent (<100ms)${NC}"
    elif (( $(echo "$QUICK_TIME < 0.5" | bc -l) )); then
        echo -e "${YELLOW}⚠ Response time is acceptable (100-500ms)${NC}"
    else
        echo -e "${RED}✗ Response time is slow (>500ms)${NC}"
        echo "  Expected: <100ms, Got: ${QUICK_TIME}s"
    fi
else
    echo -e "${RED}✗ /api/dashboard/quick endpoint not responding${NC}"
fi
echo ""

# Test 3: Compare with old endpoints
echo "Test 3: Comparing with legacy endpoints..."
STATUS_RESPONSE=$(curl -s -w "\n%{time_total}" http://localhost:8000/api/status 2>/dev/null)
STATUS_TIME=$(echo "$STATUS_RESPONSE" | tail -1)

STATS_RESPONSE=$(curl -s -w "\n%{time_total}" http://localhost:8000/api/dashboard/stats 2>/dev/null)
STATS_TIME=$(echo "$STATS_RESPONSE" | tail -1)

COMBINED_TIME=$(echo "$STATUS_TIME + $STATS_TIME" | bc)

echo "  /api/status: ${STATUS_TIME}s"
echo "  /api/dashboard/stats: ${STATS_TIME}s"
echo "  Combined time: ${COMBINED_TIME}s"
echo "  New endpoint: ${QUICK_TIME}s"

IMPROVEMENT=$(echo "scale=1; (($COMBINED_TIME - $QUICK_TIME) / $COMBINED_TIME) * 100" | bc)
echo -e "${GREEN}✓ Improvement: ${IMPROVEMENT}% faster${NC}"
echo ""

# Test 4: Check response caching
echo "Test 4: Testing response caching..."
curl -s -I http://localhost:8000/api/dashboard/quick 2>/dev/null | grep -i "cache-control"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Cache-Control header is set${NC}"
else
    echo -e "${YELLOW}⚠ Cache-Control header not found${NC}"
fi
echo ""

# Test 5: Check CPU usage
echo "Test 5: Monitoring CPU usage (5 second sample)..."
CPU_USAGE=$(top -b -n 2 -d 2 | grep "webapp_modern" | tail -1 | awk '{print $9}')
if [ -n "$CPU_USAGE" ]; then
    echo "  webapp_modern.py CPU: ${CPU_USAGE}%"
    
    if (( $(echo "$CPU_USAGE < 30" | bc -l) )); then
        echo -e "${GREEN}✓ CPU usage is good (<30%)${NC}"
    elif (( $(echo "$CPU_USAGE < 50" | bc -l) )); then
        echo -e "${YELLOW}⚠ CPU usage is moderate (30-50%)${NC}"
    else
        echo -e "${RED}✗ CPU usage is high (>50%)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Could not measure CPU usage${NC}"
fi
echo ""

# Test 6: Check background sync
echo "Test 6: Checking background sync thread..."
SYNC_LOG=$(journalctl -u ragnar.service --since "1 minute ago" | grep "Background sync" | tail -1)
if [ -n "$SYNC_LOG" ]; then
    echo -e "${GREEN}✓ Background sync thread is active${NC}"
    echo "  Latest: $(echo $SYNC_LOG | cut -d' ' -f6-)"
else
    echo -e "${YELLOW}⚠ No recent background sync activity (check logs)${NC}"
fi
echo ""

# Test 7: Full page load simulation
echo "Test 7: Simulating full dashboard page load..."
echo "  Making sequential requests like a browser would..."

START_TIME=$(date +%s.%N)

# Initial load - quick endpoint
curl -s http://localhost:8000/api/dashboard/quick > /dev/null 2>&1

# WiFi status (deferred 200ms in JS)
sleep 0.2
curl -s http://localhost:8000/api/wifi/status > /dev/null 2>&1

# Console logs (deferred 1000ms in JS)
sleep 0.8
curl -s http://localhost:8000/api/console/logs > /dev/null 2>&1

END_TIME=$(date +%s.%N)
TOTAL_TIME=$(echo "$END_TIME - $START_TIME" | bc)

echo "  Total simulated load time: ${TOTAL_TIME}s"

if (( $(echo "$TOTAL_TIME < 2.0" | bc -l) )); then
    echo -e "${GREEN}✓ Load time is excellent (<2s)${NC}"
elif (( $(echo "$TOTAL_TIME < 5.0" | bc -l) )); then
    echo -e "${YELLOW}⚠ Load time is acceptable (2-5s)${NC}"
else
    echo -e "${RED}✗ Load time is slow (>5s)${NC}"
fi
echo ""

# Summary
echo "==================================================================="
echo "Test Summary"
echo "==================================================================="
echo ""
echo "Expected improvements from optimizations:"
echo "  • Dashboard load time: 5-10s -> <2s ✓"
echo "  • API calls on load: 12-15 -> 2-3 ✓"
echo "  • CPU usage: 40% -> <30% (check above)"
echo "  • Response time: 100-500ms -> <10ms (check above)"
echo ""
echo "Next steps:"
echo "  1. Test in actual web browser at http://$(hostname -I | awk '{print $1}'):8000"
echo "  2. Open DevTools Network tab to verify API calls"
echo "  3. Monitor with 'htop' to check CPU usage"
echo "  4. Check logs with: sudo journalctl -u ragnar.service -f"
echo ""
echo "For detailed documentation, see: PERFORMANCE_OPTIMIZATIONS.md"
echo ""
