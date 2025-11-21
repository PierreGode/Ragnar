#!/bin/bash
# Memory Profiler - Find what's eating RAM on Pi Zero W2
# Run this on the Pi to see memory breakdown

echo "=========================================="
echo "  Pi Zero W2 Memory Analysis"
echo "=========================================="
echo ""

echo "Total System Memory:"
free -h
echo ""

echo "=========================================="
echo "Top Memory Consumers:"
echo "=========================================="
ps aux --sort=-%mem | head -20
echo ""

echo "=========================================="
echo "Python Process Details:"
echo "=========================================="
ps aux | grep python | grep -v grep
echo ""

echo "=========================================="
echo "Memory by Process Name:"
echo "=========================================="
ps aux | awk '{print $11, $4}' | sort | uniq -c | sort -rn | head -15
echo ""

echo "=========================================="
echo "Ragnar-specific processes:"
echo "=========================================="
pgrep -a python | grep -i ragnar
echo ""

echo "=========================================="
echo "Python modules loaded (if available):"
echo "=========================================="
python3 -c "import sys; print('\n'.join(sorted(sys.modules.keys())))" 2>/dev/null | head -30
echo ""

echo "=========================================="
echo "Recommendations:"
echo "=========================================="
echo "1. Disable AI features (saves ~60-100MB)"
echo "2. Reduce display updates"
echo "3. Minimize loaded libraries"
echo "4. Consider running without web server"
