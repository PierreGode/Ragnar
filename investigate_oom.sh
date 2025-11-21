#!/bin/bash
# OOM Investigation Script - Check what caused the last kill
# Run this on the Raspberry Pi to diagnose the OOM issue

echo "=========================================="
echo "  OOM Kill Investigation"
echo "  Analyzing last systemd SIGKILL"
echo "=========================================="
echo ""

# Get the timestamp of the last kill
LAST_KILL=$(journalctl -u ragnar --since "24 hours ago" | grep "code=killed, status=9" | tail -1 | awk '{print $1, $2, $3}')

if [ -z "$LAST_KILL" ]; then
    echo "No recent kills found in last 24 hours"
    exit 0
fi

echo "Last kill occurred at: $LAST_KILL"
echo ""

# Parse the timestamp
KILL_DATE=$(echo "$LAST_KILL" | awk '{print $1}')
KILL_TIME=$(echo "$LAST_KILL" | awk '{print $2}')

# Get logs 2 minutes before the kill
echo "=========================================="
echo "Logs from 2 minutes before kill:"
echo "=========================================="
journalctl -u ragnar --since "$KILL_DATE $KILL_TIME" --until "$KILL_DATE $KILL_TIME" -n 100 | grep -E "AI|scan|memory|GC|evaluation|display|image"

echo ""
echo "=========================================="
echo "Last 50 lines before kill:"
echo "=========================================="
journalctl -u ragnar --since "$KILL_DATE $KILL_TIME" --until "$KILL_DATE $KILL_TIME" -n 50

echo ""
echo "=========================================="
echo "System messages around kill time:"
echo "=========================================="
journalctl --since "$KILL_DATE $KILL_TIME" --until "$KILL_DATE $KILL_TIME" | grep -E "oom|kill|memory|Out of memory"

echo ""
echo "=========================================="
echo "dmesg OOM killer messages:"
echo "=========================================="
dmesg -T | grep -i "oom" | tail -10

echo ""
echo "=========================================="
echo "Analysis Complete"
echo "=========================================="
echo ""
echo "To see full logs around kill time, run:"
echo "journalctl -u ragnar --since '$KILL_DATE $KILL_TIME' -n 200"
