# OOM Kill Prevention - Quick Start Guide

## What Was Fixed?

Your Ragnar service was being killed by systemd (SIGKILL/signal 9) due to **out-of-memory (OOM)** conditions on the Raspberry Pi Zero W2.

## The Problem

Multiple heavy operations running simultaneously:
- ✅ AI evaluations (5 targets at once)
- ✅ Network scanning (ARP + Nmap)
- ✅ E-ink display updates
- ✅ Image loading (hundreds of BMPs)
- ✅ Bluetooth initialization
- ✅ Database operations

**Result:** Memory spike → 90%+ usage → Kernel OOM killer → systemd SIGKILL → Service crash

## The Solution

### 🔧 Implemented Fixes

1. **Reduced Concurrent Operations**
   - Orchestrator: 2 threads → 1 thread
   - AI batch: 5 targets → 1 target at a time

2. **Added Memory Checks**
   - Before actions: Require 30MB free
   - Before AI eval: Require 40MB free
   - Before vuln scans: Require 50MB free

3. **Aggressive Garbage Collection**
   - Trigger at 65% memory (was 75%)
   - Run every 3 minutes (was 5 minutes)

4. **Display Throttling**
   - Defer updates when memory low
   - Limited image cache (20 images max)

5. **Smart Backpressure**
   - Pause operations at 85% memory
   - Resume when memory drops

## Quick Test

### 1. Check Service Status
```bash
sudo systemctl status ragnar
```

**Look for:**
- ✅ `Active: active (running)` - Good!
- ❌ `code=killed, status=9/KILL` - Still having issues

### 2. Monitor Memory
```bash
# Option A: Simple watch
watch -n 2 free -h

# Option B: Use our script
chmod +x monitor_memory.sh
./monitor_memory.sh
```

**What to expect:**
- Memory should stay below **70%** most of the time
- Brief spikes to **75-80%** during scans (OK)
- Garbage collection should bring it back down
- Should **NOT** hit 90%+ anymore

### 3. Check for OOM Kills
```bash
# Check last 24 hours
journalctl -u ragnar --since "24 hours ago" | grep -i "killed"

# Watch live
journalctl -u ragnar -f
```

**Good signs:**
- ✅ "garbage collection freed X objects" in logs
- ✅ "Insufficient memory" warnings (means throttling works!)
- ✅ No "code=killed, status=9" messages

**Bad signs:**
- ❌ "Main process exited, code=killed, status=9/KILL"
- ❌ Repeated crashes
- ❌ OOM killer messages in `dmesg`

## Expected Behavior Changes

### Before Fixes
```
Memory: 60% → 75% → 85% → 95% → 💥 CRASH
Web UI: Stops responding → 💥 Dead
```

### After Fixes
```
Memory: 60% → 68% → [GC runs] → 62% → 65% → [operations throttled] → 60%
Web UI: Stays responsive ✅
Service: Keeps running ✅
```

You might notice:
- Slightly slower operation during high memory
- More "waiting" messages in logs
- Fewer simultaneous actions
- **But NO crashes!** 🎉

## Troubleshooting

### Issue: Still getting killed

**Check 1:** Verify fixes were applied
```bash
cd /path/to/Ragnar
grep "Semaphore(1)" orchestrator.py  # Should find the line
grep "batch_size.*1" ai_target_evaluator.py  # Should show batch size 1
```

**Check 2:** Other processes eating memory?
```bash
ps aux --sort=-%mem | head -10
```

**Check 3:** Increase swap space
```bash
sudo dmesg | grep -i oom  # Check if OOM killer is active
```

### Issue: Too slow now

If Ragnar feels too sluggish, you can carefully relax limits:

**In config file** (adjust cautiously):
```json
{
  "ai_evaluation_batch_size": 2,  // Try 2 instead of 1
  "scan_interval": 240            // Slower scans = less memory spikes
}
```

### Issue: Want to disable AI temporarily

**Quick test:**
```json
{
  "ai_enabled": false,
  "ai_target_evaluation_enabled": false
}
```

This frees ~100MB during AI evaluations.

## Monitoring for Success

### Week 1: Watch Closely
```bash
# Set up monitoring script
chmod +x monitor_memory.sh
./monitor_memory.sh

# Let it run for a few hours
# Memory should stabilize below 70%
```

### Week 2: Spot Check
```bash
# Check once a day
journalctl -u ragnar --since "24 hours ago" | grep -E "killed|OOM|SIGKILL"

# Should see nothing!
```

### Long Term: Relax
Once stable for 2 weeks, you're good! Just check occasionally.

## Performance vs Stability Trade-offs

| Setting | Memory | Speed | Stability |
|---------|--------|-------|-----------|
| **Current (Safe)** | Low | Moderate | ⭐⭐⭐⭐⭐ |
| Increase batch to 2 | Medium | Faster | ⭐⭐⭐⭐ |
| Remove throttling | High | Fastest | ⭐⭐ (risky) |

**Recommendation:** Keep current settings for Pi Zero W2.

## What to Report

If you see improvements, great! 

If issues persist, capture:
```bash
# Memory at crash time
free -h > memory_at_crash.txt

# Last 100 log lines before crash
journalctl -u ragnar -n 100 > logs_before_crash.txt

# System info
dmesg | grep -i oom > oom_messages.txt
```

## Files Changed

All fixes documented in: `OOM_FIXES.md`

- `orchestrator.py` - Thread limits, memory checks, GC
- `ai_target_evaluator.py` - Batch size, memory checks
- `display.py` - Display throttling
- `shared.py` - Image cache management
- `resource_monitor.py` - (already had monitoring)

---

**TL;DR:** We added memory checks everywhere, reduced concurrent operations, and made Ragnar pause when memory is tight instead of crashing. Your Pi Zero W2 should now run stable! 🎯
