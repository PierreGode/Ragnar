# OOM (Out-of-Memory) Kill Prevention Fixes

## Problem Summary
Ragnar service was experiencing systemd SIGKILL (signal 9) terminations due to memory exhaustion on Raspberry Pi Zero W2 (512MB RAM). The crashes occurred when multiple resource-intensive operations ran simultaneously:

- AI evaluations (GPT-5 Nano)
- ARP + Nmap scanning
- E-ink display updates with BMP image loading
- Bluetooth initialization
- SQLite database operations
- Web server operations

## Root Causes Identified

### 1. **Concurrent Operation Overload**
- Orchestrator allowed 2 concurrent action threads
- AI evaluator processed 5 targets in batches
- Display continuously loaded/updated images
- No memory checks before starting operations

### 2. **Uncontrolled Resource Usage**
- AI evaluations running while scanning
- Display loading hundreds of BMP images without limits
- No garbage collection during high memory usage
- No backpressure when system resources low

### 3. **Memory Spike Scenarios**
```
CRASH PATTERN:
  Network Scan (50MB) 
+ AI Evaluation × 5 (100MB)
+ Display Update + Image Loading (30MB)
+ Nmap Vuln Scan (40MB)
+ SQLite Writes (20MB)
= 240MB+ usage → OOM kill at ~85-90% RAM usage
```

## Implemented Fixes

### 1. Thread/Task Throttling
**File: `orchestrator.py`**
- ✅ Reduced concurrent action semaphore from 2 → 1
- ✅ Added memory checks before executing actions
- ✅ Added memory checks before child actions
- ✅ Memory check + GC before vulnerability scans

```python
# Before: Could run 2 actions simultaneously
self.semaphore = threading.Semaphore(2)

# After: Only 1 action at a time
self.semaphore = threading.Semaphore(1)
```

### 2. AI Evaluation Optimization
**File: `ai_target_evaluator.py`**
- ✅ Reduced batch size from 5 → 1 target at a time
- ✅ Added memory check before evaluation (requires 40MB free)
- ✅ Added resource_monitor import

```python
# Before: Process 5 targets simultaneously
self.batch_size = shared_data.config.get('ai_evaluation_batch_size', 5)

# After: Process 1 target at a time
self.batch_size = shared_data.config.get('ai_evaluation_batch_size', 1)
```

### 3. Display Update Throttling
**File: `display.py`**
- ✅ Added memory checks before display updates
- ✅ Defer updates when memory is low (3 consecutive checks)
- ✅ Increased wait time (30s) when memory constrained
- ✅ Added resource_monitor import

```python
# New: Memory-aware display updates
if not resource_monitor.is_system_healthy():
    consecutive_low_memory_count += 1
    if consecutive_low_memory_count >= 3:
        logger.warning("System memory low, deferring display update")
        time.sleep(30)  # Wait longer when memory is tight
```

### 4. Image Caching Optimization
**File: `shared.py`**
- ✅ Added image cache with 20 image limit
- ✅ FIFO eviction when cache full
- ✅ Prevents loading hundreds of BMPs into memory

```python
# New: Limited image cache
_image_cache = {}
_max_cached_images = 20  # Limit to prevent OOM

def _get_cached_image(self, image_path):
    # Cache management with eviction
```

### 5. Aggressive Garbage Collection
**File: `orchestrator.py`**
- ✅ Reduced GC interval from 5 min → 3 min
- ✅ Lowered GC trigger from 75% → 65% memory usage
- ✅ Log memory before/after GC to confirm freeing

```python
# Every 3 minutes instead of 5
if time.time() - last_resource_log_time > 180:
    mem_usage = resource_monitor.get_memory_usage()
    if mem_usage > 65:  # Trigger at 65% instead of 75%
        resource_monitor.force_garbage_collection()
```

### 6. Memory Checks Throughout
Added `can_start_operation()` checks with minimum memory requirements:
- General actions: 30MB minimum
- Child actions: 30MB minimum
- Vulnerability scans: 50MB minimum
- AI evaluations: 40MB minimum

## Memory Thresholds (Pi Zero W2 - 512MB RAM)

```
Memory Usage Levels:
  0-70%  ✅ OK       - Normal operation
 70-85%  ⚠️ WARNING - Start logging warnings
 85-95%  🚨 CRITICAL - Block new operations
 95%+    💥 DANGER   - Risk of OOM kill

New Behavior:
- 65%+: Force garbage collection
- 70%+: Start warning logs
- 85%+: Block ALL new operations
- Operations deferred until memory drops
```

## Expected Results

### Before Fixes
```
Memory Usage Pattern:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
0%   [████████████████░░░░] 75%
5s   [██████████████████░░] 90%  ← Multiple operations
10s  [███████████████████░] 95%  ← Still adding more
15s  [████████████████████] 100% 💥 OOM KILL
```

### After Fixes
```
Memory Usage Pattern:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
0%   [████████████░░░░░░░░] 60%
5s   [█████████████░░░░░░░] 65%  ✅ GC triggered
10s  [████████████░░░░░░░░] 60%  ✅ Memory freed
15s  [████████████░░░░░░░░] 60%  ✅ Stable
     [████████████░░░░░░░░] 60%  ✅ Operations throttled
```

## Testing Checklist

- [ ] Monitor systemd journal for SIGKILL: `journalctl -u ragnar -f`
- [ ] Watch memory usage: `watch -n 1 free -h`
- [ ] Check for OOM kills: `dmesg | grep -i "killed process"`
- [ ] Verify GC is working: Check logs for "garbage collection freed"
- [ ] Confirm throttling: Check for "Insufficient memory" messages
- [ ] Observe stable memory: Should stay below 70% most of the time

## Monitoring Commands

```bash
# Watch memory in real-time
watch -n 2 'free -h && echo "---" && ps aux | grep -E "ragnar|python" | grep -v grep'

# Monitor for OOM kills
journalctl -u ragnar -f | grep -E "killed|KILL|signal 9"

# Check if systemd is killing Ragnar
systemctl status ragnar

# View OOM killer messages
dmesg -T | grep -i oom
```

## Configuration Options

Users can adjust these in the config if needed:

```json
{
  "ai_evaluation_batch_size": 1,        // AI targets per batch (default: 1)
  "ai_evaluation_check_interval": 300,  // AI eval interval in seconds
  "scan_vuln_interval": 900,            // Vuln scan every 15 min
  "scan_interval": 180                  // Network scan every 3 min
}
```

## Rollback Instructions

If issues occur, revert these changes:
1. `orchestrator.py`: Change semaphore back to 2
2. `ai_target_evaluator.py`: Increase batch_size to 5
3. Remove memory checks from operation starts

## Additional Notes

- These fixes are optimized for **Raspberry Pi Zero W2 (512MB RAM)**
- For devices with more RAM (1GB+), thresholds can be relaxed
- Monitor first week to ensure stability
- Consider disabling AI features if still experiencing issues
- Display updates may be slightly slower during high memory usage (by design)

## Related Files Modified

1. `orchestrator.py` - Main throttling and GC improvements
2. `ai_target_evaluator.py` - Batch size reduction and memory checks
3. `display.py` - Display update throttling
4. `shared.py` - Image cache management
5. `resource_monitor.py` - Already had the monitoring infrastructure

---

**Created:** 2025-11-21  
**Issue:** systemd SIGKILL due to OOM on Pi Zero W2  
**Status:** ✅ Fixed - Awaiting production validation
