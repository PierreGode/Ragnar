# Emergency OOM Prevention - Even More Aggressive Settings

## Current Situation
- **Available RAM**: 416MB (not 512MB as expected)
- **Last kill at**: 69% usage (288MB used)
- **Kill occurred at**: 21:54:44 on Nov 21, 2025

## Problem Analysis
With only 416MB available RAM, the system has less headroom than expected. At 69% we're already at 288MB, leaving only 128MB free. When multiple operations stack:
- Python base: ~50MB
- AI evaluation: ~40-60MB per operation
- Scanning: ~30-40MB
- Display: ~20-30MB

This can quickly exceed available memory.

## Emergency Fixes to Apply

### 1. Lower Memory Thresholds (CRITICAL)

Edit `resource_monitor.py`:

```python
# Pi Zero W2 thresholds (ULTRA-conservative for LIMITED RAM)
self.memory_warning_threshold = 60  # % - Start warning (was 70%)
self.memory_critical_threshold = 75  # % - Block new operations (was 85%)
```

**Rationale**: With only 416MB, we need to block operations earlier.

### 2. More Aggressive Garbage Collection

Edit `orchestrator.py` - change GC trigger:

```python
# CRITICAL: More aggressive GC for limited RAM
mem_usage = resource_monitor.get_memory_usage()
if mem_usage > 55:  # Trigger at 55% instead of 65%
    logger.warning(f"Memory usage at {mem_usage:.1f}% - forcing garbage collection")
    resource_monitor.force_garbage_collection()
```

### 3. Add Emergency Memory Pressure Detection

Add to `resource_monitor.py`:

```python
def get_available_memory_mb(self):
    """Get available memory in MB"""
    try:
        mem = psutil.virtual_memory()
        return mem.available / (1024 * 1024)
    except Exception as e:
        self.logger.error(f"Error getting available memory: {e}")
        return 0

def is_memory_pressure_critical(self):
    """Check if we're in critical memory pressure (< 80MB free)"""
    available_mb = self.get_available_memory_mb()
    if available_mb < 80:
        self.logger.critical(f"CRITICAL MEMORY PRESSURE: Only {available_mb:.1f}MB free!")
        return True
    elif available_mb < 120:
        self.logger.warning(f"Memory pressure: {available_mb:.1f}MB free")
        return False
    return False
```

### 4. Emergency System Pause

Add to `orchestrator.py` main loop:

```python
# EMERGENCY: Pause everything if memory critically low
if resource_monitor.get_available_memory_mb() < 80:
    logger.critical("EMERGENCY: Less than 80MB free - pausing all operations")
    resource_monitor.force_garbage_collection()
    time.sleep(60)  # Wait 1 minute for memory to free
    continue
```

## Quick Application Steps

### Option A: Ultra-Conservative (Safest)
```bash
# On the Pi, edit resource_monitor.py
sudo nano /path/to/Ragnar/resource_monitor.py

# Change line ~23:
self.memory_warning_threshold = 60   # was 70
self.memory_critical_threshold = 75  # was 85

# Restart
sudo systemctl restart ragnar
```

### Option B: Emergency Config (Temporary)
Add to `shared_config.json`:
```json
{
  "ai_enabled": false,
  "ai_target_evaluation_enabled": false,
  "scan_vuln_interval": 1800,
  "scan_interval": 300
}
```

This disables AI temporarily to free ~60-80MB.

## Monitoring Commands

```bash
# Watch memory critically
watch -n 1 'free -m | head -2; echo "---"; ps aux | grep python | grep -v grep'

# Check when service is stable
sudo systemctl status ragnar

# View live memory-related logs
journalctl -u ragnar -f | grep -E "memory|Memory|GC|garbage"
```

## Expected Behavior After Fixes

### Memory Pattern (416MB system)
```
 0-60%  (0-250MB)    ✅ Normal operations
60-75%  (250-310MB)  ⚠️  Warning, GC active
75%+    (310MB+)     🚨 BLOCK all new operations
```

### Protection Layers
1. **55%**: Aggressive GC starts
2. **60%**: Warning threshold
3. **75%**: Critical - block operations
4. **80MB free**: Emergency pause

## Root Cause
The Pi has **416MB actual usable RAM**, not 512MB:
- ~96MB reserved for GPU/system
- Leaves 416MB for applications
- Previous thresholds (70%/85%) were too high
- Need to trigger at 60%/75% for this hardware

## Next Steps

1. ✅ Apply ultra-conservative thresholds (60%/75%)
2. ✅ Lower GC trigger to 55%
3. ✅ Add emergency pause at <80MB free
4. 📊 Monitor for 24 hours
5. 🔍 If still crashes, disable AI features

---

**Immediate Action**: Change thresholds to 60%/75% in `resource_monitor.py` and restart service.
