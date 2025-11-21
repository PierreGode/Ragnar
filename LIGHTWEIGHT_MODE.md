# Pi Zero W2 Lightweight Mode - Survival Configuration

## Problem
Pi Zero W2 uses **70% RAM just running Ragnar** - this is unsustainable.

## Root Cause
Python + Flask + SocketIO + AI + Display + Threading = massive memory footprint

Typical breakdown:
- Python base: 40-60MB
- Flask/SocketIO web server: 30-50MB
- AI/OpenAI libraries: 50-80MB (even when not running)
- PIL/Image libraries: 20-30MB
- pandas/numpy (data processing): 30-40MB
- Display/threading overhead: 20-30MB
- **Total idle**: ~200-290MB = 70% of 416MB

## Lightweight Mode Configuration

Add this to `config/shared_config.json`:

```json
{
  "__LIGHTWEIGHT_MODE_FOR_PI_ZERO_W2__": "Memory optimization",
  
  "ai_enabled": false,
  "ai_target_evaluation_enabled": false,
  "ai_vulnerability_summaries": false,
  "ai_network_insights": false,
  "ai_generated_comments": false,
  
  "websrv": false,
  "displaying_csv": false,
  
  "scan_interval": 600,
  "scan_vuln_interval": 1800,
  "screen_delay": 60,
  "web_delay": 30,
  
  "debug_mode": false,
  "log_debug": false
}
```

**Expected memory savings**: ~120-160MB (drops to 40-50% idle)

## Alternative: Headless Mode

Even more aggressive - no display, no web:

```json
{
  "__HEADLESS_MODE__": "Absolute minimum for Pi Zero W2",
  
  "ai_enabled": false,
  "ai_target_evaluation_enabled": false,
  "websrv": false,
  "displaying_csv": false,
  
  "manual_mode": false,
  "enable_attacks": true,
  "scan_vuln_running": true,
  
  "scan_interval": 300,
  "scan_vuln_interval": 900,
  
  "debug_mode": false,
  "log_debug": false,
  "log_info": true
}
```

**Expected memory savings**: ~180-200MB (drops to 25-35% idle)

## Code-Level Optimizations

### 1. Lazy Import Heavy Libraries

Edit `shared.py` - only import when needed:

```python
# OLD: Import everything at startup
from PIL import Image, ImageFont
import pandas as pd

# NEW: Import only when needed
def load_image(self, path):
    from PIL import Image
    return Image.open(path)
```

### 2. Disable Unused Modules

Edit `Ragnar.py`:

```python
# Conditional imports based on config
if shared_data.config.get("websrv", False):
    from webapp_modern import run_server

if shared_data.config.get("epd_enabled", True):
    from display import Display
```

### 3. Remove pandas Where Not Critical

Many CSV operations can use plain Python:

```python
# OLD: 30MB pandas
import pandas as pd
df = pd.read_csv(file)

# NEW: 0MB builtin csv
import csv
with open(file) as f:
    reader = csv.DictReader(f)
    data = list(reader)
```

## Immediate Actions (Do These Now)

### Option 1: Quick Config (No Code Changes)
```bash
# On Pi, edit config
sudo nano /path/to/Ragnar/config/shared_config.json

# Add:
{
  "ai_enabled": false,
  "websrv": false,
  "displaying_csv": false
}

# Restart
sudo systemctl restart ragnar
```

### Option 2: Environment Variable
```bash
# Quick disable via systemd
sudo systemctl edit ragnar

# Add:
[Service]
Environment="RAGNAR_LIGHTWEIGHT=1"
Environment="RAGNAR_NO_WEB=1"
Environment="RAGNAR_NO_AI=1"

# Restart
sudo systemctl restart ragnar
```

### Option 3: Separate Lightweight Script

Create `ragnar_lite.py` that only runs:
- Network scanner
- Orchestrator  
- Minimal logging

No web, no display, no AI - just pure pentesting.

## Memory Reduction Strategy

### Phase 1: Disable Heavy Features (Today)
- ✅ Turn off AI (saves 60-80MB)
- ✅ Turn off web server (saves 40-50MB)
- ✅ Reduce display updates (saves 20-30MB)
- **Target**: 50% idle memory

### Phase 2: Lazy Loading (This Week)
- Move PIL imports to display module
- Lazy load pandas only when needed
- Conditional feature imports
- **Target**: 40% idle memory

### Phase 3: Rewrite Critical Paths (Long Term)
- Replace pandas with csv module
- Minimize threading
- Reduce PIL usage
- **Target**: 30% idle memory

## Hardware Reality Check

**Pi Zero W2 Specs:**
- 512MB RAM (416MB usable)
- Single-core ARM Cortex-A53 @ 1GHz
- **Not designed for heavy Python workloads**

**Realistic Expectations:**
- ✅ **Can do**: Network scanning, port scanning, basic attacks
- ⚠️ **Struggles with**: AI, web serving, heavy image processing
- ❌ **Can't handle**: All features simultaneously

## Recommended Setup

### For Pentesting Only
```json
{
  "ai_enabled": false,
  "websrv": false,
  "enable_attacks": true,
  "scan_vuln_running": true
}
```
Access via: SSH + log files

### For Monitoring
```json
{
  "ai_enabled": false,
  "websrv": true,
  "enable_attacks": false,
  "scan_vuln_running": true
}
```
Access via: Web interface (lightweight mode)

### For Demo/Display
```json
{
  "ai_enabled": false,
  "websrv": false,
  "displaying_csv": true,
  "enable_attacks": false
}
```
Access via: E-paper display only

## Quick Disable Commands

```bash
# Disable AI only
curl -X POST http://ragnar.local:8000/api/config/update -d '{"ai_enabled": false}'

# Disable web (requires restart)
sudo systemctl stop ragnar
# Edit config, then:
sudo systemctl start ragnar

# Check current memory
free -m
ps aux | grep python
```

## The Nuclear Option

If still having issues, run Ragnar in **scan-only mode**:

```bash
# Kill full service
sudo systemctl stop ragnar

# Run minimal scanner only
cd /path/to/Ragnar
python3 -c "
from init_shared import shared_data
from actions.scanning import Scanner
scanner = Scanner(shared_data)
while True:
    scanner.scan()
    time.sleep(300)
"
```

This uses ~40-50MB and just does network scanning.

---

**Bottom Line**: Pi Zero W2 cannot run all Ragnar features simultaneously. Choose your priority:
- **Pentesting**: Disable AI + Web
- **Monitoring**: Disable AI + Attacks  
- **Display**: Disable AI + Web + reduce scans

Start with disabling AI immediately - that's the biggest win.
