# Open Source Integration: UPS Lite v1.2 \& Clones for Ragnar OS

This guide provides a comprehensive blueprint to implement, persist, and visualize real-time battery statistics (capacity and voltage) from **UPS Lite v1.2 boards and their hardware clones** inside the Ragnar OS Modern Web UI (Port 8000).

\---

## Technical Architecture \& Core Logic

1. **Hardware Disambiguation:** Genuine boards use I2C address `0x36` (MAX17040G logic). Clones frequently utilize `0x32` or alternative registers like `0x62` (CW2015 logic). This integration handles all variants natively.
2. **CORS Bypass Solution:** Browsers block multi-port requests (Port 8000 calling Port 8080) due to strict Cross-Origin policies. To bypass this non-invasively, a background Python daemon writes a static `battery.json` directly into Ragnar's local web directory (`/web`). The Web UI loads it locally via standard relative routing.
3. **Configuration Persistence:** Manual address selections made via the dropdown menu are pushed via an internal webhook listener and saved to `ups\\\_config.json`. Settings are preserved permanently and survive system restarts or power losses.
4. **Safe Shutdown Guard:** Hardware clones cannot trigger operating system shutdown when depleted. To prevent microSD data corruption, the daemon enforces a safe execution routine. If battery capacity drops to **<= 3%** or voltage goes down to **<= 3.45V**, it automatically fires a clean `sudo shutdown -h now` ACPI call.
5. **Optimization:** Telemetry sampling and client refresh intervals are bound to **60 seconds** to minimize file I/O operations, save flash memory write-cycles, and preserve system resources.

\---

## Step 1: Create the Telemetry \& Webhook Daemon

This script runs an independent background loop, handles hardware register scaling, saves settings, monitors safe shutdown thresholds, and processes input from the frontend selector.

**File Location on Raspberry Pi:** `/home/ragnar/ups_api.py`

```python
#!/usr/bin/env python3
import struct
import smbus
import time
import json
import threading
import os
from flask import Flask, request, jsonify
from flask\\\_cors import CORS

app = Flask(\\\_\\\_name\\\_\\\_)
CORS(app)

CONFIG\\\_FILE = "/home/ragnar/ups\\\_config.json"
OUTPUT\\\_PATH = "/home/ragnar/Ragnar/web/battery.json"

def load\\\_config():
    """Loads saved I2C configuration profile from local storage."""
    if os.path.exists(CONFIG\\\_FILE):
        try:
            with open(CONFIG\\\_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"forced\\\_address": "auto"}

def save\\\_config(config\\\_data):
    """Persists user selected I2C configuration block to disk."""
    try:
        with open(CONFIG\\\_FILE, "w") as f:
            json.dump(config\\\_data, f)
    except Exception:
        pass

def get\\\_i2c\\\_address(bus):
    """Determines active hardware target address based on config or discovery routines."""
    current\\\_config = load\\\_config()
    if current\\\_config.get("forced\\\_address", "auto") != "auto":
        addr = int(current\\\_config\\\["forced\\\_address"], 16)
        try:
            bus.read\\\_word\\\_data(addr, 0x02)
            return addr
        except IOError:
            return None
            
    # Sequential auto-detection scanning
    for addr in \\\[0x36, 0x32, 0x62]:
        try:
            bus.read\\\_word\\\_data(addr, 0x02)
            return addr
        except IOError:
            continue
    return None

def read\\\_voltage(bus, address):
    """Extracts raw cell voltage registers and maps values across hardware variants."""
    try:
        read = bus.read\\\_word\\\_data(address, 0x02)
        swapped = struct.unpack("<H", struct.pack(">H", read))
        if address == 0x62:
            return (swapped \\\* 0.305) / 1000
        else:
            return swapped \\\* 1.25 / 1000 / 16
    except Exception:
        return 0.0

def read\\\_capacity(bus, address):
    """Extracts state of charge percentage calculation metrics from the active registry."""
    try:
        read = bus.read\\\_word\\\_data(address, 0x04)
        swapped = struct.unpack("<H", struct.pack(">H", read))
        if address == 0x62:
            return swapped / 256
        else:
            return swapped / 256.0
    except Exception:
        return 0.0

def battery\\\_logger():
    """Independent asynchronous core worker threading bus reads at 60-second intervals."""
    while True:
        try:
            bus = smbus.SMBus(1)
            address = get\\\_i2c\\\_address(bus)
            current\\\_config = load\\\_config()
            
            if address:
                voltage = read\\\_voltage(bus, address)
                capacity = read\\\_capacity(bus, address)
                capacity = max(0.0, min(100.0, capacity))
                
                data = {
                    "status": "ok",
                    "capacity": int(capacity),
                    "voltage": round(voltage, 2),
                    "active\\\_address": hex(address),
                    "saved\\\_address": current\\\_config.get("forced\\\_address", "auto")
                }
                
                # CRITICAL THRESHOLD TRIGGER (Safe Shutdown Guard)
                # Shuts down the operating system safely if capacity hits <= 3% OR voltage falls below 3.45V
                if (capacity <= 3 and capacity > 0) or (voltage <= 3.45 and voltage > 2.0):
                    data\\\["status"] = "shutdown\\\_triggered"
                    with open(OUTPUT\\\_PATH, "w") as f:
                        json.dump(data, f)
                    
                    os.system("sudo shutdown -h now")
                    
            else:
                data = {
                    "status": "error", 
                    "message": "UPS Not Found",
                    "saved\\\_address": current\\\_config.get("forced\\\_address", "auto")
                }
                
            with open(OUTPUT\\\_PATH, "w") as f:
                json.dump(data, f)
        except Exception:
            pass
        time.sleep(60)

@app.route('/api/set\\\_address')
def set\\\_address():
    """Webhook entry-point endpoint storing manual UI register modifications."""
    addr = request.args.get('addr', 'auto')
    if addr in \\\['auto', '0x32', '0x36', '0x62']:
        config\\\_data = {"forced\\\_address": addr}
        save\\\_config(config\\\_data)
        return jsonify({"status": "success", "address": addr})
    return jsonify({"status": "error", "message": "Invalid address"}), 400

if \\\_\\\_name\\\_\\\_ == '\\\_\\\_main\\\_\\\_':
    threading.Thread(target=battery\\\_logger, daemon=True).start()
    app.run(host='0.0.0.0', port=8080)
```

\---

## Step 2: Establish the systemd Linux Daemon

Register the background service inside the system systemd directory.

**File Location on Raspberry Pi:** `/etc/systemd/system/ups-api.service`

```ini
\\\[Unit]
Description=UPS Lite Clone API Daemon for Ragnar OS
After=network.target

\\\[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ragnar/ups\\\_api.py
Restart=always
User=root

\\\[Install]
WantedBy=multi-user.target
```

**Service Lifecycle Commands:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable ups-api.service
sudo systemctl start ups-api.service
```

\---

## Step 3: Frontend WebUI Custom Component Injection

Modify Ragnar's visual layout tree to draw the glassmorphism component block inside the Configuration panel wrapper.

**Target File Location on Raspberry Pi:** `/home/ragnar/Ragnar/web/index\_modern.html`

### A. The HTML Visual Element

Search for the `<!-- Service Control Card -->` baseline comment. Paste this template block **exactly above** that location marker line:

```html
<!-- UPS Lite Management Card -->
<div class="glass rounded-lg p-4 mb-3 border border-gray-700/30">
    <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-3">
            <!-- Graphical Miniature Battery Vector Component -->
            <div class="relative w-10 h-6 border-2 border-gray-400 rounded-md p-0.5 flex items-center">
                <div class="absolute -right-\\\[5px] top-\\\[4px] w-\\\[3px] h-\\\[10px] bg-gray-400 rounded-r-sm"></div>
                <div id="mini-bat-fill" class="h-full bg-green-500 rounded-sm transition-all duration-500" style="width: 0%;"></div>
            </div>
            <div>
                <div class="text-xs font-semibold text-gray-200">UPS Power</div>
                <div id="mini-bat-volt" class="text-\\\[10px] text-gray-400 font-mono">-- V</div>
            </div>
        </div>
        <!-- Absolute Numeric Percentage Output -->
        <div id="mini-bat-pct" class="text-2xl font-bold text-white font-sans">--%</div>
    </div>

    <!-- Interface I2C Device Address Settings Dropdown Selector -->
    <div class="flex items-center justify-between pt-2 border-t border-gray-700/40">
        <label for="i2c-select" class="text-xs font-medium text-gray-400">I2C Device Address:</label>
        <select id="i2c-select" class="bg-gray-800/80 border border-gray-700 text-gray-200 text-xs rounded-md p-1 focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 font-mono" onchange="changeI2CAddress(this.value)">
            <option value="auto">Auto-Detect</option>
            <option value="0x32">0x32 (Clone v1.2)</option>
            <option value="0x36">0x36 (Original)</option>
            <option value="0x62">0x62 (Alternative)</option>
        </select>
    </div>
</div>
```

### B. The JavaScript Telemetry Client Implementation

Scroll to the very bottom area of the file. Paste this control loop script block **exactly above** the closing HTML `</body>` tag footprint element:

```html
<script>
function updateUPSMiniature() {
    fetch('/battery.json')
        .then(response => response.json())
        .then(data => {
            // Restore persisted selection element alignment upon browser load instances
            if (data.saved\\\_address) {
                const selectEl = document.getElementById('i2c-select');
                if (selectEl \\\&\\\& selectEl.value !== data.saved\\\_address) {
                    selectEl.value = data.saved\\\_address;
                }
            }

            if (data.status === 'ok') {
                const pct = data.capacity;
                const volt = data.voltage;
                
                const fill = document.getElementById('mini-bat-fill');
                const pctTxt = document.getElementById('mini-bat-pct');
                const voltTxt = document.getElementById('mini-bat-volt');
                
                pctTxt.innerText = pct + '%';
                voltTxt.innerText = volt.toFixed(2) + ' V';
                fill.style.width = pct + '%';
                
                // Color threshold engine state updates (Tailwind mapping utilities)
                fill.className = "h-full rounded-sm transition-all duration-500";
                if (pct <= 15) {
                    fill.classList.add('bg-red-500', 'animate-pulse');
                    pctTxt.className = "text-2xl font-bold text-red-500 font-sans animate-pulse";
                } else if (pct <= 40) {
                    fill.classList.add('bg-amber-500');
                    pctTxt.className = "text-2xl font-bold text-amber-500 font-sans";
                } else {
                    fill.classList.add('bg-emerald-500');
                    pctTxt.className = "text-2xl font-bold text-white font-sans";
                }
            }
        })
        .catch(err => console.log('UPS Battery telemetry fetch error:', err));
}

function changeI2CAddress(val) {
    // Post new target preferences directly to the persistence webhook handler pipeline
    fetch('http://' + window.location.hostname + ':8080/api/set\\\_address?addr=' + val, { mode: 'no-cors' })
        .then(() => console.log('I2C device address override pushed: ' + val))
        .catch(err => console.log('I2C address push webhook failed:', err));
}

// Instantiate sequence routines on render and lock interval cycles to exactly 60 seconds
updateUPSMiniature();
setInterval(updateUPSMiniature, 60000);
</script>
```

