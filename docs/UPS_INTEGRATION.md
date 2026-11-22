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

# Ragnar OS — UPS Integration Codes

This file contains only the verified stable source codes for the UPS backend daemon (`ups_api.py`) and the web frontend card interface (`index_modern.html`).

## 1. Backend Code (`ups_api.py`)

```python
#!/usr/bin/env python3
import struct
import smbus
import time
import json
import threading
import os
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

CONFIG_FILE = "/home/ragnar/ups_config.json"
OUTPUT_PATH = "/home/ragnar/Ragnar/web/battery.json"

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"forced_address": "auto"}

def save_config(config_data):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f)
    except Exception:
        pass

def get_i2c_address(bus):
    current_config = load_config()
    if current_config.get("forced_address", "auto") != "auto":
        try:
            addr = int(current_config["forced_address"], 16)
            bus.read_word_data(addr, 0x02)
            return addr
        except (IOError, ValueError):
            return None
            
    for addr in [0x36, 0x32, 0x62]:
        try:
            bus.read_word_data(addr, 0x02)
            return addr
        except IOError:
            continue
    return None

def read_voltage(bus, address):
    try:
        read = bus.read_word_data(address, 0x02)
        swapped = struct.unpack("<H", struct.pack(">H", read))[0]
        if address == 0x62:
            return (swapped * 0.305) / 1000
        else:
            return swapped * 1.25 / 1000 / 16
    except Exception:
        return 0.0

def read_capacity(bus, address):
    try:
        read = bus.read_word_data(address, 0x04)
        swapped = struct.unpack("<H", struct.pack(">H", read))[0]
        if address == 0x62:
            return swapped / 256
        else:
            return swapped / 256.0
    except Exception:
        return 0.0

def battery_logger():
    time.sleep(10)
    while True:
        bus = None
        try:
            bus = smbus.SMBus(1)
            address = get_i2c_address(bus)
            current_config = load_config()
            
            if address:
                voltage = read_voltage(bus, address)
                capacity = read_capacity(bus, address)
                capacity = max(0.0, min(100.0, capacity))
                
                is_charging = False
                if voltage >= 4.10:
                    is_charging = True
                
                data = {
                    "status": "ok",
                    "capacity": int(capacity),
                    "voltage": round(voltage, 2),
                    "charging": is_charging,
                    "active_address": hex(address),
                    "saved_address": current_config.get("forced_address", "auto")
                }
                
                if (capacity <= 3 and capacity > 0) or (voltage <= 3.45 and voltage > 2.0):
                    data["status"] = "shutdown_triggered"
                    with open(OUTPUT_PATH, "w") as f:
                        json.dump(data, f)
                    os.system("sudo shutdown -h now")
            else:
                data = {
                    "status": "error", 
                    "message": "UPS Not Found",
                    "charging": False,
                    "saved_address": current_config.get("forced_address", "auto")
                }
                
            with open(OUTPUT_PATH, "w") as f:
                json.dump(data, f)
                
        except Exception as e:
            try:
                with open(OUTPUT_PATH, "w") as f:
                    json.dump({"status": "error", "message": f"I2C Bus Error: {str(e)}", "charging": False}, f)
            except Exception:
                pass
        finally:
            if bus is not None:
                try:
                    bus.close()
                except Exception:
                    pass
        time.sleep(60)

@app.route('/api/set_address')
def set_address():
    addr = request.args.get('addr', 'auto')
    if addr in ['auto', '0x32', '0x36', '0x62']:
        config_data = {"forced_address": addr}
        save_config(config_data)
        return jsonify({"status": "success", "address": addr})
    return jsonify({"status": "error", "message": "Invalid address"}), 400

if __name__ == '__main__':
    threading.Thread(target=battery_logger, daemon=True).start()
    app.run(host='0.0.0.0', port=8080)
```

## 2. Frontend Code (`index_modern.html`)

```html
<!-- HTML Card Layout -->
<div class="glass-card p-4 flex flex-col justify-between">
    <div class="flex items-center justify-between mb-2">
        <h3 class="font-semibold text-sm text-gray-200">Power & UPS</h3>
        <div class="relative w-10 h-6 border-2 border-gray-500 rounded p-0.5 flex items-center bg-gray-950/40">
            <div class="absolute -right-[5px] top-[5px] w-[3px] h-[10px] bg-gray-400 rounded-r-sm"></div>
            <div id="mini-bat-fill" class="h-full bg-emerald-500 rounded-sm transition-all duration-500" style="width: 0%;"></div>
        </div>
    </div>
    <div class="flex items-baseline justify-between mt-2">
        <div id="mini-bat-pct" class="text-2xl font-bold text-white">--%</div>
        <div id="mini-bat-volt" class="text-xs text-gray-400 font-mono">-- V</div>
    </div>
    <div class="flex items-center justify-between pt-2 mt-3 border-t border-gray-700/40">
        <label for="i2c-select" class="text-[10px] font-medium text-gray-400 uppercase tracking-wider">I2C Address:</label>
        <select id="i2c-select" class="bg-gray-900 border border-gray-700 text-white text-xs rounded p-1 focus:ring-1 focus:ring-indigo-500 font-mono cursor-pointer" onchange="changeI2CAddress(this.value)">
            <option value="auto">Auto-Detect</option>
            <option value="0x32">0x32 (Clone)</option>
            <option value="0x36">0x36 (Original)</option>
            <option value="0x62">0x62 (Alternative)</option>
        </select>
    </div>
</div>

<!-- JavaScript Telemetry Routine -->
<script>
function runBatteryTelemetry() {
    fetch('/battery.json')
        .then(response => response.json())
        .then(data => {
            const pctTxt = document.getElementById('mini-bat-pct');
            const voltTxt = document.getElementById('mini-bat-volt');
            const fill = document.getElementById('mini-bat-fill');
            const selectEl = document.getElementById('i2c-select');
            
            if (data.saved_address && selectEl) {
                if (selectEl.value !== data.saved_address) {
                    selectEl.value = data.saved_address;
                }
            }

            if (data.status === 'ok') {
                const pct = data.capacity;
                const volt = data.voltage;
                const isCharging = data.charging;
                
                if (pctTxt) {
                    pctTxt.innerText = isCharging ? '⚡ ' + pct + '%' : pct + '%';
                    if (isCharging) {
                        pctTxt.className = "text-2xl font-bold text-emerald-400 font-sans animate-pulse";
                    } else if (pct <= 15) {
                        pctTxt.className = "text-2xl font-bold text-red-500 font-sans animate-pulse";
                    } else if (pct <= 40) {
                        pctTxt.className = "text-2xl font-bold text-amber-500 font-sans";
                    } else {
                        pctTxt.className = "text-2xl font-bold text-white font-sans";
                    }
                }
                
                if (voltTxt) {
                    voltTxt.innerText = volt.toFixed(2) + (isCharging ? ' V (Charging)' : ' V');
                }
                
                if (fill) {
                    fill.style.display = 'block';
                    fill.style.height = '100%';
                    fill.style.width = pct + '%';
                    fill.style.transition = 'width 0.5s ease';
                    fill.className = "rounded-sm";

                    if (isCharging) {
                        fill.style.backgroundColor = '#34d399';
                    } else {
                        if (pct <= 15) {
                            fill.style.backgroundColor = '#ef4444';
                        } else if (pct <= 40) {
                            fill.style.backgroundColor = '#f59e0b';
                        } else {
                            fill.style.backgroundColor = '#10b981';
                        }
                    }
                }
            } else {
                if (pctTxt) {
                    pctTxt.innerText = "--%";
                    pctTxt.className = "text-2xl font-bold text-gray-500 font-sans";
                }
                if (voltTxt) {
                    voltTxt.innerText = "-- V";
                }
                if (fill) {
                    fill.style.width = '0%';
                    fill.style.backgroundColor = 'transparent';
                    fill.className = "rounded-sm";
                }
            }
        })
        .catch(err => console.log('UPS Telemetry Sync Error:', err));
}

function changeI2CAddress(val) {
    fetch('http://' + window.location.hostname + ':8080/api/set_address?addr=' + val)
        .then(response => response.json())
        .then(data => console.log('I2C device address updated successfully:', data))
        .catch(err => console.log('I2C address push webhook failed:', err));
}

runBatteryTelemetry();
setInterval(runBatteryTelemetry, 60000);
</script>
```
EOF
