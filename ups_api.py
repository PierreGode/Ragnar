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
    """Loads saved I2C configuration profile from local storage."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"forced_address": "auto"}

def save_config(config_data):
    """Persists user selected I2C configuration block to disk."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f)
    except Exception:
        pass

def get_i2c_address(bus):
    """Determines active hardware target address based on config or discovery routines."""
    current_config = load_config()
    if current_config.get("forced_address", "auto") != "auto":
        try:
            addr = int(current_config["forced_address"], 16)
            bus.read_word_data(addr, 0x02)
            return addr
        except (IOError, ValueError):
            return None
            
    # Sequential auto-detection scanning across known device versions
    for addr in [0x36, 0x32, 0x62]:
        try:
            bus.read_word_data(addr, 0x02)
            return addr
        except IOError:
            continue
    return None

def read_voltage(bus, address):
    """Extracts raw cell voltage registers and maps values across hardware variants."""
    try:
        read = bus.read_word_data(address, 0x02)
        # Fix: Unpack tuple using index [0] to get the raw integer value
        swapped = struct.unpack("<H", struct.pack(">H", read))[0]
        if address == 0x62:
            return (swapped * 0.305) / 1000
        else:
            return swapped * 1.25 / 1000 / 16
    except Exception:
        return 0.0

def read_capacity(bus, address):
    """Extracts state of charge percentage calculation metrics from the active registry."""
    try:
        read = bus.read_word_data(address, 0x04)
        # Fix: Unpack tuple using index [0] to get the raw integer value
        swapped = struct.unpack("<H", struct.pack(">H", read))[0]
        if address == 0x62:
            return swapped / 256
        else:
            return swapped / 256.0
    except Exception:
        return 0.0

def battery_logger():
    """Independent asynchronous core worker threading bus reads at 60-second intervals."""
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
                
                # CRITICAL THRESHOLD TRIGGER (Safe Shutdown Guard)
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
    """Webhook entry-point endpoint storing manual UI register modifications."""
    addr = request.args.get('addr', 'auto')
    if addr in ['auto', '0x32', '0x36', '0x62']:
        config_data = {"forced_address": addr}
        save_config(config_data)
        return jsonify({"status": "success", "address": addr})
    return jsonify({"status": "error", "message": "Invalid address"}), 400

if __name__ == '__main__':
    threading.Thread(target=battery_logger, daemon=True).start()
    app.run(host='0.0.0.0', port=8080)
