#!/usr/bin/env python3
import struct
import smbus
import sys

def get_i2c_address(bus):
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
        swapped = struct.unpack("<H", struct.pack(">H", read))[0] # Dodano [0]
        if address == 0x62:
            return (swapped * 0.305) / 1000
        else:
            return swapped * 1.25 / 1000 / 16
    except IOError:
        return 0.0

def read_capacity(bus, address):
    try:
        read = bus.read_word_data(address, 0x04)
        swapped = struct.unpack("<H", struct.pack(">H", read))[0] # Dodano [0]
        if address == 0x62:
            return swapped / 256
        else:
            return swapped / 256.0
    except IOError:
        return 0.0

def main():
    try:
        bus = smbus.SMBus(1)
    except FileNotFoundError:
        print("Brak I2C")
        sys.exit(1)

    address = get_i2c_address(bus)
    if not address:
        print("Brak UPS")
        sys.exit(1)

    voltage = read_voltage(bus, address)
    capacity = read_capacity(bus, address)
    capacity = max(0.0, min(100.0, capacity))

    print(f"{int(capacity)}% ({voltage:.2f}V)")

if __name__ == "__main__":
    main()

