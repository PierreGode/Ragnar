#!/usr/bin/env python3

# Copyright (c) Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form, except as embedded into a Nordic
#    Semiconductor ASA integrated circuit in a product or a software update for
#    such product, must reproduce the above copyright notice, this list of
#    conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# 4. This software, with or without modification, must only be used with a
#    Nordic Semiconductor ASA integrated circuit.
#
# 5. Any software provided in binary form under this license must not be reverse
#    engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


"""
Wireshark extcap wrapper for the nRF Sniffer for Bluetooth LE by Nordic Semiconductor.
"""

import os
import sys
import argparse
import re
import time
import struct
import logging

from SnifferAPI import Logger
try:
    import serial
except ImportError:
    Logger.initLogger()
    logging.error(f'pyserial not found, please run: "{sys.executable} -m pip install -r requirements.txt" and retry')
    sys.exit(f'pyserial not found, please run: "{sys.executable} -m pip install -r requirements.txt" and retry')

from SnifferAPI import Sniffer, UART, Devices, Pcap, Exceptions

ERROR_USAGE = 0
ERROR_ARG = 1
ERROR_INTERFACE = 2
ERROR_FIFO = 3
ERROR_INTERNAL = 4

CTRL_CMD_INIT = 0
CTRL_CMD_SET = 1
CTRL_CMD_ADD = 2
CTRL_CMD_REMOVE = 3
CTRL_CMD_ENABLE = 4
CTRL_CMD_DISABLE = 5
CTRL_CMD_STATUSBAR = 6
CTRL_CMD_INFO_MSG = 7
CTRL_CMD_WARN_MSG = 8
CTRL_CMD_ERROR_MSG = 9

CTRL_ARG_DEVICE = 0
CTRL_ARG_KEY_TYPE = 1
CTRL_ARG_KEY_VAL = 2
CTRL_ARG_ADVHOP = 3
CTRL_ARG_HELP = 4
CTRL_ARG_RESTORE = 5
CTRL_ARG_LOG = 6
CTRL_ARG_DEVICE_CLEAR = 7
CTRL_ARG_NONE = 255

CTRL_KEY_TYPE_PASSKEY = 0
CTRL_KEY_TYPE_OOB = 1
CTRL_KEY_TYPE_LEGACY_LTK = 2
CTRL_KEY_TYPE_SC_LTK = 3
CTRL_KEY_TYPE_DH_PRIVATE_KEY = 4
CTRL_KEY_TYPE_IRK = 5
CTRL_KEY_TYPE_ADD_ADDR = 6
CTRL_KEY_TYPE_FOLLOW_ADDR = 7

fn_capture = None
fn_ctrl_in = None
fn_ctrl_out = None

extcap_log_handler = None
extcap_version = None

# Wireshark nRF Sniffer for Bluetooth LE Toolbar will always cache the last used key and adv hop and send
# this when starting a capture. To ensure that the key and adv hop is always shown correctly
# in the Toolbar, even if the user has changed it but not applied it, we send the last used
# key and adv hop back as a default value.
last_used_key_type = CTRL_KEY_TYPE_PASSKEY
last_used_key_val = ""
last_used_advhop = "37,38,39"

zero_addr = "[00,00,00,00,00,00,0]"

# While searching for a selected Device we must not write packets to the pipe until
# the device is found to avoid getting advertising packets from other devices.
write_new_packets = False

# The RSSI capture filter value given from Wireshark.
rssi_filter = 0

# The RSSI filtering is not on when in follow mode.
in_follow_mode = False

# nRF Sniffer for Bluetooth LE interface option to only capture advertising packets
capture_only_advertising = False
capture_only_legacy_advertising = False
capture_scan_response = True
capture_scan_aux_pointer = True
capture_coded = False

def extcap_config(interface):
    """List configuration for the given interface"""
    print("arg {number=0}{call=--only-advertising}{display=Only advertising packets}"
          "{tooltip=The sniffer will only capture advertising packets from the selected device}{type=boolflag}{save=true}")
    print("arg {number=1}{call=--only-legacy-advertising}{display=Only legacy advertising packets}"
          "{tooltip=The sniffer will only capture legacy advertising packets from the selected device}{type=boolflag}{save=true}")
    print("arg {number=2}{call=--scan-follow-rsp}{display=Find scan response data}"
          "{tooltip=The sniffer will follow scan requests and scan responses in scan mode}{type=boolflag}{default=true}{save=true}")
    print("arg {number=3}{call=--scan-follow-aux}{display=Find auxiliary pointer data}"
          "{tooltip=The sniffer will follow aux pointers in scan mode}{type=boolflag}{default=true}{save=true}")
    print("arg {number=3}{call=--coded}{display=Scan and follow devices on LE Coded PHY}"
          "{tooltip=Scan for devices and follow advertiser on LE Coded PHY}{type=boolflag}{default=false}{save=true}")

def extcap_dlts(interface):
    """List DLTs for the given interface"""
    print("dlt {number=272}{name=NORDIC_BLE}{display=nRF Sniffer for Bluetooth LE}")


def get_baud_rates(interface):
    if not hasattr(serial, "__version__") or not serial.__version__.startswith('3.'):
        raise RuntimeError("Too old version of python 'serial' Library. Version 3 required.")
    return UART.find_sniffer_baudrates(interface)


def get_interfaces():
    if not hasattr(serial, "__version__") or not serial.__version__.startswith('3.'):
        raise RuntimeError("Too old version of python 'serial' Library. Version 3 required.")

    devices = UART.find_sniffer()
    return devices


def extcap_interfaces():
    """List available interfaces to capture from"""
    print("extcap {version=%s}{display=nRF Sniffer for Bluetooth LE}"
          "{help=https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Sniffer-for-Bluetooth-LE}"
          % Sniffer.VERSION_STRING)

    for interface_port in get_interfaces():
        if sys.platform == 'win32':
            print("interface {value=%s-%s}{display=nRF Sniffer for Bluetooth LE %s}" % (interface_port, extcap_version, interface_port))
        else:
            print("interface {value=%s-%s}{display=nRF Sniffer for Bluetooth LE}" % (interface_port, extcap_version))

    print("control {number=%d}{type=selector}{display=Device}{tooltip=Device list}" % CTRL_ARG_DEVICE)
    print("control {number=%d}{type=selector}{display=Key}{tooltip=}" % CTRL_ARG_KEY_TYPE)
    print("control {number=%d}{type=string}{display=Value}"
          "{tooltip=6 digit passkey or 16 or 32 bytes encryption key in hexadecimal starting with '0x', big endian format."
          "If the entered key is shorter than 16 or 32 bytes, it will be zero-padded in front'}"
          "{validation=\\b^(([0-9]{6})|(0x[0-9a-fA-F]{1,64})|([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}) (public|random))$\\b}" % CTRL_ARG_KEY_VAL)
    print("control {number=%d}{type=string}{display=Adv Hop}"
          "{default=37,38,39}"
          "{tooltip=Advertising channel hop sequence. "
          "Change the order in which the sniffer switches advertising channels. "
          "Valid channels are 37, 38 and 39 separated by comma.}"
          "{validation=^\s*((37|38|39)\s*,\s*){0,2}(37|38|39){1}\s*$}{required=true}" % CTRL_ARG_ADVHOP)
    print("control {number=%d}{type=button}{display=Clear}{tooltop=Clear or remove device from Device list}" % CTRL_ARG_DEVICE_CLEAR)
    print("control {number=%d}{type=button}{role=help}{display=Help}{tooltip=Access user guide (launches browser)}" % CTRL_ARG_HELP)
    print("control {number=%d}{type=button}{role=restore}{display=Defaults}{tooltip=Resets the user interface and clears the log file}" % CTRL_ARG_RESTORE)
    print("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Log per interface}" % CTRL_ARG_LOG)

    print("value {control=%d}{value= }{display=All advertising devices}{default=true}" % CTRL_ARG_DEVICE)
    print("value {control=%d}{value=%s}{display=Follow IRK}" % (CTRL_ARG_DEVICE, zero_addr))

    print("value {control=%d}{value=%d}{display=Legacy Passkey}{default=true}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_PASSKEY))
    print("value {control=%d}{value=%d}{display=Legacy OOB data}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_OOB))
    print("value {control=%d}{value=%d}{display=Legacy LTK}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_LEGACY_LTK))
    print("value {control=%d}{value=%d}{display=SC LTK}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_SC_LTK))
    print("value {control=%d}{value=%d}{display=SC Private Key}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_DH_PRIVATE_KEY))
    print("value {control=%d}{value=%d}{display=IRK}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_IRK))
    print("value {control=%d}{value=%d}{display=Add LE address}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_ADD_ADDR))
    print("value {control=%d}{value=%d}{display=Follow LE address}" % (CTRL_ARG_KEY_TYPE, CTRL_KEY_TYPE_FOLLOW_ADDR))


def string_address(address):
    """Make a string representation of the address"""
    if len(address) < 7:
        return None

    addr_string = ''

    for i in range(5):
        addr_string += (format(address[i], '02x') + ':')
    addr_string += format(address[5], '02x') + ' '

    if address[6]:
        addr_string += ' random '
    else:
        addr_string += ' public '

    return addr_string


def control_read():
    """Read a message from the control channel"""
    header = fn_ctrl_in.read(6)
    if not header:
        # Ref. https://docs.python.org/3/tutorial/inputoutput.html#methods-of-file-objects:
        # > If the end of the file has been reached, f.read() will return an
        # > empty string ('')
        return None, None, None

    _, _, length, arg, typ = struct.unpack('>sBHBB', header)

    payload = bytearray()
    if length > 2:
        payload = fn_ctrl_in.read(length - 2)

    return arg, typ, payload

def control_write(arg, typ, message):
    """Write the message to the control channel"""

    if not fn_ctrl_out:
        # No control out has been opened
        return

    packet = bytearray()
    packet += struct.pack('>BBHBB', ord('T'), 0, len(message) + 2, arg, typ)
    packet += message.encode('utf-8')

    fn_ctrl_out.write(packet)


def capture_write(message):
    """Write the message to the capture pipe"""
    fn_capture.write(message)
    fn_capture.flush()


def new_packet(notification):
    """A new Bluetooth LE packet has arrived"""
    if write_new_packets == True:
        packet = notification.msg["packet"]

        if rssi_filter == 0 or in_follow_mode == True or packet.RSSI > rssi_filter:
            p = bytes([packet.boardId] + packet.getList())
            capture_write(Pcap.create_packet(p, packet.time))


def device_added(notification):
    """A device is added or updated"""
    device = notification.msg

    # Only add devices matching RSSI filter
    if rssi_filter == 0 or device.RSSI > rssi_filter:
        # Extcap selector uses \0 character to separate value and display value,
        # therefore the display value cannot contain the \0 character as this
        # would lead to truncation of the display value.
        display = (device.name.replace('\0', '\\0') +
                   ("  " + str(device.RSSI) + " dBm  " if device.RSSI != 0 else "  ") +
                   string_address(device.address))

        message = str(device.address) + '\0' + display

        control_write(CTRL_ARG_DEVICE, CTRL_CMD_ADD, message)


def device_removed(notification):
    """A device is removed"""
    device = notification.msg
    display = device.name + "  " + string_address(device.address)

    message = ""
    message += str(device.address)

    control_write(CTRL_ARG_DEVICE, CTRL_CMD_REMOVE, message)
    logging.info("Removed: " + display)

def devices_cleared(notification):
    """Devices have been cleared"""
    message = ""
    control_write(CTRL_ARG_DEVICE, CTRL_CMD_REMOVE, message)

    control_write(CTRL_ARG_DEVICE, CTRL_CMD_ADD, " " + '\0' + "All advertising devices")
    control_write(CTRL_ARG_DEVICE, CTRL_CMD_ADD, zero_addr + '\0' + "Follow IRK")
    control_write(CTRL_ARG_DEVICE, CTRL_CMD_SET, " ")

def handle_control_command(sniffer, arg, typ, payload):
    """Handle command from control channel"""
    global last_used_key_type

    if arg == CTRL_ARG_DEVICE:
        if payload == b' ':
            scan_for_devices(sniffer)
        else:
            values = payload
            values = values.replace(b'[', b'')
            values = values.replace(b']', b'')
            device_address = values.split(b',')

            logging.info('follow_device: {}'.format(device_address))
            for i in range(6):
                device_address[i] = int(device_address[i])

            device_address[6] = 1 if device_address[6] == b' 1' else 0

            device = Devices.Device(address=device_address, name='""', RSSI=0)

            follow_device(sniffer, device)

    elif arg == CTRL_ARG_DEVICE_CLEAR:
        clear_devices(sniffer)
    elif arg == CTRL_ARG_KEY_TYPE:
        last_used_key_type = int(payload.decode('utf-8'))
    elif arg == CTRL_ARG_KEY_VAL:
        set_key_value(sniffer, payload)
    elif arg == CTRL_ARG_ADVHOP:
        set_advhop(sniffer, payload)


def control_read_initial_values(sniffer):
    """Read initial control values"""
    initialized = False

    while not initialized:
        arg, typ, payload = control_read()
        if typ == CTRL_CMD_INIT:
            initialized = True
        else:
            handle_control_command(sniffer, arg, typ, payload)


def control_write_defaults():
    """Write default control values"""
    control_write(CTRL_ARG_KEY_TYPE, CTRL_CMD_SET, str(last_used_key_type))
    control_write(CTRL_ARG_KEY_VAL, CTRL_CMD_SET, last_used_key_val)
    control_write(CTRL_ARG_ADVHOP, CTRL_CMD_SET, last_used_advhop)


def scan_for_devices(sniffer):
    """Start scanning for advertising devices"""
    global in_follow_mode
    if sniffer.state == 2:
        log = "Scanning all advertising devices"
        logging.info(log)
        sniffer.scan(capture_scan_response, capture_scan_aux_pointer, capture_coded)

    in_follow_mode = False


def clear_devices(sniffer):
    """Clear the advertising devices list"""
    global in_follow_mode

    sniffer.clearDevices()
    scan_for_devices(sniffer)

    in_follow_mode = False


def follow_device(sniffer, device):
    """Follow the selected device"""
    global write_new_packets, in_follow_mode

    sniffer.follow(device, capture_only_advertising, capture_only_legacy_advertising, capture_coded)
    time.sleep(.1)

    in_follow_mode = True
    logging.info("Following " + string_address(device.address))


def set_key_value(sniffer, payload):
    """Send key value to device"""
    global last_used_key_val

    payload = payload.decode('utf-8')
    last_used_key_val = payload

    if (last_used_key_type == CTRL_KEY_TYPE_PASSKEY):
        if re.match("^[0-9]{6}$", payload):
            set_passkey(sniffer, payload)
        else:
            logging.info("Invalid key value: " + str(payload))
    elif (last_used_key_type == CTRL_KEY_TYPE_OOB):
        if re.match("^0[xX][0-9A-Za-z]{1,32}$", payload):
            set_OOB(sniffer, payload[2:])
        else:
            logging.info("Invalid key value: " + str(payload))
    elif (last_used_key_type == CTRL_KEY_TYPE_DH_PRIVATE_KEY):
        if (re.match("^0[xX][0-9A-Za-z]{1,64}$", payload)):
            set_dh_private_key(sniffer, payload[2:])
        else:
            logging.info("Invalid key value: " + str(payload))
    elif (last_used_key_type == CTRL_KEY_TYPE_LEGACY_LTK):
        if (re.match("^0[xX][0-9A-Za-z]{1,32}$", payload)):
            set_legacy_ltk(sniffer, payload[2:])
        else:
            logging.info("Invalid key value: " + str(payload))
    elif (last_used_key_type == CTRL_KEY_TYPE_SC_LTK):
        if (re.match("^0[xX][0-9A-Za-z]{1,32}$", payload)):
            set_sc_ltk(sniffer, payload[2:])
        else:
            logging.info("Invalid key value: " + str(payload))
    elif (last_used_key_type == CTRL_KEY_TYPE_IRK):
        if (re.match("^0[xX][0-9A-Za-z]{1,32}$", payload)):
            set_irk(sniffer, payload[2:])
        else:
            logging.info("Invalid key value: " + str(payload))
    elif (last_used_key_type == CTRL_KEY_TYPE_ADD_ADDR):
        if (re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}) (public|random)$", payload)):
            add_address(sniffer, payload)
        else:
            logging.info("Invalid key value: " + str(payload))
    elif (last_used_key_type == CTRL_KEY_TYPE_FOLLOW_ADDR):
        if (re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}) (public|random)$", payload)):
            follow_address(sniffer, payload)
        else:
            logging.info("Invalid key value: " + str(payload))
    else:
        logging.info("Invalid key type: " + str(last_used_key_type))

def parse_hex(value):
        if len(value) % 2 != 0:
            value = '0' + value

        a = list(value)
        return [int(x + y, 16) for x,y in zip(a[::2], a[1::2])]

def set_passkey(sniffer, payload):
    """Send passkey to device"""
    passkey = []
    logging.info("Setting Passkey: " + payload)
    init_payload = int(payload, 10)
    if len(payload) >= 6:
        passkey = []
        passkey += [(init_payload >> 16) & 0xFF]
        passkey += [(init_payload >> 8) & 0xFF]
        passkey += [(init_payload >> 0) & 0xFF]

    sniffer.sendTK(passkey)

def set_OOB(sniffer, payload):
    """Send OOB to device"""
    logging.info("Setting OOB data: " + payload)
    sniffer.sendTK(parse_hex(payload))

def set_dh_private_key(sniffer, payload):
    """Send Diffie-Hellman private key to device"""
    logging.info("Setting DH private key: " + payload)
    sniffer.sendPrivateKey(parse_hex(payload))

def set_legacy_ltk(sniffer, payload):
    """Send Legacy Long Term Key (LTK) to device"""
    logging.info("Setting Legacy LTK: " + payload)
    sniffer.sendLegacyLTK(parse_hex(payload))

def set_sc_ltk(sniffer, payload):
    """Send LE secure connections Long Term Key (LTK) to device"""
    logging.info("Setting SC LTK: " + payload)
    sniffer.sendSCLTK(parse_hex(payload))

def set_irk(sniffer, payload):
    """Send Identity Resolving Key (IRK) to device"""
    logging.info("Setting IRK: " + payload)
    sniffer.sendIRK(parse_hex(payload))

def add_address(sniffer, payload):
    """Add LE address to device list"""
    logging.info("Adding LE address: " + payload)

    (addr,addr_type) = payload.split(' ')
    device = [int(a, 16) for a in addr.split(":")]

    device.append(1 if addr_type == "random" else 0)

    new_device = Devices.Device(address=device, name='""', RSSI=0)
    sniffer.addDevice(new_device)

def follow_address(sniffer, payload):
    """Add LE address to device list"""
    logging.info("Adding LE address: " + payload)

    (addr,addr_type) = payload.split(' ')
    device = [int(a, 16) for a in addr.split(":")]

    device.append(1 if addr_type == "random" else 0)

    new_device = Devices.Device(address=device, name='""', RSSI=0)
    sniffer.addDevice(new_device)

    control_write(CTRL_ARG_DEVICE, CTRL_CMD_SET, f"{new_device.address}")
    follow_device(sniffer, new_device)

def set_advhop(sniffer, payload):
    """Set advertising channel hop sequence"""
    global last_used_advhop

    payload = payload.decode('utf-8')

    last_used_advhop = payload

    hops = [int(channel) for channel in payload.split(',')]

    sniffer.setAdvHopSequence(hops)

    log = "AdvHopSequence: " + str(hops)
    logging.info(log)


def control_loop(sniffer):
    """Main loop reading control messages"""
    arg_read = CTRL_ARG_NONE
    while arg_read is not None:
        arg_read, typ, payload = control_read()
        handle_control_command(sniffer, arg_read, typ, payload)


def error_interface_not_found(interface, fifo):
    log = "nRF Sniffer for Bluetooth LE could not find interface: " + interface
    control_write(CTRL_ARG_NONE, CTRL_CMD_ERROR_MSG, log)
    extcap_close_fifo(fifo)
    sys.exit(ERROR_INTERFACE)


def validate_interface(interface, fifo):
    """Check if interface exists"""
    if sys.platform != 'win32' and not os.path.exists(interface):
        error_interface_not_found(interface, fifo)


def get_default_baudrate(interface, fifo):
    """Return the baud rate that interface is running at, or exit if the board is not found"""
    rates = get_baud_rates(interface)
    if rates is None:
        error_interface_not_found(interface, fifo)
    return rates["default"]

def get_supported_protocol_version(extcap_version):
    """Return the maximum supported Packet Protocol Version"""
    if extcap_version == 'None':
        return 2

    (major, minor) = extcap_version.split('.')

    major = int(major)
    minor = int(minor)

    if major > 3 or (major == 3 and minor >= 4):
        return 3
    else:
        return 2

def setup_extcap_log_handler():
    """Add the a handler that emits log messages through the extcap control out channel"""
    global extcap_log_handler
    extcap_log_handler = ExtcapLoggerHandler()
    Logger.addLogHandler(extcap_log_handler)
    control_write(CTRL_ARG_LOG, CTRL_CMD_SET, "")


def teardown_extcap_log_handler():
    """Remove and reset the extcap log handler"""
    global extcap_log_handler
    if extcap_log_handler:
        Logger.removeLogHandler(extcap_log_handler)
        extcap_log_handler = None


def sniffer_capture(interface, baudrate, fifo, control_in, control_out):
    """Start the sniffer to capture packets"""
    global fn_capture, fn_ctrl_in, fn_ctrl_out, write_new_packets, extcap_log_handler

    try:
        fn_capture = open(fifo, 'wb', 0)

        if control_out is not None:
            fn_ctrl_out = open(control_out, 'wb', 0)
            setup_extcap_log_handler()

        if control_in is not None:
            fn_ctrl_in = open(control_in, 'rb', 0)

        logging.info("Log started at %s", time.strftime("%c"))

        interface, extcap_version = interface.rsplit('-', 1)  # Ragnar: by-id paths contain '-'
        logging.info("Extcap version %s", str(extcap_version))

        capture_write(Pcap.get_global_header())
        validate_interface(interface, fifo)
        if baudrate is None:
            baudrate = get_default_baudrate(interface, fifo)

        sniffer = Sniffer.Sniffer(interface, baudrate)
        sniffer.subscribe("NEW_BLE_PACKET", new_packet)
        sniffer.subscribe("DEVICE_ADDED", device_added)
        sniffer.subscribe("DEVICE_UPDATED", device_added)
        sniffer.subscribe("DEVICE_REMOVED", device_removed)
        sniffer.subscribe("DEVICES_CLEARED", devices_cleared)
        sniffer.setAdvHopSequence([37, 38, 39])
        sniffer.setSupportedProtocolVersion(get_supported_protocol_version(extcap_version))
        logging.info("Sniffer created")

        logging.info("Software version: %s" % sniffer.swversion)
        sniffer.getFirmwareVersion()
        sniffer.getTimestamp()
        sniffer.start()
        logging.info("sniffer started")
        sniffer.scan(capture_scan_response, capture_scan_aux_pointer, capture_coded)
        logging.info("scanning started")

        if fn_ctrl_in is not None and fn_ctrl_out is not None:
            # First read initial control values
            control_read_initial_values(sniffer)

            # Then write default values
            control_write_defaults()
            logging.info("defaults written")

            # Start receiving packets
            write_new_packets = True

            # Start the control loop
            logging.info("control loop")
            control_loop(sniffer)
            logging.info("exiting control loop")

        else:
            logging.info("")
            # Start receiving packets
            write_new_packets = True
            while True:
                # Wait for keyboardinterrupt
                pass

    except Exceptions.LockedException as e:
        logging.info('{}'.format(e.message))

    except OSError:
        # We'll get OSError=22 when/if wireshark kills the pipe(s) on capture
        # stop.
        pass

    finally:
        # The first thing we should do is to tear down the extcap log handler.
        # This might already have triggered an OSError, or we will trigger one
        # by attempting to log at this point.
        teardown_extcap_log_handler()

        # Safe to use logging again.
        logging.info("Tearing down")

        sniffer.doExit()
        if fn_capture is not None and not fn_capture.closed:
            fn_capture.close()

        if fn_ctrl_in is not None and not fn_ctrl_in.closed:
            fn_ctrl_in.close()

        if fn_ctrl_out is not None and not fn_ctrl_out.closed:
            fn_ctrl_out.close()

        fn_capture = None
        fn_ctrl_out = None
        fn_ctrl_in = None

        logging.info("Exiting")


def extcap_close_fifo(fifo):
    """"Close extcap fifo"""
    if not os.path.exists(fifo):
        print("FIFO does not exist!", file=sys.stderr)
        return

    # This is apparently needed to workaround an issue on Windows/macOS
    # where the message cannot be read. (really?)
    fh = open(fifo, 'wb', 0)
    fh.close()


class ExtcapLoggerHandler(logging.Handler):
    """Handler used to display all logging messages in extcap"""

    def emit(self, record):
        """Send log message to extcap"""
        message = record.message.replace('\0', '\\0')
        log_message = f"{record.levelname}: {message}\n"
        control_write(CTRL_ARG_LOG, CTRL_CMD_ADD, log_message)


def parse_capture_filter(capture_filter):
    """"Parse given capture filter"""
    global rssi_filter
    m = re.search("^\s*rssi\s*(>=?)\s*(-?[0-9]+)\s*$", capture_filter, re.IGNORECASE)
    if m:
        rssi_filter = int(m.group(2))
        if rssi_filter > -10 or rssi_filter < -256:
            print("Illegal RSSI value, must be between -10 and -256")
        # Handle >= by modifying the threshold, since comparisons are always done with
        # the > operator
        if m.group(1) == '>=':
            rssi_filter = rssi_filter - 1
    else:
        print("Filter syntax: \"RSSI >= -value\"")

import atexit

@atexit.register
def goodbye():
   logging.info("Exiting PID {}".format(os.getpid())) 


if __name__ == '__main__':

    # Capture options
    parser = argparse.ArgumentParser(description="Nordic Semiconductor nRF Sniffer for Bluetooth LE extcap plugin")

    # Extcap Arguments
    parser.add_argument("--capture",
                        help="Start the capture",
                        action="store_true")

    parser.add_argument("--extcap-interfaces",
                        help="List available interfaces to capture from",
                        action="store_true")

    parser.add_argument("--extcap-interface",
                        help="The interface to capture from")

    parser.add_argument("--extcap-dlts",
                        help="List DLTs for the given interface",
                        action="store_true")

    parser.add_argument("--extcap-config",
                        help="List configurations for the given interface",
                        action="store_true")

    parser.add_argument("--extcap-capture-filter",
                        help="Used together with capture to provide a capture filter")

    parser.add_argument("--fifo",
                        help="Use together with capture to provide the fifo to dump data to")

    parser.add_argument("--extcap-control-in",
                        help="Used together with capture to get control messages from toolbar")

    parser.add_argument("--extcap-control-out",
                        help="Used together with capture to send control messages to toolbar")

    parser.add_argument("--extcap-version",
                        help="Set extcap supported version")

    # Interface Arguments
    parser.add_argument("--device", help="Device", default="")
    parser.add_argument("--baudrate", type=int, help="The sniffer baud rate")
    parser.add_argument("--only-advertising", help="Only advertising packets", action="store_true")
    parser.add_argument("--only-legacy-advertising", help="Only legacy advertising packets", action="store_true")
    parser.add_argument("--scan-follow-rsp", help="Find scan response data ", action="store_true")
    parser.add_argument("--scan-follow-aux", help="Find auxiliary pointer data", action="store_true")
    parser.add_argument("--coded", help="Scan and follow on LE Coded PHY", action="store_true")

    logging.info("Started PID {}".format(os.getpid()))

    try:
        args, unknown = parser.parse_known_args()
        logging.info(args)

    except argparse.ArgumentError as exc:
        print("%s" % exc, file=sys.stderr)
        fifo_found = False
        fifo = ""
        for arg in sys.argv:
            if arg == "--fifo" or arg == "--extcap-fifo":
                fifo_found = True
            elif fifo_found:
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)

    if len(sys.argv) <= 1:
        parser.exit("No arguments given!")

    if args.extcap_version:
        extcap_version = args.extcap_version

    if args.extcap_capture_filter:
        parse_capture_filter(args.extcap_capture_filter)
        if args.extcap_interface and len(sys.argv) == 5:
            sys.exit(0)

    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit("An interface must be provided or the selection must be displayed")

    if args.extcap_interfaces or args.extcap_interface is None:
        extcap_interfaces()
        sys.exit(0)

    if len(unknown) > 0:
        print("Sniffer %d unknown arguments given" % len(unknown))
        logging.info("Sniffer %d unknown arguments given" % len(unknown))

    interface = args.extcap_interface

    capture_only_advertising = args.only_advertising
    capture_only_legacy_advertising = args.only_legacy_advertising
    capture_scan_response = args.scan_follow_rsp
    capture_scan_aux_pointer = args.scan_follow_aux
    capture_coded = args.coded

    if args.extcap_config:
        extcap_config(interface)
    elif args.extcap_dlts:
        extcap_dlts(interface)
    elif args.capture:
        if args.fifo is None:
            parser.print_help()
            sys.exit(ERROR_FIFO)
        try:
            logging.info('sniffer capture')
            sniffer_capture(interface, args.baudrate, args.fifo, args.extcap_control_in, args.extcap_control_out)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            import traceback
            logging.info(traceback.format_exc())
            logging.info('internal error: {}'.format(repr(e)))
            sys.exit(ERROR_INTERNAL)
    else:
        parser.print_help()
        sys.exit(ERROR_USAGE)
    logging.info('main exit PID {}'.format(os.getpid()))
