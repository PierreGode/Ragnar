#!/usr/bin/env python3
"""
Rubber Ducky Script Parser and HID Executor
Supports both official .ducky syntax and plain text instructions

WARNING: This module contains tools for hardware-level input emulation.
Only use on systems you own or have explicit permission to test.
"""

import os
import sys
import re
import time
import logging
import subprocess
from typing import List, Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# HID key mappings (USB keycodes)
HID_KEYCODES = {
    'A': 0x04, 'B': 0x05, 'C': 0x06, 'D': 0x07, 'E': 0x08, 'F': 0x09,
    'G': 0x0A, 'H': 0x0B, 'I': 0x0C, 'J': 0x0D, 'K': 0x0E, 'L': 0x0F,
    'M': 0x10, 'N': 0x11, 'O': 0x12, 'P': 0x13, 'Q': 0x14, 'R': 0x15,
    'S': 0x16, 'T': 0x17, 'U': 0x18, 'V': 0x19, 'W': 0x1A, 'X': 0x1B,
    'Y': 0x1C, 'Z': 0x1D,
    '1': 0x1E, '2': 0x1F, '3': 0x20, '4': 0x21, '5': 0x22,
    '6': 0x23, '7': 0x24, '8': 0x25, '9': 0x26, '0': 0x27,
    'ENTER': 0x28, 'ESCAPE': 0x29, 'BACKSPACE': 0x2A, 'TAB': 0x2B,
    'SPACE': 0x2C, 'MINUS': 0x2D, 'EQUAL': 0x2E, 'LBRACKET': 0x2F,
    'RBRACKET': 0x30, 'BACKSLASH': 0x31, 'SEMICOLON': 0x33, 'QUOTE': 0x34,
    'BACKTICK': 0x35, 'COMMA': 0x36, 'PERIOD': 0x37, 'SLASH': 0x38,
    'F1': 0x3A, 'F2': 0x3B, 'F3': 0x3C, 'F4': 0x3D, 'F5': 0x3E,
    'F6': 0x3F, 'F7': 0x40, 'F8': 0x41, 'F9': 0x42, 'F10': 0x43,
    'F11': 0x44, 'F12': 0x45,
    'UP': 0x52, 'DOWN': 0x51, 'LEFT': 0x50, 'RIGHT': 0x4F,
    'HOME': 0x4A, 'END': 0x4D, 'DELETE': 0x4C, 'INSERT': 0x49,
}

# Modifier key mappings
MODIFIERS = {
    'CTRL': 0x01,
    'SHIFT': 0x02,
    'ALT': 0x04,
    'GUI': 0x08,  # Windows/Command key
}


class RubberDuckyScript:
    """Parser and executor for Rubber Ducky scripts"""

    def __init__(self):
        self.commands = []
        self.errors = []

    def parse_ducky_format(self, content: str) -> bool:
        """Parse official Rubber Ducky .ducky syntax

        Supports:
        - DELAY <milliseconds>
        - STRING <text>
        - ENTER / SPACE / TAB / etc.
        - Modifiers: CTRL, SHIFT, ALT, GUI
        """
        lines = content.strip().split('\n')
        line_num = 0

        for line_num, line in enumerate(lines, 1):
            # Remove comments
            if '#' in line:
                line = line[:line.index('#')]

            line = line.strip()
            if not line:
                continue

            parts = line.split(None, 1)
            command = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else None

            try:
                if command == 'DELAY':
                    if not arg or not arg.isdigit():
                        self.errors.append(f"Line {line_num}: DELAY requires milliseconds")
                        continue
                    self.commands.append({
                        'type': 'delay',
                        'ms': int(arg)
                    })

                elif command == 'STRING':
                    if not arg:
                        self.errors.append(f"Line {line_num}: STRING requires text")
                        continue
                    self.commands.append({
                        'type': 'string',
                        'text': arg
                    })

                elif command == 'ENTER':
                    self.commands.append({'type': 'key', 'key': 'ENTER'})

                elif command == 'SPACE':
                    self.commands.append({'type': 'key', 'key': 'SPACE'})

                elif command == 'TAB':
                    self.commands.append({'type': 'key', 'key': 'TAB'})

                elif command in HID_KEYCODES:
                    self.commands.append({'type': 'key', 'key': command})

                elif command in MODIFIERS:
                    # Modifier + optional key
                    self.commands.append({
                        'type': 'modifier',
                        'modifier': command,
                        'key': arg
                    })

                else:
                    self.errors.append(f"Line {line_num}: Unknown command '{command}'")

            except Exception as e:
                self.errors.append(f"Line {line_num}: {str(e)}")

        return len(self.errors) == 0

    def parse_text_format(self, content: str) -> bool:
        """Parse plain text instructions

        Format: line-by-line commands like:
        - type: Hello World
        - press: enter
        - wait: 500
        - key: ctrl+c
        """
        lines = content.strip().split('\n')

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                if line.lower().startswith('type:'):
                    text = line[5:].strip()
                    self.commands.append({
                        'type': 'string',
                        'text': text
                    })

                elif line.lower().startswith('press:'):
                    key = line[6:].strip().upper()
                    if key in HID_KEYCODES:
                        self.commands.append({'type': 'key', 'key': key})
                    else:
                        self.errors.append(f"Line {line_num}: Unknown key '{key}'")

                elif line.lower().startswith('wait:') or line.lower().startswith('delay:'):
                    ms = int(line.split(':', 1)[1].strip())
                    self.commands.append({'type': 'delay', 'ms': ms})

                elif line.lower().startswith('key:'):
                    key_combo = line[4:].strip()
                    self._parse_key_combo(key_combo)

                else:
                    self.errors.append(f"Line {line_num}: Invalid instruction '{line}'")

            except Exception as e:
                self.errors.append(f"Line {line_num}: {str(e)}")

        return len(self.errors) == 0

    def _parse_key_combo(self, combo: str):
        """Parse key combinations like 'CTRL+C' or 'ALT+F4'"""
        parts = combo.split('+')
        modifiers = 0
        key = None

        for part in parts:
            part = part.upper().strip()
            if part in MODIFIERS:
                modifiers |= MODIFIERS[part]
            elif part in HID_KEYCODES:
                key = part
            else:
                self.errors.append(f"Unknown key or modifier: {part}")

        if key:
            self.commands.append({
                'type': 'key_with_modifier',
                'key': key,
                'modifiers': modifiers
            })

    def get_preview(self) -> str:
        """Generate human-readable preview of the script"""
        preview = []

        for i, cmd in enumerate(self.commands, 1):
            if cmd['type'] == 'delay':
                preview.append(f"{i}. Wait {cmd['ms']}ms")

            elif cmd['type'] == 'string':
                text = cmd['text'][:50]
                if len(cmd['text']) > 50:
                    text += "..."
                preview.append(f"{i}. Type: {text}")

            elif cmd['type'] == 'key':
                preview.append(f"{i}. Press: {cmd['key']}")

            elif cmd['type'] == 'key_with_modifier':
                mods = [k for k, v in MODIFIERS.items() if cmd['modifiers'] & v]
                preview.append(f"{i}. Press: {'+'.join(mods)}+{cmd['key']}")

            elif cmd['type'] == 'modifier':
                preview.append(f"{i}. Hold: {cmd['modifier']}")

        if self.errors:
            preview.append("\n⚠ Parsing Errors:")
            for err in self.errors:
                preview.append(f"  - {err}")

        return "\n".join(preview)

    async def execute_on_device(self, device_path: str, timeout: int = 30) -> Dict:
        """Execute script on HID device

        Args:
            device_path: Path to /dev/hidraw* device
            timeout: Max execution time in seconds

        Returns:
            Dict with execution status and result
        """
        try:
            if not os.path.exists(device_path):
                return {
                    'success': False,
                    'error': f"Device not found: {device_path}"
                }

            executed = 0
            start_time = time.time()

            for cmd in self.commands:
                if time.time() - start_time > timeout:
                    return {
                        'success': False,
                        'executed': executed,
                        'error': f'Timeout after {executed} commands'
                    }

                try:
                    if cmd['type'] == 'delay':
                        time.sleep(cmd['ms'] / 1000.0)

                    elif cmd['type'] == 'string':
                        self._send_string(device_path, cmd['text'])

                    elif cmd['type'] == 'key':
                        self._send_key(device_path, cmd['key'])

                    elif cmd['type'] == 'key_with_modifier':
                        self._send_key_with_modifier(
                            device_path,
                            cmd['key'],
                            cmd['modifiers']
                        )

                    executed += 1

                except Exception as e:
                    return {
                        'success': False,
                        'executed': executed,
                        'error': f"Command {executed} failed: {str(e)}"
                    }

            return {
                'success': True,
                'executed': executed,
                'total': len(self.commands)
            }

        except Exception as e:
            logger.error(f"Script execution error: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _send_string(self, device_path: str, text: str):
        """Send string by typing each character"""
        for char in text:
            self._send_char(device_path, char)
            time.sleep(0.02)  # Small delay between chars

    def _send_char(self, device_path: str, char: str):
        """Send single character"""
        key = char.upper() if char.isalpha() else char

        if key in HID_KEYCODES:
            keycode = HID_KEYCODES[key]
        else:
            # Try to map special chars
            special_map = {
                ' ': 'SPACE',
                '.': 'PERIOD',
                ',': 'COMMA',
                '-': 'MINUS',
                '=': 'EQUAL',
                '[': 'LBRACKET',
                ']': 'RBRACKET',
                ';': 'SEMICOLON',
                "'": 'QUOTE',
                '/': 'SLASH',
                '\\': 'BACKSLASH',
                '`': 'BACKTICK',
            }
            if char in special_map:
                key = special_map[char]
                keycode = HID_KEYCODES[key]
            else:
                logger.warning(f"Cannot map character: {char}")
                return

        self._send_hid_report(device_path, keycode, 0)

    def _send_key(self, device_path: str, key: str):
        """Send key press"""
        if key in HID_KEYCODES:
            keycode = HID_KEYCODES[key]
            self._send_hid_report(device_path, keycode, 0)

    def _send_key_with_modifier(self, device_path: str, key: str, modifiers: int):
        """Send key with modifier(s)"""
        if key in HID_KEYCODES:
            keycode = HID_KEYCODES[key]
            self._send_hid_report(device_path, keycode, modifiers)

    def _send_hid_report(self, device_path: str, keycode: int, modifiers: int):
        """Send raw HID report to device

        Standard USB keyboard HID report format:
        [Modifier, Reserved, Key1, Key2, Key3, Key4, Key5, Key6]
        """
        try:
            with open(device_path, 'wb') as f:
                # Press key
                report = bytes([modifiers, 0, keycode, 0, 0, 0, 0, 0])
                f.write(report)

                # Release key
                time.sleep(0.01)
                report = bytes([0, 0, 0, 0, 0, 0, 0, 0])
                f.write(report)

        except Exception as e:
            logger.error(f"HID write error: {e}")
            raise


def list_hid_devices() -> List[Dict]:
    """List available HID devices (USB Ducky, keyboards, etc.)"""
    devices = []

    try:
        # Look for /dev/hidraw* devices
        hidraw_devices = Path('/dev').glob('hidraw*')

        for hidraw in hidraw_devices:
            try:
                # Try to get device info
                phy_path = Path('/sys/class/hidraw') / hidraw.name / 'device'
                if phy_path.exists():
                    name_file = phy_path / 'name'
                    if name_file.exists():
                        name = name_file.read_text().strip()
                    else:
                        name = hidraw.name

                    devices.append({
                        'path': str(hidraw),
                        'name': name,
                        'type': 'hidraw'
                    })
            except Exception as e:
                logger.debug(f"Error reading HID device info: {e}")

    except Exception as e:
        logger.error(f"Error listing HID devices: {e}")

    # Also check for USB Ducky devices directly
    try:
        result = subprocess.run(
            ['lsusb', '-d', '16c0:'],  # Hacker Boards vendor ID
            capture_output=True,
            text=True,
            timeout=2
        )

        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if 'Rubber Ducky' in line or 'USB Keyboard' in line:
                    devices.append({
                        'name': line.split(':', 1)[1].strip() if ':' in line else line,
                        'path': 'usb_device',
                        'type': 'usb'
                    })

    except Exception as e:
        logger.debug(f"Error running lsusb: {e}")

    return devices


def list_scripts(scripts_dir: str = 'files/rubber-ducky') -> List[Dict]:
    """List available rubber ducky scripts"""
    scripts = []
    scripts_path = Path(scripts_dir)

    if not scripts_path.exists():
        scripts_path.mkdir(parents=True, exist_ok=True)
        return scripts

    try:
        for script_file in scripts_path.glob('*'):
            if script_file.is_file() and script_file.suffix in ['.ducky', '.txt', '.py']:
                try:
                    size = script_file.stat().st_size
                    mtime = script_file.stat().st_mtime

                    scripts.append({
                        'name': script_file.name,
                        'path': str(script_file),
                        'size': size,
                        'modified': mtime,
                        'extension': script_file.suffix
                    })
                except Exception as e:
                    logger.error(f"Error reading script: {e}")

    except Exception as e:
        logger.error(f"Error listing scripts: {e}")

    return sorted(scripts, key=lambda x: x['name'])
