#!/usr/bin/env python3
"""
Rubber Ducky Script Parser and HID Executor
Supports both official .ducky syntax and plain text instructions

WARNING: This module contains tools for hardware-level input emulation.
Only use on systems you own or have explicit permission to test.
"""

import os
import time
import logging
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

# Characters produced by holding Shift. Each maps to the UNSHIFTED key whose
# keycode is sent together with the Shift modifier (US layout).
SHIFT_CHARS = {
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
    '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
    ':': ';', '"': "'", '~': '`', '<': ',', '>': '.', '?': '/',
}

# Unshifted punctuation → the HID_KEYCODES name for that physical key.
SYMBOL_KEYS = {
    ' ': 'SPACE', '-': 'MINUS', '=': 'EQUAL', '[': 'LBRACKET',
    ']': 'RBRACKET', '\\': 'BACKSLASH', ';': 'SEMICOLON', "'": 'QUOTE',
    '`': 'BACKTICK', ',': 'COMMA', '.': 'PERIOD', '/': 'SLASH',
}


def resolve_char(char: str) -> Tuple[Optional[int], int]:
    """Map a single printable character to (keycode, modifiers).

    Returns (None, 0) if the character cannot be typed on a US layout.
    Handles letter case and Shift-produced symbols so the keystrokes a host
    receives match the script text (e.g. ``!`` and uppercase letters).
    """
    if char.isalpha():
        keycode = HID_KEYCODES[char.upper()]
        mods = MODIFIERS['SHIFT'] if char.isupper() else 0
        return keycode, mods

    if char.isdigit():
        return HID_KEYCODES[char], 0

    if char in SHIFT_CHARS:
        base = SHIFT_CHARS[char]
        keycode = HID_KEYCODES.get(base)
        if keycode is None:
            keycode = HID_KEYCODES[SYMBOL_KEYS[base]]
        return keycode, MODIFIERS['SHIFT']

    if char in SYMBOL_KEYS:
        return HID_KEYCODES[SYMBOL_KEYS[char]], 0

    return None, 0


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
        - REM / leading-# comment lines
        """
        lines = content.strip().split('\n')
        line_num = 0

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # Comment lines only: a leading '#' or a REM directive. Inline '#'
            # is left intact — it is a legal character inside a STRING payload.
            if line.startswith('#'):
                continue

            parts = line.split(None, 1)
            command = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else None

            if command == 'REM':
                continue

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
                    # One or more modifiers, then an optional final key, e.g.
                    # "GUI r", "CTRL ALT t", "CTRL ALT DELETE".
                    mods = MODIFIERS[command]
                    key = None
                    for tok in (arg.split() if arg else []):
                        tu = tok.upper()
                        if tu in MODIFIERS:
                            mods |= MODIFIERS[tu]
                        else:
                            key = tu  # first non-modifier token is the key
                            break
                    self.commands.append({
                        'type': 'key_with_modifier',
                        'key': key,
                        'modifiers': mods
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
                combo = '+'.join(mods + ([cmd['key']] if cmd.get('key') else []))
                preview.append(f"{i}. Press: {combo}")

        if self.errors:
            preview.append("\n⚠ Parsing Errors:")
            for err in self.errors:
                preview.append(f"  - {err}")

        return "\n".join(preview)

    def execute_on_device(self, device_path: str, timeout: int = 30) -> Dict:
        """Execute script on a USB HID keyboard gadget.

        Args:
            device_path: Path to the HID gadget node (``/dev/hidg0``) that
                emulates a keyboard to the connected host.
            timeout: Max execution time in seconds

        Returns:
            Dict with execution status and result
        """
        if not os.path.exists(device_path):
            return {'success': False, 'error': f"Device not found: {device_path}"}

        executed = 0
        start_time = time.time()

        try:
            # Open the gadget node once and stream every report through it.
            # Re-opening per keystroke would truncate/reset the endpoint; a
            # single unbuffered handle is both correct and faster.
            with open(device_path, 'wb', buffering=0) as fh:
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
                            self._send_string(fh, cmd['text'])

                        elif cmd['type'] == 'key':
                            self._send_key(fh, cmd['key'])

                        elif cmd['type'] == 'key_with_modifier':
                            self._send_key_with_modifier(fh, cmd['key'], cmd['modifiers'])

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
            return {'success': False, 'executed': executed, 'error': str(e)}

    def _send_string(self, fh, text: str):
        """Send string by typing each character"""
        for char in text:
            self._send_char(fh, char)
            time.sleep(0.02)  # Small delay between chars

    def _send_char(self, fh, char: str):
        """Send a single character, applying Shift for capitals and symbols."""
        keycode, modifiers = resolve_char(char)
        if keycode is None:
            logger.warning(f"Cannot map character: {char!r}")
            return
        self._write_report(fh, keycode, modifiers)

    def _send_key(self, fh, key: str):
        """Send key press"""
        if key in HID_KEYCODES:
            self._write_report(fh, HID_KEYCODES[key], 0)

    def _send_key_with_modifier(self, fh, key, modifiers: int):
        """Send a key plus modifier(s); key may be None for a modifier-only press."""
        if not key:
            self._write_report(fh, 0, modifiers)          # e.g. GUI alone
        elif key in HID_KEYCODES:
            self._write_report(fh, HID_KEYCODES[key], modifiers)
        else:
            logger.warning(f"Unmapped modifier-combo key: {key!r}")
            self._write_report(fh, 0, modifiers)

    def _write_report(self, fh, keycode: int, modifiers: int):
        """Write one press+release to an open HID gadget handle.

        Standard USB boot-keyboard report:
        [Modifier, Reserved, Key1..Key6]
        """
        fh.write(bytes([modifiers, 0, keycode, 0, 0, 0, 0, 0]))  # press
        time.sleep(0.01)
        fh.write(bytes([0, 0, 0, 0, 0, 0, 0, 0]))                # release


def hid_gadget_ready() -> bool:
    """True when a USB HID keyboard gadget node (/dev/hidg*) is present.

    The node only exists when the box is configured as a USB HID gadget and
    the gadget is bound to a UDC (plugged into a host). ``install_ragnar.sh``
    adds the ``hid.usb0`` function to the composite gadget.
    """
    try:
        return any(Path('/dev').glob('hidg*'))
    except Exception:
        return False


def list_hid_devices() -> List[Dict]:
    """List USB HID keyboard gadget nodes usable as injection targets.

    These are ``/dev/hidg*`` nodes — the keyboard the Pi presents to a host it
    is plugged into. (``/dev/hidraw*`` is the opposite direction — a peripheral
    attached to the Pi — so it is intentionally not listed here.)
    """
    devices = []
    try:
        for node in sorted(Path('/dev').glob('hidg*')):
            devices.append({
                'path': str(node),
                'name': f'USB HID keyboard gadget ({node.name})',
                'type': 'gadget',
            })
    except Exception as e:
        logger.error(f"Error listing HID gadget devices: {e}")

    return devices


# Scripts live in the repo's files/ tree so the Files tab can manage them.
# Resolve from this module's location so the executor and the web upload target
# always agree regardless of the process working directory.
DEFAULT_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / 'files' / 'rubber-ducky'


def list_scripts(scripts_dir=None) -> List[Dict]:
    """List available rubber ducky scripts"""
    scripts = []
    scripts_path = Path(scripts_dir) if scripts_dir else DEFAULT_SCRIPTS_DIR

    if not scripts_path.exists():
        scripts_path.mkdir(parents=True, exist_ok=True)
        return scripts

    try:
        for script_file in scripts_path.glob('*'):
            if script_file.is_file() and script_file.suffix in ['.ducky', '.txt']:
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


# Bundled, read-only payload library shipped with the repo.
DEFAULT_LIBRARY_DIR = Path(__file__).resolve().parent.parent / 'resources' / 'ducky_payloads'


def _first_comment(path: Path) -> str:
    """First REM / leading-# line of a payload, used as its description."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                s = line.strip()
                if s.upper().startswith('REM '):
                    return s[4:].strip()
                if s.startswith('#'):
                    return s.lstrip('#').strip()
                if s:
                    break
    except Exception:
        pass
    return ''


def list_library(library_dir=None) -> List[Dict]:
    """List the bundled payload library (name + description)."""
    out = []
    lib = Path(library_dir) if library_dir else DEFAULT_LIBRARY_DIR
    if not lib.exists():
        return out
    try:
        for p in sorted(lib.glob('*')):
            if p.is_file() and p.suffix in ['.ducky', '.txt']:
                out.append({'name': p.name, 'description': _first_comment(p),
                            'size': p.stat().st_size})
    except Exception as e:
        logger.error(f"Error listing payload library: {e}")
    return out


def _safe_script_name(name: str) -> Optional[str]:
    """Return a safe basename ending in .ducky/.txt, or None if invalid."""
    if not name:
        return None
    base = os.path.basename(name.strip())
    if base in ('', '.', '..') or '/' in name or '\\' in name:
        return None
    if not base.lower().endswith(('.ducky', '.txt')):
        return None
    return base


def install_payload(name: str) -> Dict:
    """Copy a bundled library payload into the editable scripts folder."""
    base = _safe_script_name(name)
    if not base:
        return {'success': False, 'error': 'Invalid payload name'}
    src = DEFAULT_LIBRARY_DIR / base
    if not src.is_file():
        return {'success': False, 'error': f'Not in library: {base}'}
    DEFAULT_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    dst = DEFAULT_SCRIPTS_DIR / base
    try:
        dst.write_text(src.read_text(encoding='utf-8', errors='replace'), encoding='utf-8')
        return {'success': True, 'name': base}
    except Exception as e:
        logger.error(f"Error installing payload {base}: {e}")
        return {'success': False, 'error': str(e)}


def save_script(name: str, content: str) -> Dict:
    """Create or overwrite a script in the editable scripts folder."""
    base = _safe_script_name(name)
    if not base:
        return {'success': False, 'error': 'Name must be a .ducky or .txt file'}
    DEFAULT_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        (DEFAULT_SCRIPTS_DIR / base).write_text(content or '', encoding='utf-8')
        return {'success': True, 'name': base}
    except Exception as e:
        logger.error(f"Error saving script {base}: {e}")
        return {'success': False, 'error': str(e)}
