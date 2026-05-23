# espnow_coordinator.py
# Piglet-compatible ESP-Now Coordinator (Core) mode for Ragnar.
#
# Implements the JCMK mesh protocol used by PigletNode firmware so that Ragnar
# can act as the central coordinator in a Piglet wardriving mesh:
#
#   MSG_CORE_REQUEST  (1)  Node broadcasts, looking for a coordinator
#   MSG_CORE_REPLY    (2)  We unicast back to complete pairing
#   MSG_HEARTBEAT     (3)  Bidirectional keepalive (30 s timeout on nodes)
#   MSG_TEXT          (4)  Node streams WiFi records "BSSID,SSID,AUTH,CH,RSSI,W"
#   MSG_ADMIN         (5)  We assign channel-table slices to nodes
#
# Hardware requirement:
#   An ESP32 USB dongle running espnow_bridge_firmware/espnow_bridge.ino.
#   That firmware initialises ESP-Now on channel 6 and relays every packet
#   over USB-serial as a binary frame (described below).  Ragnar cannot
#   speak ESP-Now natively because Linux has no ESP-Now driver.
#
# Bridge frame format (host <-> ESP32, both directions):
#   SYNC  [2]  = 0xAB 0xCD
#   CMD   [1]  = 0x01 RX (ESP32→Pi)  0x02 TX (Pi→ESP32)
#               0x03 HELLO            0x05 STATS (Pi→ESP32 stat push)
#   MAC   [6]  = source MAC (RX) / destination MAC (TX) / bridge MAC (HELLO)
#              = 0x00*6 for STATS
#   LEN   [2]  = payload length, little-endian
#   PAYLOAD[N]
#   CRC   [1]  = XOR of CMD + MAC[0..5] + LEN_lo + LEN_hi + PAYLOAD bytes
#
# CMD_STATS payload (6 bytes):
#   nodes   [1]  active node count
#   gps_fix [1]  1 = GPS fix, 0 = no fix
#   net24   [2]  2.4 GHz network count, little-endian
#   net50   [2]  5 GHz network count, little-endian

import time
import struct
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Callable

logger = logging.getLogger("EspNowCoordinator")

# ── JCMK protocol ──────────────────────────────────────────────────────────────
JCMK_MAGIC        = b'ENOW'
MSG_CORE_REQUEST  = 1
MSG_CORE_REPLY    = 2
MSG_HEARTBEAT     = 3
MSG_TEXT          = 4
MSG_ADMIN         = 5

ESPNOW_HOME_CH    = 6
MAX_NODES         = 4
NODE_TIMEOUT_S    = 30.0
HB_INTERVAL_S     = 5.0

# 42-entry channel table matching PigletNode firmware (indices 0-41)
_CH_24 = list(range(1, 15))                                    # 14 × 2.4 GHz
_CH_50 = [36, 40, 44, 48, 52, 56, 60, 64,
          100, 104, 108, 112, 116, 120, 124, 128,
          132, 136, 140, 144, 149, 153, 157, 161,
          165, 169, 173, 177]                                   # 28 × 5 GHz
CHANNEL_TABLE = _CH_24 + _CH_50

# ── Bridge frame ───────────────────────────────────────────────────────────────
SYNC_A, SYNC_B                = 0xAB, 0xCD
CMD_RX, CMD_TX, CMD_HELLO     = 0x01, 0x02, 0x03
CMD_STATS                     = 0x05   # host → bridge: stat push for LCD
_BCAST_MAC        = bytes([0xFF] * 6)

# Maximum ESP-Now payload (ESP-IDF cap is 250 bytes)
_MAX_PAYLOAD      = 250
# jcmk_text_msg_t fixed size used by Biscuit variant
_BISCUIT_PKT_LEN  = 212


# ── Node registry entry ────────────────────────────────────────────────────────
@dataclass
class MeshNode:
    mac: bytes
    node_index: int
    start_idx: int = 0
    end_idx: int = 13           # default: all 2.4 GHz channels
    assignment_version: int = 0
    last_heartbeat: float = field(default_factory=time.time)
    records_rx: int = 0
    is_biscuit: bool = False    # True if node speaks 212-byte Biscuit frames

    @property
    def mac_str(self) -> str:
        return ':'.join(f'{b:02X}' for b in self.mac)


# ── Main coordinator class ─────────────────────────────────────────────────────
class EspNowCoordinator:
    """
    Piglet-compatible ESP-Now mesh coordinator for Ragnar.

    Attach to a WardrivingEngine by supplying an on_network callback:

        def my_cb(bssid, ssid, auth, channel, rssi, node_mac):
            # GPS-stamp and persist the record here
            ...

        coord = EspNowCoordinator(on_network=my_cb)
        coord.set_send_callback(lambda data: ser.write(data))
        coord.start()
        ...
        while running:
            data = ser.read(ser.in_waiting or 1)
            coord.feed(data)
        ...
        coord.stop()
    """

    def __init__(self, on_network: Optional[Callable] = None):
        self._on_network   = on_network
        self._nodes: List[MeshNode] = []
        self._lock         = threading.Lock()
        self._running      = False
        self._bridge_mac: Optional[bytes] = None
        self._send_cb: Optional[Callable[[bytes], None]] = None
        self._hb_thread: Optional[threading.Thread] = None

        # Binary frame parser state
        self._rx_buf  = bytearray(16 + _MAX_PAYLOAD)
        self._rx_pos  = 0
        self._in_sync = False

        # Public stats (read by WardrivingEngine for status/UI)
        self.records_rx  = 0
        self.node_count  = 0

        # Band-split counters (for LCD STATS push)
        self.networks_24 = 0   # channels 1-14
        self.networks_50 = 0   # channels 36+
        self._gps_fix    = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def set_send_callback(self, cb: Callable[[bytes], None]):
        """Register the function that writes bytes to the ESP32 bridge."""
        self._send_cb = cb

    def set_gps_fix(self, fix: bool):
        """Called by WardrivingEngine to report current GPS fix status."""
        self._gps_fix = fix

    def feed(self, data: bytes):
        """Feed raw bytes received from the serial bridge."""
        for b in data:
            self._parse_byte(b)

    def start(self):
        self._running   = True
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="espnow-coord-hb"
        )
        self._hb_thread.start()
        logger.info("ESP-Now coordinator started — listening for Piglet nodes on ch 6")

    def stop(self):
        self._running = False
        logger.info("ESP-Now coordinator stopped")

    @property
    def active_nodes(self) -> List[MeshNode]:
        with self._lock:
            return list(self._nodes)

    def get_status(self) -> dict:
        with self._lock:
            nodes = [
                {
                    'mac':        n.mac_str,
                    'index':      n.node_index,
                    'channels':   f'{CHANNEL_TABLE[n.start_idx]}–{CHANNEL_TABLE[n.end_idx]}',
                    'records_rx': n.records_rx,
                    'last_seen_s': round(time.time() - n.last_heartbeat, 1),
                    'protocol':   'Biscuit' if n.is_biscuit else 'JCMK',
                }
                for n in self._nodes
            ]
        return {
            'active':      self._running,
            'node_count':  self.node_count,
            'records_rx':  self.records_rx,
            'bridge_mac':  ':'.join(f'{b:02X}' for b in self._bridge_mac)
                           if self._bridge_mac else None,
            'nodes':       nodes,
        }

    # ── Binary frame parser ────────────────────────────────────────────────────

    def _parse_byte(self, b: int):
        if not self._in_sync:
            if self._rx_pos == 0 and b == SYNC_A:
                self._rx_buf[0] = b
                self._rx_pos    = 1
            elif self._rx_pos == 1 and b == SYNC_B:
                self._rx_buf[1] = b
                self._rx_pos    = 2
                self._in_sync   = True
            else:
                self._rx_pos = 0
            return

        self._rx_buf[self._rx_pos] = b
        self._rx_pos += 1

        # Full header: SYNC(2)+CMD(1)+MAC(6)+LEN(2) = 11 bytes
        if self._rx_pos < 11:
            return

        plen = self._rx_buf[9] | (self._rx_buf[10] << 8)
        if plen > _MAX_PAYLOAD:
            self._reset_parser()
            return

        total = 11 + plen + 1           # header + payload + crc
        if self._rx_pos < total:
            return

        cmd      = self._rx_buf[2]
        mac      = bytes(self._rx_buf[3:9])
        payload  = bytes(self._rx_buf[11:11 + plen])
        got_crc  = self._rx_buf[total - 1]

        if self._crc(cmd, mac, payload) == got_crc:
            self._handle_bridge_frame(cmd, mac, payload)
        else:
            logger.debug("Bridge frame CRC mismatch — dropped")

        self._reset_parser()

    def _reset_parser(self):
        self._rx_pos  = 0
        self._in_sync = False

    @staticmethod
    def _crc(cmd: int, mac: bytes, payload: bytes) -> int:
        crc = cmd
        for b in mac:
            crc ^= b
        crc ^= len(payload) & 0xFF
        crc ^= len(payload) >> 8
        for b in payload:
            crc ^= b
        return crc & 0xFF

    # ── Bridge frame dispatch ──────────────────────────────────────────────────

    def _handle_bridge_frame(self, cmd: int, mac: bytes, payload: bytes):
        if cmd == CMD_HELLO:
            self._bridge_mac = mac
            logger.info(f"Bridge identified: {':'.join(f'{b:02X}' for b in mac)}")
        elif cmd == CMD_RX:
            self._handle_espnow_packet(mac, payload)

    # ── ESP-Now packet dispatch ────────────────────────────────────────────────

    def _handle_espnow_packet(self, src_mac: bytes, payload: bytes):
        if len(payload) < 5 or payload[:4] != JCMK_MAGIC:
            return
        msg_type = payload[4]
        if msg_type == MSG_CORE_REQUEST:
            self._handle_core_request(src_mac, payload)
        elif msg_type == MSG_HEARTBEAT:
            self._handle_heartbeat(src_mac)
        elif msg_type == MSG_TEXT:
            self._handle_text(src_mac, payload)
        else:
            logger.debug(f"Unhandled JCMK msg_type={msg_type} from {src_mac.hex(':')}")

    # ── JCMK handlers ─────────────────────────────────────────────────────────

    def _handle_core_request(self, src_mac: bytes, payload: bytes):
        with self._lock:
            node = self._find_node(src_mac)
            if node is None:
                if len(self._nodes) >= MAX_NODES:
                    logger.warning(
                        f"MAX_NODES={MAX_NODES} reached — rejecting {src_mac.hex(':')}"
                    )
                    return
                node = MeshNode(
                    mac=src_mac,
                    node_index=len(self._nodes),
                    is_biscuit=(len(payload) == _BISCUIT_PKT_LEN),
                )
                self._nodes.append(node)
                self.node_count = len(self._nodes)
                logger.info(
                    f"[CORE] New mesh node {node.node_index}: {node.mac_str} "
                    f"({'Biscuit' if node.is_biscuit else 'JCMK'})"
                )
            self._reassign_channels()
            # Snapshot the node's current assignment while lock is held
            start, end, ver, idx, count = (
                node.start_idx, node.end_idx,
                node.assignment_version, node.node_index, len(self._nodes),
            )

        self._send_core_reply(src_mac)
        self._send_admin(src_mac, idx, count, start, end, ver)

    def _handle_heartbeat(self, src_mac: bytes):
        with self._lock:
            node = self._find_node(src_mac)
            if node:
                node.last_heartbeat = time.time()

    def _handle_text(self, src_mac: bytes, payload: bytes):
        # jcmk_text_msg_t layout: magic[4] type[1] counter[4] len[2] text[...]
        if len(payload) < 12:
            return
        text_len = struct.unpack_from('<H', payload, 9)[0]
        text_start = 11
        if text_start + text_len > len(payload):
            text_len = len(payload) - text_start
        try:
            text = payload[text_start:text_start + text_len].decode('utf-8', errors='replace').strip()
        except Exception:
            return

        with self._lock:
            node = self._find_node(src_mac)
            if node:
                node.records_rx     += text.count('\n') + (1 if text else 0)
                node.last_heartbeat  = time.time()
        self.records_rx += 1

        for line in text.splitlines():
            line = line.strip()
            if line:
                self._parse_network_record(line, src_mac)

    # ── Network record parsing ─────────────────────────────────────────────────

    def _parse_network_record(self, line: str, src_mac: bytes):
        """Parse 'BSSID,SSID,AUTH,CHANNEL,RSSI,W' emitted by PigletNode."""
        parts = line.split(',')
        if len(parts) < 5:
            return
        try:
            bssid   = parts[0].strip().upper()
            ssid    = parts[1].strip()
            auth    = parts[2].strip()
            channel = int(parts[3].strip())
            rssi    = int(parts[4].strip())
        except (ValueError, IndexError):
            return
        if len(bssid) < 11:
            return
        # Track band counts for LCD display
        if 1 <= channel <= 14:
            self.networks_24 = min(self.networks_24 + 1, 65535)
        elif channel >= 36:
            self.networks_50 = min(self.networks_50 + 1, 65535)

        if self._on_network:
            try:
                self._on_network(bssid, ssid, auth, channel, rssi, src_mac)
            except Exception as e:
                logger.debug(f"on_network callback error: {e}")

    # ── Outgoing JCMK messages ─────────────────────────────────────────────────

    def _send_core_reply(self, dest_mac: bytes):
        # jcmk_text_msg_t: magic[4] type[1] counter[4] len[2] text=''
        payload = JCMK_MAGIC + struct.pack('<BIH', MSG_CORE_REPLY, 0, 0)
        self._tx(dest_mac, payload)
        logger.debug(f"CORE_REPLY → {dest_mac.hex(':')}")

    def _send_admin(self, dest_mac: bytes,
                    idx: int, count: int,
                    start: int, end: int, ver: int):
        # jcmk_admin_msg_t: magic[4] type[1] ver[1] idx[1] count[1] start[1] end[1]
        payload = JCMK_MAGIC + struct.pack('BBBBBB',
                                           MSG_ADMIN, ver, idx, count, start, end)
        self._tx(dest_mac, payload)
        ch_from = CHANNEL_TABLE[start] if start < len(CHANNEL_TABLE) else start
        ch_to   = CHANNEL_TABLE[end]   if end   < len(CHANNEL_TABLE) else end
        logger.info(f"ADMIN → node {idx} ({dest_mac.hex(':')})  "
                    f"ch {ch_from}–{ch_to}  ver={ver}")

    def _send_heartbeat(self, dest_mac: bytes):
        payload = JCMK_MAGIC + struct.pack('<BIH', MSG_HEARTBEAT, 0, 0)
        self._tx(dest_mac, payload)

    def _send_stats(self):
        """Push LCD status update to the ESP32-C6 bridge (CMD_STATS)."""
        if not self._send_cb:
            return
        n24  = min(self.networks_24, 0xFFFF)
        n50  = min(self.networks_50, 0xFFFF)
        with self._lock:
            nodes = len(self._nodes)
        payload = struct.pack('<BBHH',
                              nodes,
                              1 if self._gps_fix else 0,
                              n24, n50)
        null_mac = bytes(6)
        frame = self._build_frame(CMD_STATS, null_mac, payload)
        try:
            self._send_cb(frame)
        except Exception as e:
            logger.debug(f"STATS send error: {e}")

    # ── Bridge TX helper ───────────────────────────────────────────────────────

    def _tx(self, dest_mac: bytes, esp_payload: bytes):
        if not self._send_cb:
            return
        frame = self._build_frame(CMD_TX, dest_mac, esp_payload)
        try:
            self._send_cb(frame)
        except Exception as e:
            logger.warning(f"Bridge TX error: {e}")

    @classmethod
    def _build_frame(cls, cmd: int, mac: bytes, payload: bytes) -> bytes:
        plen = len(payload)
        crc  = cls._crc(cmd, mac, payload)
        return (bytes([SYNC_A, SYNC_B, cmd])
                + mac
                + struct.pack('<H', plen)
                + payload
                + bytes([crc]))

    # ── Channel assignment ─────────────────────────────────────────────────────

    def _reassign_channels(self):
        """Distribute CHANNEL_TABLE evenly across all registered nodes."""
        n = len(self._nodes)
        if n == 0:
            return
        total   = len(CHANNEL_TABLE)
        chunk   = total // n
        extra   = total % n
        cursor  = 0
        for i, node in enumerate(self._nodes):
            size            = chunk + (1 if i < extra else 0)
            node.start_idx  = cursor
            node.end_idx    = min(cursor + size - 1, total - 1)
            node.assignment_version = (node.assignment_version + 1) & 0xFF
            cursor          = node.end_idx + 1
        logger.info(f"[CORE] Reassigned: {n} nodes")

    # ── Heartbeat loop ─────────────────────────────────────────────────────────

    def _heartbeat_loop(self):
        while self._running:
            time.sleep(HB_INTERVAL_S)
            now       = time.time()
            to_remove = []

            with self._lock:
                for node in self._nodes:
                    if now - node.last_heartbeat > NODE_TIMEOUT_S:
                        to_remove.append(node)
                for node in to_remove:
                    logger.info(
                        f"[CORE] Node {node.node_index} timed out: {node.mac_str}"
                    )
                    self._nodes.remove(node)
                self.node_count = len(self._nodes)
                active = list(self._nodes)

            for node in active:
                self._send_heartbeat(node.mac)

            self._send_stats()

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _find_node(self, mac: bytes) -> Optional[MeshNode]:
        for node in self._nodes:
            if node.mac == mac:
                return node
        return None
