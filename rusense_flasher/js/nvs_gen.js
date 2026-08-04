// Byte-exact port of ESP-IDF nvs_partition_gen (v2) for a single namespace of
// string/u8/u16 keys — enough to provision the RuSense CSI node (csi_cfg).
// Validated against provision.py's output (ref.bin).

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
// Matches Python zlib.crc32(bytes, seed).
function zlibCrc32(bytes, seed) {
  let c = (seed ^ 0xFFFFFFFF) >>> 0;
  for (let i = 0; i < bytes.length; i++) c = (CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8)) >>> 0;
  return (c ^ 0xFFFFFFFF) >>> 0;
}
const CRC_SEED = 0xFFFFFFFF;

const PAGE = 4096, HDR = 32, BITMAP = 32, FIRST = 64, ESIZE = 32;
const T_U8 = 0x01, T_U16 = 0x02, T_STR = 0x21;

// entries: [{ns,type,key,value}] where namespace row is added by caller.
function buildNvsPartition(size, keys) {
  const buf = new Uint8Array(size).fill(0xFF);
  // ── page 0 header (ACTIVE) ──
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0xFFFFFFFE, true);   // state = ACTIVE
  dv.setUint32(4, 0, true);            // seq_no
  buf[8] = 0xFE;                        // version v2  (9..27 stay 0xFF)
  dv.setUint32(28, zlibCrc32(buf.subarray(4, 28), CRC_SEED), true);

  let slot = 0;
  const off = (s) => FIRST + s * ESIZE;
  const markWritten = (s) => {                 // 2 bits/slot, written = clear low bit → '10'
    const bit = s * 2, byteIdx = BITMAP + (bit >> 3), bitOff = bit & 7;
    buf[byteIdx] &= (~(1 << bitOff)) & 0xFF;
  };
  const writeHeaderEntry = (ns, type, span, key, data8) => {
    const o = off(slot);
    buf[o] = ns; buf[o + 1] = type; buf[o + 2] = span; buf[o + 3] = 0xFF; // chunk = 0xFF
    for (let i = 0; i < 16; i++) buf[o + 8 + i] = i < key.length ? key.charCodeAt(i) : 0x00;
    for (let i = 0; i < 8; i++) buf[o + 24 + i] = data8[i];
    const cd = new Uint8Array(28);
    cd.set(buf.subarray(o, o + 4), 0);
    cd.set(buf.subarray(o + 8, o + 32), 4);
    dv.setUint32(o + 4, zlibCrc32(cd, CRC_SEED), true);
    markWritten(slot); slot++;
  };
  const writePrimitive = (ns, type, key, valBytesLE) => {
    const d8 = new Uint8Array(8).fill(0xFF);
    d8.set(valBytesLE, 0);
    writeHeaderEntry(ns, type, 1, key, d8);
  };
  const writeString = (ns, key, str) => {
    const enc = new TextEncoder().encode(str);
    const data = new Uint8Array(enc.length + 1); data.set(enc); // + null terminator
    const datalen = data.length;                                // strlen + 1
    const dataEntries = ((datalen + 31) & ~31) / 32;
    const d8 = new Uint8Array(8).fill(0xFF);
    d8[0] = datalen & 0xFF; d8[1] = (datalen >> 8) & 0xFF;       // size (incl. null)
    const dcrc = zlibCrc32(data, CRC_SEED);
    d8[4] = dcrc & 0xFF; d8[5] = (dcrc >> 8) & 0xFF; d8[6] = (dcrc >> 16) & 0xFF; d8[7] = (dcrc >>> 24) & 0xFF;
    writeHeaderEntry(ns, T_STR, 1 + dataEntries, key, d8);
    for (let de = 0; de < dataEntries; de++) {                  // raw data chunks (no per-entry CRC)
      const o = off(slot);
      for (let i = 0; i < 32; i++) { const di = de * 32 + i; buf[o + i] = di < data.length ? data[di] : 0xFF; }
      markWritten(slot); slot++;
    }
  };

  for (const k of keys) {
    if (k.type === 'namespace') writePrimitive(0, T_U8, k.key, [k.value & 0xFF]);
    else if (k.type === 'string') writeString(1, k.key, String(k.value));
    else if (k.type === 'u16') writePrimitive(1, T_U16, k.key, [k.value & 0xFF, (k.value >> 8) & 0xFF]);
    else if (k.type === 'u8') writePrimitive(1, T_U8, k.key, [k.value & 0xFF]);
  }
  return buf;
}

// Build the csi_cfg WiFi/server provisioning partition (offset 0x9000, size 0x6000).
// Key set + types + order match RuView's provision.py exactly (node_id is a u8
// written right after target_port). node_id gives each node a unique identity;
// without it every node falls back to the firmware default (1) and they collide
// -- the server then only ever shows one node at a time.
function buildCsiCfgNvs({ ssid, password, target_ip, target_port = 5005, node_id, edge_tier = 0, ext_antenna }) {
  const keys = [
    { type: 'namespace', key: 'csi_cfg', value: 1 },
    { type: 'string', key: 'ssid', value: ssid },
    { type: 'string', key: 'password', value: password },
    { type: 'string', key: 'target_ip', value: target_ip },
    { type: 'u16', key: 'target_port', value: target_port },
  ];
  if (node_id !== undefined && node_id !== null) {
    keys.push({ type: 'u8', key: 'node_id', value: node_id & 0xFF });
  }
  // XIAO ESP32-C6 antenna select (u8 'ext_ant'): 1 = external u.FL, 0 = on-board.
  // Read by the firmware in app_main before the radio starts. Only meaningful on
  // a XIAO-C6; harmless on S3 (the firmware guards it on the C6 target).
  if (ext_antenna !== undefined && ext_antenna !== null) {
    keys.push({ type: 'u8', key: 'ext_ant', value: ext_antenna ? 1 : 0 });
  }
  // edge_tier (u8) selects the node's OUTPUT MODE. The RuSense/RuView server does
  // server-side multistatic fusion, so it needs RAW CSI frames: edge_tier=0
  // ("raw CSI passthrough"). The firmware DEFAULT is 2 (full on-device pipeline),
  // which makes the node emit a 60-byte rv_feature_state_t instead of CSI — the
  // server then sees no CSI frames and the source reads "esp32:offline". So we
  // always provision 0 here; a customer must never end up on the edge default.
  keys.push({ type: 'u8', key: 'edge_tier', value: edge_tier & 0xFF });
  return buildNvsPartition(0x6000, keys);
}

if (typeof module !== 'undefined') module.exports = { buildCsiCfgNvs, buildNvsPartition, zlibCrc32 };
if (typeof window !== 'undefined') window.buildCsiCfgNvs = buildCsiCfgNvs;   // exposed to the (module) flasher
