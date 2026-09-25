/*
 * espnow_bridge_c5.ino  —  Ragnar STANDALONE ESP-Now coordinator (Piglet Core)
 *
 * Target hardware: Waveshare ESP32-C5-WIFI6-KIT (headless, dual-band Wi-Fi 6,
 * BLE 5, 16 MB flash / 4 MB PSRAM). No display. USB-Serial-JTAG (HWCDC) is
 * the only connection to the host; baked-in Espressif USB CDC enumerates as
 * /dev/ttyACM0 on Linux and COMx on Windows.
 *
 * This firmware is a fully standalone Piglet Core. It pairs with PigletNode
 * devices over ESP-Now and emits the received WiFi/BLE records on USB-Serial
 * in HuginnESP-style JSON (one object per line). Ragnar's wardriving listener
 * accepts JSON regardless of detected companion ID; pairing/heartbeats keep
 * running even if the Pi-side process restarts.
 *
 * Build (arduino-cli):
 *   --fqbn "esp32:esp32:esp32c5:CDCOnBoot=cdc,PartitionScheme=default_16MB"
 *
 * Arduino IDE: Tools → USB CDC On Boot → Enabled.
 *
 * ── JCMK ENOW protocol ───────────────────────────────────────────────────
 *   magic[4]="ENOW" type[1] ...
 *   MSG_CORE_REQUEST=1  node→core broadcast (paired by replying CORE_REPLY)
 *   MSG_CORE_REPLY   =2  core→node unicast
 *   MSG_HEARTBEAT    =3  bidirectional, 5 s interval, 60 s timeout
 *   MSG_TEXT         =4  node→core: WiGLE rows ("BSSID,SSID,AUTH,CH,RSSI,W")
 *   MSG_ADMIN        =5  core→node: channel slice assignment
 *
 * Every TEXT-typed message is sent as the full 212-byte enow_text_msg_t
 * struct (matches JustCallMeKoko's ESP32DualBandWardriver reference).
 *
 * ── Serial output (consumed by Ragnar's parser) ──────────────────────────
 *   [CORE] Ragnar standalone coordinator booted (Piglet)
 *   {"device":"RagnarCoord","fw":"c5-1","board":"ESP32-C5","caps":[...]}
 *   [CORE] New mesh node 0: AA:BB:CC:DD:EE:FF (JCMK)
 *   [CORE] Reassigned: 1 nodes
 *   {"type":"WIFI","mac":"AA:BB:CC:DD:EE:FF","ssid":"Home","rssi":-65,
 *    "channel":6,"auth":"WPA2"}
 *   {"type":"BLE","mac":"11:22:33:44:55:66","name":"","rssi":-72}
 *   [CORE] alive ch=6 nodes=2 net24=120 net50=44 uptime=315s
 *   [CORE] Node 0 timed out: AA:BB:CC:DD:EE:FF
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <string.h>

// ── Serial / ESP-Now ──────────────────────────────────────────────────────────
#define BAUD        460800
#define ESPNOW_CH   6

// ── JCMK ENOW protocol — exact match for the JustCallMeKoko reference firmware
static const uint8_t ENOW_MAGIC[4] = {'E','N','O','W'};
#define MSG_CORE_REQUEST 1
#define MSG_CORE_REPLY   2
#define MSG_HEARTBEAT    3
#define MSG_TEXT         4
#define MSG_ADMIN        5

#define ENOW_TEXT_MAX    200   // matches JCMK src/configs.h
#define MAX_NODES        24    // matches JCMK src/WiFiOps.h
#define HB_INTERVAL_MS   5000
#define NODE_TIMEOUT_MS  60000

typedef struct __attribute__((packed)) {
    char     magic[4];                  // "ENOW"
    uint8_t  type;
    uint32_t counter;
    uint16_t len;
    char     text[ENOW_TEXT_MAX + 1];
} enow_text_msg_t;                      // 212 bytes

typedef struct __attribute__((packed)) {
    char    magic[4];
    uint8_t type;
    uint8_t assignment_version;
    uint8_t node_index;
    uint8_t node_count;
    uint8_t start_channel_idx;
    uint8_t end_channel_idx;
} enow_admin_msg_t;                     // 10 bytes

// JCMK scan_channels table (40 entries: 14× 2.4 GHz + 26× 5 GHz)
static const uint8_t SCAN_CHANNELS[] = {
    1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161,
    165, 169, 173, 177
};
#define NUM_SCAN_CHANNELS  (sizeof(SCAN_CHANNELS) / sizeof(SCAN_CHANNELS[0]))

// ── Node registry ─────────────────────────────────────────────────────────────
struct MeshNode {
    bool      used;
    uint8_t   mac[6];
    uint8_t   node_index;
    uint8_t   start_idx;
    uint8_t   end_idx;
    uint8_t   assignment_version;
    uint32_t  last_heartbeat_ms;
    uint32_t  records_rx;
};
static MeshNode g_nodes[MAX_NODES];

// ── Stats ─────────────────────────────────────────────────────────────────────
static uint16_t  g_node_count     = 0;
static uint16_t  g_net24          = 0;
static uint16_t  g_net50          = 0;
static uint32_t  g_last_data_ms   = 0;
static uint8_t   g_my_mac[6]      = {0};
static uint32_t  g_dropped_rows   = 0;
static uint32_t  g_queue_drops    = 0;

// ── Text-message queue (decouple radio task from Serial output) ──────────────
// MSG_TEXT must NOT be processed inline in on_recv: it triggers heavy
// Serial.printf for each row, and a saturated USB-CDC IN endpoint can block
// the WiFi task long enough to trip the task WDT. on_recv just enqueues.
struct PendingText {
    uint8_t  src_mac[6];
    uint16_t len;
    char     text[ENOW_TEXT_MAX + 1];
};
#define TEXT_QUEUE_DEPTH 16
static QueueHandle_t g_text_queue = NULL;

// ── Non-blocking Serial helper ────────────────────────────────────────────────
static void safe_serial_printf(const char *fmt, ...) {
    char buf[200];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(buf) - 1) n = sizeof(buf) - 1;
    if (Serial.availableForWrite() < n) return;   // drop rather than block
    Serial.write((const uint8_t *)buf, n);
}

// ── Node registry helpers ─────────────────────────────────────────────────────
static MeshNode *find_node(const uint8_t *mac) {
    for (int i = 0; i < MAX_NODES; i++) {
        if (g_nodes[i].used && memcmp(g_nodes[i].mac, mac, 6) == 0)
            return &g_nodes[i];
    }
    return NULL;
}

static MeshNode *alloc_node(const uint8_t *mac) {
    for (int i = 0; i < MAX_NODES; i++) {
        if (!g_nodes[i].used) {
            g_nodes[i].used               = true;
            memcpy(g_nodes[i].mac, mac, 6);
            g_nodes[i].node_index         = i;
            g_nodes[i].start_idx          = 0;
            g_nodes[i].end_idx            = NUM_SCAN_CHANNELS - 1;
            g_nodes[i].assignment_version = 0;
            g_nodes[i].last_heartbeat_ms  = millis();
            g_nodes[i].records_rx         = 0;
            return &g_nodes[i];
        }
    }
    return NULL;
}

static uint16_t count_nodes(void) {
    uint16_t n = 0;
    for (int i = 0; i < MAX_NODES; i++) if (g_nodes[i].used) n++;
    return n;
}

static void mac_to_str(const uint8_t *mac, char *out /* >= 18 */) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Distribute scan channels evenly across all registered nodes (mirrors JCMK
// WiFiOps::recalculateChannelAssignments).
static void reassign_channels(void) {
    uint16_t n = count_nodes();
    if (n == 0) return;
    uint8_t i = 0;
    for (int slot = 0; slot < MAX_NODES; slot++) {
        if (!g_nodes[slot].used) continue;
        uint8_t start_idx = (uint8_t)(((uint16_t)i       * NUM_SCAN_CHANNELS) / n);
        uint8_t end_idx   = (uint8_t)((((uint16_t)i + 1) * NUM_SCAN_CHANNELS) / n - 1);
        g_nodes[slot].start_idx          = start_idx;
        g_nodes[slot].end_idx            = end_idx;
        g_nodes[slot].assignment_version = (uint8_t)(g_nodes[slot].assignment_version + 1);
        i++;
    }
    safe_serial_printf("[CORE] Reassigned: %u nodes\r\n", (unsigned)n);
}

// ── ESP-Now send helpers ──────────────────────────────────────────────────────
static bool ensure_peer(const uint8_t *mac) {
    if (esp_now_is_peer_exist(mac)) return true;
    esp_now_peer_info_t p = {};
    memcpy(p.peer_addr, mac, 6);
    p.channel = 0;            // follow home channel (matches JCMK)
    p.encrypt = false;
    return esp_now_add_peer(&p) == ESP_OK;
}

// Send a TEXT-typed message (CORE_REPLY, HEARTBEAT, etc.) as the full
// sizeof(enow_text_msg_t) = 212 bytes. The JCMK node receiver does
// `if (len < sizeof(enow_text_msg_t)) return;` and silently drops anything
// shorter — short replies were why pairing initially failed.
static void send_text_msg(const uint8_t *dest, uint8_t type, uint32_t counter) {
    enow_text_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.magic, ENOW_MAGIC, 4);
    msg.type    = type;
    msg.counter = counter;
    msg.len     = 0;
    ensure_peer(dest);
    esp_now_send(dest, (const uint8_t *)&msg, sizeof(msg));
}

static void send_core_reply(const uint8_t *dest) {
    send_text_msg(dest, MSG_CORE_REPLY, 0);
}

static void send_heartbeat_to(const uint8_t *dest) {
    static uint32_t hb_counter = 0;
    send_text_msg(dest, MSG_HEARTBEAT, hb_counter++);
}

static void send_admin(const uint8_t *dest, uint8_t idx, uint8_t count,
                       uint8_t start, uint8_t end, uint8_t ver) {
    enow_admin_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    memcpy(msg.magic, ENOW_MAGIC, 4);
    msg.type               = MSG_ADMIN;
    msg.assignment_version = ver;
    msg.node_index         = idx;
    msg.node_count         = count;
    msg.start_channel_idx  = start;
    msg.end_channel_idx    = end;
    ensure_peer(dest);
    esp_now_send(dest, (const uint8_t *)&msg, sizeof(msg));
    uint8_t cf = start < NUM_SCAN_CHANNELS ? SCAN_CHANNELS[start] : start;
    uint8_t ct = end   < NUM_SCAN_CHANNELS ? SCAN_CHANNELS[end]   : end;
    char ms[18]; mac_to_str(dest, ms);
    safe_serial_printf("[CORE] ADMIN to node %u (%s) ch %u-%u ver=%u\r\n",
                       (unsigned)idx, ms, (unsigned)cf, (unsigned)ct, (unsigned)ver);
}

// ── Huginn-style JSON emission ────────────────────────────────────────────────
// Map JCMK/PigletNode bracketed auth strings ("[WPA2_PSK]") to Huginn's
// values ("WPA2"). Strips brackets then matches inner token.
static const char *huginn_auth(const char *auth) {
    if (!auth || !*auth) return "Unknown";
    char buf[32];
    size_t al = strlen(auth);
    if (al >= 2 && auth[0] == '[' && auth[al - 1] == ']') {
        size_t n = al - 2 < sizeof(buf) - 1 ? al - 2 : sizeof(buf) - 1;
        memcpy(buf, auth + 1, n);
        buf[n] = '\0';
    } else {
        strncpy(buf, auth, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    }
    if (!strcasecmp(buf, "OPEN"))              return "Open";
    if (!strcasecmp(buf, "WEP"))               return "WEP";
    if (!strcasecmp(buf, "WPA")
     || !strcasecmp(buf, "WPA_PSK"))           return "WPA";
    if (!strcasecmp(buf, "WPA2")
     || !strcasecmp(buf, "WPA2_PSK"))          return "WPA2";
    if (!strcasecmp(buf, "WPA_WPA2_PSK")
     || !strcasecmp(buf, "WPA/WPA2"))          return "WPA/WPA2";
    if (!strcasecmp(buf, "WPA2_ENTERPRISE")
     || !strcasecmp(buf, "WPA2-Enterprise"))   return "WPA2-Enterprise";
    if (!strcasecmp(buf, "WPA3")
     || !strcasecmp(buf, "WPA3_PSK"))          return "WPA3";
    return "Unknown";
}

// Escape `src` for inclusion inside a JSON string. Returns bytes written.
// Handles ", \, control chars (\b\f\n\r\t) and <0x20 as \u00XX.
static size_t json_escape(const char *src, char *dst, size_t dst_sz) {
    size_t o = 0;
    if (dst_sz == 0) return 0;
    for (const char *p = src; *p && o + 7 < dst_sz; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
            case '"':  dst[o++] = '\\'; dst[o++] = '"';  break;
            case '\\': dst[o++] = '\\'; dst[o++] = '\\'; break;
            case '\b': dst[o++] = '\\'; dst[o++] = 'b';  break;
            case '\f': dst[o++] = '\\'; dst[o++] = 'f';  break;
            case '\n': dst[o++] = '\\'; dst[o++] = 'n';  break;
            case '\r': dst[o++] = '\\'; dst[o++] = 'r';  break;
            case '\t': dst[o++] = '\\'; dst[o++] = 't';  break;
            default:
                if (c < 0x20) o += snprintf(dst + o, dst_sz - o, "\\u%04x", c);
                else          dst[o++] = (char)c;
        }
    }
    dst[o] = '\0';
    return o;
}

// Parse one node CSV row "BSSID,SSID,AUTH,CHANNEL,RSSI[,W|B]" and emit a
// Huginn-style JSON line. Updates LCD-band counters on the fly.
static bool emit_json_row(char *row /* modified in place */) {
    char *fields[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
    int   nf = 0;
    char *p  = row;
    while (nf < 6 && p && *p) {
        fields[nf++] = p;
        char *c = strchr(p, ',');
        if (!c) break;
        *c = '\0';
        p  = c + 1;
    }
    if (nf < 5) return false;

    const char *bssid = fields[0];
    const char *ssid  = fields[1] ? fields[1] : "";
    const char *auth  = fields[2] ? fields[2] : "";
    int channel       = atoi(fields[3] ? fields[3] : "0");
    int rssi          = atoi(fields[4] ? fields[4] : "-80");
    const char *tflag = (nf >= 6 && fields[5]) ? fields[5] : "W";

    if (!bssid || strlen(bssid) < 11) return false;

    bool is_ble = (auth && strstr(auth, "BLE")) ||
                  (tflag && (*tflag == 'B' || *tflag == 'b'));

    const char *ssid_in = ssid;
    char ssid_unquoted[96];
    size_t sl = strlen(ssid);
    if (sl >= 2 && ssid[0] == '"' && ssid[sl - 1] == '"') {
        size_t n = sl - 2 < sizeof(ssid_unquoted) - 1 ? sl - 2 : sizeof(ssid_unquoted) - 1;
        memcpy(ssid_unquoted, ssid + 1, n);
        ssid_unquoted[n] = '\0';
        ssid_in = ssid_unquoted;
    }

    char ssid_json[160];
    json_escape(ssid_in, ssid_json, sizeof(ssid_json));

    static char rowbuf[300];
    int rl;
    if (is_ble) {
        rl = snprintf(rowbuf, sizeof(rowbuf),
                      "{\"type\":\"BLE\",\"mac\":\"%s\",\"name\":\"%s\",\"rssi\":%d}\n",
                      bssid, ssid_json, rssi);
    } else {
        if (channel >= 1 && channel <= 14) {
            if (g_net24 < 0xFFFF) g_net24++;
        } else if (channel >= 36) {
            if (g_net50 < 0xFFFF) g_net50++;
        }
        rl = snprintf(rowbuf, sizeof(rowbuf),
                      "{\"type\":\"WIFI\",\"mac\":\"%s\",\"ssid\":\"%s\","
                      "\"rssi\":%d,\"channel\":%d,\"auth\":\"%s\"}\n",
                      bssid, ssid_json, rssi, channel, huginn_auth(auth));
    }
    if (rl <= 0) return false;
    if (rl > (int)sizeof(rowbuf) - 1) rl = sizeof(rowbuf) - 1;
    if (Serial.availableForWrite() < rl) {
        g_dropped_rows++;
        return false;
    }
    Serial.write((const uint8_t *)rowbuf, rl);
    return true;
}

// ── ESP-Now receive handlers ──────────────────────────────────────────────────
// MSG_TEXT: runs on the WiFi task. Must return fast — only cheap state
// updates + queue insertion. Heavy emission happens in main loop drain.
static void handle_text_msg(const uint8_t *src_mac,
                            const uint8_t *payload, int plen) {
    if (plen < (int)sizeof(enow_text_msg_t)) return;
    const enow_text_msg_t *msg = (const enow_text_msg_t *)payload;
    uint16_t text_len = msg->len;
    if (text_len == 0 || text_len > ENOW_TEXT_MAX) return;

    g_last_data_ms = millis();
    MeshNode *n = find_node(src_mac);
    if (n) n->last_heartbeat_ms = millis();

    if (!g_text_queue) return;
    PendingText pt;
    memcpy(pt.src_mac, src_mac, 6);
    pt.len = text_len;
    memcpy(pt.text, msg->text, text_len);
    pt.text[text_len] = '\0';
    if (xQueueSend(g_text_queue, &pt, 0) != pdTRUE) g_queue_drops++;
}

static void drain_text_queue(void) {
    if (!g_text_queue) return;
    PendingText pt;
    int budget = 8;
    while (budget-- > 0 && xQueueReceive(g_text_queue, &pt, 0) == pdTRUE) {
        MeshNode *n = find_node(pt.src_mac);
        char *line = pt.text;
        while (line && *line) {
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            while (*line == ' ' || *line == '\t') line++;
            if (*line) {
                if (emit_json_row(line)) {
                    if (n) n->records_rx++;
                }
            }
            if (!nl) break;
            line = nl + 1;
            while (*line == '\r' || *line == '\n') line++;
        }
    }
}

// MSG_CORE_REQUEST: register node (if new), reply, assign channels.
static void handle_core_request(const uint8_t *src_mac, int plen) {
    if (plen < (int)sizeof(enow_text_msg_t)) {
        char ms[18]; mac_to_str(src_mac, ms);
        safe_serial_printf("[CORE] CORE_REQUEST too short (%d B) from %s — ignored\r\n",
                           plen, ms);
        return;
    }
    bool is_new = false;
    MeshNode *node = find_node(src_mac);
    if (!node) {
        node = alloc_node(src_mac);
        if (!node) {
            char ms[18]; mac_to_str(src_mac, ms);
            safe_serial_printf("[CORE] MAX_NODES reached; rejecting %s\r\n", ms);
            return;
        }
        is_new = true;
        char ms[18]; mac_to_str(src_mac, ms);
        safe_serial_printf("[CORE] New mesh node %u: %s (JCMK)\r\n",
                           (unsigned)node->node_index, ms);
        g_node_count = count_nodes();
    } else {
        node->last_heartbeat_ms = millis();
    }
    send_core_reply(src_mac);
    if (is_new) reassign_channels();
    send_admin(src_mac, node->node_index, (uint8_t)count_nodes(),
               node->start_idx, node->end_idx, node->assignment_version);
}

static void handle_heartbeat(const uint8_t *src_mac, int plen) {
    if (plen < (int)sizeof(enow_text_msg_t)) return;
    MeshNode *n = find_node(src_mac);
    if (n) {
        n->last_heartbeat_ms = millis();
    } else {
        n = alloc_node(src_mac);
        if (n) {
            char ms[18]; mac_to_str(src_mac, ms);
            safe_serial_printf("[CORE] Node %u from heartbeat: %s\r\n",
                               (unsigned)n->node_index, ms);
            g_node_count = count_nodes();
            reassign_channels();
            send_admin(src_mac, n->node_index, (uint8_t)count_nodes(),
                       n->start_idx, n->end_idx, n->assignment_version);
        }
    }
}

static void on_recv(const esp_now_recv_info_t *info,
                    const uint8_t *data, int len) {
    if (len < 5) return;
    if (memcmp(data, ENOW_MAGIC, 4) != 0) return;
    uint8_t msg_type = data[4];
    switch (msg_type) {
        case MSG_CORE_REQUEST: handle_core_request(info->src_addr, len);   break;
        case MSG_HEARTBEAT:    handle_heartbeat(info->src_addr, len);      break;
        case MSG_TEXT:         handle_text_msg(info->src_addr, data, len); break;
        default: /* MSG_CORE_REPLY / MSG_ADMIN are core→node only */       break;
    }
}

static void on_send(const wifi_tx_info_t *info, esp_now_send_status_t s) {
    (void)info; (void)s;
}

// ── Periodic ticks ────────────────────────────────────────────────────────────
static uint32_t t_hb    = 0;
static uint32_t t_alive = 0;

static void heartbeat_tick(void) {
    uint32_t now = millis();
    if (now - t_hb < HB_INTERVAL_MS) return;
    t_hb = now;
    bool removed = false;
    for (int i = 0; i < MAX_NODES; i++) {
        if (!g_nodes[i].used) continue;
        if (now - g_nodes[i].last_heartbeat_ms > NODE_TIMEOUT_MS) {
            char ms[18]; mac_to_str(g_nodes[i].mac, ms);
            safe_serial_printf("[CORE] Node %u timed out: %s\r\n",
                               (unsigned)g_nodes[i].node_index, ms);
            g_nodes[i].used = false;
            removed = true;
        }
    }
    if (removed) {
        g_node_count = count_nodes();
        reassign_channels();
    }
    for (int i = 0; i < MAX_NODES; i++) {
        if (g_nodes[i].used) send_heartbeat_to(g_nodes[i].mac);
    }
}

static void alive_tick(void) {
    uint32_t now = millis();
    if (now - t_alive < 10000) return;
    t_alive = now;
    safe_serial_printf("[CORE] alive ch=%d nodes=%u net24=%u net50=%u "
                       "drops_tx=%lu drops_q=%lu uptime=%lus\r\n",
                       ESPNOW_CH, (unsigned)g_node_count,
                       (unsigned)g_net24, (unsigned)g_net50,
                       (unsigned long)g_dropped_rows,
                       (unsigned long)g_queue_drops,
                       (unsigned long)(now / 1000));
    // Per-node JSON dump so Ragnar can show MAC + contribution count.
    // One object per known node, each on its own line — fits the same
    // {"type":...} parse path the host already uses for WIFI/BLE rows.
    for (int i = 0; i < MAX_NODES; i++) {
        if (!g_nodes[i].used) continue;
        char mac[18];
        mac_to_str(g_nodes[i].mac, mac);
        uint32_t age_s = (now - g_nodes[i].last_heartbeat_ms) / 1000;
        safe_serial_printf(
            "{\"type\":\"NODE\",\"idx\":%u,\"mac\":\"%s\",\"rx\":%lu,\"age\":%lu}\n",
            (unsigned)g_nodes[i].node_index, mac,
            (unsigned long)g_nodes[i].records_rx,
            (unsigned long)age_s);
    }
}

// ── Host serial input ─────────────────────────────────────────────────────────
// Ragnar's Piglet cycle writes "scanap\r\n", "blescan -f\r\n", etc. Standalone
// coordinator pumps data continuously regardless of mode — discard all input.
static char  host_line[64];
static int   host_pos = 0;

static void poll_host_serial(void) {
    while (Serial.available()) {
        int c = Serial.read();
        if (c < 0) break;
        if (c == '\r') continue;
        if (c == '\n') {
            host_line[host_pos] = '\0';
            host_pos = 0;
            continue;
        }
        if (host_pos < (int)sizeof(host_line) - 1) host_line[host_pos++] = (char)c;
        else host_pos = 0;
    }
}

// ── setup / loop ──────────────────────────────────────────────────────────────
void setup() {
    // CDCOnBoot=cdc → Serial is HWCDC (USB-Serial-JTAG, /dev/ttyACM0).
    // 2-second settle delay after Serial.begin so HWCDC can complete CDC
    // enumeration with the host before we emit anything. Matches the
    // HuginnESP pattern that's known to work reliably on the C5.
    Serial.begin(BAUD);
    delay(2000);

    Serial.println("[CORE] Ragnar standalone coordinator booted (Piglet)");
    Serial.println(
        "{\"device\":\"RagnarCoord\",\"fw\":\"c5-1\","
        "\"board\":\"ESP32-C5\",\"caps\":[\"espnow\",\"piglet-core\"]}");

    // ESP-Now — channel set AFTER esp_now_init (matches Piglet/JCMK).
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_now_init();
    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_send);

    // Broadcast peer (channel=0 follows home channel — matches JCMK)
    {
        esp_now_peer_info_t bc = {};
        memset(bc.peer_addr, 0xFF, 6);
        bc.channel = 0;
        bc.encrypt = false;
        esp_now_add_peer(&bc);
    }

    // Lock channel after init — esp_now_init() may reset it on IDF 5.x
    esp_wifi_set_channel(ESPNOW_CH, WIFI_SECOND_CHAN_NONE);

    esp_wifi_get_mac(WIFI_IF_STA, g_my_mac);
    safe_serial_printf("[CORE] Listening on channel %d, MAC %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                       ESPNOW_CH,
                       g_my_mac[0], g_my_mac[1], g_my_mac[2],
                       g_my_mac[3], g_my_mac[4], g_my_mac[5]);

    memset(g_nodes, 0, sizeof(g_nodes));
    g_text_queue = xQueueCreate(TEXT_QUEUE_DEPTH, sizeof(PendingText));
    if (!g_text_queue) Serial.println("[CORE] FATAL: xQueueCreate failed");
}

void loop() {
    poll_host_serial();
    drain_text_queue();
    heartbeat_tick();
    alive_tick();
    delay(5);
}
