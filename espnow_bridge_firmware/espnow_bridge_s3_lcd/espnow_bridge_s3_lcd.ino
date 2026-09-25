/*
 * espnow_bridge_s3_lcd.ino — Ragnar STANDALONE ESP-Now coordinator (Piglet Core)
 *
 * Target hardware: Waveshare ESP32-S3-Touch-LCD-4B
 *   - ESP32-S3-N16R8 (16 MB flash / 8 MB PSRAM)
 *   - 480×480 RGB IPS panel via ST7701 (TCA9554 I²C GPIO expander for reset)
 *   - USB CDC + JTAG (selectable via USBMode)
 *
 * Same coordinator behaviour as espnow_bridge_c5; adds a 480×480 status UI
 * mirroring the layout of the (now retired) c6_lcd firmware:
 *   ┌────────────────────────────────────┐
 *   │ RAGNAR COORDINATOR                 │
 *   │ <status line, color-coded>         │
 *   │ NODES        n / 24                │
 *   │ NETWORKS SEEN                      │
 *   │   2.4G  <count>                    │
 *   │   5.0G  <count>                    │
 *   │ GPS  N/A                           │
 *   │ UPTIME  h:mm:ss                    │
 *   │ LAST RX  Ns / Nm / Nh              │
 *   │ CH / MAC  6  XX:XX                 │
 *   │ ragnar standalone core             │
 *   └────────────────────────────────────┘
 *
 * Build (arduino-cli):
 *   --fqbn "esp32:esp32:esp32s3:CDCOnBoot=cdc,USBMode=hwcdc,PartitionScheme=default_8MB,PSRAM=opi"
 *
 * Arduino IDE settings (Tools menu):
 *   USB CDC On Boot       → Enabled
 *   USB Mode              → Hardware CDC and JTAG
 *   PSRAM                 → OPI PSRAM
 *   Flash Size            → 8MB (or 16MB if your board is N16R8)
 *   Partition Scheme      → Default 8MB / 16MB to match
 *
 * Required Arduino library: "GFX Library for Arduino" by moononournation
 * (same one HuginnESP uses).
 */

#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <string.h>
#include <Arduino_GFX_Library.h>

// ── Serial / ESP-Now ──────────────────────────────────────────────────────────
#define BAUD        460800
#define ESPNOW_CH   6

// ── JCMK ENOW protocol — exact match for JustCallMeKoko reference firmware
static const uint8_t ENOW_MAGIC[4] = {'E','N','O','W'};
#define MSG_CORE_REQUEST 1
#define MSG_CORE_REPLY   2
#define MSG_HEARTBEAT    3
#define MSG_TEXT         4
#define MSG_ADMIN        5

#define ENOW_TEXT_MAX    200
#define MAX_NODES        24
#define HB_INTERVAL_MS   5000
#define NODE_TIMEOUT_MS  60000

typedef struct __attribute__((packed)) {
    char     magic[4];
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
static uint16_t  g_node_count    = 0;
static uint16_t  g_net24         = 0;
static uint16_t  g_net50         = 0;
static uint32_t  g_last_data_ms  = 0;
static uint8_t   g_my_mac[6]     = {0};
static uint32_t  g_dropped_rows  = 0;
static uint32_t  g_queue_drops   = 0;

// ── Text-message queue ───────────────────────────────────────────────────────
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
    if (Serial.availableForWrite() < n) return;
    Serial.write((const uint8_t *)buf, n);
}

// ── Node registry helpers ─────────────────────────────────────────────────────
static MeshNode *find_node(const uint8_t *mac) {
    for (int i = 0; i < MAX_NODES; i++) {
        if (g_nodes[i].used && memcmp(g_nodes[i].mac, mac, 6) == 0) return &g_nodes[i];
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
    p.channel = 0;
    p.encrypt = false;
    return esp_now_add_peer(&p) == ESP_OK;
}

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

static bool emit_json_row(char *row) {
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

// ── ESP-Now handlers ──────────────────────────────────────────────────────────
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
        default:                                                            break;
    }
}

static void on_send(const wifi_tx_info_t *info, esp_now_send_status_t s) {
    (void)info; (void)s;
}

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

// ─────────────────────────────────────────────────────────────────────────────
//  480×480 RGB display (ST7701 via TCA9554 I²C expander) — Waveshare 4B
//  Pin layout + reset/backlight sequence ported from the Argus firmware
//  (github.com/PierreGode/Argus), which is the proven-good reference for
//  this exact board. Differences vs. earlier attempts:
//    • I²C SDA is GPIO 47 (NOT 8 — wrong pin gave a black screen).
//    • LCD reset must be toggled via expander pin 5 before gfx->begin().
//    • Backlight is expander pin 6 (held LOW until display init OK).
//    • RGB panel constructor includes a 10-line bounce buffer so the
//      DMA refills from PSRAM cleanly (otherwise: no output).
// ─────────────────────────────────────────────────────────────────────────────
#define EXPANDER_SDA   47
#define EXPANDER_SCL   48
#define EXPANDER_ADDR  0x20

static Arduino_XCA9554SWSPI *expander = new Arduino_XCA9554SWSPI(
    7 /*SPI_MOSI*/, 0 /*SPI_SCK*/, 2 /*SPI_CS*/, 1 /*SPI_DC*/, &Wire, EXPANDER_ADDR);

static Arduino_ESP32RGBPanel *rgbpanel = new Arduino_ESP32RGBPanel(
    17 /*DE*/, 3 /*VSYNC*/, 46 /*HSYNC*/, 9 /*PCLK*/,
    10 /*B0*/, 11 /*B1*/, 12 /*B2*/, 13 /*B3*/, 14 /*B4*/,
    21 /*G0*/, 8 /*G1*/, 18 /*G2*/, 45 /*G3*/, 38 /*G4*/, 39 /*G5*/,
    40 /*R0*/, 41 /*R1*/, 42 /*R2*/, 2 /*R3*/, 1 /*R4*/,
    1, 10, 8, 50,   // hsync timing: polarity, fp, pw, bp
    1, 10, 8, 20,   // vsync timing: polarity, fp, pw, bp
    // Extended constructor: 10-line PSRAM bounce buffer eliminates the
    // "row chunk" tearing / blank screen you get when the LCD peripheral
    // reads PSRAM at the same time the CPU writes it. Mandatory on this
    // board for any visible output.
    0 /*pclk_active_neg*/, GFX_NOT_DEFINED /*prefer_speed*/, false /*useBigEndian*/,
    0 /*de_idle_high*/, 0 /*pclk_idle_high*/,
    480 * 10 /*bounce_buffer_size_px*/);

static Arduino_RGB_Display *gfx = new Arduino_RGB_Display(
    480, 480, rgbpanel, 0, true,
    expander, GFX_NOT_DEFINED,
    st7701_type1_init_operations, sizeof(st7701_type1_init_operations));

// 16-bit RGB565 palette (matches the c6_lcd / web flasher style)
#define C_BG       0x08C2  // dark blue-grey background
#define C_ACCENT   0x3CBF  // accent blue
#define C_GREEN    0x27EF  // bright green
#define C_PURPLE   0xCA3F  // purple
#define C_YELLOW   0xFE64  // warning yellow
#define C_GREY     0x4ACC
#define C_WHITE    0xDF7F
#define C_RED      0xF9C6

// Cached strings — only redraw what changes (RGB panel is slow to fully repaint)
static char  s_last_status[40] = {0};
static int   s_last_status_color = 0;
static char  s_last_nodes_text[16] = {0};
static char  s_last_net24[12] = {0};
static char  s_last_net50[12] = {0};
static char  s_last_uptime[16] = {0};
static char  s_last_lastrx[16] = {0};
static char  s_last_chmac[24] = {0};

// Layout coords (Y positions) for the 480x480 panel
#define Y_TITLE     20
#define Y_STATUS    70
#define Y_NODES_LBL 140
#define Y_NODES_VAL 170
#define Y_NET_LBL   240
#define Y_NET24     270
#define Y_NET50     310
#define Y_GPS       360
#define Y_UPTIME    400
#define Y_LASTRX    420
#define Y_CHMAC     440
#define Y_FOOTER    460

static void clear_text_rect(int x, int y, int w, int h) {
    gfx->fillRect(x, y, w, h, C_BG);
}

static void ui_init(void) {
    // I²C for TCA9554 expander — pins ported from Argus (47/48), NOT 8/48.
    Wire.begin(EXPANDER_SDA, EXPANDER_SCL);

    // Reset sequence via TCA9554 GPIO expander (Argus / HuginnESP pattern):
    //   pin 5 = LCD reset (active LOW)
    //   pin 6 = backlight enable (HIGH = on)
    // Without this dance the panel powers up in an indeterminate state and
    // gfx->begin() silently does nothing — we end up with a black screen.
    expander->pinMode(5, OUTPUT);
    expander->pinMode(6, OUTPUT);
    expander->digitalWrite(6, LOW);    // backlight off during reset
    delay(200);
    expander->digitalWrite(5, LOW);    // assert LCD reset
    delay(200);
    expander->digitalWrite(5, HIGH);   // release LCD reset
    delay(200);

    if (!gfx->begin()) {
        Serial.println("[CORE] gfx->begin() FAILED");
    } else {
        Serial.println("[CORE] Display init OK");
    }
    gfx->fillScreen(C_BG);

    // Turn the backlight on now that the panel is initialised. Doing this
    // earlier shows an ugly flash of garbage from VRAM.
    expander->digitalWrite(6, HIGH);

    // Title (drawn once)
    gfx->setTextColor(C_ACCENT);
    gfx->setTextSize(3);
    gfx->setCursor(60, Y_TITLE);
    gfx->print("RAGNAR COORDINATOR");

    // Static labels
    gfx->setTextSize(2);
    gfx->setTextColor(C_GREY);
    gfx->setCursor(20, Y_NODES_LBL); gfx->print("NODES");
    gfx->setCursor(20, Y_NET_LBL);   gfx->print("NETWORKS SEEN");
    gfx->setCursor(20, Y_NET24);     gfx->setTextColor(C_GREEN);  gfx->print("2.4G");
    gfx->setCursor(20, Y_NET50);     gfx->setTextColor(C_PURPLE); gfx->print("5.0G");

    // Footer
    gfx->setTextSize(2);
    gfx->setTextColor(C_GREY);
    gfx->setCursor(110, Y_FOOTER); gfx->print("ragnar standalone core");
}

static const char *fmt_uptime(uint32_t ms) {
    static char b[16];
    uint32_t s = ms / 1000, h = s / 3600, m = (s / 60) % 60, sec = s % 60;
    if (h > 0) snprintf(b, sizeof(b), "%lu:%02lu:%02lu",
                        (unsigned long)h, (unsigned long)m, (unsigned long)sec);
    else       snprintf(b, sizeof(b), "%lu:%02lu",
                        (unsigned long)m, (unsigned long)sec);
    return b;
}

static const char *fmt_lastrx(uint32_t now, uint32_t last) {
    static char b[16];
    if (last == 0) { strcpy(b, "—"); return b; }
    uint32_t s = (now - last) / 1000;
    if      (s < 60)   snprintf(b, sizeof(b), "%lus",  (unsigned long)s);
    else if (s < 3600) snprintf(b, sizeof(b), "%lum",  (unsigned long)(s / 60));
    else               snprintf(b, sizeof(b), "%luh",  (unsigned long)(s / 3600));
    return b;
}

static void ui_update(void) {
    char buf[40];
    uint32_t now = millis();
    bool receiving = (g_last_data_ms > 0 && (now - g_last_data_ms) < 2000);

    // Status line
    int status_color = C_YELLOW;
    if (receiving)                  { snprintf(buf, sizeof(buf), "RECEIVING DATA");        status_color = C_PURPLE; }
    else if (g_node_count > 0)      { snprintf(buf, sizeof(buf), "%u NODE%s CONNECTED",
                                                (unsigned)g_node_count,
                                                g_node_count > 1 ? "S" : "");              status_color = C_GREEN; }
    else                            { snprintf(buf, sizeof(buf), "WAITING FOR NODES");     status_color = C_YELLOW; }
    if (strcmp(buf, s_last_status) != 0 || status_color != s_last_status_color) {
        clear_text_rect(20, Y_STATUS, 440, 32);
        gfx->setTextSize(3);
        gfx->setTextColor(status_color);
        gfx->setCursor(20, Y_STATUS);
        gfx->print(buf);
        strcpy(s_last_status, buf);
        s_last_status_color = status_color;
    }

    // Nodes count
    snprintf(buf, sizeof(buf), "%u / %u",
             (unsigned)g_node_count, (unsigned)MAX_NODES);
    if (strcmp(buf, s_last_nodes_text) != 0) {
        clear_text_rect(20, Y_NODES_VAL, 200, 30);
        gfx->setTextSize(4);
        gfx->setTextColor(g_node_count > 0 ? C_GREEN : C_GREY);
        gfx->setCursor(20, Y_NODES_VAL);
        gfx->print(buf);
        strcpy(s_last_nodes_text, buf);
    }

    // 2.4G count
    snprintf(buf, sizeof(buf), "%u", (unsigned)g_net24);
    if (strcmp(buf, s_last_net24) != 0) {
        clear_text_rect(120, Y_NET24, 200, 24);
        gfx->setTextSize(2);
        gfx->setTextColor(C_GREEN);
        gfx->setCursor(120, Y_NET24);
        gfx->print(buf);
        strcpy(s_last_net24, buf);
    }
    // 5.0G count
    snprintf(buf, sizeof(buf), "%u", (unsigned)g_net50);
    if (strcmp(buf, s_last_net50) != 0) {
        clear_text_rect(120, Y_NET50, 200, 24);
        gfx->setTextSize(2);
        gfx->setTextColor(C_PURPLE);
        gfx->setCursor(120, Y_NET50);
        gfx->print(buf);
        strcpy(s_last_net50, buf);
    }

    // GPS — always N/A on bridge
    static bool gps_drawn = false;
    if (!gps_drawn) {
        gfx->setTextSize(2);
        gfx->setTextColor(C_GREY);
        gfx->setCursor(20, Y_GPS);
        gfx->print("GPS  N/A");
        gps_drawn = true;
    }

    // Uptime
    const char *upt = fmt_uptime(now);
    if (strcmp(upt, s_last_uptime) != 0) {
        clear_text_rect(150, Y_UPTIME, 200, 20);
        gfx->setTextSize(2);
        gfx->setTextColor(C_WHITE);
        gfx->setCursor(20, Y_UPTIME);
        gfx->print("UPTIME  ");
        gfx->setCursor(150, Y_UPTIME);
        gfx->print(upt);
        strcpy(s_last_uptime, upt);
    }

    // Last RX
    const char *lrx = fmt_lastrx(now, g_last_data_ms);
    if (strcmp(lrx, s_last_lastrx) != 0) {
        clear_text_rect(150, Y_LASTRX, 200, 20);
        gfx->setTextSize(2);
        gfx->setTextColor(C_GREY);
        gfx->setCursor(20, Y_LASTRX);
        gfx->print("LAST RX ");
        uint16_t rx_col = C_GREY;
        if (g_last_data_ms > 0) {
            uint32_t age = now - g_last_data_ms;
            rx_col = (age < 2000) ? C_PURPLE : (age < 60000) ? C_GREEN : C_GREY;
        }
        gfx->setTextColor(rx_col);
        gfx->setCursor(150, Y_LASTRX);
        gfx->print(lrx);
        strcpy(s_last_lastrx, lrx);
    }

    // CH / MAC (last 4 bytes of MAC for brevity)
    snprintf(buf, sizeof(buf), "CH/MAC %d  %02X:%02X",
             ESPNOW_CH, g_my_mac[4], g_my_mac[5]);
    if (strcmp(buf, s_last_chmac) != 0) {
        clear_text_rect(20, Y_CHMAC, 300, 20);
        gfx->setTextSize(2);
        gfx->setTextColor(C_WHITE);
        gfx->setCursor(20, Y_CHMAC);
        gfx->print(buf);
        strcpy(s_last_chmac, buf);
    }
}

static uint32_t t_ui = 0;

void setup() {
    // CDCOnBoot=cdc → Serial is HWCDC (USB-Serial-JTAG / CDC ACM).
    // 2-second settle delay after Serial.begin so CDC enumeration with the
    // host completes before we emit anything (matches HuginnESP S3 pattern).
    Serial.begin(BAUD);
    delay(2000);

    Serial.println("[CORE] Ragnar standalone coordinator booted (Piglet)");
    Serial.println(
        "{\"device\":\"RagnarCoord\",\"fw\":\"s3-lcd-1\","
        "\"board\":\"ESP32-S3-LCD-4B\",\"caps\":[\"espnow\",\"piglet-core\",\"display\"]}");

    // ESP-Now — channel must be set AFTER esp_now_init
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_now_init();
    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_send);

    {
        esp_now_peer_info_t bc = {};
        memset(bc.peer_addr, 0xFF, 6);
        bc.channel = 0;
        bc.encrypt = false;
        esp_now_add_peer(&bc);
    }
    esp_wifi_set_channel(ESPNOW_CH, WIFI_SECOND_CHAN_NONE);

    esp_wifi_get_mac(WIFI_IF_STA, g_my_mac);
    safe_serial_printf("[CORE] Listening on channel %d, MAC %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                       ESPNOW_CH,
                       g_my_mac[0], g_my_mac[1], g_my_mac[2],
                       g_my_mac[3], g_my_mac[4], g_my_mac[5]);

    memset(g_nodes, 0, sizeof(g_nodes));
    g_text_queue = xQueueCreate(TEXT_QUEUE_DEPTH, sizeof(PendingText));

    // Display init last — fastest path to first usable UI.
    ui_init();
}

void loop() {
    poll_host_serial();
    drain_text_queue();
    heartbeat_tick();
    alive_tick();

    uint32_t now = millis();
    if (now - t_ui >= 500) { t_ui = now; ui_update(); }

    delay(5);
}
