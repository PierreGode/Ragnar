/*
 * espnow_bridge_c6_lcd.ino  —  Ragnar ESP-Now bridge with LCD status display
 *
 * Hardware: Waveshare ESP32-C6 1.47" LCD development board
 *   Display : ST7789  172×320 IPS, portrait
 *   LED     : WS2812 RGB on GPIO 8
 *   SPI     : MOSI=6  SCLK=7  MISO=5  CS=14  DC=15  RST=21  BL=22
 *
 * Arduino IDE board : "ESP32C6 Dev Module"
 * Required libraries (Library Manager):
 *   lvgl              ≥ 9.0  (LVGL by LVGL)
 *   Adafruit NeoPixel ≥ 1.11 (Adafruit)
 * ESP32 board support: Espressif ESP32 ≥ 3.0.0
 *
 * Place lv_conf.h alongside this .ino file.
 *
 * ── Bridge serial protocol ─────────────────────────────────────────────────
 * Frame: SYNC[2=0xAB,0xCD] CMD[1] MAC[6] LEN[2-LE] PAYLOAD[N] CRC[1-XOR]
 *   CMD 0x01 RX  : ESP32→Pi, ESP-Now packet received from a node
 *   CMD 0x02 TX  : Pi→ESP32, send ESP-Now packet to MAC
 *   CMD 0x03 HELLO : bridge identification
 *   CMD 0x05 STATS : Pi→ESP32, stat update (nodes,gps,net24,net50,flags)
 *
 * ── LED indicators ─────────────────────────────────────────────────────────
 *   Fast dark-blue blink (150 ms)  →  waiting, no nodes paired
 *   Slow light-green pulse (2 s)   →  nodes connected, idle
 *   Steady purple                  →  data being received from nodes
 */

#define LV_CONF_INCLUDE_SIMPLE 1

#include <Arduino.h>
#include <SPI.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <lvgl.h>
#include <Adafruit_NeoPixel.h>

// ── Hardware pins (Waveshare ESP32-C6 1.47" LCD) ──────────────────────────────
#define PIN_MOSI    6
#define PIN_SCLK    7
#define PIN_MISO    5
#define PIN_CS      14
#define PIN_DC      15
#define PIN_RST     21
#define PIN_BL      22
#define PIN_LED     8    // WS2812 RGB

// ── Display geometry ──────────────────────────────────────────────────────────
#define LCD_W       172
#define LCD_H       320
#define LCD_X_OFS   34
#define LCD_Y_OFS   0
#define SPI_FREQ    80000000UL

// ── LVGL ──────────────────────────────────────────────────────────────────────
#define LVGL_BUF    (LCD_W * LCD_H / 20)   // ~2752 pixels per buffer
#define LVGL_TICK   5                        // ms

// ── Bridge protocol ───────────────────────────────────────────────────────────
#define BAUD        460800
#define ESPNOW_CH   6
#define MAX_PL      250

#define SYNC_A      0xAB
#define SYNC_B      0xCD
#define CMD_RX      0x01
#define CMD_TX      0x02
#define CMD_HELLO   0x03
#define CMD_STATS   0x05   // host → bridge stat push

// JCMK message types (we only peek at MSG_TEXT to update the LED)
static const uint8_t JCMK_MAGIC[4] = {'E','N','O','W'};
#define MSG_TEXT    4

// ── Stats (populated by CMD_STATS from Ragnar) ────────────────────────────────
struct Stats {
    uint8_t  nodes    = 0;
    uint8_t  gps_fix  = 0;
    uint16_t net24    = 0;
    uint16_t net50    = 0;
};
static Stats     g_stats;
static uint32_t  g_last_data_ms  = 0;   // millis() of last MSG_TEXT seen

// ── NeoPixel ──────────────────────────────────────────────────────────────────
static Adafruit_NeoPixel px(1, PIN_LED, NEO_GRB + NEO_KHZ800);

// ── ST7789 SPI driver ─────────────────────────────────────────────────────────
static SPIClass  lcd_spi(FSPI);

static inline void lcd_cmd(uint8_t c) {
    digitalWrite(PIN_DC, LOW);
    digitalWrite(PIN_CS, LOW);
    lcd_spi.write(c);
    digitalWrite(PIN_CS, HIGH);
}
static inline void lcd_dat(uint8_t d) {
    digitalWrite(PIN_DC, HIGH);
    digitalWrite(PIN_CS, LOW);
    lcd_spi.write(d);
    digitalWrite(PIN_CS, HIGH);
}
static void lcd_dat_buf(const uint8_t *buf, uint32_t n) {
    digitalWrite(PIN_DC, HIGH);
    digitalWrite(PIN_CS, LOW);
    lcd_spi.writeBytes(buf, n);
    digitalWrite(PIN_CS, HIGH);
}
static void lcd_set_cursor(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2) {
    uint16_t cx1 = x1 + LCD_X_OFS, cx2 = x2 + LCD_X_OFS;
    uint16_t cy1 = y1 + LCD_Y_OFS, cy2 = y2 + LCD_Y_OFS;
    lcd_cmd(0x2A);
    lcd_dat(cx1 >> 8); lcd_dat(cx1);
    lcd_dat(cx2 >> 8); lcd_dat(cx2);
    lcd_cmd(0x2B);
    lcd_dat(cy1 >> 8); lcd_dat(cy1);
    lcd_dat(cy2 >> 8); lcd_dat(cy2);
    lcd_cmd(0x2C);
}
static void lcd_window(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2,
                        uint16_t *pixels) {
    lcd_set_cursor(x1, y1, x2, y2);
    uint32_t n = (uint32_t)(x2 - x1 + 1) * (y2 - y1 + 1) * 2;
    digitalWrite(PIN_DC, HIGH);
    digitalWrite(PIN_CS, LOW);
    lcd_spi.writeBytes((uint8_t *)pixels, n);
    digitalWrite(PIN_CS, HIGH);
}

static void lcd_init(void) {
    pinMode(PIN_DC,  OUTPUT);
    pinMode(PIN_CS,  OUTPUT);
    pinMode(PIN_RST, OUTPUT);
    pinMode(PIN_BL,  OUTPUT);

    lcd_spi.begin(PIN_SCLK, PIN_MISO, PIN_MOSI, -1);
    lcd_spi.setFrequency(SPI_FREQ);
    lcd_spi.setDataMode(SPI_MODE0);

    // Hardware reset
    digitalWrite(PIN_RST, HIGH); delay(10);
    digitalWrite(PIN_RST, LOW);  delay(10);
    digitalWrite(PIN_RST, HIGH); delay(120);

    // ST7789 init sequence (portrait, 172×320, RGB565, IPS inversion on)
    lcd_cmd(0x11); delay(120);                    // Sleep out
    lcd_cmd(0x36); lcd_dat(0x00);                 // MADCTL portrait
    lcd_cmd(0x3A); lcd_dat(0x05);                 // 16-bit RGB565
    lcd_cmd(0xB2);                                // Porch
    lcd_dat(0x0C); lcd_dat(0x0C); lcd_dat(0x00); lcd_dat(0x33); lcd_dat(0x33);
    lcd_cmd(0xB7); lcd_dat(0x35);                 // Gate ctrl
    lcd_cmd(0xBB); lcd_dat(0x19);                 // VCOMS
    lcd_cmd(0xC0); lcd_dat(0x2C);                 // LCM ctrl
    lcd_cmd(0xC2); lcd_dat(0x01);                 // VDV/VRH enable
    lcd_cmd(0xC3); lcd_dat(0x12);                 // VRH
    lcd_cmd(0xC4); lcd_dat(0x20);                 // VDV
    lcd_cmd(0xC6); lcd_dat(0x0F);                 // FR ctrl (60 Hz)
    lcd_cmd(0xD0); lcd_dat(0xA4); lcd_dat(0xA1);  // Power ctrl
    lcd_cmd(0xE0);                                // Gamma +
    static const uint8_t gp[] = {0xD0,0x04,0x0D,0x11,0x13,0x2B,0x3F,0x54,
                                   0x4C,0x18,0x0D,0x0B,0x1F,0x23};
    lcd_dat_buf(gp, sizeof(gp));
    lcd_cmd(0xE1);                                // Gamma -
    static const uint8_t gn[] = {0xD0,0x04,0x0C,0x11,0x13,0x2C,0x3F,0x44,
                                   0x51,0x2F,0x1F,0x1F,0x20,0x23};
    lcd_dat_buf(gn, sizeof(gn));
    lcd_cmd(0x21);                                // Inversion on (IPS)
    lcd_cmd(0x29);                                // Display on

    digitalWrite(PIN_BL, HIGH);                   // Backlight on
}

// ── LVGL integration ──────────────────────────────────────────────────────────
static lv_color_t lv_buf1[LVGL_BUF];
static lv_color_t lv_buf2[LVGL_BUF];

static void lv_flush(lv_display_t *d, const lv_area_t *a, uint8_t *px_map) {
    lcd_window(a->x1, a->y1, a->x2, a->y2, (uint16_t *)px_map);
    lv_display_flush_ready(d);
}
static void lv_tick_cb(void *) { lv_tick_inc(LVGL_TICK); }

static void lvgl_init(void) {
    lv_init();
    lv_display_t *disp = lv_display_create(LCD_W, LCD_H);
    lv_display_set_flush_cb(disp, lv_flush);
    lv_display_set_buffers(disp, lv_buf1, lv_buf2,
                            sizeof(lv_buf1), LV_DISPLAY_RENDER_MODE_PARTIAL);

    const esp_timer_create_args_t ta = { .callback = lv_tick_cb, .name = "lv" };
    esp_timer_handle_t th;
    esp_timer_create(&ta, &th);
    esp_timer_start_periodic(th, LVGL_TICK * 1000ULL);
}

// ── UI widgets ────────────────────────────────────────────────────────────────
static lv_obj_t *lbl_status;
static lv_obj_t *lbl_nodes;
static lv_obj_t *lbl_node_dots;
static lv_obj_t *lbl_net24_val;
static lv_obj_t *lbl_net50_val;
static lv_obj_t *bar_net24;
static lv_obj_t *bar_net50;
static lv_obj_t *lbl_gps;

// Palette
#define C_BG       lv_color_hex(0x080C14)
#define C_ACCENT   lv_color_hex(0x3377FF)
#define C_GREEN    lv_color_hex(0x22EE88)
#define C_PURPLE   lv_color_hex(0xCC44FF)
#define C_YELLOW   lv_color_hex(0xFFCC22)
#define C_GREY     lv_color_hex(0x445566)
#define C_WHITE    lv_color_hex(0xDDEEFF)
#define C_RED      lv_color_hex(0xFF4444)

static lv_obj_t *hsep(lv_obj_t *scr, int y) {
    lv_obj_t *s = lv_obj_create(scr);
    lv_obj_set_size(s, LCD_W - 8, 1);
    lv_obj_set_style_bg_color(s, C_GREY, 0);
    lv_obj_set_style_bg_opa(s, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s, 0, 0);
    lv_obj_set_style_pad_all(s, 0, 0);
    lv_obj_set_pos(s, 4, y);
    return s;
}

static void ui_create(void) {
    lv_obj_t *scr = lv_screen_active();
    lv_obj_set_style_bg_color(scr, C_BG, 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    // ── Title ──────────────────────────────────────────────────────────────
    lv_obj_t *t = lv_label_create(scr);
    lv_label_set_text(t, "RAGNAR COORDINATOR");
    lv_obj_set_style_text_color(t, C_ACCENT, 0);
    lv_obj_set_style_text_font(t, &lv_font_montserrat_12, 0);
    lv_obj_align(t, LV_ALIGN_TOP_MID, 0, 5);

    hsep(scr, 22);

    // ── Status ─────────────────────────────────────────────────────────────
    lbl_status = lv_label_create(scr);
    lv_label_set_text(lbl_status, LV_SYMBOL_REFRESH " WAITING FOR NODES");
    lv_obj_set_style_text_color(lbl_status, C_YELLOW, 0);
    lv_obj_set_style_text_font(lbl_status, &lv_font_montserrat_12, 0);
    lv_obj_set_pos(lbl_status, 4, 28);

    hsep(scr, 46);

    // ── Nodes ──────────────────────────────────────────────────────────────
    lv_obj_t *h1 = lv_label_create(scr);
    lv_label_set_text(h1, "NODES");
    lv_obj_set_style_text_color(h1, C_GREY, 0);
    lv_obj_set_style_text_font(h1, &lv_font_montserrat_10, 0);
    lv_obj_set_pos(h1, 6, 51);

    lbl_nodes = lv_label_create(scr);
    lv_label_set_text(lbl_nodes, "0 / 4");
    lv_obj_set_style_text_color(lbl_nodes, C_GREY, 0);
    lv_obj_set_style_text_font(lbl_nodes, &lv_font_montserrat_20, 0);
    lv_obj_set_pos(lbl_nodes, 6, 63);

    // Node slot dots  ●●○○
    lbl_node_dots = lv_label_create(scr);
    lv_label_set_text(lbl_node_dots, "○ ○ ○ ○");
    lv_obj_set_style_text_color(lbl_node_dots, C_GREY, 0);
    lv_obj_set_style_text_font(lbl_node_dots, &lv_font_montserrat_14, 0);
    lv_obj_align(lbl_node_dots, LV_ALIGN_TOP_RIGHT, -6, 68);

    hsep(scr, 92);

    // ── Networks ───────────────────────────────────────────────────────────
    lv_obj_t *h2 = lv_label_create(scr);
    lv_label_set_text(h2, "NETWORKS SEEN");
    lv_obj_set_style_text_color(h2, C_GREY, 0);
    lv_obj_set_style_text_font(h2, &lv_font_montserrat_10, 0);
    lv_obj_set_pos(h2, 6, 97);

    // 2.4 GHz row
    lv_obj_t *l24 = lv_label_create(scr);
    lv_label_set_text(l24, "2.4G");
    lv_obj_set_style_text_color(l24, C_GREEN, 0);
    lv_obj_set_style_text_font(l24, &lv_font_montserrat_12, 0);
    lv_obj_set_pos(l24, 6, 111);

    bar_net24 = lv_bar_create(scr);
    lv_obj_set_size(bar_net24, 86, 9);
    lv_obj_set_style_bg_color(bar_net24, C_GREY, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(bar_net24, LV_OPA_40, LV_PART_MAIN);
    lv_obj_set_style_bg_color(bar_net24, C_GREEN, LV_PART_INDICATOR);
    lv_bar_set_range(bar_net24, 0, 500);
    lv_bar_set_value(bar_net24, 0, LV_ANIM_OFF);
    lv_obj_set_pos(bar_net24, 38, 114);

    lbl_net24_val = lv_label_create(scr);
    lv_label_set_text(lbl_net24_val, "0");
    lv_obj_set_style_text_color(lbl_net24_val, C_GREEN, 0);
    lv_obj_set_style_text_font(lbl_net24_val, &lv_font_montserrat_12, 0);
    lv_obj_align(lbl_net24_val, LV_ALIGN_TOP_RIGHT, -4, 111);

    // 5 GHz row
    lv_obj_t *l50 = lv_label_create(scr);
    lv_label_set_text(l50, "5.0G");
    lv_obj_set_style_text_color(l50, C_PURPLE, 0);
    lv_obj_set_style_text_font(l50, &lv_font_montserrat_12, 0);
    lv_obj_set_pos(l50, 6, 130);

    bar_net50 = lv_bar_create(scr);
    lv_obj_set_size(bar_net50, 86, 9);
    lv_obj_set_style_bg_color(bar_net50, C_GREY, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(bar_net50, LV_OPA_40, LV_PART_MAIN);
    lv_obj_set_style_bg_color(bar_net50, C_PURPLE, LV_PART_INDICATOR);
    lv_bar_set_range(bar_net50, 0, 500);
    lv_bar_set_value(bar_net50, 0, LV_ANIM_OFF);
    lv_obj_set_pos(bar_net50, 38, 133);

    lbl_net50_val = lv_label_create(scr);
    lv_label_set_text(lbl_net50_val, "0");
    lv_obj_set_style_text_color(lbl_net50_val, C_PURPLE, 0);
    lv_obj_set_style_text_font(lbl_net50_val, &lv_font_montserrat_12, 0);
    lv_obj_align(lbl_net50_val, LV_ALIGN_TOP_RIGHT, -4, 130);

    hsep(scr, 150);

    // ── GPS ────────────────────────────────────────────────────────────────
    lbl_gps = lv_label_create(scr);
    lv_label_set_text(lbl_gps, LV_SYMBOL_GPS "  GPS  NO FIX");
    lv_obj_set_style_text_color(lbl_gps, C_GREY, 0);
    lv_obj_set_style_text_font(lbl_gps, &lv_font_montserrat_12, 0);
    lv_obj_set_pos(lbl_gps, 6, 158);

    hsep(scr, 177);

    // ── Footer ─────────────────────────────────────────────────────────────
    lv_obj_t *foot = lv_label_create(scr);
    lv_label_set_text(foot, "ragnar wardriving mesh");
    lv_obj_set_style_text_color(foot, C_GREY, 0);
    lv_obj_set_style_text_font(foot, &lv_font_montserrat_10, 0);
    lv_obj_align(foot, LV_ALIGN_BOTTOM_MID, 0, -5);
}

// ── Dot-string helper: "●●○○" based on node count ─────────────────────────────
static const char *node_dots(uint8_t n) {
    static char buf[32];
    const char *on  = "\xE2\x97\x8F ";   // ● U+25CF
    const char *off = "\xE2\x97\x8B ";   // ○ U+25CB
    buf[0] = '\0';
    for (int i = 0; i < 4; i++)
        strcat(buf, i < n ? on : off);
    return buf;
}

// ── UI refresh (called every 500 ms from loop) ────────────────────────────────
static void ui_update(void) {
    static char b[48];
    uint32_t now = millis();
    bool receiving = (g_last_data_ms > 0 && (now - g_last_data_ms) < 2000);

    // Status line + colour
    if (receiving) {
        lv_label_set_text(lbl_status, LV_SYMBOL_DOWNLOAD " RECEIVING DATA");
        lv_obj_set_style_text_color(lbl_status, C_PURPLE, 0);
    } else if (g_stats.nodes > 0) {
        snprintf(b, sizeof(b), LV_SYMBOL_OK " %d NODE%s CONNECTED",
                 g_stats.nodes, g_stats.nodes > 1 ? "S" : "");
        lv_label_set_text(lbl_status, b);
        lv_obj_set_style_text_color(lbl_status, C_GREEN, 0);
    } else {
        lv_label_set_text(lbl_status, LV_SYMBOL_REFRESH " WAITING FOR NODES");
        lv_obj_set_style_text_color(lbl_status, C_YELLOW, 0);
    }

    // Node count + dots
    snprintf(b, sizeof(b), "%d / 4", g_stats.nodes);
    lv_label_set_text(lbl_nodes, b);
    lv_obj_set_style_text_color(lbl_nodes,
                                 g_stats.nodes > 0 ? C_GREEN : C_GREY, 0);
    lv_label_set_text(lbl_node_dots, node_dots(g_stats.nodes));

    // 2.4 GHz
    snprintf(b, sizeof(b), "%u", (unsigned)g_stats.net24);
    lv_label_set_text(lbl_net24_val, b);
    lv_bar_set_value(bar_net24,
                      (int32_t)min((uint16_t)500, g_stats.net24), LV_ANIM_ON);

    // 5 GHz
    snprintf(b, sizeof(b), "%u", (unsigned)g_stats.net50);
    lv_label_set_text(lbl_net50_val, b);
    lv_bar_set_value(bar_net50,
                      (int32_t)min((uint16_t)500, g_stats.net50), LV_ANIM_ON);

    // GPS
    if (g_stats.gps_fix) {
        lv_label_set_text(lbl_gps, LV_SYMBOL_GPS "  GPS  FIX " LV_SYMBOL_OK);
        lv_obj_set_style_text_color(lbl_gps, C_GREEN, 0);
    } else {
        lv_label_set_text(lbl_gps, LV_SYMBOL_GPS "  GPS  NO FIX");
        lv_obj_set_style_text_color(lbl_gps, C_GREY, 0);
    }
}

// ── LED state machine (called every 50 ms) ────────────────────────────────────
static void led_update(void) {
    uint32_t now = millis();
    bool receiving = (g_last_data_ms > 0 && (now - g_last_data_ms) < 2000);

    if (receiving) {
        // Steady purple
        px.setPixelColor(0, px.Color(70, 0, 110));

    } else if (g_stats.nodes > 0) {
        // Slow light-green pulse  — 2 s sine period
        float phase = (float)(now % 2000) / 2000.0f;
        float s     = (phase < 0.5f) ? phase * 2.0f : 2.0f - phase * 2.0f;
        uint8_t v   = (uint8_t)(s * 90.0f + 10.0f);   // 10–100 brightness
        px.setPixelColor(0, px.Color(0, v, v / 5));

    } else {
        // Fast dark-blue blink — 150 ms on / 150 ms off
        bool on = ((now / 150) & 1) == 0;
        px.setPixelColor(0, on ? px.Color(0, 0, 70) : 0);
    }

    px.show();
}

// ── Bridge CRC & frame sender ─────────────────────────────────────────────────
static uint8_t crc_of(uint8_t cmd, const uint8_t *mac,
                       uint16_t plen, const uint8_t *pl) {
    uint8_t c = cmd;
    for (int i = 0; i < 6; i++) c ^= mac[i];
    c ^= (uint8_t)(plen & 0xFF);
    c ^= (uint8_t)(plen >> 8);
    for (uint16_t i = 0; i < plen; i++) c ^= pl[i];
    return c;
}
static void tx_frame(uint8_t cmd, const uint8_t *mac,
                      const uint8_t *pl, uint16_t plen) {
    Serial.write(SYNC_A); Serial.write(SYNC_B);
    Serial.write(cmd);
    Serial.write(mac, 6);
    Serial.write((uint8_t)(plen));
    Serial.write((uint8_t)(plen >> 8));
    if (plen) Serial.write(pl, plen);
    Serial.write(crc_of(cmd, mac, plen, pl));
    Serial.flush();
}

// ── ESP-Now callbacks ─────────────────────────────────────────────────────────
static void on_recv(const esp_now_recv_info_t *info,
                    const uint8_t *data, int len) {
    if (len <= 0 || len > MAX_PL) return;
    // Detect MSG_TEXT passing through → set RECEIVING state
    if (len >= 5 && memcmp(data, JCMK_MAGIC, 4) == 0 && data[4] == MSG_TEXT)
        g_last_data_ms = millis();
    tx_frame(CMD_RX, info->src_addr, data, (uint16_t)len);
}
static void on_send(const uint8_t *mac, esp_now_send_status_t s) { (void)mac; (void)s; }

// ── Host → ESP32 frame parser ─────────────────────────────────────────────────
static uint8_t  rx_buf[16 + MAX_PL];
static int      rx_pos  = 0;
static bool     in_sync = false;

static void handle_host_frame(uint8_t cmd, const uint8_t *mac,
                                const uint8_t *pl, uint16_t plen) {
    if (cmd == CMD_TX) {
        if (!esp_now_is_peer_exist(mac)) {
            esp_now_peer_info_t p = {};
            memcpy(p.peer_addr, mac, 6);
            p.channel = ESPNOW_CH;
            p.encrypt = false;
            esp_now_add_peer(&p);
        }
        esp_now_send(mac, pl, plen);

    } else if (cmd == CMD_STATS && plen >= 6) {
        // Payload: nodes(1) gps_fix(1) net24(2-LE) net50(2-LE)
        g_stats.nodes   = pl[0];
        g_stats.gps_fix = pl[1];
        g_stats.net24   = (uint16_t)pl[2] | ((uint16_t)pl[3] << 8);
        g_stats.net50   = (uint16_t)pl[4] | ((uint16_t)pl[5] << 8);

    } else if (cmd == CMD_HELLO) {
        uint8_t my[6];
        esp_wifi_get_mac(WIFI_IF_STA, my);
        static const uint8_t id[] = "RagnarBridge";
        tx_frame(CMD_HELLO, my, id, sizeof(id) - 1);
    }
}

static void parse_byte(uint8_t b) {
    if (!in_sync) {
        if (rx_pos == 0 && b == SYNC_A)      { rx_buf[rx_pos++] = b; }
        else if (rx_pos == 1 && b == SYNC_B) { rx_buf[rx_pos++] = b; in_sync = true; }
        else                                  { rx_pos = 0; }
        return;
    }
    rx_buf[rx_pos++] = b;
    if (rx_pos < 11) return;

    uint8_t  cmd  = rx_buf[2];
    uint16_t plen = (uint16_t)rx_buf[9] | ((uint16_t)rx_buf[10] << 8);
    if (plen > MAX_PL) { rx_pos = 0; in_sync = false; return; }

    int total = 11 + (int)plen + 1;
    if (rx_pos < total) return;

    const uint8_t *mac = rx_buf + 3;
    const uint8_t *pl  = rx_buf + 11;
    if (crc_of(cmd, mac, plen, pl) == rx_buf[total - 1])
        handle_host_frame(cmd, mac, pl, plen);

    rx_pos = 0; in_sync = false;
}

// ── setup / loop ──────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(BAUD);

    // LED: start with slow dark-blue while booting
    px.begin();
    px.setBrightness(100);
    px.setPixelColor(0, px.Color(0, 0, 60));
    px.show();

    // Display + LVGL
    lcd_init();
    lvgl_init();
    ui_create();
    lv_timer_handler();

    // ESP-Now
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(ESPNOW_CH, WIFI_SECOND_CHAN_NONE);
    esp_now_init();
    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_send);

    // Broadcast peer (coordinator messages go here)
    {
        esp_now_peer_info_t bc = {};
        memset(bc.peer_addr, 0xFF, 6);
        bc.channel = ESPNOW_CH;
        bc.encrypt = false;
        esp_now_add_peer(&bc);
    }

    // Identify to host
    Serial.println("RagnarBridge ready");
    delay(50);
    uint8_t my[6];
    esp_wifi_get_mac(WIFI_IF_STA, my);
    static const uint8_t id[] = "RagnarBridge";
    tx_frame(CMD_HELLO, my, id, sizeof(id) - 1);
}

static uint32_t t_ui  = 0;
static uint32_t t_led = 0;

void loop() {
    while (Serial.available())
        parse_byte((uint8_t)Serial.read());

    uint32_t now = millis();

    if (now - t_ui >= 500)  { t_ui  = now; ui_update(); }
    if (now - t_led >= 50)  { t_led = now; led_update(); }

    lv_timer_handler();
    delay(5);
}
