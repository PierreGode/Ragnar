/*
 * roomscan_s3_lcd.ino — Ragnar RoomScan (touchscreen floor-plan tracer)
 *
 * Target hardware: Waveshare ESP32-S3-Touch-LCD-4B ("Smart 86 Box")
 *   - ESP32-S3-N16R8 (16 MB flash / 8 MB PSRAM)
 *   - 480x480 RGB IPS panel via ST7701 (TCA9554 I2C GPIO expander for reset/BL)
 *   - GT911 5-point capacitive touch (I2C, reset via expander pin 1, INT GPIO16)
 *   - USB CDC + JTAG
 *
 * Purpose:
 *   Sketch a building floor-plan directly on the panel — tap each corner of a
 *   room, segments draw live, tap the first corner again to close. Trace several
 *   rooms and PLACE ACCESS POINTS that Ragnar scanned: Ragnar pushes its Wi-Fi
 *   scan to the device over USB serial, you pick an AP from the on-screen list
 *   and tap where it physically sits, then SEND uploads the finished map
 *   (outline + AP positions, each tied to a real BSSID) straight back into
 *   Ragnar's Coverage Heatmap.
 *
 * Serial protocol (line-based, 115200):
 *   Ragnar -> device:
 *     PING                      -> device replies PONG
 *     SEND                      -> device emits the map JSON line
 *     APCLEAR                   -> clear the received AP list
 *     AP\t<i>\t<ssid>\t<bssid>\t<rssi>\t<band>\t<ch>   -> append one AP
 *     APDONE                    -> finalize (redraw if the list is showing)
 *   device -> Ragnar:
 *     {"type":"roomscan_hello","fw":"1.1","proto":1}          (on boot)
 *     PONG                                                    (on PING)
 *     {"type":"ragnar_roomscan","v":1,"scale_m":..,"rooms":[..],"aps":[..]}
 *                                          (on SEND, or the on-screen SEND btn)
 *
 * Coordinates are fractions (0..1) of a square floor whose real edge length in
 * metres is user-set — matching Ragnar's Coverage Heatmap floor model.
 *
 * Build (arduino-cli):
 *   --fqbn "esp32:esp32:esp32s3:CDCOnBoot=cdc,USBMode=hwcdc,PartitionScheme=default_8MB,PSRAM=opi,FlashSize=8M"
 *   --build-property "compiler.cpp.extra_flags=-fpermissive"
 *   Library: "GFX Library for Arduino" by moononournation @1.6.7
 *
 * Display bring-up (ST7701 + TCA9554 + RGB timings + bounce buffer) ported from
 * espnow_bridge_s3_lcd.ino. GT911 driver (touch.cpp/.h) is the Argus driver.
 */

#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <Arduino_GFX_Library.h>
#include "touch.h"

// ─────────────────────────────────────────────────────────────────────────────
//  480x480 RGB display (ST7701 via TCA9554 I2C expander) — Waveshare 4B
//  Pins/reset/backlight/bounce-buffer are load-bearing — do not "simplify".
// ─────────────────────────────────────────────────────────────────────────────
#define EXPANDER_SDA   47
#define EXPANDER_SCL   48
#define EXPANDER_ADDR  0x20
#define LCD_RST_PIN    5
#define LCD_BL_PIN     6
#define GT911_RST_PIN  1
#define TP_INT         16

static Arduino_XCA9554SWSPI *expander = new Arduino_XCA9554SWSPI(
    7, 0, 2, 1, &Wire, EXPANDER_ADDR);

static Arduino_ESP32RGBPanel *rgbpanel = new Arduino_ESP32RGBPanel(
    17, 3, 46, 9,
    10, 11, 12, 13, 14,
    21, 8, 18, 45, 38, 39,
    40, 41, 42, 2, 1,
    1, 10, 8, 50,
    1, 10, 8, 20,
    0, GFX_NOT_DEFINED, false, 0, 0,
    480 * 10);

static Arduino_RGB_Display *gfx = new Arduino_RGB_Display(
    480, 480, rgbpanel, 0, true,
    expander, GFX_NOT_DEFINED,
    st7701_type1_init_operations, sizeof(st7701_type1_init_operations));

// ── Palette (RGB565) ─────────────────────────────────────────────────────────
#define C_BG       0x0841
#define C_PANEL    0x10A3
#define C_GRID     0x2124
#define C_GRID5    0x39C7
#define C_ACCENT   0x3CBF
#define C_GREEN    0x27EF
#define C_YELLOW   0xFE64
#define C_WHITE    0xDF7F
#define C_GREY     0x8410
#define C_RED      0xF9C6
#define C_BTN      0x18E3
#define C_AP       0xFD20   // AP marker (orange)
#define C_APSEL    0xFFE0   // selected AP (yellow)
#define C_OBJ      0x5BDF   // furniture/object marker (light blue)

static const uint16_t ROOM_COLORS[] = {
    0x27EF, 0xFE64, 0xCA3F, 0xFD20, 0x07FF, 0xF81F, 0x67FF, 0xFFE0
};
#define NUM_ROOM_COLORS (sizeof(ROOM_COLORS)/sizeof(ROOM_COLORS[0]))

// ── Layout ───────────────────────────────────────────────────────────────────
#define SCR_W        480
#define SCR_H        480
#define TITLE_H      28
#define CANVAS_X0    40
#define CANVAS_Y0    TITLE_H
#define CANVAS_SZ    400
#define TOOLBAR_Y0   (CANVAS_Y0 + CANVAS_SZ)   // 428
#define TOOLBAR_H    (SCR_H - TOOLBAR_Y0)       // 52
#define CLOSE_R_PX   18
#define NUM_BTNS     5                          // UNDO CLOSE CLEAR APs SEND

#define SCALE_MINUS_X0 300
#define SCALE_MINUS_X1 336
#define SCALE_PLUS_X0  432
#define SCALE_PLUS_X1  468

// ── Model ────────────────────────────────────────────────────────────────────
#define MAX_ROOMS  12
#define MAX_PTS    40
#define MAX_APS    48
#define MAX_PLACED 48

struct Pt { float x, y; };
struct Room { Pt pts[MAX_PTS]; uint8_t n; };
#define AP_SRC_SCAN 0   // discovered by the device's own Wi-Fi scan (live RSSI)
#define AP_SRC_PUSH 1   // sent by Ragnar over serial
struct ApInfo { char ssid[33]; char bssid[18]; int16_t rssi; char band[6]; uint16_t ch; uint8_t src; };
// Placed APs carry their own identity (not an index) so the AP list can update,
// re-sort or be cleared — e.g. by the live scan — without corrupting placements.
struct PlacedAp { char ssid[33]; char bssid[18]; int16_t rssi; float x, y; };

static Room     g_rooms[MAX_ROOMS];
static uint8_t  g_roomCount = 0;
static Room     g_cur = { {}, 0 };
static int      g_scaleM = 10;

static ApInfo   g_aps[MAX_APS];
static uint8_t  g_apCount = 0;
static PlacedAp g_placed[MAX_PLACED];
static uint8_t  g_placedCount = 0;
static int16_t  g_selAp = -1;         // AP chosen for placement

// ── Furniture / structural objects that attenuate Wi-Fi ─────────────────────
// Each becomes a Coverage-Heatmap "column" (point obstruction: footprint radius
// + dB loss) so predicted coverage actually shadows behind it. dB values reflect
// real 2.4/5 GHz behaviour (metal/water block hard, soft furniture barely).
struct ObjType { const char *name; const char *shortl; float radius_m; uint8_t loss_db; };
static const ObjType OBJ_TYPES[] = {
    {"Concrete pillar",  "PILLAR", 0.30f, 15},
    {"Steel pillar",     "STEEL",  0.30f, 20},
    {"Wardrobe (wood)",  "WARDR",  0.60f,  5},
    {"Metal cabinet",    "METAL",  0.50f, 18},
    {"Fridge",           "FRIDGE", 0.50f, 20},
    {"Bookshelf",        "BOOKS",  0.50f,  4},
    {"Aquarium (water)", "WATER",  0.40f, 10},
    {"Mirror",           "MIRROR", 0.40f, 12},
    {"Couch / sofa",     "SOFA",   0.70f,  3},
    {"Bed",              "BED",    0.80f,  3},
    {"Desk / table",     "DESK",   0.60f,  2},
    {"TV / electronics", "TV",     0.50f,  8},
};
#define NUM_OBJ_TYPES (sizeof(OBJ_TYPES) / sizeof(OBJ_TYPES[0]))
#define MAX_OBJS  48
struct PlacedObj { int8_t typeRef; float x, y; };
static PlacedObj g_objs[MAX_OBJS];
static uint8_t   g_objCount = 0;
static int16_t   g_selObj = -1;       // object type chosen for placement

enum Mode { MODE_DRAW, MODE_APLIST, MODE_APPLACE, MODE_OBJLIST, MODE_OBJPLACE };
static Mode g_mode = MODE_DRAW;
static uint8_t g_listPage = 0;        // shared list paging (AP / object lists)

static char g_json[4096];
static bool s_gfxOk = false;

// ── Toast (transient status line over the toolbar area) ──────────────────────
static char     g_toast[40] = {0};
static uint32_t g_toastUntil = 0;

static void toast(const char *msg) {
    strncpy(g_toast, msg, sizeof(g_toast) - 1);
    g_toast[sizeof(g_toast) - 1] = 0;
    g_toastUntil = millis() + 1800;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Coordinate helpers
// ─────────────────────────────────────────────────────────────────────────────
static inline int fx2sx(float fx) { return CANVAS_X0 + (int)(fx * CANVAS_SZ + 0.5f); }
static inline int fy2sy(float fy) { return CANVAS_Y0 + (int)(fy * CANVAS_SZ + 0.5f); }
static inline bool inCanvas(int sx, int sy) {
    return sx >= CANVAS_X0 && sx < CANVAS_X0 + CANVAS_SZ &&
           sy >= CANVAS_Y0 && sy < CANVAS_Y0 + CANVAS_SZ;
}

static void drawTextCentered(const char *s, int cx, int cy, uint8_t size, uint16_t col) {
    int w = (int)strlen(s) * 6 * size;
    gfx->setTextSize(size);
    gfx->setTextColor(col);
    gfx->setCursor(cx - w / 2, cy - 4 * size);
    gfx->print(s);
}

// ─────────────────────────────────────────────────────────────────────────────
//  DRAW mode rendering
// ─────────────────────────────────────────────────────────────────────────────
static void drawTitleBar(const char *title, uint16_t tcol) {
    gfx->fillRect(0, 0, SCR_W, TITLE_H, C_PANEL);
    gfx->setTextSize(2);
    gfx->setTextColor(tcol);
    gfx->setCursor(6, 6);
    gfx->print(title);
}

static void drawScaleCtl() {
    gfx->fillRect(SCALE_MINUS_X0, 3, SCALE_MINUS_X1 - SCALE_MINUS_X0, TITLE_H - 6, C_BTN);
    drawTextCentered("-", (SCALE_MINUS_X0 + SCALE_MINUS_X1) / 2, TITLE_H / 2, 2, C_WHITE);
    char sb[12]; snprintf(sb, sizeof(sb), "%dm", g_scaleM);
    drawTextCentered(sb, (SCALE_MINUS_X1 + SCALE_PLUS_X0) / 2, TITLE_H / 2, 2, C_WHITE);
    gfx->fillRect(SCALE_PLUS_X0, 3, SCALE_PLUS_X1 - SCALE_PLUS_X0, TITLE_H - 6, C_BTN);
    drawTextCentered("+", (SCALE_PLUS_X0 + SCALE_PLUS_X1) / 2, TITLE_H / 2, 2, C_WHITE);
}

static void drawGrid() {
    gfx->fillRect(CANVAS_X0, CANVAS_Y0, CANVAS_SZ, CANVAS_SZ, C_BG);
    for (int m = 0; m <= g_scaleM; m++) {
        int off = (int)((float)m / g_scaleM * CANVAS_SZ + 0.5f);
        uint16_t col = (m % 5 == 0) ? C_GRID5 : C_GRID;
        gfx->drawFastVLine(CANVAS_X0 + off, CANVAS_Y0, CANVAS_SZ, col);
        gfx->drawFastHLine(CANVAS_X0, CANVAS_Y0 + off, CANVAS_SZ, col);
    }
    gfx->drawRect(CANVAS_X0, CANVAS_Y0, CANVAS_SZ, CANVAS_SZ, C_GREY);
}

static void drawRoom(const Room *r, uint16_t col, bool current, int idx) {
    if (r->n == 0) return;
    for (uint8_t i = 0; i < r->n; i++) {
        int sx = fx2sx(r->pts[i].x), sy = fy2sy(r->pts[i].y);
        if (i + 1 < r->n) {
            int nx = fx2sx(r->pts[i + 1].x), ny = fy2sy(r->pts[i + 1].y);
            gfx->drawLine(sx, sy, nx, ny, col);
        }
        gfx->fillCircle(sx, sy, 4, col);
    }
    if (!current && r->n >= 3) {
        int sx = fx2sx(r->pts[r->n - 1].x), sy = fy2sy(r->pts[r->n - 1].y);
        int fx0 = fx2sx(r->pts[0].x), fy0 = fy2sy(r->pts[0].y);
        gfx->drawLine(sx, sy, fx0, fy0, col);
        float cx = 0, cy = 0;
        for (uint8_t i = 0; i < r->n; i++) { cx += r->pts[i].x; cy += r->pts[i].y; }
        cx /= r->n; cy /= r->n;
        char lbl[6]; snprintf(lbl, sizeof(lbl), "%d", idx + 1);
        drawTextCentered(lbl, fx2sx(cx), fy2sy(cy), 2, col);
    }
    if (current && r->n > 0) {
        int fx0 = fx2sx(r->pts[0].x), fy0 = fy2sy(r->pts[0].y);
        gfx->drawCircle(fx0, fy0, CLOSE_R_PX, C_YELLOW);
    }
}

static void drawApMarker(const PlacedAp *pa, bool highlight) {
    int sx = fx2sx(pa->x), sy = fy2sy(pa->y);
    uint16_t col = highlight ? C_APSEL : C_AP;
    // diamond
    gfx->fillTriangle(sx, sy - 6, sx - 6, sy, sx + 6, sy, col);
    gfx->fillTriangle(sx, sy + 6, sx - 6, sy, sx + 6, sy, col);
    const char *lbl = pa->ssid[0] ? pa->ssid : (pa->bssid[0] ? pa->bssid : "?");
    char sh[8]; strncpy(sh, lbl, 6); sh[6] = 0;
    gfx->setTextSize(1); gfx->setTextColor(col);
    gfx->setCursor(sx + 8, sy - 3); gfx->print(sh);
}

static void drawObjMarker(const PlacedObj *po) {
    if (po->typeRef < 0 || po->typeRef >= (int)NUM_OBJ_TYPES) return;
    const ObjType *t = &OBJ_TYPES[po->typeRef];
    int sx = fx2sx(po->x), sy = fy2sy(po->y);
    int rpx = (int)(t->radius_m / g_scaleM * CANVAS_SZ + 0.5f);   // footprint
    if (rpx < 3) rpx = 3;
    gfx->drawCircle(sx, sy, rpx, C_OBJ);
    gfx->fillRect(sx - 3, sy - 3, 6, 6, C_OBJ);
    gfx->setTextSize(1); gfx->setTextColor(C_OBJ);
    gfx->setCursor(sx + rpx + 3, sy - 3); gfx->print(t->shortl);
}

static void drawToolbar() {
    static const char *labels[NUM_BTNS] = { "UNDO", "CLOSE", "CLEAR", "APs", "OBJ" };
    int bw = SCR_W / NUM_BTNS;
    for (int i = 0; i < NUM_BTNS; i++) {
        int x0 = i * bw;
        gfx->fillRect(x0 + 2, TOOLBAR_Y0 + 2, bw - 4, TOOLBAR_H - 4, C_BTN);
        gfx->drawRect(x0 + 2, TOOLBAR_Y0 + 2, bw - 4, TOOLBAR_H - 4, C_GREY);
        uint16_t tcol = (i == 4) ? C_OBJ : (i == 3 ? C_AP : C_WHITE);
        drawTextCentered(labels[i], x0 + bw / 2, TOOLBAR_Y0 + TOOLBAR_H / 2, 2, tcol);
    }
}

static void drawToastIfAny() {
    if (g_toast[0] && millis() < g_toastUntil) {
        gfx->fillRect(0, TOOLBAR_Y0 - 20, SCR_W, 20, C_BG);
        drawTextCentered(g_toast, SCR_W / 2, TOOLBAR_Y0 - 10, 2, C_GREEN);
    }
}

static void redrawDraw() {
    drawTitleBar("RAGNAR ROOMSCAN", C_ACCENT);
    drawScaleCtl();
    // Clear the side margins (outside the square grid) to true black so content
    // from other full-screen views (e.g. the AP list) does not bleed through.
    gfx->fillRect(0, CANVAS_Y0, CANVAS_X0, CANVAS_SZ, 0x0000);
    gfx->fillRect(CANVAS_X0 + CANVAS_SZ, CANVAS_Y0,
                  SCR_W - (CANVAS_X0 + CANVAS_SZ), CANVAS_SZ, 0x0000);
    drawGrid();
    for (uint8_t i = 0; i < g_roomCount; i++)
        drawRoom(&g_rooms[i], ROOM_COLORS[i % NUM_ROOM_COLORS], false, i);
    drawRoom(&g_cur, C_ACCENT, true, g_roomCount);
    for (uint8_t i = 0; i < g_objCount; i++)
        drawObjMarker(&g_objs[i]);
    for (uint8_t i = 0; i < g_placedCount; i++)
        drawApMarker(&g_placed[i], false);
    drawToolbar();
    drawToastIfAny();
}

// ─────────────────────────────────────────────────────────────────────────────
//  AP LIST mode — scrollable list of Ragnar-scanned APs
// ─────────────────────────────────────────────────────────────────────────────
#define LIST_ROW_H   40
#define LIST_TOP     (TITLE_H + 4)
#define LIST_ROWS    9
#define LIST_NAV_Y0  (LIST_TOP + LIST_ROWS * LIST_ROW_H)   // paging row

static void redrawApList() {
    gfx->fillScreen(C_BG);
    drawTitleBar("SELECT AP (live)", C_AP);
    gfx->fillRect(SCR_W - 116, 3, 112, TITLE_H - 6, C_BTN);
    drawTextCentered("BACK", SCR_W - 60, TITLE_H / 2, 2, C_WHITE);

    if (g_apCount == 0) {
        drawTextCentered("Scanning for Wi-Fi...", SCR_W / 2, 140, 2, C_GREY);
        drawTextCentered("(Ragnar push adds 5 GHz APs)", SCR_W / 2, 175, 2, C_GREY);
        return;
    }
    int start = g_listPage * LIST_ROWS;
    for (int r = 0; r < LIST_ROWS; r++) {
        int idx = start + r;
        if (idx >= g_apCount) break;
        int y = LIST_TOP + r * LIST_ROW_H;
        gfx->drawRect(6, y, SCR_W - 12, LIST_ROW_H - 4, C_GREY);
        ApInfo *a = &g_aps[idx];
        char name[20]; strncpy(name, a->ssid, 18); name[18] = 0;
        if (!name[0]) snprintf(name, sizeof(name), "<hidden>");
        gfx->setTextSize(2); gfx->setTextColor(C_WHITE);
        gfx->setCursor(12, y + 4); gfx->print(name);
        // MAC + radio meta on the second line so identical/hidden SSIDs are
        // still distinguishable.
        char meta[52];
        snprintf(meta, sizeof(meta), "%s  %ddBm %s ch%u",
                 a->bssid[0] ? a->bssid : "--", a->rssi, a->band, a->ch);
        gfx->setTextSize(1); gfx->setTextColor(C_GREY);
        gfx->setCursor(12, y + 24); gfx->print(meta);
    }
    // paging
    int pages = (g_apCount + LIST_ROWS - 1) / LIST_ROWS;
    if (pages > 1) {
        gfx->fillRect(6, LIST_NAV_Y0, 120, 40, C_BTN);
        drawTextCentered("< PREV", 66, LIST_NAV_Y0 + 20, 2, C_WHITE);
        gfx->fillRect(SCR_W - 126, LIST_NAV_Y0, 120, 40, C_BTN);
        drawTextCentered("NEXT >", SCR_W - 66, LIST_NAV_Y0 + 20, 2, C_WHITE);
        char pg[16]; snprintf(pg, sizeof(pg), "%d/%d", g_listPage + 1, pages);
        drawTextCentered(pg, SCR_W / 2, LIST_NAV_Y0 + 20, 2, C_GREY);
    }
}

static void redrawApPlace() {
    redrawDraw();
    // banner over the title
    gfx->fillRect(0, 0, SCR_W, TITLE_H, C_AP);
    const char *nm = (g_selAp >= 0 && g_selAp < g_apCount) ? g_aps[g_selAp].ssid : "?";
    char b[40]; snprintf(b, sizeof(b), "PLACE %.10s - tap spot", nm);
    gfx->setTextSize(2); gfx->setTextColor(0x0000);
    gfx->setCursor(6, 6); gfx->print(b);
    gfx->fillRect(SCR_W - 116, 3, 112, TITLE_H - 6, C_BTN);
    drawTextCentered("CANCEL", SCR_W - 60, TITLE_H / 2, 2, C_WHITE);
}

// ── Object palette (furniture / structural obstructions) ─────────────────────
static void redrawObjList() {
    gfx->fillScreen(C_BG);
    drawTitleBar("SELECT OBJECT", C_OBJ);
    gfx->fillRect(SCR_W - 116, 3, 112, TITLE_H - 6, C_BTN);
    drawTextCentered("BACK", SCR_W - 60, TITLE_H / 2, 2, C_WHITE);
    int start = g_listPage * LIST_ROWS;
    for (int r = 0; r < LIST_ROWS; r++) {
        int idx = start + r;
        if (idx >= (int)NUM_OBJ_TYPES) break;
        int y = LIST_TOP + r * LIST_ROW_H;
        gfx->drawRect(6, y, SCR_W - 12, LIST_ROW_H - 4, C_GREY);
        const ObjType *t = &OBJ_TYPES[idx];
        gfx->setTextSize(2); gfx->setTextColor(C_WHITE);
        gfx->setCursor(12, y + 4); gfx->print(t->name);
        char meta[44];
        snprintf(meta, sizeof(meta), "blocks %u dB  ~%.1f m footprint", t->loss_db, t->radius_m);
        gfx->setTextSize(1); gfx->setTextColor(C_OBJ);
        gfx->setCursor(12, y + 24); gfx->print(meta);
    }
    int pages = (NUM_OBJ_TYPES + LIST_ROWS - 1) / LIST_ROWS;
    if (pages > 1) {
        gfx->fillRect(6, LIST_NAV_Y0, 120, 40, C_BTN);
        drawTextCentered("< PREV", 66, LIST_NAV_Y0 + 20, 2, C_WHITE);
        gfx->fillRect(SCR_W - 126, LIST_NAV_Y0, 120, 40, C_BTN);
        drawTextCentered("NEXT >", SCR_W - 66, LIST_NAV_Y0 + 20, 2, C_WHITE);
        char pg[16]; snprintf(pg, sizeof(pg), "%d/%d", g_listPage + 1, pages);
        drawTextCentered(pg, SCR_W / 2, LIST_NAV_Y0 + 20, 2, C_GREY);
    }
}

static void redrawObjPlace() {
    redrawDraw();
    gfx->fillRect(0, 0, SCR_W, TITLE_H, C_OBJ);
    const char *nm = (g_selObj >= 0 && g_selObj < (int)NUM_OBJ_TYPES) ? OBJ_TYPES[g_selObj].name : "?";
    char b[44]; snprintf(b, sizeof(b), "PLACE %.12s - tap spot", nm);
    gfx->setTextSize(2); gfx->setTextColor(0x0000);
    gfx->setCursor(6, 6); gfx->print(b);
    gfx->fillRect(SCR_W - 116, 3, 112, TITLE_H - 6, C_BTN);
    drawTextCentered("CANCEL", SCR_W - 60, TITLE_H / 2, 2, C_WHITE);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Map JSON (device -> Ragnar over serial)
// ─────────────────────────────────────────────────────────────────────────────
static void emitMap() {
    int p = 0;
    p += snprintf(g_json + p, sizeof(g_json) - p,
                  "{\"type\":\"ragnar_roomscan\",\"v\":1,\"scale_m\":%d,\"rooms\":[",
                  g_scaleM);
    for (uint8_t r = 0; r < g_roomCount && p < (int)sizeof(g_json) - 48; r++) {
        if (r) p += snprintf(g_json + p, sizeof(g_json) - p, ",");
        p += snprintf(g_json + p, sizeof(g_json) - p, "[");
        for (uint8_t i = 0; i < g_rooms[r].n && p < (int)sizeof(g_json) - 32; i++) {
            if (i) p += snprintf(g_json + p, sizeof(g_json) - p, ",");
            p += snprintf(g_json + p, sizeof(g_json) - p, "[%.3f,%.3f]",
                          g_rooms[r].pts[i].x, g_rooms[r].pts[i].y);
        }
        p += snprintf(g_json + p, sizeof(g_json) - p, "]");
    }
    p += snprintf(g_json + p, sizeof(g_json) - p, "],\"aps\":[");
    for (uint8_t i = 0; i < g_placedCount && p < (int)sizeof(g_json) - 96; i++) {
        PlacedAp *pa = &g_placed[i];
        if (i) p += snprintf(g_json + p, sizeof(g_json) - p, ",");
        p += snprintf(g_json + p, sizeof(g_json) - p,
                      "{\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"x\":%.3f,\"y\":%.3f}",
                      pa->ssid, pa->bssid, (int)pa->rssi, pa->x, pa->y);
    }
    p += snprintf(g_json + p, sizeof(g_json) - p, "],\"objects\":[");
    for (uint8_t i = 0; i < g_objCount && p < (int)sizeof(g_json) - 128; i++) {
        PlacedObj *po = &g_objs[i];
        if (po->typeRef < 0 || po->typeRef >= (int)NUM_OBJ_TYPES) continue;
        const ObjType *t = &OBJ_TYPES[po->typeRef];
        if (i) p += snprintf(g_json + p, sizeof(g_json) - p, ",");
        p += snprintf(g_json + p, sizeof(g_json) - p,
                      "{\"type\":\"%s\",\"x\":%.3f,\"y\":%.3f,\"radius_m\":%.2f,\"loss_db\":%u}",
                      t->name, po->x, po->y, t->radius_m, t->loss_db);
    }
    snprintf(g_json + p, sizeof(g_json) - p, "]}");
    Serial.println(g_json);
}

// ── AP list upsert (shared by Ragnar push + the device's own Wi-Fi scan) ─────
static void upsertAp(const char *ssid, const char *bssid, int rssi,
                     const char *band, int ch, uint8_t src) {
    if (!bssid || !bssid[0]) return;
    int idx = -1;
    for (int i = 0; i < g_apCount; i++)
        if (!strcasecmp(g_aps[i].bssid, bssid)) { idx = i; break; }
    if (idx < 0) {
        if (g_apCount >= MAX_APS) return;
        idx = g_apCount++;
        memset(&g_aps[idx], 0, sizeof(ApInfo));
        strncpy(g_aps[idx].bssid, bssid, sizeof(g_aps[idx].bssid) - 1);
    }
    ApInfo *a = &g_aps[idx];
    if (ssid && ssid[0]) { strncpy(a->ssid, ssid, sizeof(a->ssid) - 1); a->ssid[sizeof(a->ssid) - 1] = 0; }
    a->rssi = (int16_t)rssi;
    if (band && band[0]) { strncpy(a->band, band, sizeof(a->band) - 1); a->band[sizeof(a->band) - 1] = 0; }
    a->ch = (uint16_t)ch;
    a->src = src;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Serial RX (Ragnar -> device commands)
// ─────────────────────────────────────────────────────────────────────────────
static char s_rx[256];
static int  s_rxLen = 0;

static void handleLine(char *line) {
    if (!strcmp(line, "PING")) { Serial.println("PONG"); return; }
    if (!strcmp(line, "SEND")) { emitMap(); return; }
    if (!strcmp(line, "APCLEAR")) {
        // keep the device's own live-scanned APs; drop only Ragnar-pushed ones
        uint8_t n = 0;
        for (uint8_t i = 0; i < g_apCount; i++)
            if (g_aps[i].src != AP_SRC_PUSH) g_aps[n++] = g_aps[i];
        g_apCount = n;
        return;
    }
    if (!strcmp(line, "APDONE")) {
        if (g_mode == MODE_APLIST) { g_listPage = 0; redrawApList(); }
        return;
    }
    if (!strncmp(line, "AP\t", 3)) {
        // AP\t<i>\t<ssid>\t<bssid>\t<rssi>\t<band>\t<ch>
        char *save = nullptr;
        strtok_r(line, "\t", &save);                 // "AP"
        strtok_r(nullptr, "\t", &save);              // index (ignored)
        char *ssid  = strtok_r(nullptr, "\t", &save);
        char *bssid = strtok_r(nullptr, "\t", &save);
        char *rssi  = strtok_r(nullptr, "\t", &save);
        char *band  = strtok_r(nullptr, "\t", &save);
        char *ch    = strtok_r(nullptr, "\t", &save);
        upsertAp(ssid ? ssid : "", bssid ? bssid : "", rssi ? atoi(rssi) : 0,
                 band ? band : "", ch ? atoi(ch) : 0, AP_SRC_PUSH);
        return;
    }
}

static void pollSerialRx() {
    while (Serial.available()) {
        int c = Serial.read();
        if (c < 0) break;
        if (c == '\r') continue;
        if (c == '\n') {
            s_rx[s_rxLen] = 0;
            if (s_rxLen > 0) handleLine(s_rx);
            s_rxLen = 0;
            continue;
        }
        if (s_rxLen < (int)sizeof(s_rx) - 1) s_rx[s_rxLen++] = (char)c;
        else s_rxLen = 0;   // overrun -> drop line
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Device Wi-Fi scan — keeps the AP list's 2.4 GHz strengths live as you walk
//  (the ESP32-S3 radio is 2.4 GHz only; Ragnar's push adds 5/6 GHz APs). Async
//  so it never blocks touch/redraw; upserts by BSSID so it merges with pushed APs.
// ─────────────────────────────────────────────────────────────────────────────
static bool     s_scanning = false;
static uint32_t s_lastScan = 0;
#define SCAN_INTERVAL_MS 5000

static void pollWifiScan() {
    uint32_t now = millis();
    if (!s_scanning) {
        if (now - s_lastScan >= SCAN_INTERVAL_MS) {
            WiFi.scanNetworks(true, true);   // async, include hidden
            s_scanning = true;
        }
        return;
    }
    int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_RUNNING) return;
    if (n >= 0) {
        for (int i = 0; i < n; i++) {
            String b = WiFi.BSSIDstr(i); b.toLowerCase();
            String s = WiFi.SSID(i);
            upsertAp(s.c_str(), b.c_str(), WiFi.RSSI(i), "2.4", WiFi.channel(i), AP_SRC_SCAN);
        }
        if (g_mode == MODE_APLIST) redrawApList();   // reflect live strengths
    }
    WiFi.scanDelete();
    s_scanning = false;
    s_lastScan = millis();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Touch handling
// ─────────────────────────────────────────────────────────────────────────────
static bool s_wasPressed = false;

static void addCorner(int sx, int sy) {
    if (g_cur.n >= 3) {
        int fx0 = fx2sx(g_cur.pts[0].x), fy0 = fy2sy(g_cur.pts[0].y);
        int dx = sx - fx0, dy = sy - fy0;
        if (dx * dx + dy * dy <= CLOSE_R_PX * CLOSE_R_PX) {
            if (g_roomCount < MAX_ROOMS) { g_rooms[g_roomCount++] = g_cur; g_cur.n = 0; }
            redrawDraw();
            return;
        }
    }
    if (g_cur.n < MAX_PTS) {
        float fx = (float)(sx - CANVAS_X0) / CANVAS_SZ;
        float fy = (float)(sy - CANVAS_Y0) / CANVAS_SZ;
        if (fx < 0) fx = 0; if (fx > 1) fx = 1;
        if (fy < 0) fy = 0; if (fy > 1) fy = 1;
        g_cur.pts[g_cur.n].x = fx; g_cur.pts[g_cur.n].y = fy; g_cur.n++;
        redrawDraw();
    }
}

static void handleTapDraw(int sx, int sy) {
    if (sy < TITLE_H) {
        if (sx >= SCALE_MINUS_X0 && sx <= SCALE_MINUS_X1) { if (g_scaleM > 2) { g_scaleM--; redrawDraw(); } return; }
        if (sx >= SCALE_PLUS_X0  && sx <= SCALE_PLUS_X1)  { if (g_scaleM < 50) { g_scaleM++; redrawDraw(); } return; }
        return;
    }
    if (sy >= TOOLBAR_Y0) {
        int b = sx / (SCR_W / NUM_BTNS);
        switch (b) {
            case 0: if (g_cur.n > 0) g_cur.n--; else if (g_roomCount > 0) g_cur = g_rooms[--g_roomCount]; redrawDraw(); break; // UNDO
            case 1: if (g_cur.n >= 3 && g_roomCount < MAX_ROOMS) { g_rooms[g_roomCount++] = g_cur; g_cur.n = 0; } redrawDraw(); break; // CLOSE
            case 2: g_roomCount = 0; g_cur.n = 0; g_placedCount = 0; g_objCount = 0; redrawDraw(); break; // CLEAR
            case 3: g_mode = MODE_APLIST; g_listPage = 0; redrawApList(); break;          // APs
            case 4: g_mode = MODE_OBJLIST; g_listPage = 0; redrawObjList(); break;        // OBJ
        }
        return;
    }
    if (inCanvas(sx, sy)) addCorner(sx, sy);
}

static void handleTapApList(int sx, int sy) {
    if (sy < TITLE_H && sx >= SCR_W - 116) { g_mode = MODE_DRAW; redrawDraw(); return; } // BACK
    if (g_apCount == 0) return;
    int pages = (g_apCount + LIST_ROWS - 1) / LIST_ROWS;
    if (pages > 1 && sy >= LIST_NAV_Y0 && sy < LIST_NAV_Y0 + 40) {
        if (sx < 126) { if (g_listPage > 0) { g_listPage--; redrawApList(); } return; }
        if (sx > SCR_W - 126) { if (g_listPage < pages - 1) { g_listPage++; redrawApList(); } return; }
        return;
    }
    if (sy >= LIST_TOP && sy < LIST_TOP + LIST_ROWS * LIST_ROW_H) {
        int r = (sy - LIST_TOP) / LIST_ROW_H;
        int idx = g_listPage * LIST_ROWS + r;
        if (idx < g_apCount) { g_selAp = idx; g_mode = MODE_APPLACE; redrawApPlace(); }
    }
}

static void handleTapApPlace(int sx, int sy) {
    if (sy < TITLE_H && sx >= SCR_W - 116) { g_mode = MODE_DRAW; g_selAp = -1; redrawDraw(); return; } // CANCEL
    if (inCanvas(sx, sy) && g_placedCount < MAX_PLACED && g_selAp >= 0 && g_selAp < g_apCount) {
        float fx = (float)(sx - CANVAS_X0) / CANVAS_SZ;
        float fy = (float)(sy - CANVAS_Y0) / CANVAS_SZ;
        PlacedAp *pa = &g_placed[g_placedCount];
        const ApInfo *a = &g_aps[g_selAp];
        strncpy(pa->ssid, a->ssid, sizeof(pa->ssid) - 1);  pa->ssid[sizeof(pa->ssid) - 1] = 0;
        strncpy(pa->bssid, a->bssid, sizeof(pa->bssid) - 1); pa->bssid[sizeof(pa->bssid) - 1] = 0;
        pa->rssi = a->rssi; pa->x = fx; pa->y = fy;
        g_placedCount++;
        g_selAp = -1; g_mode = MODE_DRAW;
        toast("AP placed");
        redrawDraw();
    }
}

static void handleTapObjList(int sx, int sy) {
    if (sy < TITLE_H && sx >= SCR_W - 116) { g_mode = MODE_DRAW; redrawDraw(); return; } // BACK
    int pages = (NUM_OBJ_TYPES + LIST_ROWS - 1) / LIST_ROWS;
    if (pages > 1 && sy >= LIST_NAV_Y0 && sy < LIST_NAV_Y0 + 40) {
        if (sx < 126) { if (g_listPage > 0) { g_listPage--; redrawObjList(); } return; }
        if (sx > SCR_W - 126) { if (g_listPage < pages - 1) { g_listPage++; redrawObjList(); } return; }
        return;
    }
    if (sy >= LIST_TOP && sy < LIST_TOP + LIST_ROWS * LIST_ROW_H) {
        int r = (sy - LIST_TOP) / LIST_ROW_H;
        int idx = g_listPage * LIST_ROWS + r;
        if (idx < (int)NUM_OBJ_TYPES) { g_selObj = idx; g_mode = MODE_OBJPLACE; redrawObjPlace(); }
    }
}

static void handleTapObjPlace(int sx, int sy) {
    if (sy < TITLE_H && sx >= SCR_W - 116) { g_mode = MODE_DRAW; g_selObj = -1; redrawDraw(); return; } // CANCEL
    if (inCanvas(sx, sy) && g_objCount < MAX_OBJS && g_selObj >= 0) {
        float fx = (float)(sx - CANVAS_X0) / CANVAS_SZ;
        float fy = (float)(sy - CANVAS_Y0) / CANVAS_SZ;
        g_objs[g_objCount].typeRef = (int8_t)g_selObj;
        g_objs[g_objCount].x = fx; g_objs[g_objCount].y = fy;
        g_objCount++;
        g_selObj = -1; g_mode = MODE_DRAW;
        toast("Object placed");
        redrawDraw();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Setup / loop
// ─────────────────────────────────────────────────────────────────────────────
static void displayInit() {
    Wire.begin(EXPANDER_SDA, EXPANDER_SCL);
    expander->pinMode(LCD_RST_PIN, OUTPUT);
    expander->pinMode(LCD_BL_PIN, OUTPUT);
    expander->digitalWrite(LCD_BL_PIN, LOW);
    delay(200);
    expander->digitalWrite(LCD_RST_PIN, LOW);
    delay(200);
    expander->digitalWrite(LCD_RST_PIN, HIGH);
    delay(200);
    s_gfxOk = gfx->begin();
    if (!s_gfxOk) Serial.println("[ROOMSCAN] gfx->begin() FAILED");
    else          Serial.println("[ROOMSCAN] Display init OK");
    gfx->fillScreen(C_BG);
    expander->digitalWrite(LCD_BL_PIN, HIGH);
}

void setup() {
    Serial.begin(115200);
    delay(200);
    Serial.println("\n[ROOMSCAN] boot");
    Serial.println("{\"type\":\"roomscan_hello\",\"fw\":\"1.2\",\"proto\":1}");
    displayInit();
    if (touch_init(expander, GT911_RST_PIN, TP_INT))
        Serial.printf("[ROOMSCAN] GT911 at 0x%02X\n", touch_get_addr());
    else
        Serial.println("[ROOMSCAN] GT911 init failed");
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    Serial.println("[ROOMSCAN] WiFi STA ready (live self-scan on)");
    redrawDraw();
}

void loop() {
    static uint32_t s_lastHb = 0;
    static bool s_toastShown = true;
    pollSerialRx();
    pollWifiScan();
    touch_poll();
    bool pressed = touch_is_pressed();
    if (pressed && !s_wasPressed) {
        int sx = touch_get_x(), sy = touch_get_y();
        if (sx < 0) sx = 0; if (sx >= SCR_W) sx = SCR_W - 1;
        if (sy < 0) sy = 0; if (sy >= SCR_H) sy = SCR_H - 1;
        Serial.printf("[ROOMSCAN] TAP raw x=%d y=%d mode=%d\n", sx, sy, (int)g_mode);
        switch (g_mode) {
            case MODE_DRAW:     handleTapDraw(sx, sy); break;
            case MODE_APLIST:   handleTapApList(sx, sy); break;
            case MODE_APPLACE:  handleTapApPlace(sx, sy); break;
            case MODE_OBJLIST:  handleTapObjList(sx, sy); break;
            case MODE_OBJPLACE: handleTapObjPlace(sx, sy); break;
        }
        s_toastShown = false;
        delay(120);
    }
    s_wasPressed = pressed;

    // clear an expired toast once
    if (!s_toastShown && g_toast[0] && millis() >= g_toastUntil && g_mode == MODE_DRAW) {
        g_toast[0] = 0; s_toastShown = true;
        gfx->fillRect(0, TOOLBAR_Y0 - 20, SCR_W, 20, C_BG);
    }

    uint32_t now = millis();
    if (now - s_lastHb >= 1500) {
        s_lastHb = now;
        Serial.printf("[ROOMSCAN] HB gfx=%d touch=0x%02X rooms=%d curpts=%d aps=%d placed=%d objs=%d scale=%dm mode=%d\n",
                      s_gfxOk ? 1 : 0, touch_get_addr(), g_roomCount, g_cur.n,
                      g_apCount, g_placedCount, g_objCount, g_scaleM, (int)g_mode);
    }
    delay(10);
}
