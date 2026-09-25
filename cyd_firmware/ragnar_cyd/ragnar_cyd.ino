/*
 * ragnar_cyd.ino — Ragnar CYD hybrid node (Piglet Core, 2.4 GHz)
 *
 * Target: ESP32-2432S028R "Cheap Yellow Display" (CYD)
 *   ESP32-WROOM-32 • 2.8" ILI9341 240x320 • XPT2046 resistive touch
 *
 * ROLE — a hybrid companion to a Ragnar Pi. It is NOT Ragnar: Ragnar (Flask on
 * Linux) cannot run on a WROOM-32. The node instead
 *   (1) shows a native touch dashboard of Ragnar's live status, and
 *   (2) lets the operator trigger a small allowlist of Ragnar actions, and
 *   (3) scans 2.4 GHz (WiFi promiscuous + BLE adverts) with its OWN radio and
 *       reports the counts back to Ragnar.
 *
 * The single 2.4 GHz radio cannot be joined to WiFi AND sniff other channels at
 * the same time, so the node TIME-SHARES in a duty cycle:
 *
 *   CONNECT+SYNC  -> (GET /api/cyd/status, POST /api/cyd/ingest, flush actions)
 *        |
 *   DISCONNECT -> WiFi promiscuous sweep ch 1..13
 *        |
 *   DISCONNECT -> BLE advertisement scan        (loops)
 *
 * The screen always renders the last-synced values, so status/findings are
 * near-real-time, not continuous. This is the price of a WROOM-32 vs an S3/C5.
 *
 * Build (arduino-cli):
 *   --fqbn "esp32:esp32:esp32:PartitionScheme=huge_app,FlashSize=4M"
 * Required library (already used elsewhere in Ragnar):
 *   "GFX Library for Arduino" by moononournation
 *
 * See docs/cyd-firmware.md for flashing and Ragnar-side setup.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <SPI.h>
#include <esp_wifi.h>
#include <Arduino_GFX_Library.h>
#include <AnimatedGIF.h>

#include "config.h"
#include "ragnar_boot_gif.h"      // embedded 240x320 full-screen boot animation (PROGMEM)
#include "ragnar_label_font.h"    // proportional ~10px font for HOME tile labels only

// Defined before the first include-terminated section so Arduino's auto-generated
// prototypes (inserted after the includes) can reference ActionBtn*.
struct ActionBtn { const char *label; const char *action; };

#if CYD_ENABLE_BLE
#include <BLEDevice.h>
#include <BLEScan.h>
#endif

// ── Runtime configuration (NVS-backed; provisioned via the setup portal) ──────
struct RuntimeConfig {
  String ssid, pass, url, token, name;
};
static RuntimeConfig g_cfg;
static Preferences g_prefs;

// Load config from NVS, falling back to the (optional) compile-time seeds.
// Device settings (Settings screen), persisted in NVS.
static bool    g_bleEnabled   = true;    // BLE scanning on/off
static uint8_t g_backlightPct = 100;     // backlight brightness 0..100
static bool    g_invert       = false;   // invert display colours (INVON/INVOFF)
static bool    g_flip180      = false;   // rotate display + touch 180 degrees

static void loadConfig() {
  g_prefs.begin("ragnarcyd", true);
  g_cfg.ssid  = g_prefs.getString("ssid",  CYD_WIFI_SSID);
  g_cfg.pass  = g_prefs.getString("pass",  CYD_WIFI_PASS);
  g_cfg.url   = g_prefs.getString("url",   CYD_RAGNAR_URL);
  g_cfg.token = g_prefs.getString("token", CYD_DEVICE_TOKEN);
  g_cfg.name  = g_prefs.getString("name",  CYD_NODE_NAME);
  g_bleEnabled   = g_prefs.getBool("ble", true);
  g_backlightPct = g_prefs.getUChar("bl", 100);
  g_invert       = g_prefs.getBool("inv", false);
  g_flip180      = g_prefs.getBool("flip", false);
  g_prefs.end();
  if (g_cfg.name.length() == 0) g_cfg.name = "cyd-node";
  if (g_backlightPct < 10) g_backlightPct = 10;
}

static void saveSettings() {
  g_prefs.begin("ragnarcyd", false);
  g_prefs.putBool("ble", g_bleEnabled);
  g_prefs.putUChar("bl", g_backlightPct);
  g_prefs.putBool("inv", g_invert);
  g_prefs.putBool("flip", g_flip180);
  g_prefs.end();
}

// Apply the backlight brightness (LEDC PWM; keep a floor so it never goes black).
static void applyBacklight() {
  analogWrite(TFT_BL, map(g_backlightPct, 0, 100, 26, 255));
}

static void saveConfig(const RuntimeConfig &c) {
  g_prefs.begin("ragnarcyd", false);
  g_prefs.putString("ssid",  c.ssid);
  g_prefs.putString("pass",  c.pass);
  g_prefs.putString("url",   c.url);
  g_prefs.putString("token", c.token);
  g_prefs.putString("name",  c.name.length() ? c.name : String("cyd-node"));
  g_prefs.end();
}

// Enough to attempt operation: a WiFi SSID, a Ragnar URL and a device token.
static bool haveConfig() {
  return g_cfg.ssid.length() && g_cfg.url.length() && g_cfg.token.length();
}

// Arduino_GFX 1.6.7 exposes colors as RGB565_*; alias the two bare names we use.
#define WHITE RGB565_WHITE
#define BLACK RGB565_BLACK

// ── Display ───────────────────────────────────────────────────────────────────
static Arduino_DataBus *bus = new Arduino_ESP32SPI(
    TFT_DC, TFT_CS, TFT_SCLK, TFT_MOSI, TFT_MISO, VSPI);
static Arduino_GFX *gfx = new Arduino_ILI9341(bus, TFT_RST, 0 /*rotation*/, false /*IPS*/);

// Apply display orientation + colour inversion (both persisted). Rotation 2 flips
// the panel 180 degrees; touchRead XORs its invert flags with g_flip180 to match.
static void applyDisplayOpts() {
  gfx->setRotation(g_flip180 ? 2 : 0);
  gfx->invertDisplay(g_invert);
}

static const int16_t SCR_W = 240;
static const int16_t SCR_H = 320;

// ── Boot animation (ragnar-240x320-tools.gif, decoded on-device by AnimatedGIF) ──
// The 15 s clip plays at natural speed and LOOPS until Ragnar is up (its first
// status frame lands over serial). If Ragnar is already up when the node boots
// (it reset while the Pi was running), it stops after just the 5 s minimum. A hard
// cap keeps a Pi-less node from looping forever. The 240x320 GIF fills the whole
// panel (no centring offset). Colour byte-order: LE palette + draw16bitRGBBitmap
// is correct on the (little-endian) ESP32; if colours look swapped, flip CYD_GIF_BE.
#define CYD_BOOT_ANIM_MS     5000     // minimum splash (and the whole splash if Ragnar's already up)
#define CYD_BOOT_ANIM_MAX_MS 90000    // hard cap: give up waiting for Ragnar after this
#define CYD_GIF_BE       0
static const int16_t GIF_X_OFF = 0;
static const int16_t GIF_Y_OFF = (SCR_H - 320) / 2;   // 0 px: full-screen 240x320
// Set true the moment the first Ragnar status frame is parsed (applyStatus) — the
// boot loop watches it to know the Pi's service is up. Declared here (before
// playBootAnimation) because g_rs itself is defined much further down.
static volatile bool g_bootRagnarUp = false;
#if CYD_TRANSPORT_SERIAL
static void serialDrain();            // defined in the serial section far below
#endif
// AnimatedGIF embeds tens of KB of decode buffers; it's only needed at boot, so
// it is heap-allocated in playBootAnimation() and freed before WiFi/BLE start —
// keeping it as a static global permanently starved the WiFi RX buffers.

static void GIFDraw(GIFDRAW *pDraw) {
  uint8_t *s;
  uint16_t *d, *usPalette, usTemp[240];
  int x, y, iWidth;
  iWidth = pDraw->iWidth;
  if (iWidth > SCR_W) iWidth = SCR_W;
  usPalette = pDraw->pPalette;
  y = pDraw->iY + pDraw->y;                 // absolute line within the image
  s = pDraw->pPixels;
  if (pDraw->ucDisposalMethod == 2) {       // restore to background
    for (x = 0; x < iWidth; x++)
      if (s[x] == pDraw->ucTransparent) s[x] = pDraw->ucBackground;
    pDraw->ucHasTransparency = 0;
  }
  #define CYD_BLIT(px, py, w, buf) do { \
    if (CYD_GIF_BE) gfx->draw16bitBeRGBBitmap(GIF_X_OFF + (px), GIF_Y_OFF + (py), (buf), (w), 1); \
    else            gfx->draw16bitRGBBitmap  (GIF_X_OFF + (px), GIF_Y_OFF + (py), (buf), (w), 1); \
  } while (0)
  if (pDraw->ucHasTransparency) {           // draw only opaque runs, skip transparent
    uint8_t *pEnd, c, ucTransparent = pDraw->ucTransparent;
    int iCount;
    pEnd = s + iWidth; x = 0; iCount = 0;
    while (x < iWidth) {
      c = ucTransparent - 1; d = usTemp;
      while (c != ucTransparent && s < pEnd) {
        c = *s++;
        if (c == ucTransparent) s--; else { *d++ = usPalette[c]; iCount++; }
      }
      if (iCount) { CYD_BLIT(pDraw->iX + x, y, iCount, usTemp); x += iCount; iCount = 0; }
      c = ucTransparent;
      while (c == ucTransparent && s < pEnd) { c = *s++; if (c == ucTransparent) iCount++; else s--; }
      if (iCount) { x += iCount; iCount = 0; }
    }
  } else {
    for (x = 0; x < iWidth; x++) usTemp[x] = usPalette[*s++];
    CYD_BLIT(pDraw->iX, y, iWidth, usTemp);
  }
  #undef CYD_BLIT
}

// Play the embedded GIF at its NATURAL speed (honouring per-frame delays), looping
// at the end. Stops once Ragnar is up (a status frame has arrived -> g_rs.ok) AND
// at least minMs has elapsed; if Ragnar never shows, gives up at maxMs. Passing
// minMs==maxMs makes it a plain fixed-length splash (the WiFi transport, which has
// no serial readiness signal during boot). Blocking by design — it IS the boot
// wait, and it drains serial each frame so the readiness signal can land.
static void playBootAnimation(uint32_t minMs, uint32_t maxMs) {
  AnimatedGIF *gif = new AnimatedGIF();       // ~tens of KB, freed below (boot only)
  if (!gif) return;
  gif->begin(CYD_GIF_BE ? GIF_PALETTE_RGB565_BE : GIF_PALETTE_RGB565_LE);
  if (gif->open((uint8_t *)ragnar_boot_gif, ragnar_boot_gif_len, GIFDraw)) {
    uint32_t start = millis();
    int delayMs = 0;
    for (;;) {
      if (!gif->playFrame(true, &delayMs)) gif->reset();  // end -> loop the clip
#if CYD_TRANSPORT_SERIAL
      serialDrain();          // read the Pi's status pushes while animating; the
                              // first one flips g_rs.ok = "Ragnar service is up"
#endif
      uint32_t elapsed = millis() - start;
      if (elapsed < minMs) continue;              // always show at least the minimum
      if (g_bootRagnarUp || elapsed >= maxMs) break;  // Ragnar up (or gave up waiting)
    }
    gif->close();
  }
  delete gif;                                 // reclaim the decode buffers
}

// ── Touch (XPT2046 on its own SPI bus) ────────────────────────────────────────
static SPIClass touchSPI(HSPI);

// ── UI state ──────────────────────────────────────────────────────────────────
// App-launcher model: a HOME grid of tiles that drill into full screens.
enum Screen { SCR_HOME = 0, SCR_DASH, SCR_DEFENSE, SCR_ALERTS, SCR_SCAN, SCR_SIGINT,
              SCR_WFALL, SCR_NETWORK, SCR_NETINT, SCR_TRAFFIC, SCR_MESH, SCR_NETCONN,
              SCR_KEYBOARD, SCR_SETTINGS, SCR_CTRL, SCR_TOUCHTEST, SCR_ACTION,
              SCR_WARDRIVE };
static Screen g_screen     = SCR_HOME;
static bool   g_needRedraw = true;

// Wardrive Start/Stop is a ~5s round-trip (Ragnar dispatches, then confirms via
// the pushed status). Latch a "processing" state on tap so the button greys out
// and ignores further taps until the confirmed run-state matches what we asked
// for (or a safety timeout fires, in case the action failed / no reply arrives).
static bool     g_wdPending = false;
static bool     g_wdTarget  = false;   // run-state we asked Ragnar to reach
static uint32_t g_wdPendMs  = 0;
static const uint32_t WD_PEND_TIMEOUT_MS = 9000;
// Traffic capture start is slow + variable (5-30s on a Pi Zero); latch a
// pending state so the button shows a spinner + elapsed until it confirms.
static bool     g_tfPending = false;
static bool     g_tfTarget  = false;   // capture state we asked to reach
static uint32_t g_tfPendMs  = 0;
static const uint32_t TF_PEND_TIMEOUT_MS = 40000;

// ── Live model: last status synced from Ragnar ────────────────────────────────
struct RagnarStatus {
  bool     ok        = false;
  int      meshNodes = 0;
  int      nets24    = 0;
  int      nets5     = 0;
  int      threat    = 0;      // 0..100 threat score
  char     btState[16]      = "?";
  char     unitName[24]     = "Ragnar";   // brand default (shown at boot pre-sync); big R
  uint32_t uptimeSec        = 0;
  uint32_t lastSyncMs       = 0;
  // Expanded status fields (DASH / NETWORK / ALERTS):
  char     iface[12]        = "";
  char     ip[20]           = "";
  char     wardrive[16]     = "off";
  char     worst[10]        = "none";
  int      alerts           = 0;
  bool     wids             = false;
  char     alert1[30]       = "";
  char     alert2[30]       = "";
  char     alert3[30]       = "";
  // NETWORK subpages:
  char     netint[16]       = "off";
  char     speedtest[16]    = "-";
  char     captive[16]      = "-";
  char     pwn[12]          = "off";
  char     ni1[30]          = "";
  char     ni2[30]          = "";
  char     ni3[30]          = "";
  // Traffic Analysis live capture:
  bool     tfRun            = false;
  int      tfPps            = 0;
  char     tfMbps[10]       = "0";
  int      tfHosts          = 0;
  int      tfConns          = 0;
  uint32_t tfPkts           = 0;
  int      tfAlerts         = 0;
  // Last action lifecycle (for the generic Action result subpage):
  char     actName[24]      = "";
  char     actState[12]     = "";
  char     actDetail[28]    = "";
  int      actDur          = 0;    // expected duration (s) for a timed action, 0=unknown
  // Wardrive live status (own page):
  bool     wdRun            = false;
  int      wdNets           = 0;
  int      wdScan           = 0;
  int      wdBle            = 0;
  int      wdCell           = 0;
  int      wdZig            = 0;
  int      wdComp           = 0;
  char     wdGps[16]        = "-";
  char     wdBand[12]       = "-";
  char     wdC1[28]         = "";
  char     wdC2[28]         = "";
  bool     wdEnabled        = false;
};
static RagnarStatus g_rs;

// ── Local sensor counters (this node's own radio) ─────────────────────────────
struct SensorCounts {
  volatile uint32_t beacons  = 0;
  volatile uint32_t probes   = 0;
  volatile uint32_t deauths  = 0;
  volatile uint32_t frames   = 0;
  uint32_t          bssids   = 0;   // unique BSSIDs this window
  uint32_t          bleAdv   = 0;   // BLE advertisements this window
};
static SensorCounts g_sc;

// Per-window AP sightings (RAM-bounded): BSSID + SSID + channel + strongest RSSI.
// Reported to Ragnar so its WiFi-Defense side can flag new/rogue APs.
#define MAX_AP 48
struct ApInfo {
  uint8_t bssid[6];
  char    ssid[33];
  uint8_t ch;
  int8_t  rssi;
};
static ApInfo   g_aps[MAX_AP];
static uint32_t g_apCount = 0;

// ── RF waterfall (downsampled spectrum streamed from Ragnar's SDR) ─────────────
// The CYD has no SDR; when the Waterfall screen is open it asks Ragnar to sweep
// a band and stream one quantised row per frame, which we scroll here.
#define WF_BINS 120
#define WF_ROWS 246                          // fills the waterfall area (52..298)
// ~29.5 KB ring — allocated only WHILE the waterfall screen is open (which pauses
// the WiFi/BLE duty cycle), so it never competes with the WiFi RX buffers. Keeping
// it static exhausted DRAM and the sniff phase aborted every cycle (SW_CPU_RESET).
static uint8_t (*g_wfImg)[WF_BINS] = nullptr;
static int      g_wfHead = 0;                // next write row
static void wfAlloc() { if (!g_wfImg) { g_wfImg = (uint8_t(*)[WF_BINS])malloc((size_t)WF_ROWS * WF_BINS); if (g_wfImg) memset(g_wfImg, 0, (size_t)WF_ROWS * WF_BINS); } }
static void wfFree()  { if (g_wfImg) { free(g_wfImg); g_wfImg = nullptr; } }
static bool     g_wfHave = false;            // got at least one row
static uint32_t g_wfSeq  = 0;                // last applied row seq
static int      g_wfLo = 0, g_wfHi = 0;      // band edges, MHz
static char     g_wfErr[24] = "";            // e.g. "no SDR"
// Bands the CYD cycles: sub-GHz ISM first, then a few RF bands.
static const char *WF_BANDS[] = {"433", "868", "915", "315", "fm", "air", "2.4"};
static const int   WF_NBANDS  = 7;
static int         g_wfBandIdx = 0;
static bool        g_wfActive  = false;      // screen open -> streaming requested
static void applyWfRow(const String &body);  // defined in the UI section

// ── Mesh roster + WiFi list (streamed from Ragnar while their screens open) ────
#define MAX_MESH 24
#define MAX_WIFI 24
#define ROW_LEN  40
static char g_meshRows[MAX_MESH][ROW_LEN];
static int  g_meshN = 0, g_meshScroll = 0;
static bool g_meshActive = false;
static char g_wifiRows[MAX_WIFI][ROW_LEN];
static int  g_wifiN = 0, g_wifiScroll = 0, g_wifiSel = -1;
static bool g_wifiActive = false;
static void applyRoster(const String &body, char rows[][ROW_LEN], int maxr,
                        int &count, char key);  // defined in the UI section

// ── Pending action queue (taps flushed on next sync window) ───────────────────
#define MAX_ACTIONS 6
static String g_actionQ[MAX_ACTIONS];
static uint8_t g_actionHead = 0, g_actionTail = 0;

static bool actionEnqueue(const String &a) {
  uint8_t next = (uint8_t)((g_actionTail + 1) % MAX_ACTIONS);
  if (next == g_actionHead) return false;   // full
  g_actionQ[g_actionTail] = a;
  g_actionTail = next;
  return true;
}
static bool actionDequeue(String &out) {
  if (g_actionHead == g_actionTail) return false;
  out = g_actionQ[g_actionHead];
  g_actionHead = (uint8_t)((g_actionHead + 1) % MAX_ACTIONS);
  return true;
}

// ── Status line shown at the bottom of every page ─────────────────────────────
static char g_statusLine[40] = "booting";
static uint16_t g_statusColor = WHITE;
static void serviceUI();            // defined after render()/handleTouch()
static void setStatus(const char *s, uint16_t c) {
  // Only repaint when the text or colour actually changed — a periodic status
  // set with the same value must not force a redraw (that was part of the
  // every-few-seconds twitch).
  if (g_statusColor == c && strncmp(g_statusLine, s, sizeof(g_statusLine) - 1) == 0) return;
  strncpy(g_statusLine, s, sizeof(g_statusLine) - 1);
  g_statusLine[sizeof(g_statusLine) - 1] = 0;
  g_statusColor = c;
  g_needRedraw = true;
}

// ════════════════════════════════════════════════════════════════════════════
//  XPT2046 touch — minimal SPI reader (no external lib)
// ════════════════════════════════════════════════════════════════════════════
static uint16_t xptRead(uint8_t cmd) {
  touchSPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));
  digitalWrite(TOUCH_CS, LOW);
  touchSPI.transfer(cmd);
  uint16_t hi = touchSPI.transfer(0x00);
  uint16_t lo = touchSPI.transfer(0x00);
  digitalWrite(TOUCH_CS, HIGH);
  touchSPI.endTransaction();
  return ((hi << 8) | lo) >> 3;   // 12-bit result
}

// Last raw ADC sample (exposed for the touch-test screen).
static uint16_t g_lastRawX = 0, g_lastRawY = 0;

// Returns true and fills px/py (screen coords) when the panel is pressed.
static bool touchRead(int16_t &px, int16_t &py) {
  if (digitalRead(TOUCH_IRQ) == HIGH) return false;   // IRQ idles HIGH
  // Average a few samples to debounce the resistive panel.
  uint32_t sx = 0, sy = 0; int n = 0;
  for (int i = 0; i < 4; i++) {
    uint16_t rx = xptRead(0xD0);   // X
    uint16_t ry = xptRead(0x90);   // Y
    if (rx < 100 || ry < 100) continue;
    sx += rx; sy += ry; n++;
  }
  if (n == 0) return false;
  uint16_t rawx = sx / n, rawy = sy / n;
  g_lastRawX = rawx; g_lastRawY = rawy;
#if TOUCH_SWAP_XY
  { uint16_t t = rawx; rawx = rawy; rawy = t; }
#endif
  // Map raw ADC -> pixels (portrait), honouring the orientation flags so touch
  // lines up with the display. Clamp to screen.
  // Orientation flags are compile-time; XOR with g_flip180 so a runtime 180 deg
  // flip (rotation 2) inverts touch on both axes to line up with the display.
  bool invX = (TOUCH_INVERT_X != 0) ^ g_flip180;
  bool invY = (TOUCH_INVERT_Y != 0) ^ g_flip180;
  long mx = invX ? map(rawx, TOUCH_RAW_MINX, TOUCH_RAW_MAXX, SCR_W - 1, 0)
                 : map(rawx, TOUCH_RAW_MINX, TOUCH_RAW_MAXX, 0, SCR_W - 1);
  long my = invY ? map(rawy, TOUCH_RAW_MINY, TOUCH_RAW_MAXY, SCR_H - 1, 0)
                 : map(rawy, TOUCH_RAW_MINY, TOUCH_RAW_MAXY, 0, SCR_H - 1);
  px = (int16_t)constrain(mx, 0, SCR_W - 1);
  py = (int16_t)constrain(my, 0, SCR_H - 1);
  return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  WiFi promiscuous sniffer
// ════════════════════════════════════════════════════════════════════════════
// Record a beacon's AP (BSSID/SSID/channel/RSSI). Called from the sniffer
// callback, so kept short: a bounded linear scan + a <=32-byte SSID copy.
static void apSeen(const wifi_promiscuous_pkt_t *pkt) {
  const uint8_t *p = pkt->payload;
  const uint8_t *bssid = &p[16];                 // addr3
  int8_t rssi = pkt->rx_ctrl.rssi;
  uint8_t ch = pkt->rx_ctrl.channel;
  for (uint32_t i = 0; i < g_apCount; i++) {
    if (memcmp(g_aps[i].bssid, bssid, 6) == 0) {
      if (rssi > g_aps[i].rssi) g_aps[i].rssi = rssi;   // keep the strongest
      return;
    }
  }
  if (g_apCount >= MAX_AP) return;
  ApInfo &a = g_aps[g_apCount];
  memcpy(a.bssid, bssid, 6);
  a.ch = ch;
  a.rssi = rssi;
  a.ssid[0] = 0;
  // SSID = tag 0 of the tagged params (beacon: 24-byte hdr + 12 fixed = off 36).
  int total = pkt->rx_ctrl.sig_len;
  if (total >= 38 && p[36] == 0) {
    int len = p[37];
    if (len > 32) len = 32;
    if (38 + len <= total) {
      int j = 0;
      for (int k = 0; k < len; k++) {
        char c = (char)p[38 + k];
        // Sanitize for JSON: printable ASCII only, no quote/backslash.
        a.ssid[j++] = (c >= 0x20 && c < 0x7F && c != '"' && c != '\\') ? c : '.';
      }
      a.ssid[j] = 0;
    }
  }
  g_apCount++;
}

static void IRAM_ATTR snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = pkt->payload;
  g_sc.frames++;
  uint8_t subtype = (p[0] & 0xF0) >> 4;   // frame-control subtype
  switch (subtype) {
    case 0x08: g_sc.beacons++; apSeen(pkt); break;        // beacon (BSSID @ addr3)
    case 0x04: g_sc.probes++;  break;                     // probe request
    case 0x0C: g_sc.deauths++; break;                     // deauth
    case 0x0A: g_sc.deauths++; break;                     // disassoc (count as deauth)
    default: break;
  }
}

static void sniffReset() {
  g_sc.beacons = g_sc.probes = g_sc.deauths = g_sc.frames = 0;
  g_apCount = 0;
}

static void sniffWindow(uint32_t durationMs) {
  sniffReset();
  // Keep the radio STARTED: WiFi.disconnect(true,...) powers it OFF, after which
  // esp_wifi_set_promiscuous() returns NOT_STARTED and the RX callback never fires
  // (all sniff counts stay 0 — SCAN/DEFENSE/SIGINT looked dead). disconnect(false)
  // just leaves any AP (a no-op over serial) and leaves the radio running.
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, false);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  const uint8_t channels[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
  const int nch = sizeof(channels);
  uint32_t start = millis();
  uint32_t dwell = durationMs / (nch + 1);           // per-channel dwell
  if (dwell > 120) dwell = 120;
  int idx = 0;
  bool leave = false;
  while (millis() - start < durationMs && !leave) {
    esp_wifi_set_channel(channels[idx % nch], WIFI_SECOND_CHAN_NONE);
    idx++;
    // Cooperative dwell: keep touch + display alive while the sniffer callback
    // accumulates in the background (it's an async RX cb, not this loop). This
    // is what makes touch responsive during the 6 s sweep.
    uint32_t d0 = millis();
    while (millis() - d0 < dwell) {
      serviceUI(); delay(8);
#if CYD_TRANSPORT_SERIAL
      if (g_wfActive) { leave = true; break; }   // waterfall opened: end sweep now
#endif
    }
  }
  esp_wifi_set_promiscuous(false);
  g_sc.bssids = g_apCount;
}

// ════════════════════════════════════════════════════════════════════════════
//  BLE advertisement scan
// ════════════════════════════════════════════════════════════════════════════
#if CYD_ENABLE_BLE
static bool g_bleReady = false;
static volatile bool g_bleBusy = false;
static void bleDone(BLEScanResults res) {   // completion callback (async)
  g_sc.bleAdv = res.getCount();
  g_bleBusy = false;
}
// Start a passive BLE advert scan ASYNCHRONOUSLY (returns immediately); bleDone
// records the count when it finishes. The caller services the UI meanwhile, so
// BLE no longer blocks touch for its whole window.
static void bleStart(uint32_t durationMs) {
  if (!g_bleReady || g_bleBusy || !g_bleEnabled) return;   // Settings can disable BLE
  BLEScan *scan = BLEDevice::getScan();
  scan->setActiveScan(false);
  scan->setInterval(100);
  scan->setWindow(99);
  scan->clearResults();
  uint32_t secs = durationMs / 1000; if (secs < 1) secs = 1;
  g_bleBusy = true;
  if (!scan->start(secs, bleDone, false)) g_bleBusy = false;
}
#else
static void bleStart(uint32_t) { g_sc.bleAdv = 0; }
static const bool g_bleBusy = false;
#endif

// Build the "aps":[...] fragment for an ingest payload (shared by both
// transports). Capped so the line stays small; SSIDs were sanitised on capture.
#define AP_REPORT_MAX 32
static String apsJson() {
  String s = "\"aps\":[";
  uint32_t n = g_apCount < AP_REPORT_MAX ? g_apCount : AP_REPORT_MAX;
  char mac[18];
  for (uint32_t i = 0; i < n; i++) {
    const ApInfo &a = g_aps[i];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             a.bssid[0], a.bssid[1], a.bssid[2], a.bssid[3], a.bssid[4], a.bssid[5]);
    if (i) s += ",";
    s += "{\"bssid\":\""; s += mac;
    s += "\",\"ssid\":\""; s += a.ssid;
    s += "\",\"ch\":"; s += String(a.ch);
    s += ",\"rssi\":"; s += String(a.rssi);
    s += "}";
  }
  s += "]";
  return s;
}

// ════════════════════════════════════════════════════════════════════════════
//  Ragnar REST client
// ════════════════════════════════════════════════════════════════════════════
// Flat-JSON helpers (we control the /api/cyd/status shape, so keep it simple).
static long jsonInt(const String &body, const char *key) {
  String k = String("\"") + key + "\"";
  int i = body.indexOf(k);
  if (i < 0) return 0;
  i = body.indexOf(':', i);
  if (i < 0) return 0;
  return body.substring(i + 1).toInt();
}
static String jsonStr(const String &body, const char *key) {
  String k = String("\"") + key + "\"";
  int i = body.indexOf(k);
  if (i < 0) return "";
  i = body.indexOf(':', i);
  if (i < 0) return "";
  int q1 = body.indexOf('"', i);
  if (q1 < 0) return "";
  int q2 = body.indexOf('"', q1 + 1);
  if (q2 < 0) return "";
  return body.substring(q1 + 1, q2);
}

// Apply a status JSON body (shared by the HTTP and serial transports).
static void applyStatus(const String &body) {
  g_rs.meshNodes = jsonInt(body, "mesh_nodes");
  g_rs.nets24    = jsonInt(body, "nets_24");
  g_rs.nets5     = jsonInt(body, "nets_5");
  g_rs.threat    = jsonInt(body, "threat");
  g_rs.uptimeSec = jsonInt(body, "uptime");
  g_rs.alerts = jsonInt(body, "alerts");
  g_rs.wids   = jsonInt(body, "wids") != 0;
  // Copy a string field into a fixed buffer (only if present, so a partial frame
  // doesn't wipe existing values).
  #define CYD_CPYS(field, key) do { String _v = jsonStr(body, key); \
    if (_v.length()) { strncpy(g_rs.field, _v.c_str(), sizeof(g_rs.field) - 1); \
      g_rs.field[sizeof(g_rs.field)-1] = 0; } } while (0)
  CYD_CPYS(btState, "bluetooth");
  CYD_CPYS(unitName, "unit");
  CYD_CPYS(iface, "iface");
  CYD_CPYS(ip, "ip");
  CYD_CPYS(wardrive, "wardrive");
  CYD_CPYS(worst, "worst");
  CYD_CPYS(alert1, "alert1");
  CYD_CPYS(alert2, "alert2");
  CYD_CPYS(alert3, "alert3");
  CYD_CPYS(netint, "netint");
  CYD_CPYS(speedtest, "speedtest");
  CYD_CPYS(captive, "captive");
  CYD_CPYS(pwn, "pwn");
  CYD_CPYS(ni1, "ni1");
  CYD_CPYS(ni2, "ni2");
  CYD_CPYS(ni3, "ni3");
  CYD_CPYS(tfMbps, "tf_mbps");
  CYD_CPYS(actName, "act_name");
  CYD_CPYS(actState, "act_state");
  CYD_CPYS(actDetail, "act_detail");
  g_rs.actDur = jsonInt(body, "act_dur");
  CYD_CPYS(wdGps, "wd_gps");
  CYD_CPYS(wdBand, "wd_band");
  CYD_CPYS(wdC1, "wd_c1");
  CYD_CPYS(wdC2, "wd_c2");
  #undef CYD_CPYS
  g_rs.wdRun     = jsonInt(body, "wd_run") != 0;
  g_rs.wdNets    = jsonInt(body, "wd_nets");
  g_rs.wdScan    = jsonInt(body, "wd_scan");
  g_rs.wdBle     = jsonInt(body, "wd_ble");
  g_rs.wdCell    = jsonInt(body, "wd_cell");
  g_rs.wdZig     = jsonInt(body, "wd_zig");
  g_rs.wdComp    = jsonInt(body, "wd_comp");
  g_rs.wdEnabled = jsonInt(body, "wd_enabled") != 0;
  // Clear the Start/Stop "processing" latch once Ragnar confirms the run-state we
  // asked for (the pushed wd_run now matches the target), so the button un-greys.
  if (g_wdPending && g_rs.wdRun == g_wdTarget) { g_wdPending = false; g_needRedraw = true; }
  g_rs.tfRun    = jsonInt(body, "tf_run") != 0;
  if (g_tfPending && g_rs.tfRun == g_tfTarget) { g_tfPending = false; g_needRedraw = true; }
  g_rs.tfPps    = jsonInt(body, "tf_pps");
  g_rs.tfHosts  = jsonInt(body, "tf_hosts");
  g_rs.tfConns  = jsonInt(body, "tf_conns");
  g_rs.tfPkts   = (uint32_t)jsonInt(body, "tf_pkts");
  g_rs.tfAlerts = jsonInt(body, "tf_alerts");
  g_rs.ok = true;
  g_bootRagnarUp = true;          // signals the boot animation that the Pi is up
  g_rs.lastSyncMs = millis();
  // Only repaint when a DISPLAYED value actually changed. Ragnar pushes status
  // ~every 2 s with mostly-identical data; repainting every push is what made the
  // screen twitch. Build a cheap signature (excluding time-derived fields) and
  // redraw only on change.
  String sig = String(g_rs.meshNodes) + '|' + g_rs.nets24 + '|' + g_rs.nets5 + '|'
    + g_rs.threat + '|' + g_rs.alerts + '|' + g_rs.btState + '|' + g_rs.unitName + '|'
    + g_rs.iface + '|' + g_rs.ip + '|' + g_rs.wardrive + '|' + g_rs.worst + '|'
    + g_rs.alert1 + '|' + g_rs.alert2 + '|' + g_rs.alert3 + '|'
    + g_rs.netint + '|' + g_rs.speedtest + '|' + g_rs.captive + '|' + g_rs.pwn + '|'
    + g_rs.ni1 + '|' + g_rs.ni2 + '|' + g_rs.ni3 + '|'
    + g_rs.tfRun + '|' + g_rs.tfPps + '|' + g_rs.tfMbps + '|' + g_rs.tfHosts + '|'
    + g_rs.tfConns + '|' + g_rs.tfPkts + '|' + g_rs.tfAlerts + '|'
    + g_rs.actName + '|' + g_rs.actState + '|' + g_rs.actDetail + '|' + g_rs.actDur + '|'
    + g_rs.wdRun + '|' + g_rs.wdNets + '|' + g_rs.wdScan + '|' + g_rs.wdBle + '|'
    + g_rs.wdCell + '|' + g_rs.wdZig + '|' + g_rs.wdComp + '|' + g_rs.wdGps + '|'
    + g_rs.wdBand + '|' + g_rs.wdC1 + '|' + g_rs.wdC2 + '|' + g_rs.wdEnabled;
  static String lastSig;
  if (sig != lastSig) { lastSig = sig; g_needRedraw = true; }
}

#if !CYD_TRANSPORT_SERIAL
static bool httpGetStatus() {
  HTTPClient http;
  http.setConnectTimeout(2000);
  http.setTimeout(2500);
  http.begin(g_cfg.url + "/api/cyd/status");
  http.addHeader("Authorization", String("Bearer ") + g_cfg.token);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }
  String body = http.getString();
  http.end();
  applyStatus(body);
  return true;
}

static bool httpPostIngest() {
  HTTPClient http;
  http.setConnectTimeout(2000);
  http.setTimeout(2500);
  http.begin(g_cfg.url + "/api/cyd/ingest");
  http.addHeader("Authorization", String("Bearer ") + g_cfg.token);
  http.addHeader("Content-Type", "application/json");
  String payload = String("{")
    + "\"node\":\"" + g_cfg.name + "\","
    + "\"beacons\":" + String((uint32_t)g_sc.beacons) + ","
    + "\"probes\":"  + String((uint32_t)g_sc.probes)  + ","
    + "\"deauths\":" + String((uint32_t)g_sc.deauths) + ","
    + "\"frames\":"  + String((uint32_t)g_sc.frames)  + ","
    + "\"bssids\":"  + String(g_sc.bssids) + ","
    + "\"ble_adv\":" + String(g_sc.bleAdv) + ","
    + "\"rssi\":"    + String(WiFi.RSSI()) + ","
    + apsJson() + "}";
  int code = http.POST(payload);
  http.end();
  return code == 200 || code == 204;
}

static bool httpPostAction(const String &action) {
  HTTPClient http;
  http.setConnectTimeout(2000);
  http.setTimeout(3000);
  http.begin(g_cfg.url + "/api/cyd/action");
  http.addHeader("Authorization", String("Bearer ") + g_cfg.token);
  http.addHeader("Content-Type", "application/json");
  String payload = String("{\"node\":\"") + g_cfg.name + "\",\"action\":\"" + action + "\"}";
  int code = http.POST(payload);
  http.end();
  return code == 200 || code == 202;
}

// Connect to WiFi within the timeout. Returns true on success.
static bool wifiConnect() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(g_cfg.ssid.c_str(), g_cfg.pass.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < CYD_WIFI_CONNECT_TO) {
    delay(150);
  }
  return WiFi.status() == WL_CONNECTED;
}
#endif // !CYD_TRANSPORT_SERIAL

// ════════════════════════════════════════════════════════════════════════════
//  USB-serial transport — newline-delimited JSON to/from cyd_serial_bridge.py
// ════════════════════════════════════════════════════════════════════════════
#if CYD_TRANSPORT_SERIAL
// Pi -> node: {"t":"st","unit":..,"mesh_nodes":..,"nets_24":..,"nets_5":..,
//              "threat":..,"bluetooth":"idle","uptime":..}
// node -> Pi: {"t":"in", <sensor counts>}   and   {"t":"ac","action":".."}
static void handleSerialLine(const String &line) {
  if (line.indexOf("\"wf\"") >= 0) { applyWfRow(line); return; }   // waterfall frame
  if (line.indexOf("\"me\"") >= 0) { applyRoster(line, g_meshRows, MAX_MESH, g_meshN, 'm'); g_needRedraw = true; return; }
  if (line.indexOf("\"wl\"") >= 0) { applyRoster(line, g_wifiRows, MAX_WIFI, g_wifiN, 'w'); g_needRedraw = true; return; }
  if (line.indexOf("\"st\"") >= 0) applyStatus(line);             // status frame
}

// Ask Ragnar to (start/stop) streaming the mesh roster / wifi list.
static void serialSendMeshReq(bool on) {
  Serial.print("{\"t\":\"mr\",\"on\":"); Serial.print(on ? "1" : "0"); Serial.println("}");
}
static void serialSendWifiReq(bool on) {
  Serial.print("{\"t\":\"wsr\",\"on\":"); Serial.print(on ? "1" : "0"); Serial.println("}");
}
static void serialSendConnect(int idx, const String &pw) {
  Serial.print("{\"t\":\"wc\",\"idx\":"); Serial.print(idx);
  Serial.print(",\"pw\":\""); Serial.print(pw); Serial.println("\"}");
}

// Ask Ragnar to (start/stop) streaming the current band's spectrum.
static void serialSendWfReq(bool on) {
  Serial.print("{\"t\":\"wr\",\"band\":\"");
  Serial.print(WF_BANDS[g_wfBandIdx]);
  Serial.print("\",\"on\":"); Serial.print(on ? "1" : "0");
  Serial.println("}");
}

// Drain any pending inbound bytes and apply complete lines (non-blocking).
static void serialDrain() {
  static String buf;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') { if (buf.length()) handleSerialLine(buf); buf = ""; }
    else if (c != '\r' && buf.length() < 2048) buf += c;  // roster/wifi frames are large
  }
}

static void serialSendIngest() {
  Serial.print("{\"t\":\"in\",\"node\":\"");
  Serial.print(g_cfg.name);
  Serial.print("\",\"beacons\":");  Serial.print((uint32_t)g_sc.beacons);
  Serial.print(",\"probes\":");     Serial.print((uint32_t)g_sc.probes);
  Serial.print(",\"deauths\":");    Serial.print((uint32_t)g_sc.deauths);
  Serial.print(",\"frames\":");     Serial.print((uint32_t)g_sc.frames);
  Serial.print(",\"bssids\":");     Serial.print(g_sc.bssids);
  Serial.print(",\"ble_adv\":");    Serial.print(g_sc.bleAdv);
  Serial.print(",");                Serial.print(apsJson());
  Serial.println("}");
}

static void serialSendAction(const String &action) {
  Serial.print("{\"t\":\"ac\",\"node\":\"");
  Serial.print(g_cfg.name);
  Serial.print("\",\"action\":\"");
  Serial.print(action);
  Serial.println("\"}");
}
#endif // CYD_TRANSPORT_SERIAL

// ════════════════════════════════════════════════════════════════════════════
//  UI
// ════════════════════════════════════════════════════════════════════════════
// ── Ragnar palette ────────────────────────────────────────────────────────────
static uint16_t colBg()    { return gfx->color565(11, 14, 20); }
static uint16_t colHead()  { return gfx->color565(16, 22, 34); }
static uint16_t colBlue()  { return gfx->color565(40, 120, 200); }
static uint16_t colSky()   { return gfx->color565(90, 180, 255); }
static uint16_t colGray()  { return gfx->color565(140, 152, 165); }
static uint16_t colDim()   { return gfx->color565(90, 100, 112); }
static uint16_t colGreen() { return gfx->color565(70, 200, 120); }
static uint16_t colAmber() { return gfx->color565(230, 170, 50); }
static uint16_t colRed()   { return gfx->color565(224, 64, 64); }

static uint16_t threatColor(int t) {
  if (t >= 66) return colRed();
  if (t >= 33) return colAmber();
  return colGreen();
}

// ── Launcher: a dense, data-driven 2-column menu (half-height tiles) ──────────
// Add a feature by adding one row to g_menu[] (and a case in render()/drawScreen)
// — the grid lays itself out. Up to 10 items fit without scrolling.
static const int16_t HEAD_H   = 30;
static const int16_t TILE_W   = 105;
static const int16_t TILE_H   = 34;                 // sized so 12 tiles (6 rows) fit
static const int16_t TILE_XL  = 10, TILE_XR = 125;
static const int16_t MENU_Y0  = 34;                 // first row top
static const int16_t MENU_PITCH = TILE_H + 8;       // row stride (42)

struct MenuItem { const char *label; Screen scr; uint8_t r, g, b; };
static const MenuItem g_menu[] = {
  {"DASH",     SCR_DASH,      40, 120, 200},
  {"DEFEND",   SCR_DEFENSE,   70, 200, 120},
  {"ALERTS",   SCR_ALERTS,   224,  64,  64},
  {"SCAN",     SCR_SCAN,     150,  90, 210},
  {"SIGINT",   SCR_SIGINT,    60, 190, 190},
  {"WFALL",    SCR_WFALL,    230, 170,  50},
  {"NET",      SCR_NETWORK,   80, 160, 120},
  {"NETCONN",  SCR_NETCONN,   90, 140, 210},
  {"MESH",     SCR_MESH,     120, 190, 120},
  {"TRAFFIC",  SCR_TRAFFIC,  210, 130,  90},
  {"SETTINGS", SCR_SETTINGS, 140, 152, 165},
  {"CTRL",     SCR_CTRL,     120, 130, 200},
};
static const int N_MENU = sizeof(g_menu) / sizeof(g_menu[0]);
static void menuItemXY(int i, int16_t &x, int16_t &y) {
  x = (i & 1) ? TILE_XR : TILE_XL;
  y = MENU_Y0 + (i / 2) * MENU_PITCH;
}

static void drawStatusBar() {
  gfx->fillRect(0, SCR_H - 22, SCR_W, 22, colHead());
  gfx->setTextSize(1);
  gfx->setTextColor(g_statusColor);
  gfx->setCursor(6, SCR_H - 15);
  gfx->print(g_statusLine);
}

static void kv(int16_t y, const char *k, const String &v, uint16_t vc) {
  // Clear this field's row first so a same-screen refresh needs no full wipe
  // (that's what removes the flicker) yet leaves no stale pixels behind.
  gfx->fillRect(0, y - 1, SCR_W, 30, colBg());
  gfx->setTextSize(1);
  gfx->setTextColor(colGray());
  gfx->setCursor(12, y);
  gfx->print(k);
  gfx->setTextColor(vc);
  gfx->setTextSize(2);
  gfx->setCursor(12, y + 10);
  gfx->print(v);
}

// Brand header (home) or a titled back-bar (drill-in screens).
static void drawHeader(const char *title, bool home) {
  gfx->fillRect(0, 0, SCR_W, HEAD_H, colHead());
  if (home) {
    // Title = this unit's identity (mesh short-name, or 'Ragnar' when no mesh) —
    // no fixed 'RAGNAR' brand + name (which read 'RAGNAR Ragnar' off-mesh).
    String u = g_rs.unitName; if (!u.length()) u = "Ragnar";
    if (u.equalsIgnoreCase("ragnar")) u = "Ragnar";   // brand always renders with a big R
    if (u.length() > 18) u = u.substring(0, 18);
    gfx->setTextColor(colSky()); gfx->setTextSize(2);
    gfx->setCursor(8, 8); gfx->print(u);
  } else {
    // Bigger, obvious back target: a rounded chip filling the header-left, with a
    // large arrow. The touch zone (see handleTouch) is even larger than the chip.
    gfx->fillRoundRect(2, 2, 58, HEAD_H - 4, 6, gfx->color565(30, 90, 160));
    gfx->drawRoundRect(2, 2, 58, HEAD_H - 4, 6, colSky());
    gfx->setTextColor(WHITE); gfx->setTextSize(3);
    gfx->setCursor(14, 5); gfx->print("<");
    gfx->setTextSize(2);
    gfx->setTextColor(WHITE);
    gfx->setCursor(70, 8); gfx->print(title);
  }
}

// Back target: the full header, plus a generous top-left zone that extends below
// the header edge (resistive panels are least sensitive at the very top edge, so
// a taller/wider hit box makes "back" easy to hit).
static const int16_t BACK_ZONE_W = 90;
static const int16_t BACK_ZONE_H = HEAD_H + 12;
static bool inBackZone(int16_t px, int16_t py) {
  return (py < HEAD_H) || (px < BACK_ZONE_W && py < BACK_ZONE_H);
}

// A half-height menu tile: left accent bar + label, with a compact live value
// on the right where one is useful. Label stays legible up to ~8 chars.
static void drawMenuTile(int16_t x, int16_t y, const char *label,
                         const String &val, uint16_t accent, uint16_t vcol) {
  gfx->fillRoundRect(x, y, TILE_W, TILE_H, 6, gfx->color565(22, 28, 40));
  gfx->drawRoundRect(x, y, TILE_W, TILE_H, 6, gfx->color565(45, 55, 70));
  gfx->fillRoundRect(x, y + 4, 4, TILE_H - 8, 2, accent);   // left accent bar
  // HOME tile label in the proportional ~10px font (a bit smaller than size-2,
  // still clean). Custom fonts position by BASELINE, so y is the baseline row;
  // revert to the built-in font right after so every other screen is unchanged.
  gfx->setTextColor(WHITE); gfx->setFont(&RagnarLabel); gfx->setTextSize(1);
  gfx->setCursor(x + 12, y + 22); gfx->print(label);
  gfx->setFont();
  if (val.length()) {
    gfx->setTextColor(vcol); gfx->setTextSize(1);
    int16_t vx = x + TILE_W - (int16_t)val.length() * 6 - 6;
    gfx->setCursor(vx, y + (TILE_H - 8) / 2); gfx->print(val);
  }
}

// Compact per-tile live value (empty where none is useful). Takes an int (not
// Screen) so Arduino's auto-prototype doesn't reference the enum before it's
// declared.
static String menuValue(int s, uint16_t &vcol) {
  vcol = colGray();
  switch (s) {
    case SCR_DASH:    vcol = threatColor(g_rs.threat); return String(g_rs.threat);
    case SCR_DEFENSE: { bool a = g_sc.deauths > 0; vcol = a ? colRed() : colGreen();
                        return a ? String((uint32_t)g_sc.deauths) : String("ok"); }
    case SCR_ALERTS:  vcol = g_rs.alerts ? colRed() : colGreen(); return String(g_rs.alerts);
    case SCR_SCAN:    vcol = colSky(); return String(g_sc.bssids);
    case SCR_SIGINT:  vcol = colSky(); return String(g_apCount);
    case SCR_WFALL:   vcol = colAmber(); return String(WF_BANDS[g_wfBandIdx]);
    case SCR_NETWORK: vcol = colSky(); return String(g_rs.nets24) + "/" + String(g_rs.nets5);
    default:          return String("");
  }
}

static void drawHome() {
  drawHeader(nullptr, true);
  for (int i = 0; i < N_MENU; i++) {
    int16_t x, y; menuItemXY(i, x, y);
    uint16_t vcol; String val = menuValue(g_menu[i].scr, vcol);
    drawMenuTile(x, y, g_menu[i].label, val,
                 gfx->color565(g_menu[i].r, g_menu[i].g, g_menu[i].b), vcol);
  }
}

static void drawDash() {
  drawHeader("DASHBOARD", false);
  int16_t y = HEAD_H + 8;   // no UNIT row — the name is on HOME already
  kv(y, "THREAT", String(g_rs.threat) + " / 100", threatColor(g_rs.threat)); y += 38;
  kv(y, "ALERTS", String(g_rs.alerts) + "  " + g_rs.worst,
     g_rs.alerts ? colRed() : colGreen()); y += 38;
  kv(y, "NETWORKS", String(g_rs.nets24) + " / " + String(g_rs.nets5) + " (2.4/5G)", WHITE); y += 38;
  kv(y, "WARDRIVE", String(g_rs.wardrive), WHITE); y += 38;
  if (strlen(g_rs.iface))
    kv(y, "LINK", String(g_rs.iface) + " " + g_rs.ip, colSky());
  else
    kv(y, "BLUETOOTH", String(g_rs.btState), WHITE);
  y += 38;
  uint32_t since = g_rs.lastSyncMs ? (millis() - g_rs.lastSyncMs) / 1000 : 0;
  kv(y, "LAST SYNC", String(since) + "s ago", g_rs.ok ? colGreen() : colRed());
}

static void drawDefense() {
  drawHeader("DEFENSE", false);
  int16_t y = HEAD_H + 8;
  // Headline banner: attack (red) vs watching (green)
  bool attack = g_sc.deauths > 0;
  gfx->fillRoundRect(10, y, SCR_W - 20, 30, 6, attack ? colRed() : gfx->color565(20, 60, 40));
  gfx->setTextColor(WHITE); gfx->setTextSize(2);
  gfx->setCursor(20, y + 8);
  gfx->print(attack ? "DEAUTH SEEN" : "WATCHING 2.4G");
  y += 44;
  kv(y, "DEAUTH/DISASSOC", String((uint32_t)g_sc.deauths), attack ? colRed() : WHITE); y += 38;
  kv(y, "APs THIS SWEEP", String(g_sc.bssids), WHITE); y += 38;
  kv(y, "PROBE REQUESTS", String((uint32_t)g_sc.probes), WHITE); y += 38;
  kv(y, "BLE DEVICES", String(g_sc.bleAdv), WHITE); y += 38;
  gfx->setTextSize(1); gfx->setTextColor(colDim());
  gfx->setCursor(12, y + 6); gfx->print("reported to Ragnar WiFi Defense");
}

static void drawScan() {
  drawHeader("SCAN 2.4 GHz", false);
  int16_t y = HEAD_H + 8;
  kv(y, "BEACONS", String((uint32_t)g_sc.beacons), WHITE); y += 38;
  kv(y, "UNIQUE APs", String(g_sc.bssids), WHITE); y += 38;
  kv(y, "PROBE REQ", String((uint32_t)g_sc.probes), WHITE); y += 38;
  kv(y, "DEAUTH/DISASSOC", String((uint32_t)g_sc.deauths), g_sc.deauths > 0 ? colRed() : WHITE); y += 38;
  kv(y, "BLE ADVERTS", String(g_sc.bleAdv), WHITE); y += 38;
  kv(y, "FRAMES SEEN", String((uint32_t)g_sc.frames), colDim());
}

// ── Signal Intelligence: a radar/dome view of the 2.4 GHz APs we hear ─────────
static void drawSigInt() {
  drawHeader("SIGINT", false);
  // Clear the plot area (moving dots would smear without the full-screen wipe).
  gfx->fillRect(0, HEAD_H, SCR_W, SCR_H - HEAD_H - 22, colBg());
  int16_t cx = SCR_W / 2;
  int16_t cy = HEAD_H + 118;
  int16_t rmax = 100;
  for (int r = rmax; r > 0; r -= rmax / 3)
    gfx->drawCircle(cx, cy, r, gfx->color565(28, 38, 50));
  gfx->drawCircle(cx, cy, rmax, colDim());
  gfx->fillCircle(cx, cy, 3, colSky());                 // this node = centre
  for (uint32_t i = 0; i < g_apCount; i++) {
    const ApInfo &a = g_aps[i];
    float frac = (-30.0f - a.rssi) / 60.0f;             // -30dBm→centre, -90→edge
    if (frac < 0) frac = 0; if (frac > 1) frac = 1;
    int rr = (int)(frac * rmax);
    uint32_t h = a.bssid[5] | (a.bssid[4] << 8) | (a.bssid[3] << 16);
    float ang = (h % 360) * 0.017453f;
    int px = cx + (int)(rr * cosf(ang));
    int py = cy + (int)(rr * sinf(ang));
    gfx->fillCircle(px, py, 2, a.rssi > -55 ? colGreen() : (a.rssi > -75 ? colAmber() : colRed()));
  }
  gfx->setTextColor(colDim()); gfx->setTextSize(1);
  gfx->setCursor(8, SCR_H - 38);
  gfx->print(String(g_apCount) + " APs  centre=here  outer ring=weak");
}

// ── RF waterfall: palette + a streamed-row renderer ───────────────────────────
// Inferno colour map — the SAME 5-stop LUT the web RF-waterfall uses
// (black→purple→red→orange→pale), so the two match. Dark noise floor, warm signals.
static uint16_t wfColor(uint8_t v) {
  static const uint8_t stops[5][3] = {
    {4,3,18},{87,16,110},{188,55,84},{249,142,9},{252,255,164}
  };
  int seg = v * 4 / 255; if (seg > 3) seg = 3;
  int t0 = seg * 255 / 4, t1 = (seg + 1) * 255 / 4;
  int f = (t1 > t0) ? (v - t0) * 255 / (t1 - t0) : 0;
  const uint8_t *a = stops[seg], *b = stops[seg + 1];
  uint8_t r = a[0] + (b[0] - a[0]) * f / 255;
  uint8_t g = a[1] + (b[1] - a[1]) * f / 255;
  uint8_t bl = a[2] + (b[2] - a[2]) * f / 255;
  return gfx->color565(r, g, bl);
}

static void drawWaterfall() {
  drawHeader("WATERFALL", false);
  int16_t by = HEAD_H;
  gfx->fillRect(0, by, SCR_W, 20, gfx->color565(24, 30, 42));
  gfx->setTextColor(colAmber()); gfx->setTextSize(2);
  gfx->setCursor(8, by + 3); gfx->print(WF_BANDS[g_wfBandIdx]);
  gfx->setTextColor(colDim()); gfx->setTextSize(1);
  if (g_wfLo) { gfx->setCursor(58, by + 7);
                gfx->print(String(g_wfLo) + "-" + String(g_wfHi) + "MHz"); }
  gfx->setTextColor(colSky()); gfx->setCursor(184, by + 7); gfx->print("band>");
  int16_t yTop = by + 22;
  // Reserve a bottom spectrum strip (live signal per frequency) + a frequency axis,
  // like the web waterfall. The scrolling waterfall fills the space above them.
  const int16_t AXIS_H = 10, STRIP_H = 30;
  int16_t wfBottom = SCR_H - 22 - AXIS_H - STRIP_H;   // waterfall ends here
  int16_t hArea = wfBottom - yTop;
  if (g_wfErr[0]) {
    gfx->fillRect(0, yTop, SCR_W, SCR_H - 22 - yTop, colBg());
    gfx->setTextColor(colRed()); gfx->setTextSize(2);
    gfx->setCursor(16, yTop + 40); gfx->print(g_wfErr);
    gfx->setTextColor(colDim()); gfx->setTextSize(1);
    gfx->setCursor(16, yTop + 70); gfx->print("attach a HackRF/RTL-SDR to Ragnar");
    return;
  }
  if (!g_wfHave || !g_wfImg) {
    gfx->setTextColor(colDim()); gfx->setTextSize(1);
    gfx->setCursor(16, yTop + 40); gfx->print("waiting for spectrum...");
    return;
  }
  // Fast path: build one RGB565 line (240px = 120 bins x2) and blit it per row —
  // one bitmap push per row instead of 120 fillRects (was ~18k fillRects/frame).
  static uint16_t linebuf[240];
  int rows = hArea < WF_ROWS ? hArea : WF_ROWS;
  for (int r = 0; r < rows; r++) {
    int src = (g_wfHead - 1 - r + WF_ROWS * 2) % WF_ROWS;   // newest at the top
    const uint8_t *row = g_wfImg[src];
    for (int c = 0; c < WF_BINS; c++) {
      uint16_t col = wfColor(row[c]);
      linebuf[c * 2] = col; linebuf[c * 2 + 1] = col;
    }
    gfx->draw16bitRGBBitmap(0, yTop + r, linebuf, 240, 1);
  }
  // ── live spectrum strip: the newest row as inferno-coloured bars ─────────────
  int newest = (g_wfHead - 1 + WF_ROWS) % WF_ROWS;
  const uint8_t *cur = g_wfImg[newest];
  int16_t sBot = wfBottom + STRIP_H;
  gfx->fillRect(0, wfBottom, SCR_W, STRIP_H, colBg());
  for (int c = 0; c < WF_BINS; c++) {
    int16_t h = (int16_t)cur[c] * STRIP_H / 255;
    if (h > 0) gfx->fillRect(c * 2, sBot - h, 2, h, wfColor(cur[c]));
  }
  // ── frequency axis (MHz): lo · mid · hi ─────────────────────────────────────
  gfx->fillRect(0, sBot, SCR_W, AXIS_H, colBg());
  gfx->setTextSize(1); gfx->setTextColor(colDim());
  if (g_wfLo) {
    String loS = String(g_wfLo), midS = String((g_wfLo + g_wfHi) / 2), hiS = String(g_wfHi);
    gfx->setCursor(2, sBot + 1);                             gfx->print(loS);
    gfx->setCursor(SCR_W / 2 - midS.length() * 3, sBot + 1); gfx->print(midS);
    gfx->setCursor(SCR_W - hiS.length() * 6 - 2, sBot + 1);  gfx->print(hiS);
  }
}

// Apply one streamed waterfall frame (shared by both transports).
static void applyWfRow(const String &body) {
  String err = jsonStr(body, "err");
  if (err.length()) {
    strncpy(g_wfErr, err.c_str(), sizeof(g_wfErr) - 1);
    g_wfErr[sizeof(g_wfErr) - 1] = 0;
    g_needRedraw = true;
    return;
  }
  g_wfErr[0] = 0;
  if (!g_wfImg) return;                      // buffer only exists while the screen is open
  // Bail on 'waiting' frames (no bins) BEFORE touching lo/hi/seq, so the band
  // label doesn't flicker to 0-0 and we don't force a needless redraw.
  int i = body.indexOf("\"bins\"");
  if (i < 0) return;
  i = body.indexOf('[', i);
  int end = (i >= 0) ? body.indexOf(']', i) : -1;
  if (i < 0 || end < 0) return;
  g_wfLo = jsonInt(body, "lo");
  g_wfHi = jsonInt(body, "hi");
  g_wfSeq = jsonInt(body, "seq");
  int col = 0, p = i + 1;
  while (p < end && col < WF_BINS) {
    while (p < end && (body[p] == ' ' || body[p] == ',')) p++;
    int v = 0; bool any = false;
    while (p < end && body[p] >= '0' && body[p] <= '9') { v = v * 10 + (body[p] - '0'); p++; any = true; }
    if (!any) break;
    g_wfImg[g_wfHead][col++] = (uint8_t)(v > 255 ? 255 : v);
  }
  while (col < WF_BINS) g_wfImg[g_wfHead][col++] = 0;
  g_wfHead = (g_wfHead + 1) % WF_ROWS;
  g_wfHave = true;
  g_needRedraw = true;
}

// Parse a roster frame {"t":..,"n":K,"<key>0":"..","<key>1":".."} into rows[].
static void applyRoster(const String &body, char rows[][ROW_LEN], int maxr,
                        int &count, char key) {
  int n = jsonInt(body, "n");
  if (n < 0) n = 0; if (n > maxr) n = maxr;
  char k[4] = {key, 0, 0, 0};
  for (int i = 0; i < n; i++) {
    if (i < 10) { k[1] = '0' + i; k[2] = 0; }
    else { k[1] = '0' + (i / 10); k[2] = '0' + (i % 10); k[3] = 0; }
    String v = jsonStr(body, k);
    strncpy(rows[i], v.c_str(), ROW_LEN - 1); rows[i][ROW_LEN - 1] = 0;
  }
  count = n;
}

// CONTROLS screen actions.
static const ActionBtn g_ctrlActions[] = {
  {"WiFi Defense scan", "wifi_defense_scan"},
  {"BLE scan",          "ble_scan"},
  {"Watchtower clear",  "watchtower_clear"},
  {"Restart Ragnar",    "service_restart"},
};
static const int N_CTRL = sizeof(g_ctrlActions) / sizeof(g_ctrlActions[0]);

// NETWORK screen items — a dense 2-column grid mixing sub-page navigation and
// one-tap actions (nav=true opens `scr`; nav=false enqueues `action`).
struct NetItem { const char *label; bool nav; uint8_t scr; const char *action; };
static const NetItem g_netItems[] = {
  {"Net Int",    true,  SCR_NETINT,   ""},
  {"Watchtower", true,  SCR_ALERTS,   ""},
  {"Wardrive",   true,  SCR_WARDRIVE, ""},
  {"Speed test", false, 0, "speed_test"},
  {"Captive",    false, 0, "captive_check"},
  {"Airspace",   false, 0, "network_scan"},
  {"WIDS scan",  false, 0, "wifi_defense_scan"},
};
static const int N_NET = sizeof(g_netItems) / sizeof(g_netItems[0]);

static const int16_t BTN_BH = 40, BTN_GAP = 8;

// Compact 2-column grid geometry (half-height buttons); NETWORK draws its own
// mixed nav/action tiles using this layout.
static const int16_t GBTN_W = 105, GBTN_H = 34, GBTN_GAP = 7;
static void gridBtnXY(int i, int16_t y0, int16_t &x, int16_t &y) {
  x = (i & 1) ? 125 : 10;
  y = y0 + (i / 2) * (GBTN_H + GBTN_GAP);
}

// Draw a vertical list of action buttons from y0; returns the y after the list.
static int16_t drawActionList(const ActionBtn *items, int n, int16_t y0) {
  int16_t y = y0;
  for (int i = 0; i < n; i++) {
    gfx->fillRoundRect(10, y, SCR_W - 20, BTN_BH, 8, colBlue());
    gfx->drawRoundRect(10, y, SCR_W - 20, BTN_BH, 8, colSky());
    gfx->setTextColor(WHITE); gfx->setTextSize(2);
    gfx->setCursor(22, y + 12);
    gfx->print(items[i].label);
    y += BTN_BH + BTN_GAP;
  }
  return y;
}

// Hit-test an action list at y0; enqueues the tapped action. Returns true if hit.

static const int16_t CTRL_Y0 = HEAD_H + 10;
static void drawControls() {
  drawHeader("CONTROLS", false);
  drawActionList(g_ctrlActions, N_CTRL, CTRL_Y0);
}

// ── Generic Action result subpage ─────────────────────────────────────────────
// A tap on a one-shot action navigates here and shows starting -> running ->
// done/error with the result Ragnar reports (act_name/act_state/act_detail),
// instead of firing blind. requestAction() sends the action immediately (serial)
// so there's no wait for the sync window.
static Screen   g_actReturn = SCR_HOME;    // where the tap came from
static char     g_actLabel[24] = "";       // friendly label of what we asked
static char     g_actName[24]  = "";       // action id we're tracking
static uint32_t g_actStartMs   = 0;
static uint32_t g_actRunStart  = 0;   // when THIS action first reported 'running'
static bool     g_actAnimate   = false; // tick the Action page (spinner/countdown)
static String   g_actSig;              // static-content signature (full repaint only on change)

static void requestAction(const char *action, const char *label) {
#if CYD_TRANSPORT_SERIAL
  serialSendAction(String(action));        // send now, don't wait for SYNC
#else
  actionEnqueue(action);
#endif
  strncpy(g_actName, action, sizeof(g_actName) - 1);  g_actName[sizeof(g_actName)-1] = 0;
  strncpy(g_actLabel, label,  sizeof(g_actLabel) - 1); g_actLabel[sizeof(g_actLabel)-1] = 0;
  // Clear the local copy of the last result so we show "starting..." until Ragnar
  // reports THIS action (avoids flashing a previous run's result).
  g_rs.actName[0] = 0; g_rs.actState[0] = 0; g_rs.actDetail[0] = 0;
  g_actReturn = g_screen;
  g_actStartMs = millis();
  g_actRunStart = 0;
  g_actAnimate = true;   // spinner runs until Ragnar reports a terminal state
  g_actSig = "";         // force a full repaint of the Action page on entry
  g_screen = SCR_ACTION;
  g_needRedraw = true;
}

static void drawAction() {
  // Fixed layout so the animated bits (spinner / bar / countdown) can repaint in
  // place — the whole frame is redrawn ONLY when the static content changes, so
  // the ~7 Hz spinner tick no longer flickers the entire screen.
  const int16_t YLBL = HEAD_H + 14, YWORD = HEAD_H + 46, YDET = HEAD_H + 92;
  const int16_t YBAR = HEAD_H + 126, YCNT = YBAR + 24;

  bool  mine  = (strcmp(g_rs.actName, g_actName) == 0) && g_rs.actState[0];
  bool  grace = (millis() - g_actStartMs) < 1200;
  const char *st = g_rs.actState;
  bool starting = (!mine) || (grace && strcmp(st, "running") != 0);
  bool running  = !starting && strcmp(st, "running") == 0;
  bool done     = !starting && strcmp(st, "done")  == 0;
  bool failed   = !starting && strcmp(st, "error") == 0;
  bool timed    = running && g_rs.actDur > 0;

  // Static-content signature: repaint the frame once when it changes.
  String sig = String(starting ? 's' : running ? 'r' : done ? 'd' : 'f') + '|'
             + g_actLabel + '|' + g_rs.actDetail + '|' + g_rs.actDur;
  if (sig != g_actSig) {
    g_actSig = sig;
    drawHeader("ACTION", false);
    gfx->fillRect(0, HEAD_H, SCR_W, SCR_H - HEAD_H - 22, colBg());
    gfx->setTextColor(colSky()); gfx->setTextSize(2);
    gfx->setCursor(12, YLBL); gfx->print(g_actLabel);
    uint16_t wc = (starting || running) ? colAmber() : (done ? colGreen() : colRed());
    const char *word = starting ? "STARTING" : running ? "RUNNING" : done ? "DONE" : "FAILED";
    gfx->setTextColor(wc); gfx->setTextSize(3);
    gfx->setCursor(12, YWORD); gfx->print(word);
    if (starting || running) {
      const char *what = starting ? "waiting for Ragnar"
                                  : (g_rs.actDetail[0] ? g_rs.actDetail : "working");
      gfx->setTextColor(WHITE); gfx->setTextSize(2);
      gfx->setCursor(12, YDET); gfx->print(what);
      if (timed) gfx->drawRoundRect(12, YBAR, SCR_W - 24, 16, 4, colSky());  // bar outline
    } else {
      if (g_rs.actDetail[0]) {
        gfx->setTextColor(WHITE); gfx->setTextSize(2);
        gfx->setCursor(12, YDET); gfx->print(g_rs.actDetail);
      }
      if (strcmp(g_actName, "service_restart") == 0 || strcmp(g_actName, "ragnar_update") == 0) {
        gfx->setTextColor(colDim()); gfx->setTextSize(1);
        gfx->setCursor(12, YDET + 30); gfx->print("link will drop, reconnects shortly");
      }
      gfx->setTextColor(colDim()); gfx->setTextSize(1);
      gfx->setCursor(12, SCR_H - 40); gfx->print("tap < to go back");
    }
  }

  // ── animated bits: repaint in place each tick (small clears only) ───────────
  g_actAnimate = (starting || running);
  if (!g_actAnimate) return;

  static const char SPN[4] = {'|', '/', '-', '\\'};
  char sc = SPN[(millis() / 125) % 4];
  gfx->fillRect(SCR_W - 34, YWORD, 26, 26, colBg());          // spinner cell
  gfx->setTextColor(colAmber()); gfx->setTextSize(3);
  gfx->setCursor(SCR_W - 30, YWORD); gfx->print(sc);

  if (timed) {
    if (g_actRunStart == 0) g_actRunStart = millis();
    uint32_t dur = (uint32_t)g_rs.actDur;
    uint32_t el  = (millis() - g_actRunStart) / 1000;
    uint32_t cl  = el < dur ? el : dur;
    int fill = (int)(((uint32_t)(SCR_W - 26)) * cl / dur);
    gfx->fillRect(13, YBAR + 1, SCR_W - 26, 14, colBg());     // clear bar interior
    if (fill > 0) gfx->fillRoundRect(13, YBAR + 1, fill, 14, 3, colGreen());
    int rem = (int)dur - (int)el; if (rem < 0) rem = 0;
    gfx->fillRect(12, YCNT, 180, 18, colBg());                // clear countdown text
    gfx->setTextColor(colAmber()); gfx->setTextSize(2); gfx->setCursor(12, YCNT);
    if (rem > 0) { gfx->print(rem); gfx->print("s left"); }
    else gfx->print("finishing...");
  } else {
    uint32_t el = (millis() - g_actStartMs) / 1000;
    gfx->fillRect(12, YBAR, 180, 12, colBg());                // clear elapsed text
    gfx->setTextColor(colDim()); gfx->setTextSize(1);
    gfx->setCursor(12, YBAR); gfx->print("elapsed "); gfx->print(el); gfx->print("s");
  }
}

// ── Network: compact status header + wardrive/scan action buttons ─────────────
static const int16_t NET_GRID_Y0 = HEAD_H + 44;
static void drawNetwork() {
  drawHeader("NETWORK", false);
  // Condensed 2-line status header, then a dense grid of subpages + actions.
  int16_t y = HEAD_H + 6;
  gfx->fillRect(0, y, SCR_W, 36, colBg());
  gfx->setTextSize(1);
  String l1 = (strlen(g_rs.iface) ? (String(g_rs.iface) + " " + g_rs.ip) : String("link --"))
              + "  " + String(g_rs.nets24) + "/" + String(g_rs.nets5) + "G";
  gfx->setTextColor(colSky()); gfx->setCursor(12, y); gfx->print(l1);
  gfx->setTextColor(colGray()); gfx->setCursor(12, y + 16); gfx->print("netint ");
  bool niBad = strcmp(g_rs.netint, "ok") && strcmp(g_rs.netint, "off");
  gfx->setTextColor(niBad ? colRed() : colGreen()); gfx->print(g_rs.netint);
  gfx->setTextColor(colGray()); gfx->print("  alrt ");
  gfx->setTextColor(g_rs.alerts ? colRed() : colGreen());
  gfx->print(String(g_rs.alerts));
  for (int i = 0; i < N_NET; i++) {
    int16_t x, gy; gridBtnXY(i, NET_GRID_Y0, x, gy);
    uint16_t bg = g_netItems[i].nav ? gfx->color565(30, 70, 110) : colBlue();
    gfx->fillRoundRect(x, gy, GBTN_W, GBTN_H, 6, bg);
    gfx->drawRoundRect(x, gy, GBTN_W, GBTN_H, 6, colSky());
    gfx->setTextColor(WHITE); gfx->setTextSize(1);
    gfx->setCursor(x + 8, gy + (GBTN_H - 8) / 2); gfx->print(g_netItems[i].label);
    if (g_netItems[i].nav) { gfx->setTextColor(colSky()); gfx->setCursor(x + GBTN_W - 10, gy + (GBTN_H-8)/2); gfx->print(">"); }
  }
}

// Net-Integrity Monitor subpage: overall verdict + the worst check lines +
// on-demand speed-test / captive-portal results (tap NET buttons to run those).
static void drawNetInt() {
  drawHeader("NET INTEGRITY", false);
  int16_t y = HEAD_H + 10;
  bool bad = strcmp(g_rs.netint, "ok") && strcmp(g_rs.netint, "off");
  kv(y, "STATUS", String(g_rs.netint), strcmp(g_rs.netint, "off") == 0 ? colDim() : (bad ? colRed() : colGreen())); y += 34;
  const char *lines[3] = { g_rs.ni1, g_rs.ni2, g_rs.ni3 };
  for (int i = 0; i < 3; i++) {
    if (!strlen(lines[i])) continue;
    gfx->setTextSize(1); gfx->setTextColor(colAmber());
    gfx->fillRect(0, y, SCR_W, 12, colBg());
    gfx->setCursor(12, y); gfx->print(lines[i]); y += 14;
  }
  if (y < HEAD_H + 44) y = HEAD_H + 44;
  y += 6;
  kv(y, "SPEED TEST", String(g_rs.speedtest), colSky()); y += 34;
  kv(y, "CAPTIVE", String(g_rs.captive),
     strcmp(g_rs.captive, "portal!") == 0 ? colRed() : WHITE); y += 34;
  gfx->setTextSize(1); gfx->setTextColor(colDim());
  gfx->setCursor(12, y + 4); gfx->print("run tests from the NETWORK buttons");
}

// Traffic Analysis — live capture stats from Ragnar + a start/stop button.
static const int16_t TRAF_BTN_Y = SCR_H - 22 - 46;
// The Start/Stop button. While a toggle is pending it greys out and shows a
// spinner + elapsed clock (capture can take 5-30s to start). Repainted in place
// on a tick so it never flickers the whole page.
static void drawTrafficButton() {
  gfx->fillRect(10, TRAF_BTN_Y, SCR_W - 20, 44, colBg());
  if (g_tfPending) {
    gfx->fillRoundRect(10, TRAF_BTN_Y, SCR_W - 20, 44, 8, colDim());
    gfx->drawRoundRect(10, TRAF_BTN_Y, SCR_W - 20, 44, 8, colGray());
    static const char SPN[4] = {'|', '/', '-', '\\'};
    char sc = SPN[(millis() / 125) % 4];
    uint32_t el = (millis() - g_tfPendMs) / 1000;
    gfx->setTextColor(colAmber()); gfx->setTextSize(2);
    gfx->setCursor(24, TRAF_BTN_Y + 7); gfx->print(g_tfTarget ? "starting" : "stopping");
    gfx->setCursor(SCR_W - 34, TRAF_BTN_Y + 7); gfx->print(sc);
    gfx->setTextColor(colDim()); gfx->setTextSize(1);
    gfx->setCursor(24, TRAF_BTN_Y + 28); gfx->print("elapsed "); gfx->print(el);
    gfx->print("s (up to ~30s)");
  } else {
    uint16_t bc = g_rs.tfRun ? colRed() : colGreen();
    gfx->fillRoundRect(10, TRAF_BTN_Y, SCR_W - 20, 44, 8, bc);
    gfx->drawRoundRect(10, TRAF_BTN_Y, SCR_W - 20, 44, 8, colSky());
    gfx->setTextColor(WHITE); gfx->setTextSize(2);
    gfx->setCursor(40, TRAF_BTN_Y + 14); gfx->print(g_rs.tfRun ? "STOP capture" : "START capture");
  }
}
static void drawTraffic() {
  drawHeader("TRAFFIC", false);
  int16_t y = HEAD_H + 10;
  gfx->fillRect(0, HEAD_H, SCR_W, TRAF_BTN_Y - HEAD_H, colBg());
  gfx->setTextSize(2);
  if (g_tfPending) {
    gfx->setTextColor(colAmber());
    gfx->setCursor(12, y); gfx->print(g_tfTarget ? "STARTING..." : "STOPPING...");
  } else {
    gfx->setTextColor(g_rs.tfRun ? colGreen() : colGray());
    gfx->setCursor(12, y); gfx->print(g_rs.tfRun ? "CAPTURING" : "stopped");
  }
  y += 30;
  kv(y, "THROUGHPUT", String(g_rs.tfMbps) + " Mbps", colSky()); y += 34;
  kv(y, "PACKETS/S", String(g_rs.tfPps), WHITE); y += 34;
  kv(y, "HOSTS / CONNS", String(g_rs.tfHosts) + " / " + String(g_rs.tfConns), WHITE); y += 34;
  kv(y, "TOTAL PKTS", String(g_rs.tfPkts), colGreen()); y += 34;
  kv(y, "ALERTS", String(g_rs.tfAlerts), g_rs.tfAlerts ? colRed() : colGreen());
  drawTrafficButton();
}

// ── Wardrive: own page with live status + Start/Stop (stays on the page) ───────
static const int16_t WD_BTN_Y = SCR_H - 22 - 46;
// One centered stat: a small dim label with a bigger coloured value under it.
static void wdStat(int16_t y, const char *label, const String &val,
                   uint8_t vsize, uint16_t vcol) {
  int16_t cx = SCR_W / 2;
  gfx->setTextSize(1); gfx->setTextColor(colGray());
  gfx->setCursor(cx - (int16_t)strlen(label) * 3, y); gfx->print(label);
  gfx->setTextSize(vsize); gfx->setTextColor(vcol);
  gfx->setCursor(cx - (int16_t)(val.length() * 3 * vsize), y + 11); gfx->print(val);
}
static void drawWardrive() {
  drawHeader("WARDRIVE", false);
  int16_t y = HEAD_H + 10;
  gfx->fillRect(0, HEAD_H, SCR_W, WD_BTN_Y - HEAD_H, colBg());
  if (!g_rs.wdEnabled) {
    gfx->setTextColor(colAmber()); gfx->setTextSize(2);
    gfx->setCursor(12, y); gfx->print("DISABLED"); y += 30;
    gfx->setTextColor(colDim()); gfx->setTextSize(1);
    gfx->setCursor(12, y); gfx->print("enable wardriving in Ragnar first");
    return;
  }
  // ── Single centered column, larger fonts (readable at a glance) ────────────
  int16_t cx = SCR_W / 2;
  // Status headline (big).
  const char *stx = g_rs.wdRun ? "WARDRIVING" : "IDLE";
  gfx->setTextSize(3); gfx->setTextColor(g_rs.wdRun ? colGreen() : colGray());
  gfx->setCursor(cx - (int16_t)strlen(stx) * 9, y); gfx->print(stx);
  y += 30;
  // Band, centered under the status.
  String bnd = String("band ") + g_rs.wdBand;
  gfx->setTextSize(1); gfx->setTextColor(colDim());
  gfx->setCursor(cx - (int16_t)(bnd.length() * 3), y); gfx->print(bnd);
  y += 22;
  // Headline metric first (networks), then the rest — one centered column.
  wdStat(y, "NETWORKS", String(g_rs.wdNets), 3, colSky());  y += 44;
  wdStat(y, "BLE DEVICES", String(g_rs.wdBle), 2, WHITE);   y += 38;
  wdStat(y, "COMPANIONS", String(g_rs.wdComp), 2, colSky()); y += 38;
  wdStat(y, "GPS", String(g_rs.wdGps), 2,
         strncmp(g_rs.wdGps, "fix", 3) == 0 ? colGreen() : colDim());
  // Start/Stop button — toggles and STAYS on the page so the status stays live.
  // While a tap is in flight (~5s round-trip) it greys out and shows the pending
  // verb so the operator gets instant feedback and can't double-fire the toggle.
  gfx->setTextSize(2);
  if (g_wdPending) {
    gfx->fillRoundRect(10, WD_BTN_Y, SCR_W - 20, 44, 8, colDim());
    gfx->drawRoundRect(10, WD_BTN_Y, SCR_W - 20, 44, 8, colGray());
    gfx->setTextColor(colAmber());
    gfx->setCursor(40, WD_BTN_Y + 14); gfx->print(g_wdTarget ? "starting..." : "stopping...");
  } else {
    uint16_t bc = g_rs.wdRun ? colRed() : colGreen();
    gfx->fillRoundRect(10, WD_BTN_Y, SCR_W - 20, 44, 8, bc);
    gfx->drawRoundRect(10, WD_BTN_Y, SCR_W - 20, 44, 8, colSky());
    gfx->setTextColor(WHITE);
    gfx->setCursor(30, WD_BTN_Y + 14); gfx->print(g_rs.wdRun ? "STOP wardrive" : "START wardrive");
  }
}

// ── Scrollable list plumbing (Mesh + Net-Conn) ────────────────────────────────
static const int16_t SB_X = SCR_W - 26, SB_W = 24, SB_H = 26;
static const int16_t LIST_Y0 = HEAD_H + 4, LIST_ROWH = 26;
static void drawScrollButtons(int16_t bottomY, int scroll, int n, int vis) {
  gfx->fillRoundRect(SB_X, LIST_Y0, SB_W, SB_H, 4, scroll > 0 ? colBlue() : gfx->color565(24,30,42));
  gfx->setTextColor(WHITE); gfx->setTextSize(2); gfx->setCursor(SB_X + 7, LIST_Y0 + 5); gfx->print("^");
  gfx->fillRoundRect(SB_X, bottomY, SB_W, SB_H, 4, (scroll + vis) < n ? colBlue() : gfx->color565(24,30,42));
  gfx->setCursor(SB_X + 7, bottomY + 5); gfx->print("v");
}
// Draw rows[scroll..] into the list area; colorFn tints by row content.
static int listVisible(int16_t bottomY) { return (bottomY - LIST_Y0) / LIST_ROWH; }

// ── Mesh: scrollable roster of mesh nodes ─────────────────────────────────────
static void drawMesh() {
  drawHeader("MESH", false);
  int16_t bottomY = SCR_H - 22 - SB_H;
  int vis = listVisible(SCR_H - 22);
  gfx->fillRect(0, HEAD_H, SCR_W, SCR_H - 22 - HEAD_H, colBg());
  if (g_meshN == 0) {
    gfx->setTextSize(1); gfx->setTextColor(colDim());
    gfx->setCursor(12, LIST_Y0 + 8); gfx->print("no mesh nodes (or mesh off)");
  }
  for (int i = 0; i < vis && g_meshScroll + i < g_meshN; i++) {
    int idx = g_meshScroll + i; int16_t y = LIST_Y0 + i * LIST_ROWH;
    bool on = strncmp(g_meshRows[idx], "on", 2) == 0;
    gfx->fillRoundRect(6, y, SB_X - 12, LIST_ROWH - 3, 4, gfx->color565(20, 26, 36));
    gfx->setTextSize(1); gfx->setTextColor(on ? colGreen() : colGray());
    gfx->setCursor(12, y + 7); gfx->print(g_meshRows[idx]);
  }
  drawScrollButtons(bottomY, g_meshScroll, g_meshN, vis);
}

// ── Net-Conn: Pi WiFi scan list (tap to connect) + AP / scanner buttons ───────
static const int16_t NC_BTN_Y = SCR_H - 22 - 34;
static void drawNetConn() {
  drawHeader("NET CONN", false);
  gfx->fillRect(0, HEAD_H, SCR_W, NC_BTN_Y - HEAD_H, colBg());
  int16_t listBottom = NC_BTN_Y - 4;
  int vis = (listBottom - LIST_Y0) / LIST_ROWH;
  if (g_wifiN == 0) {
    gfx->setTextSize(1); gfx->setTextColor(colDim());
    gfx->setCursor(12, LIST_Y0 + 8); gfx->print("scanning Pi WiFi...");
  }
  for (int i = 0; i < vis && g_wifiScroll + i < g_wifiN; i++) {
    int idx = g_wifiScroll + i; int16_t y = LIST_Y0 + i * LIST_ROWH;
    gfx->fillRoundRect(6, y, SB_X - 12, LIST_ROWH - 3, 4, gfx->color565(20, 26, 36));
    gfx->setTextSize(1); gfx->setTextColor(WHITE);
    gfx->setCursor(12, y + 7); gfx->print(g_wifiRows[idx]);
  }
  drawScrollButtons(listBottom - SB_H, g_wifiScroll, g_wifiN, vis);
  // bottom action buttons: AP toggle, Scanner start/stop
  const char *labels[3] = {"AP", "Scan+", "Scan-"};
  for (int i = 0; i < 3; i++) {
    int16_t x = 8 + i * 76;
    gfx->fillRoundRect(x, NC_BTN_Y, 72, 32, 6, colBlue());
    gfx->drawRoundRect(x, NC_BTN_Y, 72, 32, 6, colSky());
    gfx->setTextColor(WHITE); gfx->setTextSize(1);
    gfx->setCursor(x + 12, NC_BTN_Y + 12); gfx->print(labels[i]);
  }
}

// ── On-screen keyboard (WiFi password entry) ──────────────────────────────────
static String g_kbBuf = "";
static bool   g_kbShift = false, g_kbSym = false;
static const char *KB_ABC[3] = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
static const char *KB_SYM[3] = {"1234567890", "@#$_&-+()/", "*\"':;!?%="};
static const int16_t KB_Y0 = 66, KEY_W = 24, KEY_H = 34, KEY_GAP = 2;
static int16_t kbRowY(int r) { return KB_Y0 + r * (KEY_H + KEY_GAP); }
static int16_t kbRowStartX(int len) { return (SCR_W - len * KEY_W) / 2; }
static const int16_t KB_CTRL_Y = KB_Y0 + 3 * (KEY_H + KEY_GAP);

static void drawKeyboard() {
  drawHeader("WIFI PW", false);
  // buffer bar
  gfx->fillRect(0, HEAD_H, SCR_W, KB_Y0 - HEAD_H, gfx->color565(16, 20, 28));
  gfx->setTextSize(1); gfx->setTextColor(colGray());
  gfx->setCursor(8, HEAD_H + 4); gfx->print("pw:");
  gfx->setTextColor(colSky()); gfx->setTextSize(2);
  String shown = g_kbBuf; if (shown.length() > 18) shown = shown.substring(shown.length() - 18);
  gfx->setCursor(30, HEAD_H + 6); gfx->print(shown);
  const char **rows = g_kbSym ? KB_SYM : KB_ABC;
  for (int r = 0; r < 3; r++) {
    int len = strlen(rows[r]); int16_t sx = kbRowStartX(len), y = kbRowY(r);
    for (int c = 0; c < len; c++) {
      char ch = rows[r][c];
      if (!g_kbSym && g_kbShift && ch >= 'a' && ch <= 'z') ch -= 32;
      int16_t x = sx + c * KEY_W;
      gfx->fillRoundRect(x, y, KEY_W - KEY_GAP, KEY_H - KEY_GAP, 4, gfx->color565(30, 38, 52));
      gfx->setTextColor(WHITE); gfx->setTextSize(2);
      gfx->setCursor(x + 6, y + 9); gfx->print(ch);
    }
  }
  // control row: [Shift/abc][space][123/ABC][<-][OK]
  struct { int16_t x, w; const char *l; uint16_t c; } ctl[5] = {
    {2,   44, g_kbSym ? "abc" : (g_kbShift ? "SHFT" : "shft"), colGray()},
    {48,  86, "space", gfx->color565(30,38,52)},
    {136, 40, g_kbSym ? "ABC" : "123", colGray()},
    {178, 26, "<-", colAmber()},
    {206, 32, "OK", colGreen()},
  };
  for (int i = 0; i < 5; i++) {
    gfx->fillRoundRect(ctl[i].x, KB_CTRL_Y, ctl[i].w, KEY_H, 4, ctl[i].c);
    gfx->setTextColor(WHITE); gfx->setTextSize(1);
    gfx->setCursor(ctl[i].x + 6, KB_CTRL_Y + 12); gfx->print(ctl[i].l);
  }
}

// Handle a keyboard tap. Returns true if the tap was consumed.
static bool kbHandleTouch(int16_t px, int16_t py) {
  const char **rows = g_kbSym ? KB_SYM : KB_ABC;
  for (int r = 0; r < 3; r++) {
    int16_t y = kbRowY(r);
    if (py < y || py >= y + KEY_H) continue;
    int len = strlen(rows[r]); int16_t sx = kbRowStartX(len);
    int c = (px - sx) / KEY_W;
    if (c < 0 || c >= len) return true;
    char ch = rows[r][c];
    if (!g_kbSym && g_kbShift && ch >= 'a' && ch <= 'z') ch -= 32;
    if (g_kbBuf.length() < 63) g_kbBuf += ch;
    g_needRedraw = true; return true;
  }
  if (py >= KB_CTRL_Y && py < KB_CTRL_Y + KEY_H) {
    if (px < 46)        { g_kbShift = !g_kbShift; }
    else if (px < 134)  { if (g_kbBuf.length() < 63) g_kbBuf += ' '; }
    else if (px < 176)  { g_kbSym = !g_kbSym; }
    else if (px < 204)  { if (g_kbBuf.length()) g_kbBuf.remove(g_kbBuf.length() - 1); }
    else                { // OK -> connect
#if CYD_TRANSPORT_SERIAL
      if (g_wifiSel >= 0) serialSendConnect(g_wifiSel, g_kbBuf);
#endif
      setStatus("connecting...", colAmber());
      g_kbBuf = ""; g_kbShift = g_kbSym = false;
      g_screen = SCR_NETCONN;
    }
    g_needRedraw = true; return true;
  }
  return true;
}

// ── Alerts: newest Watchtower findings pushed from Ragnar ─────────────────────
static void drawAlerts() {
  drawHeader("ALERTS", false);
  int16_t y = HEAD_H + 10;
  gfx->fillRect(0, y, SCR_W, SCR_H - HEAD_H - 32, colBg());
  gfx->setTextSize(2);
  uint16_t hc = g_rs.alerts ? colRed() : colGreen();
  gfx->setTextColor(hc);
  gfx->setCursor(12, y); gfx->print(String(g_rs.alerts) + " active");
  gfx->setTextColor(colDim()); gfx->setTextSize(1);
  gfx->setCursor(150, y + 4); gfx->print("worst: "); gfx->print(g_rs.worst);
  y += 30;
  const char *titles[3] = { g_rs.alert1, g_rs.alert2, g_rs.alert3 };
  bool any = false;
  for (int i = 0; i < 3; i++) {
    if (!strlen(titles[i])) continue;
    any = true;
    gfx->fillRoundRect(10, y, SCR_W - 20, 40, 6, gfx->color565(30, 22, 26));
    gfx->drawRoundRect(10, y, SCR_W - 20, 40, 6, gfx->color565(90, 50, 55));
    gfx->fillRoundRect(10, y + 4, 4, 32, 2, colRed());
    gfx->setTextColor(WHITE); gfx->setTextSize(1);
    gfx->setCursor(22, y + 15); gfx->print(titles[i]);
    y += 48;
  }
  if (!any) {
    gfx->setTextColor(colDim()); gfx->setTextSize(1);
    gfx->setCursor(12, y + 6); gfx->print("no recent alerts");
  }
  gfx->setTextColor(colDim()); gfx->setTextSize(1);
  gfx->setCursor(12, SCR_H - 40); gfx->print("tap CTRL to clear the Watchtower pane");
}

// ── Settings: device-local, tappable rows + info. Persisted to NVS ────────────
static const char *FW_BUILD = "cyd 0.5 " __DATE__;
static const int16_t SET_Y0 = HEAD_H + 8, SET_ROWH = 28, SET_PITCH = 32;

// Settings rows, built at draw time (Pwnagotchi row only when the bridge exists).
enum { STAG_BLE, STAG_BL, STAG_INV, STAG_FLIP, STAG_WDRV, STAG_UPDATE, STAG_SVC, STAG_PWN, STAG_TOUCH };
static int settingsRows(uint8_t *tags) {
  int n = 0;
  tags[n++] = STAG_BLE;
  tags[n++] = STAG_BL;
  tags[n++] = STAG_INV;
  tags[n++] = STAG_FLIP;
  // Wardriving moved to its own page (NET -> Wardrive) with live status.
  tags[n++] = STAG_UPDATE;
  tags[n++] = STAG_SVC;
  if (strcmp(g_rs.pwn, "off") != 0) tags[n++] = STAG_PWN;
  tags[n++] = STAG_TOUCH;
  return n;
}
static void settingRowText(uint8_t tag, const char *&label, String &val, uint16_t &vcol) {
  vcol = colSky();
  switch (tag) {
    case STAG_BLE:    label = "BLE scan";  val = g_bleEnabled ? "ON" : "OFF"; vcol = g_bleEnabled ? colGreen() : colGray(); break;
    case STAG_BL:     label = "Backlight"; val = String(g_backlightPct) + "%"; break;
    case STAG_INV:    label = "Invert colors"; val = g_invert ? "ON" : "OFF"; vcol = g_invert ? colGreen() : colGray(); break;
    case STAG_FLIP:   label = "Flip 180"; val = g_flip180 ? "ON" : "OFF"; vcol = g_flip180 ? colGreen() : colGray(); break;
    case STAG_WDRV:   label = "Wardriving"; val = String(g_rs.wardrive); vcol = (strcmp(g_rs.wardrive,"off")==0)?colGray():colGreen(); break;
    case STAG_UPDATE: label = "Ragnar update"; val = "run"; vcol = colAmber(); break;
    case STAG_SVC:    label = "Restart svc"; val = "go"; vcol = colAmber(); break;
    case STAG_PWN:    label = "Pwnagotchi"; val = String(g_rs.pwn); break;
    case STAG_TOUCH:  label = "Touch test"; val = "open"; vcol = colAmber(); break;
    default:          label = "?"; val = ""; break;
  }
}
static void drawSettingRow(int16_t y, const char *label, const String &val, uint16_t vcol) {
  gfx->fillRoundRect(10, y, SCR_W - 20, SET_ROWH, 6, gfx->color565(28, 34, 48));
  gfx->drawRoundRect(10, y, SCR_W - 20, SET_ROWH, 6, gfx->color565(50, 60, 78));
  gfx->setTextColor(WHITE); gfx->setTextSize(2);
  gfx->setCursor(18, y + 7); gfx->print(label);
  gfx->setTextColor(vcol); gfx->setTextSize(1);
  int16_t vx = SCR_W - 20 - (int16_t)val.length() * 6 - 8;
  gfx->setCursor(vx, y + 11); gfx->print(val);
}

static void drawSettings() {
  drawHeader("SETTINGS", false);
  uint8_t tags[10]; int n = settingsRows(tags);
  for (int i = 0; i < n; i++) {
    const char *label; String val; uint16_t vcol;
    settingRowText(tags[i], label, val, vcol);
    drawSettingRow(SET_Y0 + i * SET_PITCH, label, val, vcol);
  }
}

// ── Touch test / orientation validator ────────────────────────────────────────
// Hold the board antenna-UP. The banner must read at the TOP (antenna end) — that
// confirms display orientation. Then tap each labelled corner: the dot must land
// under your finger — that confirms touch mapping. If a corner is wrong, note
// which and the TOUCH_INVERT_X/Y / TOUCH_SWAP_XY flags in config.h get set.
static int16_t g_ttX = -1, g_ttY = -1;
static void drawTouchTest() {
  drawHeader("TOUCH TEST", false);
  int16_t top = HEAD_H, bot = SCR_H - 22;
  gfx->fillRect(0, top, SCR_W, bot - top, colBg());
  // TOP banner (antenna end) + corner labels
  gfx->setTextColor(colAmber()); gfx->setTextSize(1);
  gfx->setCursor(60, top + 4); gfx->print("^ TOP - antenna up ^");
  gfx->setTextColor(colDim());
  gfx->setCursor(6, top + 16);            gfx->print("TL");
  gfx->setCursor(SCR_W - 20, top + 16);   gfx->print("TR");
  gfx->setCursor(6, bot - 12);            gfx->print("BL");
  gfx->setCursor(SCR_W - 20, bot - 12);   gfx->print("BR");
  // centre crosshair
  gfx->drawFastHLine(SCR_W/2 - 10, (top+bot)/2, 20, gfx->color565(40,50,64));
  gfx->drawFastVLine(SCR_W/2, (top+bot)/2 - 10, 20, gfx->color565(40,50,64));
  // last tap marker + readout
  if (g_ttX >= 0) {
    gfx->drawCircle(g_ttX, g_ttY, 8, colSky());
    gfx->fillCircle(g_ttX, g_ttY, 3, colRed());
    gfx->setTextColor(WHITE); gfx->setTextSize(1);
    gfx->setCursor(6, (top+bot)/2 + 14);
    gfx->print("x="); gfx->print(g_ttX); gfx->print(" y="); gfx->print(g_ttY);
    gfx->setTextColor(colDim());
    gfx->setCursor(6, (top+bot)/2 + 26);
    gfx->print("raw "); gfx->print(g_lastRawX); gfx->print(","); gfx->print(g_lastRawY);
  } else {
    gfx->setTextColor(colGray()); gfx->setTextSize(1);
    gfx->setCursor(30, (top+bot)/2 + 20); gfx->print("tap the labelled corners");
  }
  gfx->setTextColor(colDim()); gfx->setTextSize(1);
  gfx->setCursor(6, bot + 2); gfx->print("tap < to exit");
}

static void render() {
  // Only wipe the whole panel when the SCREEN changes; a same-screen refresh
  // repaints its own field backgrounds (kv/tiles/etc), so a periodic data update
  // no longer black-flashes the display every few seconds (the "twitch").
  static Screen g_rendered = (Screen)255;
  if (g_screen != g_rendered) { gfx->fillScreen(colBg()); g_rendered = g_screen; }
  switch (g_screen) {
    case SCR_HOME:    drawHome();      break;
    case SCR_DASH:    drawDash();      break;
    case SCR_DEFENSE: drawDefense();   break;
    case SCR_ALERTS:  drawAlerts();    break;
    case SCR_SCAN:    drawScan();      break;
    case SCR_SIGINT:  drawSigInt();    break;
    case SCR_WFALL:   drawWaterfall(); break;
    case SCR_NETWORK: drawNetwork();   break;
    case SCR_NETINT:  drawNetInt();    break;
    case SCR_TRAFFIC: drawTraffic();   break;
    case SCR_MESH:    drawMesh();      break;
    case SCR_NETCONN: drawNetConn();   break;
    case SCR_KEYBOARD:drawKeyboard();  break;
    case SCR_SETTINGS:drawSettings();  break;
    case SCR_CTRL:    drawControls();  break;
    case SCR_TOUCHTEST: drawTouchTest(); break;
    case SCR_ACTION:  drawAction();    break;
    case SCR_WARDRIVE:drawWardrive();  break;
  }
  drawStatusBar();
  g_needRedraw = false;
}

static bool inRect(int16_t px, int16_t py, int16_t x, int16_t y, int16_t w, int16_t h) {
  return px >= x && px < x + w && py >= y && py < y + h;
}

// Reset the waterfall image (band change / (re)open).
static void wfReset() {
  g_wfHave = false; g_wfHead = 0; g_wfErr[0] = 0; g_wfLo = g_wfHi = 0;
}

// Touch: HOME picks a tile; a drill-in screen's header returns HOME; CONTROLS
// buttons enqueue an action; WATERFALL's band bar cycles the band.
static void handleTouch(int16_t px, int16_t py) {
  if (g_screen == SCR_HOME) {
    for (int i = 0; i < N_MENU; i++) {
      int16_t x, y; menuItemXY(i, x, y);
      if (!inRect(px, py, x, y, TILE_W, TILE_H)) continue;
      g_screen = g_menu[i].scr;
      if (g_screen == SCR_WFALL) {
        wfAlloc();                                // ~30KB, freed on exit (see back)
        wfReset();
#if CYD_TRANSPORT_SERIAL
        g_wfActive = true;                        // stream over the cable
#else
        strncpy(g_wfErr, "USB-serial only", sizeof(g_wfErr) - 1);
#endif
      } else if (g_screen == SCR_MESH) {
        g_meshScroll = 0; g_meshActive = true;    // request roster stream
      } else if (g_screen == SCR_NETCONN) {
        g_wifiScroll = 0; g_wifiActive = true;    // request Pi wifi scan stream
      }
      g_needRedraw = true;
      return;
    }
    return;
  }
  // Keyboard: header-left cancels back to Net-Conn; everything else is a key.
  if (g_screen == SCR_KEYBOARD) {
    if (py < HEAD_H && px < 60) { g_screen = SCR_NETCONN; g_needRedraw = true; return; }
    kbHandleTouch(px, py);
    return;
  }
  // Back: enlarged hit zone everywhere except WFALL, whose band bar sits right
  // under the header (there, back stays header-only so band-cycling is usable).
  bool back = (g_screen == SCR_WFALL) ? (py < HEAD_H) : inBackZone(px, py);
  if (back) {
    if (g_screen == SCR_WFALL) { g_wfActive = false; wfFree(); }  // reclaim ~30KB
    g_meshActive = false; g_wifiActive = false;   // stop roster/wifi streams
    // The Action subpage returns to wherever it was launched from.
    g_screen = (g_screen == SCR_ACTION) ? g_actReturn : SCR_HOME;
    g_needRedraw = true; return;
  }
  if (g_screen == SCR_SETTINGS) {
    uint8_t tags[10]; int n = settingsRows(tags);
    for (int i = 0; i < n; i++) {
      int16_t ry = SET_Y0 + i * SET_PITCH;
      if (!inRect(px, py, 10, ry, SCR_W - 20, SET_ROWH)) continue;
      switch (tags[i]) {
        case STAG_BLE: g_bleEnabled = !g_bleEnabled; saveSettings(); break;
        case STAG_BL:  g_backlightPct = g_backlightPct > 66 ? 66 : (g_backlightPct > 33 ? 33 : 100);
                       applyBacklight(); saveSettings(); break;
        case STAG_INV: g_invert = !g_invert; applyDisplayOpts(); saveSettings(); break;
        case STAG_FLIP: g_flip180 = !g_flip180; applyDisplayOpts(); saveSettings();
                        gfx->fillScreen(colBg()); break;
        case STAG_WDRV:   requestAction("wardrive_toggle", "Wardriving"); return;
        case STAG_UPDATE: requestAction("ragnar_update", "Ragnar update"); return;
        case STAG_SVC:    requestAction("service_restart", "Restart service"); return;
        case STAG_PWN:    requestAction("pwn_swap", "Pwnagotchi swap"); return;
        case STAG_TOUCH:  g_ttX = g_ttY = -1; g_screen = SCR_TOUCHTEST; break;
      }
      g_needRedraw = true;
      return;
    }
    return;
  }
  if (g_screen == SCR_TOUCHTEST) {
    g_ttX = px; g_ttY = py; g_needRedraw = true;            // mark the tap
    // Diagnostic line for host-side calibration (ignored by the JSON bridge).
    Serial.print("TT raw="); Serial.print(g_lastRawX); Serial.print(",");
    Serial.print(g_lastRawY); Serial.print(" map="); Serial.print(px);
    Serial.print(","); Serial.println(py);
    return;
  }
  if (g_screen == SCR_WFALL) {
    // Tap the band bar (top strip) to cycle to the next band.
    if (py >= HEAD_H && py < HEAD_H + 20) {
      g_wfBandIdx = (g_wfBandIdx + 1) % WF_NBANDS;
      wfReset();
      g_needRedraw = true;
    }
    return;
  }
  if (g_screen == SCR_CTRL) {
    int16_t y = CTRL_Y0;
    for (int i = 0; i < N_CTRL; i++) {
      if (inRect(px, py, 10, y, SCR_W - 20, BTN_BH)) {
        requestAction(g_ctrlActions[i].action, g_ctrlActions[i].label); return;
      }
      y += BTN_BH + BTN_GAP;
    }
    return;
  }
  if (g_screen == SCR_TRAFFIC) {
    if (!g_tfPending && inRect(px, py, 10, TRAF_BTN_Y, SCR_W - 20, 44)) {
      g_tfTarget = !g_rs.tfRun;                 // capture state we expect to reach
      if (actionEnqueue("traffic_toggle")) {
        g_tfPending = true; g_tfPendMs = millis();
        setStatus(g_tfTarget ? "starting capture" : "stopping", colAmber());
      } else setStatus("queue full", colRed());
      g_needRedraw = true;
    }
    return;
  }
  if (g_screen == SCR_WARDRIVE) {
    // Start/Stop toggles in place; status updates live from the feed (no nav away).
    // Ignore taps while one is already in flight (the button is greyed/pending).
    if (g_rs.wdEnabled && !g_wdPending && inRect(px, py, 10, WD_BTN_Y, SCR_W - 20, 44)) {
      const char *a = g_rs.wdRun ? "wardrive_stop" : "wardrive_start";
      g_wdTarget = !g_rs.wdRun;               // run-state we expect to reach
      g_wdPending = true; g_wdPendMs = millis();
#if CYD_TRANSPORT_SERIAL
      serialSendAction(String(a));   // send now — don't wait for the sync window
#else
      actionEnqueue(a);
#endif
      setStatus(g_wdTarget ? "starting..." : "stopping...", colAmber());
      g_needRedraw = true;                    // repaint into the processing state
    }
    return;
  }
  if (g_screen == SCR_MESH) {
    int vis = listVisible(SCR_H - 22);
    if (inRect(px, py, SB_X, LIST_Y0, SB_W, SB_H)) { if (g_meshScroll > 0) g_meshScroll--; g_needRedraw = true; }
    else if (inRect(px, py, SB_X, SCR_H - 22 - SB_H, SB_W, SB_H)) { if (g_meshScroll + vis < g_meshN) g_meshScroll++; g_needRedraw = true; }
    return;
  }
  if (g_screen == SCR_NETCONN) {
    int16_t listBottom = NC_BTN_Y - 4;
    int vis = (listBottom - LIST_Y0) / LIST_ROWH;
    if (inRect(px, py, SB_X, LIST_Y0, SB_W, SB_H)) { if (g_wifiScroll > 0) g_wifiScroll--; g_needRedraw = true; return; }
    if (inRect(px, py, SB_X, listBottom - SB_H, SB_W, SB_H)) { if (g_wifiScroll + vis < g_wifiN) g_wifiScroll++; g_needRedraw = true; return; }
    // bottom action buttons: AP / Scan+ / Scan-
    if (py >= NC_BTN_Y && py < NC_BTN_Y + 32) {
      int b = -1; for (int i = 0; i < 3; i++) if (px >= 8 + i * 76 && px < 8 + i * 76 + 72) b = i;
      const char *acts[3]   = {"ap_toggle", "scanner_start", "scanner_stop"};
      const char *labels[3] = {"AP mode", "Scanner on", "Scanner off"};
      if (b >= 0) requestAction(acts[b], labels[b]);
      return;
    }
    // tap a WiFi row -> pick it and open the password keyboard
    for (int i = 0; i < vis && g_wifiScroll + i < g_wifiN; i++) {
      int16_t y = LIST_Y0 + i * LIST_ROWH;
      if (inRect(px, py, 6, y, SB_X - 12, LIST_ROWH - 3)) {
        g_wifiSel = g_wifiScroll + i;
        g_kbBuf = ""; g_kbShift = g_kbSym = false;
        g_screen = SCR_KEYBOARD; g_needRedraw = true;
        return;
      }
    }
    return;
  }
  if (g_screen == SCR_NETWORK) {
    for (int i = 0; i < N_NET; i++) {
      int16_t x, gy; gridBtnXY(i, NET_GRID_Y0, x, gy);
      if (!inRect(px, py, x, gy, GBTN_W, GBTN_H)) continue;
      if (g_netItems[i].nav) { g_screen = (Screen)g_netItems[i].scr; g_needRedraw = true; }
      else requestAction(g_netItems[i].action, g_netItems[i].label);
      return;
    }
    return;
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  Setup portal — SoftAP + captive form to provision WiFi / URL / token / name
//  (WiFi transport only; the serial build is cabled and needs no provisioning)
// ════════════════════════════════════════════════════════════════════════════
#if !CYD_TRANSPORT_SERIAL
static WebServer g_portalServer(80);
static DNSServer g_portalDNS;

static String htmlAttr(const String &s) {
  String o; o.reserve(s.length() + 8);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;";
    else if (c == '>') o += "&gt;"; else if (c == '"') o += "&quot;";
    else o += c;
  }
  return o;
}

static String portalPage() {
  String p =
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Ragnar CYD setup</title><style>"
    "body{font-family:system-ui,sans-serif;background:#0f172a;color:#e5e7eb;margin:0;padding:20px}"
    ".c{max-width:440px;margin:0 auto}h1{font-size:20px}label{display:block;margin:12px 0 4px;font-size:14px;color:#94a3b8}"
    "input{width:100%;box-sizing:border-box;background:#1e293b;border:1px solid #334155;color:#e5e7eb;border-radius:8px;padding:10px;font-size:15px}"
    "button{margin-top:18px;width:100%;background:#0284c7;color:#fff;border:0;border-radius:8px;padding:12px;font-size:16px}"
    "p{color:#94a3b8;font-size:13px}</style></head><body><div class='c'>"
    "<h1>Ragnar CYD node setup</h1>"
    "<p>Join this node to your WiFi and point it at your Ragnar. The device token comes from Ragnar → Config → CYD Nodes.</p>"
    "<form method='POST' action='/save'>"
    "<label>WiFi SSID (2.4 GHz)</label><input name='ssid' value='" + htmlAttr(g_cfg.ssid) + "'>"
    "<label>WiFi password</label><input name='pass' type='password' value='" + htmlAttr(g_cfg.pass) + "'>"
    "<label>Ragnar URL</label><input name='url' placeholder='http://192.168.1.50:8080' value='" + htmlAttr(g_cfg.url) + "'>"
    "<label>Device token</label><input name='token' value='" + htmlAttr(g_cfg.token) + "'>"
    "<label>Node name</label><input name='name' value='" + htmlAttr(g_cfg.name) + "'>"
    "<button type='submit'>Save &amp; reboot</button></form></div></body></html>";
  return p;
}

static void handlePortalRoot() { g_portalServer.send(200, "text/html", portalPage()); }

static void handlePortalSave() {
  RuntimeConfig c;
  c.ssid  = g_portalServer.arg("ssid");
  c.pass  = g_portalServer.arg("pass");
  c.url   = g_portalServer.arg("url");
  c.token = g_portalServer.arg("token");
  c.name  = g_portalServer.arg("name");
  // Trim a trailing slash on the URL so our path concatenation stays correct.
  while (c.url.endsWith("/")) c.url.remove(c.url.length() - 1);
  saveConfig(c);
  g_portalServer.send(200, "text/html",
    "<html><body style='font-family:system-ui,sans-serif;background:#0f172a;color:#e5e7eb;padding:24px'>"
    "<h2>Saved. Rebooting…</h2></body></html>");
  delay(800);
  ESP.restart();
}

static void drawPortalScreen(const String &ip) {
  gfx->fillScreen(gfx->color565(10, 12, 16));
  gfx->setTextColor(gfx->color565(90, 180, 255));
  gfx->setTextSize(2);
  gfx->setCursor(10, 16); gfx->print("SETUP MODE");
  gfx->setTextSize(1);
  gfx->setTextColor(gfx->color565(150, 160, 170));
  int16_t y = 60;
  gfx->setCursor(10, y); gfx->print("1) Join WiFi:"); y += 16;
  gfx->setTextColor(WHITE); gfx->setTextSize(2);
  gfx->setCursor(16, y); gfx->print(CYD_SETUP_AP_SSID); y += 26;
  gfx->setTextSize(1); gfx->setTextColor(gfx->color565(150, 160, 170));
  gfx->setCursor(16, y); gfx->print("pass: "); gfx->print(CYD_SETUP_AP_PASS); y += 26;
  gfx->setCursor(10, y); gfx->print("2) Open in a browser:"); y += 16;
  gfx->setTextColor(WHITE); gfx->setTextSize(2);
  gfx->setCursor(16, y); gfx->print("http://"); gfx->print(ip); y += 30;
  gfx->setTextSize(1); gfx->setTextColor(gfx->color565(120, 130, 140));
  gfx->setCursor(10, y); gfx->print("Fill WiFi + Ragnar URL + token,");  y += 14;
  gfx->setCursor(10, y); gfx->print("save, and the node reboots.");
}

// Raise the SoftAP + captive portal and serve requests until a save reboots us.
static void runConfigPortal() {
  WiFi.mode(WIFI_AP);
  const char *pw = strlen(CYD_SETUP_AP_PASS) >= 8 ? CYD_SETUP_AP_PASS : nullptr;
  WiFi.softAP(CYD_SETUP_AP_SSID, pw);
  IPAddress ip = WiFi.softAPIP();
  g_portalDNS.start(53, "*", ip);
  g_portalServer.on("/", handlePortalRoot);
  g_portalServer.on("/save", HTTP_POST, handlePortalSave);
  g_portalServer.onNotFound(handlePortalRoot);   // captive: any URL -> the form
  g_portalServer.begin();
  setStatus("setup portal", gfx->color565(230, 170, 50));
  drawPortalScreen(ip.toString());
  for (;;) {
    g_portalDNS.processNextRequest();
    g_portalServer.handleClient();
    delay(5);
  }
}
#endif // !CYD_TRANSPORT_SERIAL

// ════════════════════════════════════════════════════════════════════════════
//  Lifecycle
// ════════════════════════════════════════════════════════════════════════════
void setup() {
  // Enlarge the UART RX buffer BEFORE begin(). The default is 256 B, which the
  // direct GPIO UART (no flow control) can overflow during a long render() or
  // radio window when we're not draining — lost bytes = corrupt frames = a screen
  // that never updates. Over USB the CH340 hides this; on the P1 header it bites.
  Serial.setRxBufferSize(4096);
  Serial.begin(CYD_SERIAL_BAUD);

  pinMode(PIN_LED_R, OUTPUT); pinMode(PIN_LED_G, OUTPUT); pinMode(PIN_LED_B, OUTPUT);
  digitalWrite(PIN_LED_R, HIGH); digitalWrite(PIN_LED_G, HIGH); digitalWrite(PIN_LED_B, HIGH); // off (active LOW)

  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, HIGH);

  gfx->begin();
  gfx->fillScreen(BLACK);

  // Touch bus + CS/IRQ
  pinMode(TOUCH_CS, OUTPUT); digitalWrite(TOUCH_CS, HIGH);
  pinMode(TOUCH_IRQ, INPUT);
  touchSPI.begin(TOUCH_SCLK, TOUCH_MISO, TOUCH_MOSI, TOUCH_CS);

  loadConfig();   // node name (+ optional WiFi seeds) + BLE/backlight settings
  applyBacklight();
  applyDisplayOpts();   // orientation + colour inversion (persisted)

  // Boot splash. Over serial it plays the full 15 s clip and LOOPS until the Pi's
  // Ragnar service is up (first status frame), so a co-booting Pi gets covered; if
  // the Pi is already up it stops after the 5 s minimum. Over WiFi there's no
  // readiness signal yet, so it's a fixed 5 s splash (min==max).
#if CYD_TRANSPORT_SERIAL
  playBootAnimation(CYD_BOOT_ANIM_MS, CYD_BOOT_ANIM_MAX_MS);
#else
  playBootAnimation(CYD_BOOT_ANIM_MS, CYD_BOOT_ANIM_MS);
#endif
  gfx->fillScreen(BLACK);
#if CYD_TRANSPORT_SERIAL
  Serial.setTimeout(20);   // cabled to the Pi; cyd_serial_bridge.py is the link
#else
  // WiFi transport: enter the setup portal if unconfigured or if BOOT is held.
  pinMode(PIN_BOOT_BUTTON, INPUT_PULLUP);
  bool forcePortal = (digitalRead(PIN_BOOT_BUTTON) == LOW);
  if (forcePortal || !haveConfig()) {
    runConfigPortal();   // never returns — reboots on save
  }
#endif

  setStatus("init BLE/WiFi", WHITE);
  render();

#if CYD_ENABLE_BLE
  BLEDevice::init("");
  g_bleReady = true;
#endif

  WiFi.mode(WIFI_STA);   // start the radio so promiscuous works later
  setStatus("ready", gfx->color565(70,200,120));
  g_needRedraw = true;
}

// One UI service step: drain serial, read touch, render if dirty. Called from
// every wait loop (sync, sniff dwell, BLE wait) so touch/display never stall.
static void serviceUI() {
#if CYD_TRANSPORT_SERIAL
  serialDrain();   // keep the display current with the Pi's status pushes
#endif
  // Safety net: if the Start/Stop confirmation never arrives (action failed, or no
  // status push), drop the "processing" latch so the button can't get stuck greyed.
  if (g_wdPending && millis() - g_wdPendMs > WD_PEND_TIMEOUT_MS) {
    g_wdPending = false; g_needRedraw = true;
  }
  // Keep the Action page's spinner + countdown ticking while work is in flight.
  if (g_screen == SCR_ACTION && g_actAnimate) {
    static uint32_t lastSpin = 0;
    if (millis() - lastSpin > 130) { lastSpin = millis(); g_needRedraw = true; }
  }
  // Traffic capture is slow to start; time out the pending latch and tick its
  // button (spinner + elapsed) in place so it doesn't flicker the whole page.
  if (g_tfPending && millis() - g_tfPendMs > TF_PEND_TIMEOUT_MS) {
    g_tfPending = false; g_needRedraw = true;
  }
  if (g_screen == SCR_TRAFFIC && g_tfPending) {
    static uint32_t lastTf = 0;
    if (millis() - lastTf > 140) { lastTf = millis(); drawTrafficButton(); }
  }
  static uint32_t lastTap = 0;
  int16_t px, py;
  if (touchRead(px, py) && millis() - lastTap > 250) {
    lastTap = millis();
    handleTouch(px, py);
  }
  if (g_needRedraw) {
    render();
#if CYD_TRANSPORT_SERIAL
    serialDrain();   // render() can take 50-100ms of SPI; drain the bytes that
                     // piled up during it so the UART RX buffer doesn't overflow
#endif
  }
}

// Service the UI for `ms` (touch stays responsive across long radio phases).
static void pollTouchFor(uint32_t ms) {
  uint32_t start = millis();
  while (millis() - start < ms) { serviceUI(); delay(12); }
}

void loop() {
  // ── 0) WATERFALL MODE ───────────────────────────────────────────────────────
  // While the Waterfall screen is open, dedicate the loop to streaming spectrum
  // (skip the sniff/BLE windows) so it stays live. Tell Ragnar to stop the SDR
  // when the screen closes.
  static bool wasWf = false, wasMesh = false, wasWifi = false;
#if CYD_TRANSPORT_SERIAL
  if (g_wfActive) {
    serialSendWfReq(true);
    wasWf = true;
    pollTouchFor(1500);                  // drains wf frames, renders, handles touch
    return;
  }
  if (wasWf) { serialSendWfReq(false); wasWf = false; }
  // Mesh roster / WiFi list streams: request while their screen (or the keyboard
  // launched from Net-Conn) is open, and dedicate the loop to draining them.
  if (g_meshActive || g_wifiActive) {
    if (g_meshActive) { serialSendMeshReq(true); wasMesh = true; }
    if (g_wifiActive) { serialSendWifiReq(true); wasWifi = true; }
    pollTouchFor(1500);
    return;
  }
  if (wasMesh) { serialSendMeshReq(false); wasMesh = false; }
  if (wasWifi) { serialSendWifiReq(false); wasWifi = false; }
#endif

  // The LED is a STEADY link indicator, not a per-phase blinker (the old
  // per-phase toggling was the "LED twitch"). Solid blue = linked/running.
  digitalWrite(PIN_LED_R, HIGH); digitalWrite(PIN_LED_G, HIGH);
  digitalWrite(PIN_LED_B, LOW);

  // ── 1) SYNC WITH RAGNAR ─────────────────────────────────────────────────────
#if CYD_TRANSPORT_SERIAL
  // Cabled transport: push counts, flush queued actions, read pushed status.
  serialSendIngest();
  { String a; while (actionDequeue(a)) serialSendAction(a); }
  serialDrain();
  setStatus("usb-serial", colGreen());   // only redraws if the text changed
  pollTouchFor(CYD_SYNC_WINDOW_MS);       // responsive; renders only on change
#else
  setStatus("connecting wifi", colAmber());
  serviceUI();
  if (wifiConnect()) {
    httpPostIngest();
    httpGetStatus();
    String a;
    while (actionDequeue(a)) httpPostAction(a);
    setStatus(g_rs.ok ? "online" : "sync failed", g_rs.ok ? colGreen() : colRed());
    pollTouchFor(CYD_SYNC_WINDOW_MS);
  } else {
    setStatus("wifi unavailable", colRed());
    g_rs.ok = false;
    pollTouchFor(CYD_SYNC_WINDOW_MS);
  }
#endif

  // ── 2) WiFi promiscuous sweep — cooperative (services UI throughout) ─────────
  sniffWindow(CYD_SNIFF_WINDOW_MS);

  // ── 3) BLE advert scan — async; service UI while it runs (never blocks touch)─
#if CYD_ENABLE_BLE
  if (CYD_BLE_WINDOW_MS > 0) {
    bleStart(CYD_BLE_WINDOW_MS);
    uint32_t t0 = millis();
    while (g_bleBusy && millis() - t0 < (uint32_t)CYD_BLE_WINDOW_MS + 1500) {
      serviceUI(); delay(12);
    }
  }
#endif

  // Refresh the sensor-driven screens (SCAN/DEFEND/HOME) once per cycle, and only
  // when the counts actually changed — a real data update (~every sniff cycle),
  // not the every-2s status-push twitch.
  static uint32_t lastSensorSig = 0xFFFFFFFFu;
  uint32_t ss = (uint32_t)g_sc.beacons + ((uint32_t)g_sc.bssids << 9)
              + ((uint32_t)g_sc.deauths << 16) + ((uint32_t)g_sc.probes << 20)
              + ((uint32_t)g_sc.bleAdv << 25);
  if (ss != lastSensorSig) { lastSensorSig = ss; g_needRedraw = true; serviceUI(); }
}
