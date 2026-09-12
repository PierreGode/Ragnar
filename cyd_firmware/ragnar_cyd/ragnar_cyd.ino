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
 * See cyd_firmware/README.md for flashing and Ragnar-side setup.
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

#include "config.h"

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
static void loadConfig() {
  g_prefs.begin("ragnarcyd", true);
  g_cfg.ssid  = g_prefs.getString("ssid",  CYD_WIFI_SSID);
  g_cfg.pass  = g_prefs.getString("pass",  CYD_WIFI_PASS);
  g_cfg.url   = g_prefs.getString("url",   CYD_RAGNAR_URL);
  g_cfg.token = g_prefs.getString("token", CYD_DEVICE_TOKEN);
  g_cfg.name  = g_prefs.getString("name",  CYD_NODE_NAME);
  g_prefs.end();
  if (g_cfg.name.length() == 0) g_cfg.name = "cyd-node";
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

static const int16_t SCR_W = 240;
static const int16_t SCR_H = 320;

// ── Touch (XPT2046 on its own SPI bus) ────────────────────────────────────────
static SPIClass touchSPI(HSPI);

// ── UI state ──────────────────────────────────────────────────────────────────
enum Page { PAGE_STATUS = 0, PAGE_SCAN = 1, PAGE_ACTIONS = 2 };
static Page   g_page       = PAGE_STATUS;
static bool   g_needRedraw = true;

// ── Live model: last status synced from Ragnar ────────────────────────────────
struct RagnarStatus {
  bool     ok        = false;
  int      meshNodes = 0;
  int      nets24    = 0;
  int      nets5     = 0;
  int      threat    = 0;      // 0..100 threat score
  char     btState[16]      = "?";
  char     unitName[24]     = "ragnar";
  uint32_t uptimeSec        = 0;
  uint32_t lastSyncMs       = 0;
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

// Small unique-BSSID set (RAM-bounded).
#define MAX_BSSID 96
static uint8_t  g_bssidSet[MAX_BSSID][6];
static uint32_t g_bssidCount = 0;

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
static void setStatus(const char *s, uint16_t c) {
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
  // Map raw ADC -> pixels (rotation 0, portrait). Clamp to screen.
  long mx = map(rawx, TOUCH_RAW_MINX, TOUCH_RAW_MAXX, 0, SCR_W - 1);
  long my = map(rawy, TOUCH_RAW_MINY, TOUCH_RAW_MAXY, 0, SCR_H - 1);
  px = (int16_t)constrain(mx, 0, SCR_W - 1);
  py = (int16_t)constrain(my, 0, SCR_H - 1);
  return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  WiFi promiscuous sniffer
// ════════════════════════════════════════════════════════════════════════════
static void bssidSeen(const uint8_t *mac) {
  for (uint32_t i = 0; i < g_bssidCount; i++)
    if (memcmp(g_bssidSet[i], mac, 6) == 0) return;
  if (g_bssidCount < MAX_BSSID) {
    memcpy(g_bssidSet[g_bssidCount], mac, 6);
    g_bssidCount++;
  }
}

static void IRAM_ATTR snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = pkt->payload;
  g_sc.frames++;
  uint8_t subtype = (p[0] & 0xF0) >> 4;   // frame-control subtype
  switch (subtype) {
    case 0x08: g_sc.beacons++; bssidSeen(&p[16]); break;  // beacon (BSSID @ addr3)
    case 0x04: g_sc.probes++;  break;                     // probe request
    case 0x0C: g_sc.deauths++; break;                     // deauth
    case 0x0A: g_sc.deauths++; break;                     // disassoc (count as deauth)
    default: break;
  }
}

static void sniffReset() {
  g_sc.beacons = g_sc.probes = g_sc.deauths = g_sc.frames = 0;
  g_bssidCount = 0;
}

static void sniffWindow(uint32_t durationMs) {
  sniffReset();
  WiFi.disconnect(true, false);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  const uint8_t channels[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
  const int nch = sizeof(channels);
  uint32_t start = millis();
  int idx = 0;
  while (millis() - start < durationMs) {
    esp_wifi_set_channel(channels[idx % nch], WIFI_SECOND_CHAN_NONE);
    idx++;
    delay(durationMs / (nch + 1) > 60 ? 60 : durationMs / (nch + 1));
  }
  esp_wifi_set_promiscuous(false);
  g_sc.bssids = g_bssidCount;
}

// ════════════════════════════════════════════════════════════════════════════
//  BLE advertisement scan
// ════════════════════════════════════════════════════════════════════════════
#if CYD_ENABLE_BLE
static bool g_bleReady = false;
static void bleWindow(uint32_t durationMs) {
  if (!g_bleReady) return;
  BLEScan *scan = BLEDevice::getScan();
  scan->setActiveScan(false);       // passive: just count adverts
  scan->setInterval(100);
  scan->setWindow(99);
  BLEScanResults *res = scan->start((int)(durationMs / 1000), false);
  g_sc.bleAdv = res ? res->getCount() : 0;
  scan->clearResults();
}
#else
static void bleWindow(uint32_t) { g_sc.bleAdv = 0; }
#endif

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
  String bt = jsonStr(body, "bluetooth");
  String un = jsonStr(body, "unit");
  if (bt.length()) { strncpy(g_rs.btState, bt.c_str(), sizeof(g_rs.btState) - 1); g_rs.btState[sizeof(g_rs.btState)-1]=0; }
  if (un.length()) { strncpy(g_rs.unitName, un.c_str(), sizeof(g_rs.unitName) - 1); g_rs.unitName[sizeof(g_rs.unitName)-1]=0; }
  g_rs.ok = true;
  g_rs.lastSyncMs = millis();
  g_needRedraw = true;
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
    + "\"rssi\":"    + String(WiFi.RSSI()) + "}";
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
  if (line.indexOf("\"st\"") < 0) return;   // only status frames are inbound
  applyStatus(line);
}

// Drain any pending inbound bytes and apply complete lines (non-blocking).
static void serialDrain() {
  static String buf;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') { if (buf.length()) handleSerialLine(buf); buf = ""; }
    else if (c != '\r' && buf.length() < 512) buf += c;
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
static const int16_t TAB_H = 34;

static void drawTabs() {
  const char *labels[3] = {"STATUS", "SCAN", "ACT"};
  int16_t w = SCR_W / 3;
  for (int i = 0; i < 3; i++) {
    uint16_t bg = (i == (int)g_page) ? gfx->color565(30, 90, 160) : gfx->color565(20, 24, 30);
    gfx->fillRect(i * w, 0, w, TAB_H, bg);
    gfx->drawRect(i * w, 0, w, TAB_H, gfx->color565(60, 70, 80));
    gfx->setTextColor(WHITE);
    gfx->setTextSize(2);
    gfx->setCursor(i * w + 8, 9);
    gfx->print(labels[i]);
  }
}

static void drawStatusBar() {
  gfx->fillRect(0, SCR_H - 22, SCR_W, 22, gfx->color565(16, 18, 22));
  gfx->setTextSize(1);
  gfx->setTextColor(g_statusColor);
  gfx->setCursor(6, SCR_H - 15);
  gfx->print(g_statusLine);
}

static void kv(int16_t y, const char *k, const String &v, uint16_t vc) {
  gfx->setTextSize(1);
  gfx->setTextColor(gfx->color565(150, 160, 170));
  gfx->setCursor(10, y);
  gfx->print(k);
  gfx->setTextColor(vc);
  gfx->setTextSize(2);
  gfx->setCursor(10, y + 10);
  gfx->print(v);
}

static uint16_t threatColor(int t) {
  if (t >= 66) return gfx->color565(220, 60, 60);
  if (t >= 33) return gfx->color565(230, 170, 50);
  return gfx->color565(70, 200, 120);
}

static void drawStatusPage() {
  int16_t y = TAB_H + 10;
  gfx->setTextColor(gfx->color565(90, 180, 255));
  gfx->setTextSize(2);
  gfx->setCursor(10, y); gfx->print(g_rs.unitName);
  y += 30;
  kv(y, "MESH NODES", String(g_rs.meshNodes), WHITE); y += 40;
  kv(y, "NETWORKS 2.4G", String(g_rs.nets24), WHITE); y += 40;
  kv(y, "NETWORKS 5G", String(g_rs.nets5), gfx->color565(120,130,140)); y += 40;
  kv(y, "BLUETOOTH", String(g_rs.btState), WHITE); y += 40;
  kv(y, "THREAT", String(g_rs.threat) + " / 100", threatColor(g_rs.threat)); y += 40;
  uint32_t since = g_rs.lastSyncMs ? (millis() - g_rs.lastSyncMs) / 1000 : 0;
  kv(y, "LAST SYNC", String(since) + "s ago", g_rs.ok ? gfx->color565(70,200,120) : gfx->color565(220,60,60));
}

static void drawScanPage() {
  int16_t y = TAB_H + 10;
  gfx->setTextColor(gfx->color565(90, 180, 255));
  gfx->setTextSize(2);
  gfx->setCursor(10, y); gfx->print("LOCAL 2.4 GHz");
  y += 30;
  kv(y, "BEACONS", String((uint32_t)g_sc.beacons), WHITE); y += 40;
  kv(y, "UNIQUE APs", String(g_sc.bssids), WHITE); y += 40;
  kv(y, "PROBE REQ", String((uint32_t)g_sc.probes), WHITE); y += 40;
  kv(y, "DEAUTH/DISASSOC", String((uint32_t)g_sc.deauths),
     g_sc.deauths > 0 ? gfx->color565(220,60,60) : WHITE); y += 40;
  kv(y, "BLE ADVERTS", String(g_sc.bleAdv), WHITE); y += 40;
  kv(y, "FRAMES SEEN", String((uint32_t)g_sc.frames), gfx->color565(120,130,140));
}

struct ActionBtn { const char *label; const char *action; };
static const ActionBtn g_actions[] = {
  {"WiFi Defense scan", "wifi_defense_scan"},
  {"BLE scan",          "ble_scan"},
  {"Watchtower clear",  "watchtower_clear"},
};
static const int N_ACTIONS = sizeof(g_actions) / sizeof(g_actions[0]);

static void drawActionsPage() {
  int16_t y = TAB_H + 14;
  gfx->setTextColor(gfx->color565(90, 180, 255));
  gfx->setTextSize(2);
  gfx->setCursor(10, y); gfx->print("TRIGGER");
  y += 30;
  for (int i = 0; i < N_ACTIONS; i++) {
    gfx->fillRoundRect(10, y, SCR_W - 20, 44, 6, gfx->color565(30, 90, 160));
    gfx->drawRoundRect(10, y, SCR_W - 20, 44, 6, gfx->color565(70, 130, 200));
    gfx->setTextColor(WHITE);
    gfx->setTextSize(2);
    gfx->setCursor(22, y + 14);
    gfx->print(g_actions[i].label);
    y += 54;
  }
}

static void render() {
  gfx->fillScreen(gfx->color565(10, 12, 16));
  drawTabs();
  switch (g_page) {
    case PAGE_STATUS:  drawStatusPage();  break;
    case PAGE_SCAN:    drawScanPage();    break;
    case PAGE_ACTIONS: drawActionsPage(); break;
  }
  drawStatusBar();
  g_needRedraw = false;
}

// Handle a touch at (px,py): tab switching + action buttons.
static void handleTouch(int16_t px, int16_t py) {
  if (py < TAB_H) {
    Page np = (Page)(px / (SCR_W / 3));
    if (np != g_page) { g_page = np; g_needRedraw = true; }
    return;
  }
  if (g_page == PAGE_ACTIONS) {
    int16_t y = TAB_H + 14 + 30;
    for (int i = 0; i < N_ACTIONS; i++) {
      if (py >= y && py < y + 44 && px >= 10 && px <= SCR_W - 10) {
        if (actionEnqueue(g_actions[i].action)) {
          setStatus((String("queued: ") + g_actions[i].label).c_str(), gfx->color565(230,170,50));
        } else {
          setStatus("action queue full", gfx->color565(220,60,60));
        }
        return;
      }
      y += 54;
    }
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

  loadConfig();   // node name (+ optional WiFi seeds)
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

// Poll touch between long radio phases so the UI stays responsive.
static void pollTouchFor(uint32_t ms) {
  uint32_t start = millis();
  static uint32_t lastTap = 0;
  while (millis() - start < ms) {
#if CYD_TRANSPORT_SERIAL
    serialDrain();   // keep the display current with the Pi's status pushes
#endif
    int16_t px, py;
    if (touchRead(px, py) && millis() - lastTap > 250) {
      lastTap = millis();
      handleTouch(px, py);
    }
    if (g_needRedraw) render();
    delay(20);
  }
}

void loop() {
  // ── 1) SYNC WITH RAGNAR ─────────────────────────────────────────────────────
#if CYD_TRANSPORT_SERIAL
  // Cabled transport: push our counts, flush queued actions, and read whatever
  // status the Pi has sent. serialDrain() also runs inside pollTouchFor so the
  // display keeps up with the Pi's ~2 s status pushes.
  digitalWrite(PIN_LED_B, LOW);          // blue = linked
  serialSendIngest();
  { String a; while (actionDequeue(a)) serialSendAction(a); }
  serialDrain();
  setStatus("usb-serial", gfx->color565(70,200,120));
  digitalWrite(PIN_LED_B, HIGH);
  g_needRedraw = true;
  render();
  pollTouchFor(CYD_SYNC_WINDOW_MS);
#else
  setStatus("connecting wifi", gfx->color565(230,170,50));
  if (g_needRedraw) render();
  if (wifiConnect()) {
    digitalWrite(PIN_LED_B, LOW);   // blue = online
    setStatus("syncing", gfx->color565(90,180,255));
    if (g_needRedraw) render();

    httpPostIngest();               // push last window's counts
    httpGetStatus();                // pull fresh status

    String a;                       // flush any queued operator actions
    while (actionDequeue(a)) httpPostAction(a);

    setStatus(g_rs.ok ? "online" : "sync failed",
              g_rs.ok ? gfx->color565(70,200,120) : gfx->color565(220,60,60));
    digitalWrite(PIN_LED_B, HIGH);
    g_needRedraw = true;
    render();
    pollTouchFor(CYD_SYNC_WINDOW_MS);
  } else {
    setStatus("wifi unavailable", gfx->color565(220,60,60));
    g_rs.ok = false;
    render();
    pollTouchFor(CYD_SYNC_WINDOW_MS);
  }
#endif

  // ── 2) WiFi promiscuous sweep (disconnected) ────────────────────────────────
  setStatus("sniffing 2.4G", gfx->color565(200,120,255));
  render();
  digitalWrite(PIN_LED_G, LOW);     // green = sensing
  sniffWindow(CYD_SNIFF_WINDOW_MS);
  digitalWrite(PIN_LED_G, HIGH);
  g_needRedraw = true;
  render();
  pollTouchFor(400);

  // ── 3) BLE advert scan (disconnected) ───────────────────────────────────────
#if CYD_ENABLE_BLE
  if (CYD_BLE_WINDOW_MS > 0) {
    setStatus("scanning BLE", gfx->color565(200,120,255));
    render();
    digitalWrite(PIN_LED_G, LOW);
    bleWindow(CYD_BLE_WINDOW_MS);
    digitalWrite(PIN_LED_G, HIGH);
    g_needRedraw = true;
    render();
    pollTouchFor(400);
  }
#endif
}
