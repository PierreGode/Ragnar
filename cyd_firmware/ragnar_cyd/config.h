/*
 * config.h — Ragnar CYD hybrid node: board pin-map + operator settings.
 *
 * Board: ESP32-2432S028R ("Cheap Yellow Display" / CYD)
 *   - ESP32-WROOM-32 (dual-core Xtensa, 520 KB RAM, 4 MB flash, NO PSRAM)
 *   - 2.8" ILI9341 240x320 SPI TFT
 *   - XPT2046 RESISTIVE touch on a SECOND (bit-addressable) SPI bus
 *   - RGB LED (active LOW), LDR, speaker amp, microSD slot
 *   - 2.4 GHz only radio shared by WiFi + BT (no 5 GHz / no WiFi 6)
 *
 * Copy-and-edit file: put your WiFi creds, Ragnar URL and the device token
 * (generated in Ragnar: Config -> CYD nodes -> Generate token) below.
 */
#ifndef RAGNAR_CYD_CONFIG_H
#define RAGNAR_CYD_CONFIG_H

// ── Operator settings ─────────────────────────────────────────────────────────
// WiFi the node joins to reach Ragnar's REST API (2.4 GHz SSID only).
#define CYD_WIFI_SSID        "YOUR_WIFI_SSID"
#define CYD_WIFI_PASS        "YOUR_WIFI_PASSWORD"

// Ragnar base URL, reachable from the node (LAN IP of the Pi, no trailing slash).
#define CYD_RAGNAR_URL       "http://192.168.1.50:8080"

// Device token issued by Ragnar (Bearer). Scopes the node to the /api/cyd/* role.
#define CYD_DEVICE_TOKEN     "PASTE_TOKEN_FROM_RAGNAR"

// Human label shown on screen and reported to Ragnar.
#define CYD_NODE_NAME        "cyd-01"

// ── Duty-cycle timing (ms) — the single 2.4 GHz radio is time-shared ──────────
#define CYD_SYNC_WINDOW_MS   2500    // connected: pull status, push findings, send queued actions
#define CYD_SNIFF_WINDOW_MS  6000    // disconnected: WiFi promiscuous sweep
#define CYD_BLE_WINDOW_MS    3000    // disconnected: BLE advertisement scan (0 = skip)
#define CYD_WIFI_CONNECT_TO  8000    // WiFi connect timeout

// Compile-time feature gates (BLE+WiFi+GFX is tight on a 4 MB / no-PSRAM WROOM-32)
#define CYD_ENABLE_BLE       1       // set 0 to drop BLE (saves flash/RAM)

// ── TFT (ILI9341) — hardware VSPI ─────────────────────────────────────────────
#define TFT_SCLK   14
#define TFT_MOSI   13
#define TFT_MISO   12
#define TFT_CS     15
#define TFT_DC      2
#define TFT_RST    -1      // tied to board reset on the CYD
#define TFT_BL     21      // backlight (active HIGH)

// ── XPT2046 resistive touch — SEPARATE SPI bus (bit-addressed) ────────────────
#define TOUCH_SCLK 25
#define TOUCH_MOSI 32
#define TOUCH_MISO 39
#define TOUCH_CS   33
#define TOUCH_IRQ  36

// Touch calibration (raw ADC span -> pixels). Tune per panel if taps are off.
#define TOUCH_RAW_MINX  200
#define TOUCH_RAW_MAXX 3700
#define TOUCH_RAW_MINY  240
#define TOUCH_RAW_MAXY 3800

// ── On-board extras ───────────────────────────────────────────────────────────
#define PIN_LED_R  4      // RGB LED, active LOW
#define PIN_LED_G  16
#define PIN_LED_B  17
#define PIN_LDR    34     // ambient light (ADC)

#endif // RAGNAR_CYD_CONFIG_H
