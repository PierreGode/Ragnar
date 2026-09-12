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
 * Transport is chosen by CYD_TRANSPORT_SERIAL below: USB-serial (cabled to the
 * Pi, default) or WiFi (provisioned on-device via the setup portal). Neither
 * needs secrets baked in here.
 */
#ifndef RAGNAR_CYD_CONFIG_H
#define RAGNAR_CYD_CONFIG_H

// ── Operator settings ─────────────────────────────────────────────────────────
// PRIMARY provisioning is the on-device captive portal: an unconfigured node
// (or one that fails to connect, or one booted with the BOOT button held) raises
// its own "Ragnar-CYD-setup" AP and serves a form for WiFi + Ragnar URL + device
// token + node name, saved to NVS. So a single generic firmware image works on
// any node without baking in secrets.
//
// These compile-time values are OPTIONAL SEEDS: leave them empty ("") for the
// portal path, or fill them to pre-seed NVS on first boot (developer convenience
// — do NOT commit real secrets). NVS always wins once set in the portal.
#define CYD_WIFI_SSID        ""    // 2.4 GHz SSID only
#define CYD_WIFI_PASS        ""
#define CYD_RAGNAR_URL       ""    // e.g. http://192.168.1.50:8080  (no trailing slash)
#define CYD_DEVICE_TOKEN     ""    // Bearer token issued by Ragnar (Config → CYD Nodes)
#define CYD_NODE_NAME        "cyd-01"

// SoftAP name/password for the setup portal (password >= 8 chars, or "" for open).
#define CYD_SETUP_AP_SSID    "Ragnar-CYD-setup"
#define CYD_SETUP_AP_PASS    "ragnarcyd"
#define PIN_BOOT_BUTTON      0     // hold at boot to force the setup portal (GPIO0)

// ── Duty-cycle timing (ms) — the single 2.4 GHz radio is time-shared ──────────
#define CYD_SYNC_WINDOW_MS   2500    // connected: pull status, push findings, send queued actions
#define CYD_SNIFF_WINDOW_MS  6000    // disconnected: WiFi promiscuous sweep
#define CYD_BLE_WINDOW_MS    3000    // disconnected: BLE advertisement scan (0 = skip)
#define CYD_WIFI_CONNECT_TO  8000    // WiFi connect timeout

// Compile-time feature gates (BLE+WiFi+GFX is tight on a 4 MB / no-PSRAM WROOM-32)
#define CYD_ENABLE_BLE       1       // set 0 to drop BLE (saves flash/RAM)

// ── Transport to Ragnar ───────────────────────────────────────────────────────
// 1 = USB SERIAL: the node is cabled to the Pi and exchanges newline-delimited
//     JSON over USB (run cyd_serial_bridge.py on the Pi). No WiFi association,
//     no provisioning portal, no baked-in URL/token — the cable IS the link, so
//     the 2.4 GHz radio is free for sensing. This is the "one connected unit".
// 0 = WIFI: the node joins WiFi and talks to Ragnar's REST API (needs the setup
//     portal / a device token).
#define CYD_TRANSPORT_SERIAL 1
#define CYD_SERIAL_BAUD      115200

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
