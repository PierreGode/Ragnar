/*
 * espnow_bridge.ino  –  Ragnar ESP-Now ↔ USB-Serial bridge
 *
 * Flash this sketch onto any ESP32 (WROOM, S3, C3, …) connected to the
 * Raspberry Pi via USB.  It initialises ESP-Now on channel 6 and relays
 * every received packet to the host as a binary frame, and every TX frame
 * from the host as an ESP-Now transmission.
 *
 * Frame format (both directions):
 *   SYNC  [2]   0xAB 0xCD
 *   CMD   [1]   0x01 RX (ESP32→Pi)  0x02 TX (Pi→ESP32)  0x03 HELLO
 *   MAC   [6]   source MAC (RX) / destination MAC (TX) / bridge MAC (HELLO)
 *   LEN   [2]   payload length, little-endian
 *   PAYLOAD[N]
 *   CRC   [1]   XOR of CMD + MAC[0..5] + LEN_lo + LEN_hi + PAYLOAD bytes
 *
 * Build requirements:
 *   - Arduino IDE ≥ 2.x  with  esp32 board support ≥ 3.x
 *   - Board:  "ESP32 Dev Module" (or matching variant)
 *   - Flash:  default partitions, any size ≥ 4 MB
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

// ── Configuration ──────────────────────────────────────────────────────────────
static constexpr uint32_t SERIAL_BAUD   = 460800;
static constexpr uint8_t  ESPNOW_CH     = 6;
static constexpr uint16_t MAX_PAYLOAD   = 250;

// ── Frame command bytes ────────────────────────────────────────────────────────
static constexpr uint8_t CMD_RX    = 0x01;
static constexpr uint8_t CMD_TX    = 0x02;
static constexpr uint8_t CMD_HELLO = 0x03;

// ── Frame sync bytes ───────────────────────────────────────────────────────────
static constexpr uint8_t SYNC_A = 0xAB;
static constexpr uint8_t SYNC_B = 0xCD;

// ── CRC helper ─────────────────────────────────────────────────────────────────
static uint8_t frame_crc(uint8_t cmd,
                          const uint8_t *mac,
                          uint16_t       plen,
                          const uint8_t *payload)
{
    uint8_t crc = cmd;
    for (int i = 0; i < 6; i++) crc ^= mac[i];
    crc ^= (uint8_t)(plen & 0xFF);
    crc ^= (uint8_t)(plen >> 8);
    for (uint16_t i = 0; i < plen; i++) crc ^= payload[i];
    return crc;
}

// ── Frame builder ──────────────────────────────────────────────────────────────
static void send_frame(uint8_t        cmd,
                        const uint8_t *mac,
                        const uint8_t *payload,
                        uint16_t       plen)
{
    uint8_t crc = frame_crc(cmd, mac, plen, payload);
    Serial.write(SYNC_A);
    Serial.write(SYNC_B);
    Serial.write(cmd);
    Serial.write(mac, 6);
    Serial.write((uint8_t)(plen & 0xFF));
    Serial.write((uint8_t)(plen >> 8));
    if (plen > 0) Serial.write(payload, plen);
    Serial.write(crc);
    Serial.flush();
}

// ── ESP-Now receive callback ───────────────────────────────────────────────────
static void on_recv(const esp_now_recv_info_t *info,
                    const uint8_t             *data,
                    int                        len)
{
    if (len <= 0 || len > MAX_PAYLOAD) return;
    send_frame(CMD_RX, info->src_addr, data, (uint16_t)len);
}

// ── ESP-Now send callback (fire-and-forget) ────────────────────────────────────
static void on_send(const uint8_t *mac, esp_now_send_status_t status)
{
    (void)mac;
    (void)status;
}

// ── Host → ESP32 binary parser ─────────────────────────────────────────────────
static uint8_t  rx_buf[16 + MAX_PAYLOAD];
static int      rx_pos  = 0;
static bool     in_sync = false;

static void process_host_frame(uint8_t        cmd,
                                 const uint8_t *mac,
                                 const uint8_t *payload,
                                 uint16_t       plen)
{
    if (cmd == CMD_TX) {
        // Register peer if not already known
        if (!esp_now_is_peer_exist(mac)) {
            esp_now_peer_info_t peer = {};
            memcpy(peer.peer_addr, mac, 6);
            peer.channel = ESPNOW_CH;
            peer.encrypt = false;
            esp_now_add_peer(&peer);
        }
        esp_now_send(mac, payload, plen);
    } else if (cmd == CMD_HELLO) {
        // Host re-requesting identification — reply with another HELLO
        uint8_t my_mac[6];
        esp_wifi_get_mac(WIFI_IF_STA, my_mac);
        static const uint8_t id[] = "RagnarBridge";
        send_frame(CMD_HELLO, my_mac, id, sizeof(id) - 1);
    }
}

static void parse_host_byte(uint8_t b)
{
    if (!in_sync) {
        if (rx_pos == 0 && b == SYNC_A) { rx_buf[rx_pos++] = b; }
        else if (rx_pos == 1 && b == SYNC_B) { rx_buf[rx_pos++] = b; in_sync = true; }
        else { rx_pos = 0; }
        return;
    }
    rx_buf[rx_pos++] = b;

    // Need full header: SYNC(2)+CMD(1)+MAC(6)+LEN(2) = 11 bytes before payload
    if (rx_pos < 11) return;

    uint8_t  cmd  = rx_buf[2];
    uint16_t plen = (uint16_t)rx_buf[9] | ((uint16_t)rx_buf[10] << 8);

    if (plen > MAX_PAYLOAD) { rx_pos = 0; in_sync = false; return; }

    uint16_t total = 11u + plen + 1u;   // header + payload + crc
    if (rx_pos < (int)total) return;

    const uint8_t *mac_ptr     = rx_buf + 3;
    const uint8_t *payload_ptr = rx_buf + 11;
    uint8_t        expected    = frame_crc(cmd, mac_ptr, plen, payload_ptr);
    uint8_t        got         = rx_buf[total - 1];

    if (expected == got)
        process_host_frame(cmd, mac_ptr, payload_ptr, plen);

    rx_pos  = 0;
    in_sync = false;
}

// ── Arduino setup ─────────────────────────────────────────────────────────────
void setup()
{
    Serial.begin(SERIAL_BAUD);

    // Print text identification line so Ragnar's boot-banner detector finds it
    Serial.println("RagnarBridge ready");
    delay(50);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_channel(ESPNOW_CH, WIFI_SECOND_CHAN_NONE);

    esp_now_init();
    esp_now_register_recv_cb(on_recv);
    esp_now_register_send_cb(on_send);

    // Pre-register broadcast peer so coordinator can reach all nodes
    esp_now_peer_info_t bc = {};
    memset(bc.peer_addr, 0xFF, 6);
    bc.channel = ESPNOW_CH;
    bc.encrypt = false;
    esp_now_add_peer(&bc);

    // Send binary HELLO frame — Ragnar uses this to learn the bridge MAC
    uint8_t my_mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, my_mac);
    static const uint8_t id[] = "RagnarBridge";
    send_frame(CMD_HELLO, my_mac, id, sizeof(id) - 1);
}

// ── Arduino loop ──────────────────────────────────────────────────────────────
void loop()
{
    while (Serial.available())
        parse_host_byte((uint8_t)Serial.read());
}
