#include "touch.h"
#include <Arduino.h>
#include <Wire.h>

// GT911 register map (subset)
//   0x8140-0x8147 : product id (bytes "911")
//   0x814E        : touch status   (bit7 = data ready, bits0..3 = count)
//   0x8150        : touch[0] X low byte (followed by X_hi, Y_lo, Y_hi, size_lo, size_hi)
static constexpr uint16_t REG_PRODUCT_ID = 0x8140;
static constexpr uint16_t REG_STATUS     = 0x814E;
static constexpr uint16_t REG_POINT1     = 0x8150;

static uint8_t  s_addr = 0;           // 0x5D, 0x14, or 0 if not found
static bool     s_pressed = false;
static uint16_t s_x = 0;
static uint16_t s_y = 0;

static bool gt_read(uint16_t reg, uint8_t* buf, size_t n) {
    if (!s_addr) return false;
    Wire.beginTransmission(s_addr);
    Wire.write((uint8_t)(reg >> 8));
    Wire.write((uint8_t)(reg & 0xFF));
    if (Wire.endTransmission(false) != 0) return false;
    size_t got = Wire.requestFrom((int)s_addr, (int)n);
    if (got != n) return false;
    for (size_t i = 0; i < n; i++) buf[i] = Wire.read();
    return true;
}

static bool gt_write_u8(uint16_t reg, uint8_t val) {
    if (!s_addr) return false;
    Wire.beginTransmission(s_addr);
    Wire.write((uint8_t)(reg >> 8));
    Wire.write((uint8_t)(reg & 0xFF));
    Wire.write(val);
    return Wire.endTransmission(true) == 0;
}

// Probe an address by attempting to read 4 bytes of the product-id register.
// GT911 returns "911\0".
static bool probe(uint8_t addr) {
    s_addr = addr;
    uint8_t id[4] = {0};
    if (!gt_read(REG_PRODUCT_ID, id, sizeof(id))) { s_addr = 0; return false; }
    bool ok = (id[0] == '9' && id[1] == '1' && id[2] == '1');
    if (!ok) s_addr = 0;
    return ok;
}

bool touch_init(Arduino_XCA9554SWSPI* expander, uint8_t rst_expander_pin, int int_pin) {
    // Reset sequence — INT held LOW during the trailing edge of RST selects 0x5D.
    // INT held HIGH selects 0x14. We try 0x5D first.
    pinMode(int_pin, OUTPUT);
    digitalWrite(int_pin, LOW);

    expander->pinMode(rst_expander_pin, OUTPUT);
    expander->digitalWrite(rst_expander_pin, LOW);
    delay(20);
    expander->digitalWrite(rst_expander_pin, HIGH);
    delay(5);                         // INT must stay LOW ≥5ms after RST rises
    pinMode(int_pin, INPUT);          // release INT so chip can use it as interrupt out
    delay(50);                        // chip boot time

    if (probe(0x5D)) {
        Serial.printf("GT911 found at 0x%02X\n", s_addr);
        return true;
    }
    if (probe(0x14)) {
        Serial.printf("GT911 found at 0x%02X (alt addr)\n", s_addr);
        return true;
    }
    Serial.println("GT911 not responding on either address");
    return false;
}

void touch_poll(void) {
    if (!s_addr) { s_pressed = false; return; }

    uint8_t status = 0;
    if (!gt_read(REG_STATUS, &status, 1)) {
        // I2C glitch — drop the read but keep state so a one-off bus
        // failure doesn't fake a release. A real release will arrive as
        // status & 0x80 with count==0.
        return;
    }

    // Bit 7 ("buffer status") = a fresh sample is ready. If it's clear,
    // we're between the chip's report intervals (~10 ms). Earlier this
    // path flipped s_pressed false, which made a steady hold oscillate
    // pressed/released at our poll rate and tricked LVGL into firing a
    // CLICKED on every gap — visible as the screen rapidly cycling pages
    // when the user just kept a finger on the panel. Keep the previous
    // state instead; the chip will eventually push a sample with
    // count==0 when the finger actually lifts.
    if (!(status & 0x80)) return;

    uint8_t count = status & 0x0F;
    if (count == 0) {
        s_pressed = false;
    } else {
        uint8_t p[4] = {0};
        if (gt_read(REG_POINT1, p, sizeof(p))) {
            s_x = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
            s_y = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
            s_pressed = true;
        }
    }

    // Clear status so the chip starts filling the next sample. GT911 demands this.
    gt_write_u8(REG_STATUS, 0);
}

bool     touch_is_pressed(void) { return s_pressed; }
uint16_t touch_get_x(void)      { return s_x; }
uint16_t touch_get_y(void)      { return s_y; }
uint8_t  touch_get_addr(void)   { return s_addr; }
