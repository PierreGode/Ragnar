#pragma once
#include <stdint.h>
#include <Arduino_GFX_Library.h>

// Minimal GT911 capacitive-touch driver for the Waveshare ESP32-S3-Touch-LCD-4
// family. Shares the I2C bus (EXPANDER_SDA/SCL) with the TCA9554 GPIO expander.
//
// The GT911 reset line is wired through the TCA9554 — pass the expander pin
// number to touch_init(). I2C address (0x5D vs 0x14) is auto-probed after reset.
//
// No UI bindings: poll once per loop, then query via the getters. LVGL or any
// other consumer can decide what to do with the coordinates.

bool     touch_init(Arduino_XCA9554SWSPI* expander, uint8_t rst_expander_pin, int int_pin);
void     touch_poll(void);
bool     touch_is_pressed(void);
uint16_t touch_get_x(void);
uint16_t touch_get_y(void);
uint8_t  touch_get_addr(void);  // 0 if init failed
