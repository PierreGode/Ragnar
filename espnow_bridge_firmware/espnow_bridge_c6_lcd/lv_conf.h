/*
 * lv_conf.h  —  LVGL 9.x config for Ragnar ESP32-C6 bridge display.
 *
 * Keep this file in the same folder as espnow_bridge_c6_lcd.ino.
 * LVGL will find it automatically when LV_CONF_INCLUDE_SIMPLE is set.
 *
 * Based on the minimal config used by WaveshareESP32C6LCD/bandwatch.
 * All options not listed here use LVGL's built-in defaults.
 */

#ifndef LV_CONF_H
#define LV_CONF_H

/* ST7789 speaks RGB565 */
#define LV_COLOR_DEPTH     16

/* Physical resolution (portrait) */
#define LV_HOR_RES_MAX     172
#define LV_VER_RES_MAX     320

/* Montserrat fonts used by the UI */
#define LV_FONT_MONTSERRAT_10  1
#define LV_FONT_MONTSERRAT_12  1
#define LV_FONT_MONTSERRAT_14  1
#define LV_FONT_MONTSERRAT_20  1

/* Save flash — disable logging */
#define LV_USE_LOG     0

#endif /* LV_CONF_H */
