// ui.h - drawing on the screen: rectangles and text with a tiny font
#pragma once
#include <stdint.h>

uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b);
void fillRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color);

// Text with a 3x5 pixel font, scaled "scale" times (1 to 4).
// It only knows: digits, space, '-' and the letters C E K O Q R S T X.
void drawText(uint16_t x, uint16_t y, const char* text, uint8_t scale,
              uint16_t color, uint16_t bg);
