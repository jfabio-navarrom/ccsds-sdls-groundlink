// ui.cpp - see ui.h
#include "ui.h"
#include "Display_ST7789.h"

uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b) {
  return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
}

static uint16_t lineBuf[LCD_WIDTH];

void fillRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color) {
  if (w == 0 || h == 0) return;
  for (uint16_t i = 0; i < w; i++) lineBuf[i] = color;
  for (uint16_t row = 0; row < h; row++) {
    LCD_addWindow(x, y + row, x + w - 1, y + row, lineBuf);
  }
}

// Each glyph: 5 rows of 3 bits (bit 2 = left column)
static const uint8_t* glyph(char c) {
  static const uint8_t DIGITS[10][5] = {
    {7, 5, 5, 5, 7},  // 0
    {2, 6, 2, 2, 7},  // 1
    {7, 1, 7, 4, 7},  // 2
    {7, 1, 7, 1, 7},  // 3
    {5, 5, 7, 1, 1},  // 4
    {7, 4, 7, 1, 7},  // 5
    {7, 4, 7, 5, 7},  // 6
    {7, 1, 1, 1, 1},  // 7
    {7, 5, 7, 5, 7},  // 8
    {7, 5, 7, 1, 7},  // 9
  };
  static const uint8_t C[5] = {7, 4, 4, 4, 7};
  static const uint8_t E[5] = {7, 4, 7, 4, 7};
  static const uint8_t K[5] = {5, 5, 6, 5, 5};
  static const uint8_t O[5] = {2, 5, 5, 5, 2};
  static const uint8_t Q[5] = {2, 5, 5, 6, 3};
  static const uint8_t R[5] = {6, 5, 6, 5, 5};
  static const uint8_t S[5] = {3, 4, 2, 1, 6};
  static const uint8_t T[5] = {7, 2, 2, 2, 2};
  static const uint8_t X[5] = {5, 5, 2, 5, 5};
  static const uint8_t DASH[5] = {0, 0, 7, 0, 0};
  static const uint8_t SPACE[5] = {0, 0, 0, 0, 0};

  if (c >= '0' && c <= '9') return DIGITS[c - '0'];
  switch (c) {
    case 'C': return C;
    case 'E': return E;
    case 'K': return K;
    case 'O': return O;
    case 'Q': return Q;
    case 'R': return R;
    case 'S': return S;
    case 'T': return T;
    case 'X': return X;
    case '-': return DASH;
    default: return SPACE;
  }
}

void drawText(uint16_t x, uint16_t y, const char* text, uint8_t scale,
              uint16_t color, uint16_t bg) {
  if (scale < 1) scale = 1;
  if (scale > 4) scale = 4;
  const uint16_t cellW = 4 * scale;  // 3 glyph columns + 1 for spacing
  const uint16_t cellH = 5 * scale;
  static uint16_t cell[16 * 20];

  for (const char* p = text; *p != '\0'; p++) {
    if (x + cellW > LCD_WIDTH) break;
    const uint8_t* g = glyph(*p);
    for (uint16_t py = 0; py < cellH; py++) {
      for (uint16_t px = 0; px < cellW; px++) {
        uint16_t gx = px / scale, gy = py / scale;
        bool on = gx < 3 && ((g[gy] >> (2 - gx)) & 1);
        cell[py * cellW + px] = on ? color : bg;
      }
    }
    LCD_addWindow(x, y, x + cellW - 1, y + cellH - 1, cell);
    x += cellW;
  }
}
