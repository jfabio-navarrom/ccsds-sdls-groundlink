// ui.h - dibujo en la pantalla: rectangulos y texto con una fuente minima
#pragma once
#include <stdint.h>

uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b);
void fillRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color);

// Texto con una fuente de 3x5 pixeles ampliada "scale" veces (1 a 4).
// Solo conoce: digitos, espacio, '-' y las letras C E K O Q R S T X.
void drawText(uint16_t x, uint16_t y, const char* text, uint8_t scale,
              uint16_t color, uint16_t bg);
