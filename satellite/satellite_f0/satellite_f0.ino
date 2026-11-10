// =====================================================================
//  satellite_f0.ino  -  Phase 0 of the ccsds-sdls-groundlink project
//  Board: Waveshare ESP32-C5-Touch-LCD-2.8 (ST7789 screen 240x320)
//
//  The ESP32-C5 plays the "satellite": it joins your Wi-Fi, listens for
//  telecommands (TC) over UDP and paints the screen with the color they
//  sends. The screen is the "payload".
//
//  What each zone of the screen means:
//    - AMBER top bar           = mode with NO security (phase 0)
//    - Center box              = the payload (commanded color)
//    - Bottom bar              = blinks white with each TC received
//
//  WARNING: this version has NO security at all, and this is on purpose.
//  This is the "before" of the demo: anyone on the network can send it
//  commands. Security (SDLS) comes in phase 2.
//
//  The Board_IO and Display_ST7789 files are the official drivers from
//  Waveshare for this board (Apache 2.0 license), copied without changes.
// =====================================================================

#include <WiFi.h>
#include <WiFiUdp.h>
#include "Board_IO.h"
#include "Display_ST7789.h"
#include "secrets.h"   // WIFI_SSID and WIFI_PASS go here (not pushed to GitHub)

const uint16_t TC_PORT = 10025;   // UDP port where the telecommands arrive
const size_t   MAX_TC  = 128;     // max size of a telecommand (bytes)

WiFiUDP udp;
char tc[MAX_TC];                  // fixed size buffer for the received TC
unsigned long tcCount = 0;        // how many telecommands we received
unsigned long tcFlashUntil = 0;   // until when the "TC received" blink lasts

// ----------------------------- Screen --------------------------------

static uint16_t lineBuf[LCD_WIDTH];  // one line of pixels

// Converts a color (r, g, b from 0 to 255) to the screen format (RGB565)
uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b) {
  return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
}

const uint16_t COLOR_GRIS  = 0x2104;   // very dark gray
const uint16_t COLOR_BLANCO = 0xFFFF;

// Paints a rectangle with one color
void fillRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color) {
  if (w == 0 || h == 0) return;
  for (uint16_t i = 0; i < w; i++) lineBuf[i] = color;
  for (uint16_t row = 0; row < h; row++) {
    LCD_addWindow(x, y + row, x + w - 1, y + row, lineBuf);
  }
}

// The payload: the center box of the screen
void setPayload(uint8_t r, uint8_t g, uint8_t b) {
  fillRect(16, 56, 208, 216, rgb565(r, g, b));
}

void drawFrame() {
  fillRect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_GRIS);   // background
  fillRect(0, 0, LCD_WIDTH, 40, rgb565(255, 140, 0));  // amber bar: NO security
  fillRect(0, 288, LCD_WIDTH, 32, COLOR_GRIS);         // activity bar
}

// ------------------------------ Link ---------------------------------

// Answers whoever sent us the last packet
void reply(const char* msg) {
  udp.beginPacket(udp.remoteIP(), udp.remotePort());
  udp.print(msg);
  udp.endPacket();
}

void setup() {
  Serial.begin(115200);
  delay(1500);  // gives time to open the Serial Monitor
  Serial.println();
  Serial.println("[SAT] Simulated satellite - phase 0 (NO security)");

  // Screen: first the IO expander (controls reset and brightness), then the LCD
  if (!Board_IO_Init()) {
    Serial.println("[SAT] WARNING: the board IO expander does not answer");
  }
  LCD_Init();
  Set_Backlight(80);
  drawFrame();
  setPayload(0, 0, 80);  // dark blue = starting

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("[SAT] Connecting to the Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("[SAT] Connected. MY IP IS: ");
  Serial.println(WiFi.localIP());

  udp.begin(TC_PORT);
  Serial.printf("[SAT] Listening for telecommands on UDP %u\n", TC_PORT);

  setPayload(0, 0, 0);  // black = payload off, ready
}

void loop() {
  // Turns off the "TC received" blink when it is time
  if (tcFlashUntil != 0 && millis() > tcFlashUntil) {
    fillRect(0, 288, LCD_WIDTH, 32, COLOR_GRIS);
    tcFlashUntil = 0;
  }

  int size = udp.parsePacket();
  if (size <= 0) {
    delay(5);
    return;  // nothing arrived
  }

  // We read at most MAX_TC-1 bytes: we never write outside the buffer
  int n = udp.read(tc, MAX_TC - 1);
  if (n < 0) n = 0;
  tc[n] = '\0';

  // Remove line breaks or spaces at the end
  while (n > 0 && (tc[n - 1] == '\n' || tc[n - 1] == '\r' || tc[n - 1] == ' ')) {
    tc[--n] = '\0';
  }

  tcCount++;
  Serial.printf("[TC #%lu] from %s:%u -> \"%s\"\n",
                tcCount,
                udp.remoteIP().toString().c_str(),
                (unsigned)udp.remotePort(),
                tc);

  // White blink on the bottom bar: a TC arrived
  fillRect(0, 288, LCD_WIDTH, 32, COLOR_BLANCO);
  tcFlashUntil = millis() + 200;

  // --- Read the telecommand ---
  int r, g, b;
  if (strcmp(tc, "PING") == 0) {
    reply("PONG");
  } else if (sscanf(tc, "LED %d %d %d", &r, &g, &b) == 3 &&
             r >= 0 && r <= 255 && g >= 0 && g <= 255 && b >= 0 && b <= 255) {
    setPayload(r, g, b);
    reply("ACK LED");
    Serial.printf("[SAT] Payload: color = (%d, %d, %d)\n", r, g, b);
  } else {
    reply("NACK unknown command");
  }
}
