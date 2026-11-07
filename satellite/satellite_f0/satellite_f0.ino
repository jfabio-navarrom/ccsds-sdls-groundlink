// =====================================================================
//  satellite_f0.ino  -  Fase 0 del proyecto ccsds-sdls-groundlink
//  Placa: Waveshare ESP32-C5-Touch-LCD-2.8 (pantalla ST7789 240x320)
//
//  El ESP32-C5 hace de "satelite": se conecta a tu Wi-Fi, escucha
//  telecomandos (TC) por UDP y pinta la pantalla del color que le
//  manden. La pantalla es la "carga util".
//
//  Que significa cada zona de la pantalla:
//    - Franja de arriba AMBAR  = modo SIN seguridad (fase 0)
//    - Recuadro central        = la carga util (color comandado)
//    - Franja de abajo         = parpadea en blanco con cada TC recibido
//
//  AVISO: esta version NO tiene ninguna seguridad, y es a proposito.
//  Es el "antes" de la demo: cualquiera en la red puede mandarle
//  comandos. La seguridad (SDLS) llega en la fase 2.
//
//  Los archivos Board_IO y Display_ST7789 son los drivers oficiales de
//  Waveshare para esta placa (licencia Apache 2.0), copiados sin cambios.
// =====================================================================

#include <WiFi.h>
#include <WiFiUdp.h>
#include "Board_IO.h"
#include "Display_ST7789.h"
#include "secrets.h"   // Aqui van WIFI_SSID y WIFI_PASS (no se sube a GitHub)

const uint16_t TC_PORT = 10025;   // puerto UDP donde llegan los telecomandos
const size_t   MAX_TC  = 128;     // tamano maximo de un telecomando (bytes)

WiFiUDP udp;
char tc[MAX_TC];                  // buffer de tamano fijo para el TC recibido
unsigned long tcCount = 0;        // cuantos telecomandos hemos recibido
unsigned long tcFlashUntil = 0;   // hasta cuando dura el parpadeo de "TC recibido"

// ----------------------------- Pantalla ------------------------------

static uint16_t lineBuf[LCD_WIDTH];  // una linea de pixeles

// Convierte un color (r, g, b de 0 a 255) al formato de la pantalla (RGB565)
uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b) {
  return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
}

const uint16_t COLOR_GRIS  = 0x2104;   // gris muy oscuro
const uint16_t COLOR_BLANCO = 0xFFFF;

// Pinta un rectangulo de un color
void fillRect(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color) {
  if (w == 0 || h == 0) return;
  for (uint16_t i = 0; i < w; i++) lineBuf[i] = color;
  for (uint16_t row = 0; row < h; row++) {
    LCD_addWindow(x, y + row, x + w - 1, y + row, lineBuf);
  }
}

// La carga util: el recuadro central de la pantalla
void setPayload(uint8_t r, uint8_t g, uint8_t b) {
  fillRect(16, 56, 208, 216, rgb565(r, g, b));
}

void drawFrame() {
  fillRect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_GRIS);   // fondo
  fillRect(0, 0, LCD_WIDTH, 40, rgb565(255, 140, 0));  // franja ambar: SIN seguridad
  fillRect(0, 288, LCD_WIDTH, 32, COLOR_GRIS);         // franja de actividad
}

// ------------------------------ Enlace -------------------------------

// Responde al que nos envio el ultimo paquete
void reply(const char* msg) {
  udp.beginPacket(udp.remoteIP(), udp.remotePort());
  udp.print(msg);
  udp.endPacket();
}

void setup() {
  Serial.begin(115200);
  delay(1500);  // da tiempo a abrir el Monitor Serie
  Serial.println();
  Serial.println("[SAT] Satelite simulado - fase 0 (SIN seguridad)");

  // Pantalla: primero el expansor de IO (controla reset y brillo), luego el LCD
  if (!Board_IO_Init()) {
    Serial.println("[SAT] AVISO: no responde el expansor de IO de la placa");
  }
  LCD_Init();
  Set_Backlight(80);
  drawFrame();
  setPayload(0, 0, 80);  // azul oscuro = arrancando

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("[SAT] Conectando a la Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("[SAT] Conectado. MI IP ES: ");
  Serial.println(WiFi.localIP());

  udp.begin(TC_PORT);
  Serial.printf("[SAT] Escuchando telecomandos en UDP %u\n", TC_PORT);

  setPayload(0, 0, 0);  // negro = carga util apagada, listo
}

void loop() {
  // Apaga el parpadeo de "TC recibido" cuando toca
  if (tcFlashUntil != 0 && millis() > tcFlashUntil) {
    fillRect(0, 288, LCD_WIDTH, 32, COLOR_GRIS);
    tcFlashUntil = 0;
  }

  int size = udp.parsePacket();
  if (size <= 0) {
    delay(5);
    return;  // no ha llegado nada
  }

  // Leemos como mucho MAX_TC-1 bytes: nunca escribimos fuera del buffer
  int n = udp.read(tc, MAX_TC - 1);
  if (n < 0) n = 0;
  tc[n] = '\0';

  // Quitamos saltos de linea o espacios del final
  while (n > 0 && (tc[n - 1] == '\n' || tc[n - 1] == '\r' || tc[n - 1] == ' ')) {
    tc[--n] = '\0';
  }

  tcCount++;
  Serial.printf("[TC #%lu] de %s:%u -> \"%s\"\n",
                tcCount,
                udp.remoteIP().toString().c_str(),
                (unsigned)udp.remotePort(),
                tc);

  // Parpadeo blanco en la franja de abajo: ha llegado un TC
  fillRect(0, 288, LCD_WIDTH, 32, COLOR_BLANCO);
  tcFlashUntil = millis() + 200;

  // --- Interpretamos el telecomando ---
  int r, g, b;
  if (strcmp(tc, "PING") == 0) {
    reply("PONG");
  } else if (sscanf(tc, "LED %d %d %d", &r, &g, &b) == 3 &&
             r >= 0 && r <= 255 && g >= 0 && g <= 255 && b >= 0 && b <= 255) {
    setPayload(r, g, b);
    reply("ACK LED");
    Serial.printf("[SAT] Carga util: color = (%d, %d, %d)\n", r, g, b);
  } else {
    reply("NACK comando desconocido");
  }
}
