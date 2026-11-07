// =====================================================================
//  satellite_f1.ino  -  Fase 1 del proyecto ccsds-sdls-groundlink
//  Placa: Waveshare ESP32-C5-Touch-LCD-2.8
//
//  Novedad respecto a la fase 0: el satelite ya no entiende texto, sino
//  tramas CCSDS reales:
//    - recibe tramas TC (CCSDS 232.0-B) con un Space Packet dentro
//    - responde con tramas TM de 128 bytes (CCSDS 132.0-B) con su CLCW
//    - cada 5 s envia un informe de housekeeping (HK) a la estacion de tierra
//
//  Pantalla:
//    - franja AMBAR arriba        = modo SIN seguridad (todavia no hay SDLS)
//    - recuadro central            = carga util (color comandado)
//    - OK / ERR / SEQ              = TC aceptados, TC rechazados, ultima secuencia
//    - franja de abajo             = blanca si llega un TC valido, roja si se rechaza
//
//  AVISO: sigue SIN seguridad a proposito. El CRC solo detecta errores de
//  transmision: un atacante tambien sabe calcularlo. SDLS llega en la fase 2.
// =====================================================================

#include <WiFi.h>
#include <WiFiUdp.h>
#include "Board_IO.h"
#include "Display_ST7789.h"
#include "ccsds.h"
#include "ui.h"
#include "secrets.h"   // WIFI_SSID y WIFI_PASS (no se sube a GitHub)

using namespace ccsds;

// Servicios PUS-lite (ver ground/ccsds/services.py)
const uint8_t SVC_TEST = 17, SUB_PING = 1, SUB_PONG = 2;
const uint8_t SVC_PAYLOAD = 8, SUB_SET_COLOR = 1;
const uint8_t SVC_HK = 3, SUB_HK_REPORT = 25, SUB_HK_REQUEST = 27;
const uint8_t SVC_VERIF = 1, SUB_ACK_FAIL = 2, SUB_ACK_OK = 7;
const uint8_t FAIL_BAD_PACKET = 10, FAIL_UNKNOWN_SERVICE = 11, FAIL_BAD_DATA = 12;

const uint16_t TC_PORT = 10025;
const unsigned long HK_PERIOD_MS = 5000;

WiFiUDP udp;
uint8_t rx[256];              // buffer fijo para la trama recibida

// Estado de a bordo
uint8_t mcCount = 0, vcCount = 0;  // contadores de tramas TM
uint16_t tmSeq = 0;                // contador de paquetes TM
uint16_t tcAccepted = 0, tcRejected = 0;
uint8_t lastFrameSeq = 0;
uint8_t payload[3] = {0, 0, 0};

// A donde mandamos la telemetria: a quien envio el ultimo TC valido.
// OJO: en la fase 1 cualquiera puede "convertirse" en la estacion de tierra
// mandando un TC valido. Es otra debilidad que cerrara la fase 2.
IPAddress groundIP;
uint16_t groundPort = 0;
bool haveGround = false;
unsigned long lastHk = 0;
unsigned long flashUntil = 0;

const uint16_t COLOR_GRIS = 0x2104;
const uint16_t COLOR_BLANCO = 0xFFFF;

// ------------------------------ Pantalla ------------------------------

void drawPayload() {
  fillRect(16, 52, 208, 150, rgb565(payload[0], payload[1], payload[2]));
}

void drawCounters() {
  char line[16];
  snprintf(line, sizeof(line), "OK  %03u", (unsigned)(tcAccepted % 1000));
  drawText(24, 214, line, 3, COLOR_BLANCO, COLOR_GRIS);
  snprintf(line, sizeof(line), "ERR %03u", (unsigned)(tcRejected % 1000));
  drawText(24, 236, line, 3, rgb565(255, 90, 90), COLOR_GRIS);
  snprintf(line, sizeof(line), "SEQ %03u", (unsigned)lastFrameSeq);
  drawText(24, 258, line, 3, rgb565(255, 140, 0), COLOR_GRIS);
}

void flashBar(uint16_t color) {
  fillRect(0, 288, LCD_WIDTH, 32, color);
  flashUntil = millis() + 200;
}

// ----------------------------- Telemetria -----------------------------

static void put16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
static void put32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

void sendTm(IPAddress ip, uint16_t port, uint8_t svc, uint8_t sub,
            const uint8_t* app, size_t appLen) {
  uint8_t data[2 + 32];
  if (appLen > 32) return;
  data[0] = svc;
  data[1] = sub;
  if (appLen > 0) memcpy(data + 2, app, appLen);

  uint8_t pkt[SP_HEADER_LEN + sizeof(data)];
  size_t pktLen = buildSpacePacket(pkt, sizeof(pkt), 0, APID_SAT, tmSeq & 0x3FFF, data, 2 + appLen);
  tmSeq++;

  uint8_t frame[TM_FRAME_LEN];
  uint32_t clcw = buildClcw(VCID, (uint8_t)(lastFrameSeq + 1));  // V(R)
  if (pktLen == 0 || buildTmFrame(frame, mcCount++, vcCount++, pkt, pktLen, clcw) == 0) return;

  udp.beginPacket(ip, port);
  udp.write(frame, TM_FRAME_LEN);
  udp.endPacket();
}

void sendAckFail(IPAddress ip, uint16_t port, uint16_t pktSeq, uint8_t code) {
  uint8_t app[3];
  put16(app, pktSeq);
  app[2] = code;
  sendTm(ip, port, SVC_VERIF, SUB_ACK_FAIL, app, 3);
}

void sendHk() {
  if (!haveGround) return;
  uint8_t app[17];
  put32(app, millis() / 1000);
  put16(app + 4, tcAccepted);
  put16(app + 6, tcRejected);
  app[8] = lastFrameSeq;
  app[9] = payload[0];
  app[10] = payload[1];
  app[11] = payload[2];
  app[12] = (uint8_t)(int8_t)WiFi.RSSI();
  put32(app + 13, ESP.getFreeHeap());
  sendTm(groundIP, groundPort, SVC_HK, SUB_HK_REPORT, app, sizeof(app));
}

// ----------------------------- Telecomandos ---------------------------

void reject(IPAddress ip, uint16_t port, uint16_t pktSeq, uint8_t code, const char* why) {
  tcRejected++;
  Serial.printf("[SAT] TC RECHAZADO (%s)\n", why);
  sendAckFail(ip, port, pktSeq, code);
  flashBar(rgb565(255, 0, 0));
  drawCounters();
}

void handleTc(const uint8_t* buf, size_t len, IPAddress ip, uint16_t port) {
  // 1) Trama TC
  TcFrame f;
  TcError err = parseTcFrame(buf, len, f);
  if (err != TC_OK) {
    reject(ip, port, 0xFFFF, (uint8_t)err, tcErrorName(err));
    return;
  }

  // 2) Space Packet dentro de la trama
  SpacePacket p;
  if (!parseSpacePacket(f.data, f.dataLen, p) || p.type != 1 || p.apid != APID_SAT || p.dataLen < 2) {
    reject(ip, port, 0xFFFF, FAIL_BAD_PACKET, "paquete mal formado");
    return;
  }

  // 3) Servicio
  uint8_t svc = p.data[0], sub = p.data[1];
  const uint8_t* app = p.data + 2;
  size_t appLen = p.dataLen - 2;

  if (svc == SVC_TEST && sub == SUB_PING) {
    // ok
  } else if (svc == SVC_PAYLOAD && sub == SUB_SET_COLOR) {
    if (appLen != 3) {
      reject(ip, port, p.seqCount, FAIL_BAD_DATA, "color sin 3 bytes");
      return;
    }
  } else if (svc == SVC_HK && sub == SUB_HK_REQUEST) {
    // ok
  } else {
    reject(ip, port, p.seqCount, FAIL_UNKNOWN_SERVICE, "servicio desconocido");
    return;
  }

  // Aceptado. Sin autenticacion, quien lo envio pasa a ser "la tierra".
  tcAccepted++;
  lastFrameSeq = f.seq;
  groundIP = ip;
  groundPort = port;
  haveGround = true;

  Serial.printf("[SAT] TC aceptado: trama #%u, paquete #%u, servicio (%u,%u), de %s:%u\n",
                f.seq, p.seqCount, svc, sub, ip.toString().c_str(), (unsigned)port);

  if (svc == SVC_TEST) {
    sendTm(ip, port, SVC_TEST, SUB_PONG, nullptr, 0);
  } else if (svc == SVC_PAYLOAD) {
    memcpy(payload, app, 3);
    drawPayload();
    uint8_t ack[2];
    put16(ack, p.seqCount);
    sendTm(ip, port, SVC_VERIF, SUB_ACK_OK, ack, 2);
    Serial.printf("[SAT] Carga util: color = (%u, %u, %u)\n", payload[0], payload[1], payload[2]);
  } else {
    sendHk();
  }

  flashBar(COLOR_BLANCO);
  drawCounters();
}

// ------------------------------- Arranque -----------------------------

void setup() {
  Serial.begin(115200);
  delay(1500);
  Serial.println();
  Serial.println("[SAT] Satelite simulado - fase 1 (CCSDS, SIN seguridad)");

  if (!Board_IO_Init()) Serial.println("[SAT] AVISO: no responde el expansor de IO");
  LCD_Init();
  Set_Backlight(80);
  fillRect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_GRIS);
  fillRect(0, 0, LCD_WIDTH, 40, rgb565(255, 140, 0));
  payload[2] = 80;  // azul oscuro mientras conecta
  drawPayload();
  drawCounters();

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
  Serial.printf("[SAT] Escuchando tramas TC en UDP %u (SCID 0x%03X)\n", TC_PORT, SCID);

  payload[2] = 0;  // negro: carga util apagada
  drawPayload();
}

void loop() {
  unsigned long now = millis();

  if (flashUntil != 0 && now > flashUntil) {
    fillRect(0, 288, LCD_WIDTH, 32, COLOR_GRIS);
    flashUntil = 0;
  }

  if (haveGround && now - lastHk >= HK_PERIOD_MS) {
    lastHk = now;
    sendHk();
  }

  int size = udp.parsePacket();
  if (size <= 0) {
    delay(5);
    return;
  }
  IPAddress ip = udp.remoteIP();
  uint16_t port = udp.remotePort();
  int n = udp.read(rx, sizeof(rx));  // nunca mas de 256 bytes
  if (n <= 0) return;
  if (size > (int)sizeof(rx)) {
    reject(ip, port, 0xFFFF, TC_ERR_LENGTH, "trama demasiado larga");
    return;
  }
  handleTc(rx, (size_t)n, ip, port);
}
