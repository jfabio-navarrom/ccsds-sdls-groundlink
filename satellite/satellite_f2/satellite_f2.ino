// =====================================================================
//  satellite_f2.ino  -  Fase 2 del proyecto ccsds-sdls-groundlink
//  Placa: Waveshare ESP32-C5-Touch-LCD-2.8
//
//  Novedad respecto a la fase 1: el enlace esta protegido con SDLS
//  (CCSDS 355.0-B) usando AES-256-GCM:
//    - cada TC tiene que llevar una MAC valida (clave TC, SPI 1)
//    - el IV de cada TC tiene que ser mayor que el anterior (anti-replay),
//      y el ultimo IV aceptado se guarda en la flash (NVS): reiniciar la
//      placa no reabre la puerta al replay
//    - toda la TM va cifrada y autenticada (clave TM, SPI 2)
//    - el satelite SOLO habla con quien ha demostrado tener la clave: a un
//      desconocido no le responde nada. Lo que hace es avisar a la tierra
//      con un EVENTO DE SEGURIDAD (servicio 5,4) y contarlo en el HK
//
//  Pantalla:
//    - franja VERDE arriba         = SDLS activo
//    - recuadro central            = carga util (color comandado)
//    - OK / ERR / SEC              = TC aceptados, tramas mal formadas,
//                                    tramas rechazadas por seguridad
//    - franja de abajo             = blanca si el TC es valido, roja si se
//                                    rechaza por seguridad, ambar si llega rota
// =====================================================================

#include <WiFi.h>
#include <WiFiUdp.h>
#include <Preferences.h>
#include "Board_IO.h"
#include "Display_ST7789.h"
#include "ccsds.h"
#include "sdls.h"
#include "ui.h"
#include "secrets.h"   // WIFI_SSID, WIFI_PASS, SDLS_TC_KEY, SDLS_TM_KEY (no se sube a GitHub)

#if !defined(SDLS_TC_KEY) || !defined(SDLS_TM_KEY)
#error "Faltan las claves en secrets.h. Ejecuta en el PC: py tools/gen_keys_f2.py y copia las dos lineas #define que imprime."
#endif

using namespace ccsds;
using namespace sdls;

// Servicios PUS-lite (ver ground/ccsds/services.py)
const uint8_t SVC_TEST = 17, SUB_PING = 1, SUB_PONG = 2;
const uint8_t SVC_PAYLOAD = 8, SUB_SET_COLOR = 1;
const uint8_t SVC_HK = 3, SUB_HK_REPORT = 25, SUB_HK_REQUEST = 27;
const uint8_t SVC_VERIF = 1, SUB_ACK_FAIL = 2, SUB_ACK_OK = 7;
const uint8_t SVC_EVENT = 5, SUB_EVENT_HIGH = 4;
const uint8_t FAIL_BAD_PACKET = 10, FAIL_UNKNOWN_SERVICE = 11, FAIL_BAD_DATA = 12;

const uint16_t TC_PORT = 10025;
const unsigned long HK_PERIOD_MS = 5000;
const uint64_t TM_IV_BLOCK = 1024;   // IV de TM reservados de golpe en la flash

const uint8_t TC_KEY[KEY_LEN] = SDLS_TC_KEY;
const uint8_t TM_KEY[KEY_LEN] = SDLS_TM_KEY;

WiFiUDP udp;
Preferences nvs;
SecurityAssociation tcSa, tmSa;
uint8_t rx[256];
uint8_t plain[256];

// Estado de a bordo
uint8_t mcCount = 0, vcCount = 0;
uint16_t tmSeq = 0;
uint16_t tcAccepted = 0, tcRejected = 0;
uint16_t secSpi = 0, secMac = 0, secReplay = 0;
uint8_t lastFrameSeq = 0;
uint8_t payload[3] = {0, 0, 0};
uint64_t tmIv = 0, tmIvReserved = 0;

// La estacion de tierra: solo cambia con un TC autenticado
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
  drawText(24, 236, line, 3, rgb565(255, 140, 0), COLOR_GRIS);
  unsigned sec = (unsigned)secSpi + secMac + secReplay;
  snprintf(line, sizeof(line), "SEC %03u", sec % 1000);
  drawText(24, 258, line, 3, rgb565(255, 90, 90), COLOR_GRIS);
}

void flashBar(uint16_t color) {
  fillRect(0, 288, LCD_WIDTH, 32, color);
  flashUntil = millis() + 200;
}

// ------------------------- Memoria permanente -------------------------

void saveLastTcIv() {
  nvs.putBytes("tciv", tcSa.lastIv, IV_LEN);
}

// Nunca repetir un IV de TM, ni siquiera tras un reinicio: reservamos
// bloques de IV en la flash y empezamos siempre por encima de lo reservado.
uint64_t nextTmIv() {
  if (tmIv >= tmIvReserved) {
    tmIvReserved = tmIv + TM_IV_BLOCK;
    nvs.putULong64("tmiv", tmIvReserved);
  }
  return ++tmIv;
}

// ----------------------------- Telemetria -----------------------------

static void put16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
static void put32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

// Toda la TM va a la estacion de tierra autenticada, nunca a un desconocido
void sendTm(uint8_t svc, uint8_t sub, const uint8_t* app, size_t appLen) {
  if (!haveGround || appLen > 32) return;
  uint8_t data[2 + 32];
  data[0] = svc;
  data[1] = sub;
  if (appLen > 0) memcpy(data + 2, app, appLen);

  uint8_t pkt[SP_HEADER_LEN + sizeof(data)];
  size_t pktLen = buildSpacePacket(pkt, sizeof(pkt), 0, APID_SAT, tmSeq & 0x3FFF, data, 2 + appLen);
  tmSeq++;

  uint8_t iv[IV_LEN];
  ivFromCounter(nextTmIv(), iv);
  uint8_t frame[TM_FRAME_LEN];
  uint32_t clcw = buildClcw(VCID, (uint8_t)(lastFrameSeq + 1));
  if (pktLen == 0 || buildSecureTmFrame(tmSa, frame, mcCount++, vcCount++, pkt, pktLen, clcw, iv) == 0) return;

  udp.beginPacket(groundIP, groundPort);
  udp.write(frame, TM_FRAME_LEN);
  udp.endPacket();
}

void sendHk() {
  uint8_t app[23];
  put32(app, millis() / 1000);
  put16(app + 4, tcAccepted);
  put16(app + 6, tcRejected);
  put16(app + 8, secSpi);
  put16(app + 10, secMac);
  put16(app + 12, secReplay);
  app[14] = lastFrameSeq;
  app[15] = payload[0];
  app[16] = payload[1];
  app[17] = payload[2];
  app[18] = (uint8_t)(int8_t)WiFi.RSSI();
  put32(app + 19, ESP.getFreeHeap());
  sendTm(SVC_HK, SUB_HK_REPORT, app, sizeof(app));
}

// Evento de seguridad: que se ha rechazado, de donde venia y con que IV
void sendSecurityEvent(uint8_t code, uint8_t frameSeq, IPAddress ip, uint16_t port, const uint8_t* iv) {
  uint8_t app[16];
  app[0] = code;
  app[1] = frameSeq;
  for (int i = 0; i < 4; i++) app[2 + i] = ip[i];
  put16(app + 6, port);
  uint64_t c = iv ? ivToCounter(iv) : 0;
  for (int i = 0; i < 8; i++) app[8 + i] = (uint8_t)(c >> (56 - 8 * i));
  sendTm(SVC_EVENT, SUB_EVENT_HIGH, app, sizeof(app));
}

// ----------------------------- Telecomandos ---------------------------

void rejectLink(TcError err) {
  // Trama rota (CRC, longitud...): es un error de enlace, no se responde
  tcRejected++;
  Serial.printf("[SAT] Trama descartada (%s)\n", tcErrorName(err));
  flashBar(rgb565(255, 140, 0));
  drawCounters();
}

void rejectSecurity(SecError err, const TcFrame& f, IPAddress ip, uint16_t port, const uint8_t* iv) {
  if (err == SEC_ERR_MAC) secMac++;
  else if (err == SEC_ERR_REPLAY) secReplay++;
  else secSpi++;
  Serial.printf("[SAT] SEGURIDAD: trama rechazada (%s) desde %s:%u. Al emisor no se le responde.\n",
                secErrorName(err), ip.toString().c_str(), (unsigned)port);
  sendSecurityEvent((uint8_t)err, f.seq, ip, port, iv);
  flashBar(rgb565(255, 0, 0));
  drawCounters();
}

void rejectAuthenticated(uint16_t pktSeq, uint8_t code, const char* why) {
  // TC autenticado pero con contenido incorrecto: viene de la tierra legitima
  tcRejected++;
  Serial.printf("[SAT] TC autenticado pero RECHAZADO (%s)\n", why);
  uint8_t app[3];
  put16(app, pktSeq);
  app[2] = code;
  sendTm(SVC_VERIF, SUB_ACK_FAIL, app, 3);
  flashBar(rgb565(255, 140, 0));
  drawCounters();
}

void handleTc(const uint8_t* buf, size_t len, IPAddress ip, uint16_t port) {
  // 1) Trama TC (CRC, SCID, canal...)
  TcFrame f;
  TcError err = parseTcFrame(buf, len, f);
  if (err != TC_OK) {
    rejectLink(err);
    return;
  }

  // 2) SDLS: SPI, MAC y anti-replay
  uint8_t iv[IV_LEN];
  size_t plainLen = 0;
  SecError sec = processTc(tcSa, buf, f, plain, sizeof(plain), plainLen, iv);
  if (sec != SEC_OK) {
    bool ivRead = (sec == SEC_ERR_MAC || sec == SEC_ERR_REPLAY);
    rejectSecurity(sec, f, ip, port, ivRead ? iv : nullptr);
    return;
  }
  saveLastTcIv();

  // Autenticado: quien lo envio tiene la clave, asi que es la tierra
  groundIP = ip;
  groundPort = port;
  haveGround = true;
  lastFrameSeq = f.seq;

  // 3) Space Packet descifrado
  SpacePacket p;
  if (!parseSpacePacket(plain, plainLen, p) || p.type != 1 || p.apid != APID_SAT || p.dataLen < 2) {
    rejectAuthenticated(0xFFFF, FAIL_BAD_PACKET, "paquete mal formado");
    return;
  }

  uint8_t svc = p.data[0], sub = p.data[1];
  const uint8_t* app = p.data + 2;
  size_t appLen = p.dataLen - 2;

  if (svc == SVC_PAYLOAD && sub == SUB_SET_COLOR && appLen != 3) {
    rejectAuthenticated(p.seqCount, FAIL_BAD_DATA, "color sin 3 bytes");
    return;
  }
  if (!(svc == SVC_TEST && sub == SUB_PING) && !(svc == SVC_PAYLOAD && sub == SUB_SET_COLOR) &&
      !(svc == SVC_HK && sub == SUB_HK_REQUEST)) {
    rejectAuthenticated(p.seqCount, FAIL_UNKNOWN_SERVICE, "servicio desconocido");
    return;
  }

  tcAccepted++;
  Serial.printf("[SAT] TC autenticado y aceptado: trama #%u, IV #%llu, servicio (%u,%u)\n",
                f.seq, (unsigned long long)ivToCounter(iv), svc, sub);

  if (svc == SVC_TEST) {
    sendTm(SVC_TEST, SUB_PONG, nullptr, 0);
  } else if (svc == SVC_PAYLOAD) {
    memcpy(payload, app, 3);
    drawPayload();
    uint8_t ack[2];
    put16(ack, p.seqCount);
    sendTm(SVC_VERIF, SUB_ACK_OK, ack, 2);
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
  Serial.println("[SAT] Satelite simulado - fase 2 (CCSDS + SDLS, AES-256-GCM)");

  if (!Board_IO_Init()) Serial.println("[SAT] AVISO: no responde el expansor de IO");
  LCD_Init();
  Set_Backlight(80);
  fillRect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_GRIS);
  fillRect(0, 0, LCD_WIDTH, 40, rgb565(0, 170, 70));
  payload[2] = 80;
  drawPayload();
  drawCounters();

  // Asociaciones de seguridad y estado anti-replay guardado en la flash
  if (!saInit(tcSa, SPI_TC, TC_KEY) || !saInit(tmSa, SPI_TM, TM_KEY)) {
    Serial.println("[SAT] ERROR: no se pudieron cargar las claves");
  }
  nvs.begin("sdls", false);
  if (nvs.getBytesLength("tciv") == IV_LEN) nvs.getBytes("tciv", tcSa.lastIv, IV_LEN);
  tmIv = nvs.getULong64("tmiv", 0);   // empezamos por encima de todo lo reservado
  tmIvReserved = tmIv;
  Serial.printf("[SAT] Anti-replay: ultimo IV de TC aceptado #%llu, siguiente IV de TM > #%llu\n",
                (unsigned long long)ivToCounter(tcSa.lastIv), (unsigned long long)tmIv);

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
  Serial.printf("[SAT] Escuchando tramas TC en UDP %u (SCID 0x%03X, SDLS activo)\n", TC_PORT, SCID);

  payload[2] = 0;
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
  int n = udp.read(rx, sizeof(rx));
  if (n <= 0) return;
  if (size > (int)sizeof(rx)) {
    rejectLink(TC_ERR_LENGTH);
    return;
  }
  handleTc(rx, (size_t)n, ip, port);
}
