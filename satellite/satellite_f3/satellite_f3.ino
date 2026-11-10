// =====================================================================
//  satellite_f3.ino  -  Fase 3 del proyecto ccsds-sdls-groundlink
//  Placa: Waveshare ESP32-C5-Touch-LCD-2.8
//
//  Sobre la fase 2 (SDLS con AES-256-GCM y anti-replay) anade:
//
//  1) Rotacion de claves en vuelo (OTAR): la tierra sube claves nuevas
//     cifradas con una clave maestra (KEK) y luego las activa. No hace falta
//     reflashear la placa si una clave se filtra.
//  2) FARM-1 (COP-1): los telecomandos AD se ejecutan en orden, sin huecos
//     ni duplicados. La CLCW de cada trama TM le dice a la tierra que trama
//     espera el satelite y si tiene que retransmitir.
//  3) Defensa ante inundacion: los eventos de seguridad tienen un limite de
//     frecuencia (los que sobran se resumen) y la pantalla se redibuja como
//     mucho unas pocas veces por segundo, para que un atacante no pueda
//     saturar al satelite ni a la tierra.
//
//  Pantalla:
//    - franja VERDE arriba = SDLS activo; cuadradito a la derecha = ID de clave
//    - OK / ERR / SEC      = TC aceptados, tramas rotas o fuera de secuencia,
//                            rechazos de seguridad
// =====================================================================

#include <WiFi.h>
#include <WiFiUdp.h>
#include <Preferences.h>
#include "Board_IO.h"
#include "Display_ST7789.h"
#include "ccsds.h"
#include "sdls.h"
#include "farm.h"
#include "ui.h"
#include "secrets.h"   // WIFI_*, SDLS_KEK, SDLS_TC_KEY, SDLS_TM_KEY (no se sube a GitHub)

#if !defined(SDLS_TC_KEY) || !defined(SDLS_TM_KEY) || !defined(SDLS_KEK)
#error "Faltan claves en secrets.h. Ejecuta en el PC: py tools/gen_keys_f3.py y copia las tres lineas #define que imprime."
#endif

using namespace ccsds;
using namespace sdls;

// Servicios PUS-lite (ver ground/ccsds/services.py)
const uint8_t SVC_TEST = 17, SUB_PING = 1, SUB_PONG = 2;
const uint8_t SVC_PAYLOAD = 8, SUB_SET_COLOR = 1;
const uint8_t SVC_HK = 3, SUB_HK_REPORT = 25, SUB_HK_REQUEST = 27;
const uint8_t SVC_VERIF = 1, SUB_ACK_FAIL = 2, SUB_ACK_OK = 7;
const uint8_t SVC_EVENT = 5, SUB_EVENT_HIGH = 4, SUB_EVENTS_SUPPRESSED = 5;
const uint8_t SVC_KEYS = 24, SUB_OTAR_UPLOAD = 1, SUB_OTAR_ACTIVATE = 2;

const uint8_t FAIL_BAD_PACKET = 10, FAIL_UNKNOWN_SERVICE = 11, FAIL_BAD_DATA = 12;
const uint8_t FAIL_FARM_AHEAD = 30, FAIL_FARM_LOCKOUT = 31, FAIL_FARM_CONTROL = 32;
const uint8_t FAIL_OTAR_INVALID = 40, FAIL_OTAR_OLD_ID = 41, FAIL_OTAR_NO_PENDING = 42;

const uint16_t TC_PORT = 10025;
const unsigned long HK_PERIOD_MS = 5000;
const uint64_t TM_IV_BLOCK = 1024;

// Limite de eventos de seguridad: rafaga de 3 y luego 1 por segundo
const uint8_t EVENT_BURST = 3;
const unsigned long EVENT_REFILL_MS = 1000;
const unsigned long REDRAW_MS = 150;

const uint8_t KEK[KEY_LEN] = SDLS_KEK;
const uint8_t INITIAL_TC_KEY[KEY_LEN] = SDLS_TC_KEY;
const uint8_t INITIAL_TM_KEY[KEY_LEN] = SDLS_TM_KEY;

WiFiUDP udp;
Preferences nvs;
SecurityAssociation tcSa, tmSa;
mbedtls_gcm_context kekCtx;
farm::State farmState;
uint8_t rx[256];
uint8_t plain[256];

// Estado de a bordo
uint8_t mcCount = 0, vcCount = 0;
uint16_t tmSeq = 0;
uint16_t tcAccepted = 0, tcRejected = 0, farmDiscards = 0;
uint16_t secSpi = 0, secMac = 0, secReplay = 0;
uint16_t eventsSuppressed = 0, suppressedPending = 0;
uint8_t payload[3] = {0, 0, 0};
uint64_t tmIv = 0, tmIvReserved = 0;
uint8_t activeKeyId = 1;
uint8_t pendingKeyId = 0;               // 0 = no hay claves pendientes
uint8_t pendingTc[KEY_LEN], pendingTm[KEY_LEN];

IPAddress groundIP;
uint16_t groundPort = 0;
bool haveGround = false;
unsigned long lastHk = 0, flashUntil = 0, lastRefill = 0, lastRedraw = 0;
uint8_t eventTokens = EVENT_BURST;
bool countersDirty = false;

const uint16_t COLOR_GRIS = 0x2104;
const uint16_t COLOR_BLANCO = 0xFFFF;

// ------------------------------ Pantalla ------------------------------

void drawPayload() {
  fillRect(16, 52, 208, 150, rgb565(payload[0], payload[1], payload[2]));
}

void drawHeader() {
  fillRect(0, 0, LCD_WIDTH, 40, rgb565(0, 170, 70));
  char id[6];
  snprintf(id, sizeof(id), "%u", (unsigned)activeKeyId);   // ID de la clave activa
  drawText(200, 8, id, 4, COLOR_BLANCO, rgb565(0, 170, 70));
}

void drawCounters() {
  char line[16];
  snprintf(line, sizeof(line), "OK  %03u", (unsigned)(tcAccepted % 1000));
  drawText(24, 214, line, 3, COLOR_BLANCO, COLOR_GRIS);
  snprintf(line, sizeof(line), "ERR %03u", (unsigned)((tcRejected + farmDiscards) % 1000));
  drawText(24, 236, line, 3, rgb565(255, 140, 0), COLOR_GRIS);
  unsigned sec = (unsigned)secSpi + secMac + secReplay;
  snprintf(line, sizeof(line), "SEC %03u", sec % 1000);
  drawText(24, 258, line, 3, rgb565(255, 90, 90), COLOR_GRIS);
  countersDirty = false;
  lastRedraw = millis();
}

// Durante una inundacion no redibujamos en cada trama: solo marcamos
void markCounters() { countersDirty = true; }

void flashBar(uint16_t color) {
  if (flashUntil != 0) return;   // ya hay un destello en curso
  fillRect(0, 288, LCD_WIDTH, 32, color);
  flashUntil = millis() + 200;
}

// ------------------------- Memoria permanente -------------------------

void saveLastTcIv() { nvs.putBytes("tciv", tcSa.lastIv, IV_LEN); }

uint64_t nextTmIv() {
  if (tmIv >= tmIvReserved) {
    tmIvReserved = tmIv + TM_IV_BLOCK;
    nvs.putULong64("tmiv", tmIvReserved);
  }
  return ++tmIv;
}

// Claves activas en la flash: [huella KEK 8][ID 1][TC 32][TM 32]
void saveActiveKeys(const uint8_t tc[KEY_LEN], const uint8_t tm[KEY_LEN]) {
  uint8_t rec[8 + 1 + 2 * KEY_LEN];
  if (!kekFingerprint(kekCtx, rec)) {
    Serial.println("[SAT] ERROR: no pude calcular la huella de la KEK; las claves no se guardan en la flash");
    return;
  }
  rec[8] = activeKeyId;
  memcpy(rec + 9, tc, KEY_LEN);
  memcpy(rec + 9 + KEY_LEN, tm, KEY_LEN);
  size_t written = nvs.putBytes("keys", rec, sizeof(rec));
  memset(rec, 0, sizeof(rec));
  Serial.printf("[SAT] Claves ID %u guardadas en la flash (%s)\n", activeKeyId,
                written == sizeof(rec) ? "OK" : "ERROR al escribir");
}

void loadKeys() {
  uint8_t rec[8 + 1 + 2 * KEY_LEN], fp[8];
  bool ok = kekFingerprint(kekCtx, fp) && nvs.getBytesLength("keys") == sizeof(rec) && nvs.getBytes("keys", rec, sizeof(rec)) == sizeof(rec) &&
            memcmp(rec, fp, 8) == 0;
  if (ok) {
    activeKeyId = rec[8];
    saInit(tcSa, SPI_TC, rec + 9);
    saInit(tmSa, SPI_TM, rec + 9 + KEY_LEN);
    Serial.printf("[SAT] Claves: uso las rotadas en vuelo (ID %u), guardadas en la flash\n", activeKeyId);
  } else {
    // Primera vez, o has cambiado la KEK en secrets.h: claves iniciales
    activeKeyId = 1;
    saInit(tcSa, SPI_TC, INITIAL_TC_KEY);
    saInit(tmSa, SPI_TM, INITIAL_TM_KEY);
    nvs.remove("keys");
    Serial.println("[SAT] Claves: uso las iniciales de secrets.h (ID 1)");
  }
  memset(rec, 0, sizeof(rec));
}

// ----------------------------- Telemetria -----------------------------

static void put16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
static void put32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

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
  if (pktLen == 0 || buildSecureTmFrame(tmSa, frame, mcCount++, vcCount++, pkt, pktLen,
                                        farm::clcw(farmState, VCID), iv) == 0) return;

  udp.beginPacket(groundIP, groundPort);
  udp.write(frame, TM_FRAME_LEN);
  udp.endPacket();
}

void sendHk() {
  uint8_t app[27];
  put32(app, millis() / 1000);
  put16(app + 4, tcAccepted);
  put16(app + 6, tcRejected);
  put16(app + 8, secSpi);
  put16(app + 10, secMac);
  put16(app + 12, secReplay);
  put16(app + 14, farmDiscards);
  put16(app + 16, eventsSuppressed);
  app[18] = payload[0];
  app[19] = payload[1];
  app[20] = payload[2];
  app[21] = (uint8_t)(int8_t)WiFi.RSSI();
  put32(app + 22, ESP.getFreeHeap());
  app[26] = activeKeyId;
  sendTm(SVC_HK, SUB_HK_REPORT, app, sizeof(app));
}

void sendAck(uint16_t pktSeq) {
  uint8_t a[2];
  put16(a, pktSeq);
  sendTm(SVC_VERIF, SUB_ACK_OK, a, 2);
}

void sendAckFail(uint16_t pktSeq, uint8_t code) {
  uint8_t a[3];
  put16(a, pktSeq);
  a[2] = code;
  sendTm(SVC_VERIF, SUB_ACK_FAIL, a, 3);
}

// Evento de seguridad con limite de frecuencia (cubo de fichas)
void sendSecurityEvent(uint8_t code, uint8_t frameSeq, IPAddress ip, uint16_t port, const uint8_t* iv) {
  if (eventTokens == 0) {
    eventsSuppressed++;
    suppressedPending++;
    return;
  }
  eventTokens--;
  uint8_t app[16];
  app[0] = code;
  app[1] = frameSeq;
  for (int i = 0; i < 4; i++) app[2 + i] = ip[i];
  put16(app + 6, port);
  uint64_t c = iv ? ivToCounter(iv) : 0;
  for (int i = 0; i < 8; i++) app[8 + i] = (uint8_t)(c >> (56 - 8 * i));
  sendTm(SVC_EVENT, SUB_EVENT_HIGH, app, sizeof(app));
}

void refillEventTokens(unsigned long now) {
  if (now - lastRefill < EVENT_REFILL_MS) return;
  lastRefill = now;
  if (eventTokens < EVENT_BURST) eventTokens++;
  // Resumen de lo que no se pudo notificar uno a uno
  if (suppressedPending > 0 && eventTokens > 0) {
    eventTokens--;
    uint8_t app[2];
    put16(app, suppressedPending);
    sendTm(SVC_EVENT, SUB_EVENTS_SUPPRESSED, app, 2);
    Serial.printf("[SAT] Inundacion: %u eventos resumidos en uno\n", suppressedPending);
    suppressedPending = 0;
  }
}

// ----------------------------- Telecomandos ---------------------------

void rejectLink() {
  tcRejected++;
  flashBar(rgb565(255, 140, 0));
  markCounters();
}

void rejectSecurity(SecError err, const TcFrame& f, IPAddress ip, uint16_t port, const uint8_t* iv) {
  if (err == SEC_ERR_MAC) secMac++;
  else if (err == SEC_ERR_REPLAY) secReplay++;
  else secSpi++;
  sendSecurityEvent((uint8_t)err, f.seq, ip, port, iv);
  flashBar(rgb565(255, 0, 0));
  markCounters();
}

// Gestion de claves: subir (OTAR) y activar
bool handleKeys(uint8_t sub, const uint8_t* app, size_t appLen, uint16_t pktSeq) {
  if (sub == SUB_OTAR_UPLOAD) {
    if (appLen != 1 + OTAR_BLOCK_LEN) {
      sendAckFail(pktSeq, FAIL_BAD_DATA);
      return false;
    }
    uint8_t id = app[0];
    if (id <= activeKeyId) {   // nunca volver a una clave anterior (rollback)
      sendAckFail(pktSeq, FAIL_OTAR_OLD_ID);
      Serial.printf("[SAT] OTAR rechazado: el ID %u no es mayor que el activo (%u)\n", id, activeKeyId);
      return false;
    }
    if (!otarUnwrap(kekCtx, id, app + 1, pendingTc, pendingTm)) {
      sendAckFail(pktSeq, FAIL_OTAR_INVALID);
      Serial.println("[SAT] OTAR rechazado: el bloque no se descifra con la KEK");
      return false;
    }
    pendingKeyId = id;
    Serial.printf("[SAT] OTAR: claves con ID %u recibidas y pendientes de activar\n", id);
    sendAck(pktSeq);
    return true;
  } else if (sub == SUB_OTAR_ACTIVATE) {
    if (appLen != 1) {
      sendAckFail(pktSeq, FAIL_BAD_DATA);
      return false;
    }
    if (pendingKeyId == 0 || app[0] != pendingKeyId) {
      sendAckFail(pktSeq, FAIL_OTAR_NO_PENDING);
      return false;
    }
    if (!saSetKey(tcSa, pendingTc) || !saSetKey(tmSa, pendingTm)) {
      Serial.println("[SAT] ERROR: no pude cargar las claves nuevas");
      sendAckFail(pktSeq, FAIL_OTAR_INVALID);
      return false;
    }
    activeKeyId = pendingKeyId;
    saveActiveKeys(pendingTc, pendingTm);
    memset(pendingTc, 0, KEY_LEN);   // destruir las copias en RAM
    memset(pendingTm, 0, KEY_LEN);
    pendingKeyId = 0;
    Serial.printf("[SAT] Claves ID %u ACTIVAS. Las anteriores quedan destruidas.\n", activeKeyId);
    drawHeader();
    sendAck(pktSeq);   // esta TM ya sale con la clave nueva
    return true;
  }
  sendAckFail(pktSeq, FAIL_UNKNOWN_SERVICE);
  return false;
}

void executePacket(const uint8_t* buf, size_t len) {
  SpacePacket p;
  if (!parseSpacePacket(buf, len, p) || p.type != 1 || p.apid != APID_SAT || p.dataLen < 2) {
    tcRejected++;
    sendAckFail(0xFFFF, FAIL_BAD_PACKET);
    return;
  }
  uint8_t svc = p.data[0], sub = p.data[1];
  const uint8_t* app = p.data + 2;
  size_t appLen = p.dataLen - 2;

  if (svc == SVC_TEST && sub == SUB_PING) {
    sendTm(SVC_TEST, SUB_PONG, nullptr, 0);
  } else if (svc == SVC_PAYLOAD && sub == SUB_SET_COLOR) {
    if (appLen != 3) {
      tcRejected++;
      sendAckFail(p.seqCount, FAIL_BAD_DATA);
      return;
    }
    memcpy(payload, app, 3);
    drawPayload();
    sendAck(p.seqCount);
  } else if (svc == SVC_HK && sub == SUB_HK_REQUEST) {
    sendHk();
  } else if (svc == SVC_KEYS) {
    if (!handleKeys(sub, app, appLen, p.seqCount)) {
      tcRejected++;
      return;
    }
  } else {
    tcRejected++;
    sendAckFail(p.seqCount, FAIL_UNKNOWN_SERVICE);
    return;
  }
  tcAccepted++;
}

void handleTc(const uint8_t* buf, size_t len, IPAddress ip, uint16_t port) {
  // 1) Trama TC (CRC, SCID, canal...)
  TcFrame f;
  if (parseTcFrame(buf, len, f) != TC_OK) {
    rejectLink();
    return;
  }

  // 2) SDLS: SPI, MAC y anti-replay. Se aplica a TODOS los tipos (AD, BD, BC):
  //    el bypass se salta el FARM, nunca la seguridad.
  uint8_t iv[IV_LEN];
  size_t plainLen = 0;
  SecError sec = processTc(tcSa, buf, f, plain, sizeof(plain), plainLen, iv);
  if (sec != SEC_OK) {
    bool ivRead = (sec == SEC_ERR_MAC || sec == SEC_ERR_REPLAY);
    rejectSecurity(sec, f, ip, port, ivRead ? iv : nullptr);
    return;
  }
  saveLastTcIv();
  groundIP = ip;
  groundPort = port;
  haveGround = true;

  // 3) FARM-1 segun el tipo de trama
  if (f.bypass && f.controlCommand) {                      // BC
    farm::Result r = farm::onBc(farmState, plain, plainLen);
    Serial.printf("[SAT] Comando de control (BC): %s. V(R) = %u\n", farm::resultName(r), farmState.vr);
    if (r == farm::CONTROL_OK) sendAck(0xFFFF);
    else sendAckFail(0xFFFF, FAIL_FARM_CONTROL);
    markCounters();
    return;
  }
  if (!f.bypass) {                                         // AD
    farm::Result r = farm::onAd(farmState, f.seq);
    if (r != farm::ACCEPT) {
      farmDiscards++;
      Serial.printf("[SAT] FARM: trama N(S)=%u descartada (%s). V(R) = %u\n", f.seq, farm::resultName(r),
                    farmState.vr);
      if (r == farm::DISCARD_AHEAD) sendAckFail(0xFFFF, FAIL_FARM_AHEAD);
      if (r == farm::LOCKOUT || r == farm::DISCARD_LOCKED) sendAckFail(0xFFFF, FAIL_FARM_LOCKOUT);
      // Las repetidas se descartan en silencio: la CLCW ya le dice a la tierra que llegaron
      flashBar(rgb565(255, 140, 0));
      markCounters();
      return;
    }
  } else {                                                 // BD
    farm::onBd(farmState);
    Serial.println("[SAT] Trama BD (bypass): se salta el FARM, pero ha pasado SDLS");
  }

  // 4) Ejecutar el Space Packet
  Serial.printf("[SAT] TC aceptado: trama #%u, IV #%llu\n", f.seq, (unsigned long long)ivToCounter(iv));
  executePacket(plain, plainLen);
  flashBar(COLOR_BLANCO);
  markCounters();
}

// ------------------------------- Arranque -----------------------------

void setup() {
  Serial.begin(115200);
  delay(1500);
  Serial.println();
  Serial.println("[SAT] Satelite simulado - fase 3 (SDLS + OTAR + FARM-1)");

  if (!Board_IO_Init()) Serial.println("[SAT] AVISO: no responde el expansor de IO");
  LCD_Init();
  Set_Backlight(80);

  mbedtls_gcm_init(&kekCtx);
  mbedtls_gcm_setkey(&kekCtx, MBEDTLS_CIPHER_ID_AES, KEK, KEY_LEN * 8);
  nvs.begin("sdls", false);
  loadKeys();
  if (nvs.getBytesLength("tciv") == IV_LEN) nvs.getBytes("tciv", tcSa.lastIv, IV_LEN);
  tmIv = nvs.getULong64("tmiv", 0);
  tmIvReserved = tmIv;
  Serial.printf("[SAT] Anti-replay: ultimo IV de TC aceptado #%llu\n", (unsigned long long)ivToCounter(tcSa.lastIv));

  fillRect(0, 0, LCD_WIDTH, LCD_HEIGHT, COLOR_GRIS);
  drawHeader();
  payload[2] = 80;
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

  payload[2] = 0;
  drawPayload();
}

void loop() {
  unsigned long now = millis();

  if (flashUntil != 0 && now > flashUntil) {
    fillRect(0, 288, LCD_WIDTH, 32, COLOR_GRIS);
    flashUntil = 0;
  }
  if (countersDirty && now - lastRedraw >= REDRAW_MS) drawCounters();
  refillEventTokens(now);

  if (haveGround && now - lastHk >= HK_PERIOD_MS) {
    lastHk = now;
    sendHk();
  }

  int size = udp.parsePacket();
  if (size <= 0) {
    delay(2);
    return;
  }
  IPAddress ip = udp.remoteIP();
  uint16_t port = udp.remotePort();
  int n = udp.read(rx, sizeof(rx));
  if (n <= 0) return;
  if (size > (int)sizeof(rx)) {
    rejectLink();
    return;
  }
  handleTc(rx, (size_t)n, ip, port);
}
