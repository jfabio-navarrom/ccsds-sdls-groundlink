// =====================================================================
//  ccsds.h - Subconjunto de CCSDS para el satelite (fases 1 a 3)
//
//  - TC Space Data Link Protocol (CCSDS 232.0-B): tramas de telecomando
//  - TM Space Data Link Protocol (CCSDS 132.0-B): tramas de telemetria
//  - Space Packet Protocol (CCSDS 133.0-B): paquetes dentro de las tramas
//  - CRC-16 (FECF) y CLCW (palabra de control del enlace, COP-1)
//
//  Este archivo no depende de Arduino: se compila tambien en un PC para
//  los tests (tests/native). La misma pila esta escrita en Python en
//  ground/ccsds/frames.py, y los tests comprueban que ambas se entienden.
// =====================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace ccsds {

// Identificadores de nuestra "mision"
const uint16_t SCID = 0x0C5;       // Spacecraft ID (10 bits): "C5"
const uint8_t  VCID = 0;           // canal virtual por defecto
const uint16_t APID_SAT = 0x010;   // aplicacion de a bordo
const uint16_t APID_IDLE = 0x7FF;  // paquete de relleno (idle)

const size_t TC_HEADER_LEN = 5;
const size_t TC_FECF_LEN = 2;
const size_t TM_FRAME_LEN = 128;   // las tramas TM tienen longitud fija
const size_t TM_HEADER_LEN = 6;
const size_t TM_OCF_LEN = 4;
const size_t TM_FECF_LEN = 2;
const size_t TM_DATA_LEN = TM_FRAME_LEN - TM_HEADER_LEN - TM_OCF_LEN - TM_FECF_LEN;  // 116
const size_t SP_HEADER_LEN = 6;

// CRC-16-CCITT (polinomio 0x1021, valor inicial 0xFFFF), el FECF de CCSDS
uint16_t crc16(const uint8_t* data, size_t len);

// ----- Tramas TC (tierra -> satelite) -----
enum TcError {
  TC_OK = 0,
  TC_ERR_SHORT,    // demasiado corta
  TC_ERR_VERSION,  // version de trama distinta de 0
  TC_ERR_LENGTH,   // la longitud de la cabecera no cuadra con lo recibido
  TC_ERR_CRC,      // el CRC no coincide (trama corrupta)
  TC_ERR_SCID,     // va dirigida a otro satelite
  TC_ERR_VCID,     // canal virtual desconocido
};

struct TcFrame {
  bool bypass;          // flag de bypass (trama tipo BD)
  bool controlCommand;  // flag de comando de control
  uint16_t scid;
  uint8_t vcid;
  uint8_t seq;          // numero de secuencia de trama N(S)
  const uint8_t* data;  // campo de datos (dentro del buffer original)
  size_t dataLen;
};

TcError parseTcFrame(const uint8_t* buf, size_t len, TcFrame& out);
const char* tcErrorName(TcError e);

// ----- Space Packets -----
struct SpacePacket {
  uint8_t type;          // 1 = telecomando, 0 = telemetria
  bool secondaryHeader;
  uint16_t apid;
  uint8_t seqFlags;
  uint16_t seqCount;
  const uint8_t* data;   // campo de datos del paquete
  size_t dataLen;
};

// Exige que el paquete ocupe exactamente len bytes
bool parseSpacePacket(const uint8_t* buf, size_t len, SpacePacket& out);
// Devuelve la longitud total escrita, o 0 si no cabe
size_t buildSpacePacket(uint8_t* out, size_t cap, uint8_t type, uint16_t apid,
                        uint16_t seqCount, const uint8_t* data, size_t dataLen);

// ----- Tramas TM (satelite -> tierra) -----
uint32_t buildClcw(uint8_t vcid, uint8_t reportValue);
// Escribe TM_FRAME_LEN bytes en out. Devuelve TM_FRAME_LEN, o 0 si el paquete no cabe.
size_t buildTmFrame(uint8_t* out, uint8_t mcCount, uint8_t vcCount,
                    const uint8_t* packet, size_t packetLen, uint32_t clcw);

}  // namespace ccsds
