// ccsds.cpp - implementacion del subconjunto CCSDS (ver ccsds.h)
#include "ccsds.h"
#include <string.h>

namespace ccsds {

uint16_t crc16(const uint8_t* data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int b = 0; b < 8; b++) {
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
  }
  return crc;
}

TcError parseTcFrame(const uint8_t* buf, size_t len, TcFrame& out) {
  if (len < TC_HEADER_LEN + TC_FECF_LEN + 1) return TC_ERR_SHORT;

  uint8_t version = buf[0] >> 6;
  if (version != 0) return TC_ERR_VERSION;

  size_t frameLen = ((((size_t)buf[2] & 0x03) << 8) | buf[3]) + 1;
  if (frameLen != len) return TC_ERR_LENGTH;

  uint16_t received = ((uint16_t)buf[len - 2] << 8) | buf[len - 1];
  if (crc16(buf, len - 2) != received) return TC_ERR_CRC;

  out.bypass = (buf[0] >> 5) & 1;
  out.controlCommand = (buf[0] >> 4) & 1;
  out.scid = (((uint16_t)buf[0] & 0x03) << 8) | buf[1];
  out.vcid = buf[2] >> 2;
  out.seq = buf[4];
  out.data = buf + TC_HEADER_LEN;
  out.dataLen = len - TC_HEADER_LEN - TC_FECF_LEN;

  if (out.scid != SCID) return TC_ERR_SCID;
  if (out.vcid != VCID) return TC_ERR_VCID;
  return TC_OK;
}

const char* tcErrorName(TcError e) {
  switch (e) {
    case TC_OK: return "OK";
    case TC_ERR_SHORT: return "trama demasiado corta";
    case TC_ERR_VERSION: return "version incorrecta";
    case TC_ERR_LENGTH: return "longitud incorrecta";
    case TC_ERR_CRC: return "CRC incorrecto";
    case TC_ERR_SCID: return "SCID de otro satelite";
    case TC_ERR_VCID: return "canal virtual desconocido";
  }
  return "desconocido";
}

bool parseSpacePacket(const uint8_t* buf, size_t len, SpacePacket& out) {
  if (len < SP_HEADER_LEN + 1) return false;
  if ((buf[0] >> 5) != 0) return false;  // version 0
  size_t dataLen = (((size_t)buf[4] << 8) | buf[5]) + 1;
  if (SP_HEADER_LEN + dataLen != len) return false;

  out.type = (buf[0] >> 4) & 1;
  out.secondaryHeader = (buf[0] >> 3) & 1;
  out.apid = (((uint16_t)buf[0] & 0x07) << 8) | buf[1];
  out.seqFlags = buf[2] >> 6;
  out.seqCount = (((uint16_t)buf[2] & 0x3F) << 8) | buf[3];
  out.data = buf + SP_HEADER_LEN;
  out.dataLen = dataLen;
  return true;
}

size_t buildSpacePacket(uint8_t* out, size_t cap, uint8_t type, uint16_t apid,
                        uint16_t seqCount, const uint8_t* data, size_t dataLen) {
  if (dataLen < 1 || dataLen > 65536 || SP_HEADER_LEN + dataLen > cap) return 0;
  out[0] = (uint8_t)(((type & 1) << 4) | ((apid >> 8) & 0x07));
  out[1] = (uint8_t)(apid & 0xFF);
  out[2] = (uint8_t)(0xC0 | ((seqCount >> 8) & 0x3F));  // 11 = paquete no segmentado
  out[3] = (uint8_t)(seqCount & 0xFF);
  size_t l = dataLen - 1;
  out[4] = (uint8_t)(l >> 8);
  out[5] = (uint8_t)(l & 0xFF);
  if (data != nullptr) memcpy(out + SP_HEADER_LEN, data, dataLen);
  return SP_HEADER_LEN + dataLen;
}

uint32_t buildClcw(uint8_t vcid, uint8_t reportValue) {
  // Tipo 0, version 00, status 000, COP en uso = 01, VCID (6 bits),
  // flags a 0, contador FARM-B 00, y el report value = V(R)
  return (1UL << 24) | (((uint32_t)vcid & 0x3F) << 18) | reportValue;
}

size_t buildTmFrame(uint8_t* out, uint8_t mcCount, uint8_t vcCount,
                    const uint8_t* packet, size_t packetLen, uint32_t clcw) {
  if (packetLen > TM_DATA_LEN) return 0;
  size_t rest = TM_DATA_LEN - packetLen;
  if (rest != 0 && rest < SP_HEADER_LEN + 1) return 0;  // no cabe un paquete de relleno

  // Cabecera primaria (6 bytes)
  out[0] = (uint8_t)((SCID >> 4) & 0x3F);                         // version 00 + SCID alto
  out[1] = (uint8_t)(((SCID & 0x0F) << 4) | ((VCID & 0x07) << 1) | 1);  // ... + VCID + OCF presente
  out[2] = mcCount;
  out[3] = vcCount;
  out[4] = 0x18;  // sin cabecera secundaria, paquetes en orden, segment length id = 11
  out[5] = 0x00;  // first header pointer = 0: el paquete empieza al inicio del campo de datos

  // Campo de datos: nuestro paquete + paquete de relleno
  uint8_t* d = out + TM_HEADER_LEN;
  memcpy(d, packet, packetLen);
  if (rest != 0) {
    buildSpacePacket(d + packetLen, rest, 0, APID_IDLE, 0, nullptr, rest - SP_HEADER_LEN);
    memset(d + packetLen + SP_HEADER_LEN, 0x55, rest - SP_HEADER_LEN);
  }

  // OCF con la CLCW
  uint8_t* o = out + TM_HEADER_LEN + TM_DATA_LEN;
  o[0] = (uint8_t)(clcw >> 24);
  o[1] = (uint8_t)(clcw >> 16);
  o[2] = (uint8_t)(clcw >> 8);
  o[3] = (uint8_t)clcw;

  // FECF
  uint16_t crc = crc16(out, TM_FRAME_LEN - TM_FECF_LEN);
  out[TM_FRAME_LEN - 2] = (uint8_t)(crc >> 8);
  out[TM_FRAME_LEN - 1] = (uint8_t)(crc & 0xFF);
  return TM_FRAME_LEN;
}

}  // namespace ccsds
