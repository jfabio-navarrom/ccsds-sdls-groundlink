// sdls.cpp - implementacion del subconjunto SDLS (ver sdls.h)
#include "sdls.h"
#include <string.h>

namespace sdls {

using namespace ccsds;

const char* secErrorName(SecError e) {
  switch (e) {
    case SEC_OK: return "OK";
    case SEC_ERR_SPI: return "sin SDLS o SPI desconocido";
    case SEC_ERR_MAC: return "MAC invalida";
    case SEC_ERR_REPLAY: return "repeticion (replay)";
    case SEC_ERR_LENGTH: return "demasiado corta para SDLS";
  }
  return "desconocido";
}

bool saInit(SecurityAssociation& sa, uint16_t spi, const uint8_t key[KEY_LEN]) {
  sa.spi = spi;
  memset(sa.lastIv, 0, IV_LEN);
  mbedtls_gcm_init(&sa.gcm);
  return mbedtls_gcm_setkey(&sa.gcm, MBEDTLS_CIPHER_ID_AES, key, KEY_LEN * 8) == 0;
}

void ivFromCounter(uint64_t counter, uint8_t iv[IV_LEN]) {
  memset(iv, 0, 4);
  for (int i = 0; i < 8; i++) iv[4 + i] = (uint8_t)(counter >> (56 - 8 * i));
}

uint64_t ivToCounter(const uint8_t iv[IV_LEN]) {
  uint64_t c = 0;
  for (int i = 0; i < 8; i++) c = (c << 8) | iv[4 + i];
  return c;
}

SecError processTc(SecurityAssociation& sa, const uint8_t* frame, const TcFrame& f,
                   uint8_t* plain, size_t cap, size_t& plainLen, uint8_t iv[IV_LEN]) {
  if (f.dataLen < SEC_OVERHEAD + 1) return SEC_ERR_LENGTH;

  // 1) Security Header: SPI + IV
  const uint8_t* sh = f.data;
  uint16_t spi = ((uint16_t)sh[0] << 8) | sh[1];
  if (spi != sa.spi) return SEC_ERR_SPI;
  memcpy(iv, sh + SPI_LEN, IV_LEN);

  const uint8_t* ct = sh + SEC_HEADER_LEN;
  size_t ctLen = f.dataLen - SEC_OVERHEAD;
  const uint8_t* mac = ct + ctLen;
  if (ctLen > cap) return SEC_ERR_LENGTH;

  // 2) Autenticar y descifrar. AAD = cabecera de trama + Security Header
  size_t aadLen = TC_HEADER_LEN + SEC_HEADER_LEN;
  int rc = mbedtls_gcm_auth_decrypt(&sa.gcm, ctLen, iv, IV_LEN, frame, aadLen,
                                    mac, MAC_LEN, ct, plain);
  if (rc != 0) {
    memset(plain, 0, ctLen);  // no dejar datos sin autenticar a la vista
    return SEC_ERR_MAC;
  }

  // 3) Anti-replay: solo despues de comprobar la MAC, para que una trama
  //    falsa con un IV enorme no pueda mover la ventana.
  if (memcmp(iv, sa.lastIv, IV_LEN) <= 0) return SEC_ERR_REPLAY;

  memcpy(sa.lastIv, iv, IV_LEN);
  plainLen = ctLen;
  return SEC_OK;
}

size_t buildSecureTmFrame(SecurityAssociation& sa, uint8_t* out, uint8_t mcCount, uint8_t vcCount,
                          const uint8_t* packet, size_t packetLen, uint32_t clcw,
                          const uint8_t iv[IV_LEN]) {
  if (packetLen > TM_SDLS_DATA_LEN) return 0;
  size_t rest = TM_SDLS_DATA_LEN - packetLen;
  if (rest != 0 && rest < SP_HEADER_LEN + 1) return 0;

  // Cabecera primaria (igual que en la fase 1)
  out[0] = (uint8_t)((SCID >> 4) & 0x3F);
  out[1] = (uint8_t)(((SCID & 0x0F) << 4) | ((VCID & 0x07) << 1) | 1);
  out[2] = mcCount;
  out[3] = vcCount;
  out[4] = 0x18;
  out[5] = 0x00;

  // Security Header
  uint8_t* sh = out + TM_HEADER_LEN;
  sh[0] = (uint8_t)(sa.spi >> 8);
  sh[1] = (uint8_t)(sa.spi & 0xFF);
  memcpy(sh + SPI_LEN, iv, IV_LEN);

  // Campo de datos en claro: paquete + relleno
  uint8_t plain[TM_SDLS_DATA_LEN];
  memcpy(plain, packet, packetLen);
  if (rest != 0) {
    buildSpacePacket(plain + packetLen, rest, 0, APID_IDLE, 0, nullptr, rest - SP_HEADER_LEN);
    memset(plain + packetLen + SP_HEADER_LEN, 0x55, rest - SP_HEADER_LEN);
  }

  // Cifrar + MAC. AAD = cabecera TM + Security Header
  uint8_t* ct = sh + SEC_HEADER_LEN;
  uint8_t* mac = ct + TM_SDLS_DATA_LEN;
  if (mbedtls_gcm_crypt_and_tag(&sa.gcm, MBEDTLS_GCM_ENCRYPT, TM_SDLS_DATA_LEN, iv, IV_LEN,
                                out, TM_HEADER_LEN + SEC_HEADER_LEN, plain, ct,
                                MAC_LEN, mac) != 0) {
    return 0;
  }

  // OCF (CLCW): fuera de la zona protegida, como en el estandar
  uint8_t* o = mac + MAC_LEN;
  o[0] = (uint8_t)(clcw >> 24);
  o[1] = (uint8_t)(clcw >> 16);
  o[2] = (uint8_t)(clcw >> 8);
  o[3] = (uint8_t)clcw;

  uint16_t crc = crc16(out, TM_FRAME_LEN - TM_FECF_LEN);
  out[TM_FRAME_LEN - 2] = (uint8_t)(crc >> 8);
  out[TM_FRAME_LEN - 1] = (uint8_t)(crc & 0xFF);
  return TM_FRAME_LEN;
}

}  // namespace sdls
