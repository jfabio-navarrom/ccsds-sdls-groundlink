// =====================================================================
//  sdls.h - Space Data Link Security (CCSDS 355.0-B), subconjunto
//
//  Cada trama lleva una Security Header y una Security Trailer:
//
//  Trama TC (tierra -> satelite), longitud variable:
//    [cabecera TC 5][SPI 2][IV 12][Space Packet CIFRADO][MAC 16][FECF 2]
//
//  Trama TM (satelite -> tierra), 128 bytes fijos:
//    [cabecera TM 6][SPI 2][IV 12][datos CIFRADOS 86][MAC 16][CLCW 4][FECF 2]
//
//  - Algoritmo: AES-256-GCM (cifrado autenticado).
//  - Datos autenticados sin cifrar (AAD): cabecera de trama + SPI + IV.
//    Asi nadie puede cambiar el SCID, el canal o el N(S) sin romper la MAC.
//  - El IV es tambien el numero de secuencia anti-replay (ARSN): el
//    satelite solo acepta un IV estrictamente mayor que el ultimo aceptado.
//  - Una clave por sentido (SPI 1 para TC, SPI 2 para TM): con la misma
//    clave en los dos sentidos, tierra y satelite podrian repetir un IV,
//    y en GCM repetir IV con la misma clave rompe la seguridad.
//
//  Usa mbedTLS, que viene con el core ESP32 de Arduino. Tambien compila en
//  un PC (tests/native) con libmbedtls-dev.
// =====================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "mbedtls/gcm.h"
#include "ccsds.h"

namespace sdls {

const size_t SPI_LEN = 2;
const size_t IV_LEN = 12;
const size_t MAC_LEN = 16;
const size_t KEY_LEN = 32;                       // AES-256
const size_t SEC_HEADER_LEN = SPI_LEN + IV_LEN;  // 14
const size_t SEC_OVERHEAD = SEC_HEADER_LEN + MAC_LEN;  // 30

const uint16_t SPI_TC = 1;
const uint16_t SPI_TM = 2;

// Datos de una trama TM protegida (ver dibujo de arriba)
const size_t TM_SDLS_DATA_LEN = ccsds::TM_FRAME_LEN - ccsds::TM_HEADER_LEN - SEC_OVERHEAD -
                                ccsds::TM_OCF_LEN - ccsds::TM_FECF_LEN;  // 86

// Motivos de rechazo (tambien son los codigos de evento de seguridad)
enum SecError {
  SEC_OK = 0,
  SEC_ERR_SPI = 20,     // sin cabecera SDLS o SPI desconocido
  SEC_ERR_MAC = 21,     // la MAC no cuadra: clave incorrecta o trama manipulada
  SEC_ERR_REPLAY = 22,  // IV no mayor que el ultimo aceptado: repeticion
  SEC_ERR_LENGTH = 23,  // demasiado corta para llevar SDLS
};
const char* secErrorName(SecError e);

// Asociacion de seguridad (SA): SPI + clave + estado anti-replay
struct SecurityAssociation {
  uint16_t spi;
  mbedtls_gcm_context gcm;
  uint8_t lastIv[IV_LEN];   // ultimo IV aceptado (anti-replay), solo para recepcion
};

bool saInit(SecurityAssociation& sa, uint16_t spi, const uint8_t key[KEY_LEN]);

// Procesa el campo de datos de una trama TC ya validada (CRC, SCID...).
//   frame/frameLen: trama completa (la cabecera va en los datos autenticados)
//   f:              resultado de ccsds::parseTcFrame
//   plain:          aqui se escribe el Space Packet descifrado (cap bytes)
//   iv:             aqui se escribe el IV recibido
// Solo si devuelve SEC_OK actualiza sa.lastIv: una trama falsa nunca mueve
// la ventana anti-replay.
SecError processTc(SecurityAssociation& sa, const uint8_t* frame, const ccsds::TcFrame& f,
                   uint8_t* plain, size_t cap, size_t& plainLen, uint8_t iv[IV_LEN]);

// Construye una trama TM protegida de TM_FRAME_LEN bytes. El llamador da un
// IV que nunca haya usado antes con esta clave. Devuelve TM_FRAME_LEN o 0.
size_t buildSecureTmFrame(SecurityAssociation& sa, uint8_t* out, uint8_t mcCount, uint8_t vcCount,
                          const uint8_t* packet, size_t packetLen, uint32_t clcw,
                          const uint8_t iv[IV_LEN]);

// IV de 12 bytes = 4 bytes a cero + contador de 64 bits (big-endian)
void ivFromCounter(uint64_t counter, uint8_t iv[IV_LEN]);
uint64_t ivToCounter(const uint8_t iv[IV_LEN]);

}  // namespace sdls
