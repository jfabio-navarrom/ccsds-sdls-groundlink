// =====================================================================
//  sdls.h - Space Data Link Security (CCSDS 355.0-B), subset
//
//  Each frame has a Security Header and a Security Trailer:
//
//  TC frame (ground -> satellite), variable length:
//    [TC header 5][SPI 2][IV 12][ENCRYPTED Space Packet][MAC 16][FECF 2]
//
//  TM frame (satellite -> ground), always 128 bytes:
//    [TM header 6][SPI 2][IV 12][ENCRYPTED data 86][MAC 16][CLCW 4][FECF 2]
//
//  - Algorithm: AES-256-GCM (authenticated encryption).
//  - Authenticated data, not encrypted (AAD): frame header + SPI + IV.
//    So nobody can change the SCID, the channel or the N(S) without breaking the MAC.
//  - The IV is also the anti-replay sequence number (ARSN): the
//    satellite only accepts an IV strictly higher than the last accepted one.
//  - One key per direction (SPI 1 for TC, SPI 2 for TM): with the same
//    key in both directions, ground and satellite could repeat an IV,
//    and in GCM a repeated IV with the same key breaks the security.
//
//  Uses mbedTLS, which comes with the Arduino ESP32 core. It also compiles on
//  a PC (tests/native) with libmbedtls-dev.
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

// Data of a protected TM frame (see the drawing above)
const size_t TM_SDLS_DATA_LEN = ccsds::TM_FRAME_LEN - ccsds::TM_HEADER_LEN - SEC_OVERHEAD -
                                ccsds::TM_OCF_LEN - ccsds::TM_FECF_LEN;  // 86

// Rejection reasons (also the security event codes)
enum SecError {
  SEC_OK = 0,
  SEC_ERR_SPI = 20,     // no SDLS header or unknown SPI
  SEC_ERR_MAC = 21,     // the MAC does not match: wrong key or modified frame
  SEC_ERR_REPLAY = 22,  // IV not higher than the last accepted one: replay
  SEC_ERR_LENGTH = 23,  // too short to carry SDLS
};
const char* secErrorName(SecError e);

// Security association (SA): SPI + key + anti-replay state
struct SecurityAssociation {
  uint16_t spi;
  mbedtls_gcm_context gcm;
  uint8_t lastIv[IV_LEN];   // last accepted IV (anti-replay), only for receiving
};

bool saInit(SecurityAssociation& sa, uint16_t spi, const uint8_t key[KEY_LEN]);

// Processes the data field of a TC frame that is already checked (CRC, SCID...).
//   frame/frameLen: full frame (the header is part of the authenticated data)
//   f:              result of ccsds::parseTcFrame
//   plain:          the decrypted Space Packet is written here (cap bytes)
//   iv:             the received IV is written here
// It only updates sa.lastIv if it returns SEC_OK: a fake frame never moves
// the anti-replay window.
SecError processTc(SecurityAssociation& sa, const uint8_t* frame, const ccsds::TcFrame& f,
                   uint8_t* plain, size_t cap, size_t& plainLen, uint8_t iv[IV_LEN]);

// Builds a protected TM frame of TM_FRAME_LEN bytes. The caller gives an
// IV never used before with this key. Returns TM_FRAME_LEN or 0.
size_t buildSecureTmFrame(SecurityAssociation& sa, uint8_t* out, uint8_t mcCount, uint8_t vcCount,
                          const uint8_t* packet, size_t packetLen, uint32_t clcw,
                          const uint8_t iv[IV_LEN]);

// 12 byte IV = 4 zero bytes + 64 bit counter (big-endian)
void ivFromCounter(uint64_t counter, uint8_t iv[IV_LEN]);
uint64_t ivToCounter(const uint8_t iv[IV_LEN]);

}  // namespace sdls
