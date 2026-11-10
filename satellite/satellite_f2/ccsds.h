// =====================================================================
//  ccsds.h - CCSDS subset for the satellite (phases 1 and 2)
//
//  - TC Space Data Link Protocol (CCSDS 232.0-B): telecommand frames
//  - TM Space Data Link Protocol (CCSDS 132.0-B): telemetry frames
//  - Space Packet Protocol (CCSDS 133.0-B): packets inside the frames
//  - CRC-16 (FECF) and CLCW (link control word, COP-1)
//
//  This file does not depend on Arduino: it also compiles on a PC for
//  the tests (tests/native). The same stack is written in Python in
//  ground/ccsds/frames.py, and the tests check that both understand each other.
// =====================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace ccsds {

// Identifiers of our "mission"
const uint16_t SCID = 0x0C5;       // Spacecraft ID (10 bits): "C5"
const uint8_t  VCID = 0;           // default virtual channel
const uint16_t APID_SAT = 0x010;   // on-board application
const uint16_t APID_IDLE = 0x7FF;  // idle packet

const size_t TC_HEADER_LEN = 5;
const size_t TC_FECF_LEN = 2;
const size_t TM_FRAME_LEN = 128;   // TM frames have a fixed length
const size_t TM_HEADER_LEN = 6;
const size_t TM_OCF_LEN = 4;
const size_t TM_FECF_LEN = 2;
const size_t TM_DATA_LEN = TM_FRAME_LEN - TM_HEADER_LEN - TM_OCF_LEN - TM_FECF_LEN;  // 116
const size_t SP_HEADER_LEN = 6;

// CRC-16-CCITT (polynomial 0x1021, initial value 0xFFFF), the CCSDS FECF
uint16_t crc16(const uint8_t* data, size_t len);

// ----- TC frames (ground -> satellite) -----
enum TcError {
  TC_OK = 0,
  TC_ERR_SHORT,    // too short
  TC_ERR_VERSION,  // frame version is not 0
  TC_ERR_LENGTH,   // the header length does not match what was received
  TC_ERR_CRC,      // the CRC does not match (corrupted frame)
  TC_ERR_SCID,     // it is for another spacecraft
  TC_ERR_VCID,     // unknown virtual channel
};

struct TcFrame {
  bool bypass;          // bypass flag (BD frame type)
  bool controlCommand;  // control command flag
  uint16_t scid;
  uint8_t vcid;
  uint8_t seq;          // frame sequence number N(S)
  const uint8_t* data;  // data field (inside the original buffer)
  size_t dataLen;
};

TcError parseTcFrame(const uint8_t* buf, size_t len, TcFrame& out);
const char* tcErrorName(TcError e);

// ----- Space Packets -----
struct SpacePacket {
  uint8_t type;          // 1 = telecommand, 0 = telemetry
  bool secondaryHeader;
  uint16_t apid;
  uint8_t seqFlags;
  uint16_t seqCount;
  const uint8_t* data;   // packet data field
  size_t dataLen;
};

// Requires the packet to be exactly len bytes
bool parseSpacePacket(const uint8_t* buf, size_t len, SpacePacket& out);
// Returns the total length written, or 0 if it does not fit
size_t buildSpacePacket(uint8_t* out, size_t cap, uint8_t type, uint16_t apid,
                        uint16_t seqCount, const uint8_t* data, size_t dataLen);

// ----- TM frames (satellite -> ground) -----
uint32_t buildClcw(uint8_t vcid, uint8_t reportValue);
// Writes TM_FRAME_LEN bytes in out. Returns TM_FRAME_LEN, or 0 if the packet does not fit.
size_t buildTmFrame(uint8_t* out, uint8_t mcCount, uint8_t vcCount,
                    const uint8_t* packet, size_t packetLen, uint32_t clcw);

}  // namespace ccsds
