// =====================================================================
//  farm.h - FARM-1 (COP-1, CCSDS 232.1-B), simple version
//
//  The FARM lives in the satellite and makes sure that AD telecommands
//  run in order, with no gaps and no duplicates. For this it uses the
//  frame sequence number N(S) and its own counter V(R): the number
//  of the next frame it expects.
//
//  Frame types (flags in the TC header):
//    AD (bypass 0, control 0): sequenced, goes through the FARM
//    BD (bypass 1, control 0): "expedited", skips the FARM (emergencies)
//    BC (bypass 1, control 1): control command for the FARM itself
//                              (Unlock, Set V(R))
//
//  NOTE: the FARM is NOT a security mechanism. N(S) has 8 bits, travels in
//  clear and wraps every 256 frames. Security comes from SDLS, which
//  runs BEFORE it: a BD or BC frame without a valid MAC does not pass either.
//
//  It does not depend on Arduino: it compiles on the PC for the tests.
// =====================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace farm {

const uint8_t WINDOW = 10;           // FARM window (W)
const uint8_t POS_WINDOW = WINDOW / 2;  // PW: frames "ahead" that ask for retransmit
const uint8_t NEG_WINDOW = WINDOW / 2;  // NW: repeated frames that are just dropped

struct State {
  uint8_t vr = 0;           // V(R): next expected N(S)
  bool lockout = false;     // lockout: an Unlock is needed
  bool wait = false;        // no buffer (not used: always false)
  bool retransmit = false;  // a frame is missing: ground must retransmit
  uint8_t farmB = 0;        // counter of accepted BD/BC frames (2 bits)
};

enum Result {
  ACCEPT = 0,          // AD in order, or BD: execute
  DISCARD_AHEAD,       // AD ahead (gap): drop it and ask for retransmit
  DISCARD_DUPLICATE,   // AD already received: drop it
  LOCKOUT,             // AD outside every window: the FARM goes to lockout
  DISCARD_LOCKED,      // the FARM was already in lockout
  CONTROL_OK,          // BC executed (Unlock or Set V(R))
  CONTROL_BAD,         // unknown or not allowed BC
};

const char* resultName(Result r);

// AD frame with sequence number ns
Result onAd(State& s, uint8_t ns);
// BD frame (bypass)
Result onBd(State& s);
// BC frame. Commands: Unlock = {0x00}; Set V(R) = {0x82, 0x00, N}
Result onBc(State& s, const uint8_t* data, size_t len);

// CLCW with the FARM state (goes in the OCF of each TM frame)
uint32_t clcw(const State& s, uint8_t vcid);

}  // namespace farm
