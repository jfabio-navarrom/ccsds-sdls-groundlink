// farm.cpp - simple FARM-1 (see farm.h)
#include "farm.h"

namespace farm {

const char* resultName(Result r) {
  switch (r) {
    case ACCEPT: return "accepted";
    case DISCARD_AHEAD: return "ahead: one frame is missing, retransmit";
    case DISCARD_DUPLICATE: return "duplicate: it was already executed";
    case LOCKOUT: return "out of window: FARM lockout";
    case DISCARD_LOCKED: return "FARM in lockout: Unlock is needed";
    case CONTROL_OK: return "control command executed";
    case CONTROL_BAD: return "invalid control command";
  }
  return "unknown";
}

Result onAd(State& s, uint8_t ns) {
  if (s.lockout) return DISCARD_LOCKED;
  if (ns == s.vr) {
    s.vr++;
    s.retransmit = false;
    return ACCEPT;
  }
  uint8_t ahead = (uint8_t)(ns - s.vr);
  uint8_t behind = (uint8_t)(s.vr - ns);
  if (ahead < POS_WINDOW) {
    s.retransmit = true;
    return DISCARD_AHEAD;
  }
  if (behind <= NEG_WINDOW) return DISCARD_DUPLICATE;
  s.lockout = true;
  return LOCKOUT;
}

Result onBd(State& s) {
  s.farmB = (s.farmB + 1) & 0x03;
  return ACCEPT;
}

Result onBc(State& s, const uint8_t* data, size_t len) {
  if (len == 1 && data[0] == 0x00) {  // Unlock
    s.lockout = false;
    s.retransmit = false;
    s.wait = false;
    s.farmB = (s.farmB + 1) & 0x03;
    return CONTROL_OK;
  }
  if (len == 3 && data[0] == 0x82 && data[1] == 0x00) {  // Set V(R)
    if (s.lockout) return CONTROL_BAD;  // by the standard, only without lockout
    s.vr = data[2];
    s.retransmit = false;
    s.farmB = (s.farmB + 1) & 0x03;
    return CONTROL_OK;
  }
  return CONTROL_BAD;
}

uint32_t clcw(const State& s, uint8_t vcid) {
  return (1UL << 24) |                        // COP in use = 01 (COP-1)
         (((uint32_t)vcid & 0x3F) << 18) |
         ((uint32_t)s.lockout << 13) |
         ((uint32_t)s.wait << 12) |
         ((uint32_t)s.retransmit << 11) |
         ((uint32_t)(s.farmB & 0x03) << 9) |
         s.vr;
}

}  // namespace farm
