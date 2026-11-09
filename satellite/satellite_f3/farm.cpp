// farm.cpp - FARM-1 simplificado (ver farm.h)
#include "farm.h"

namespace farm {

const char* resultName(Result r) {
  switch (r) {
    case ACCEPT: return "aceptada";
    case DISCARD_AHEAD: return "adelantada: falta una trama, retransmitir";
    case DISCARD_DUPLICATE: return "repetida: ya se habia ejecutado";
    case LOCKOUT: return "fuera de ventana: FARM bloqueado (lockout)";
    case DISCARD_LOCKED: return "FARM bloqueado: hace falta Unlock";
    case CONTROL_OK: return "comando de control ejecutado";
    case CONTROL_BAD: return "comando de control no valido";
  }
  return "desconocido";
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
    if (s.lockout) return CONTROL_BAD;  // segun el estandar, solo sin lockout
    s.vr = data[2];
    s.retransmit = false;
    s.farmB = (s.farmB + 1) & 0x03;
    return CONTROL_OK;
  }
  return CONTROL_BAD;
}

uint32_t clcw(const State& s, uint8_t vcid) {
  return (1UL << 24) |                        // COP en uso = 01 (COP-1)
         (((uint32_t)vcid & 0x3F) << 18) |
         ((uint32_t)s.lockout << 13) |
         ((uint32_t)s.wait << 12) |
         ((uint32_t)s.retransmit << 11) |
         ((uint32_t)(s.farmB & 0x03) << 9) |
         s.vr;
}

}  // namespace farm
