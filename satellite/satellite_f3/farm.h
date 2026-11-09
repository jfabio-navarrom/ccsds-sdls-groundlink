// =====================================================================
//  farm.h - FARM-1 (COP-1, CCSDS 232.1-B), version simplificada
//
//  El FARM vive en el satelite y garantiza que los telecomandos de tipo AD
//  se ejecutan en orden, sin huecos y sin duplicados. Para eso usa el
//  numero de secuencia de trama N(S) y su propio contador V(R): el numero
//  de la siguiente trama que espera.
//
//  Tipos de trama (flags de la cabecera TC):
//    AD (bypass 0, control 0): secuenciada, pasa por el FARM
//    BD (bypass 1, control 0): "expedita", se salta el FARM (emergencias)
//    BC (bypass 1, control 1): comando de control del propio FARM
//                              (Unlock, Set V(R))
//
//  OJO: el FARM NO es un mecanismo de seguridad. N(S) tiene 8 bits, va en
//  claro y da la vuelta cada 256 tramas. La seguridad la pone SDLS, que se
//  aplica ANTES: una trama BD o BC sin MAC valida tampoco pasa.
//
//  No depende de Arduino: se compila en el PC para los tests.
// =====================================================================
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace farm {

const uint8_t WINDOW = 10;           // ventana del FARM (W)
const uint8_t POS_WINDOW = WINDOW / 2;  // PW: tramas "adelantadas" que piden retransmision
const uint8_t NEG_WINDOW = WINDOW / 2;  // NW: tramas repetidas que se descartan sin mas

struct State {
  uint8_t vr = 0;           // V(R): siguiente N(S) esperado
  bool lockout = false;     // bloqueado: hace falta un Unlock
  bool wait = false;        // sin buffer (no lo usamos: siempre false)
  bool retransmit = false;  // falta una trama: la tierra debe retransmitir
  uint8_t farmB = 0;        // contador de tramas BD/BC aceptadas (2 bits)
};

enum Result {
  ACCEPT = 0,          // AD en orden, o BD: ejecutar
  DISCARD_AHEAD,       // AD adelantada (hueco): descartar y pedir retransmision
  DISCARD_DUPLICATE,   // AD ya recibida: descartar
  LOCKOUT,             // AD fuera de toda ventana: el FARM se bloquea
  DISCARD_LOCKED,      // el FARM ya estaba bloqueado
  CONTROL_OK,          // BC ejecutado (Unlock o Set V(R))
  CONTROL_BAD,         // BC desconocido o no permitido
};

const char* resultName(Result r);

// Trama AD con numero de secuencia ns
Result onAd(State& s, uint8_t ns);
// Trama BD (bypass)
Result onBd(State& s);
// Trama BC. Comandos: Unlock = {0x00}; Set V(R) = {0x82, 0x00, N}
Result onBc(State& s, const uint8_t* data, size_t len);

// CLCW con el estado del FARM (va en el OCF de cada trama TM)
uint32_t clcw(const State& s, uint8_t vcid);

}  // namespace farm
