# ADR-011: COP-1 por debajo de SDLS y límite de eventos ante inundación

- **Estado:** aceptada
- **Fecha:** 2026-11-09

## Contexto

El enlace UDP pierde tramas (ADR-007). Sin un protocolo de retransmisión, un telecomando perdido simplemente no se ejecuta, y la tierra no lo sabe. CCSDS resuelve esto con COP-1: FOP en tierra y FARM-1 a bordo. Al combinar COP-1 con SDLS aparecen tres preguntas de diseño:

1. ¿En qué orden se aplican SDLS y FARM?
2. ¿Cómo se retransmite si el anti-replay rechaza IV repetidos?
3. Si cada rechazo de seguridad genera un evento, un atacante puede inundar el enlace.

## Decisión

- **Orden: primero SDLS y después FARM**, para todos los tipos de trama:
  - AD (secuenciada) y BD (bypass) llevan servicios;
  - BC (control) lleva Unlock y Set V(R).
  - El bypass se salta el FARM, nunca la seguridad.
- **Retransmisión: misma N(S) con un IV nuevo.** El FOP vuelve a proteger la trama en cada intento. Si el original sí llegó, el FARM descarta la copia como duplicada (descarte silencioso).
- **FOP de una trama cada vez** (ventana 1): la tierra no envía la siguiente hasta que la CLCW confirma la anterior. Hace como máximo 4 intentos de 1,5 s.
- **Lockout:** se desbloquea con `sync` (Unlock + Set V(R)), que el operador ejecuta a propósito. La tierra no lo hace sola.
- **Límite de eventos:** cubo de fichas con ráfagas de 3 y 1 evento por segundo. Los eventos que no caben se cuentan y se resumen en un único aviso (servicio 5,5). Además, la pantalla se redibuja como máximo cada 150 ms y no se escribe en el puerto serie por cada trama rechazada.

## Por qué

- **SDLS antes que FARM:** si el FARM procesara tramas sin autenticar, un atacante podría bloquearlo (lockout) o desalinearlo con tramas falsas, lo que sería una denegación de servicio trivial. Con SDLS delante, solo quien tiene la clave toca el estado del FARM. Además, N(S) va en el AAD, así que no se puede alterar.
- **IV nuevo en cada retransmisión:** el anti-replay solo acepta IV crecientes. Reenviar los mismos bytes funcionaría si el original se perdió, pero si llegó y lo que se perdió fue la confirmación, la copia se marcaría como replay y generaría una falsa alarma de seguridad. Con IV nuevo, el FARM resuelve los duplicados sin ruido.
- **Ventana 1:** si hubiera varias tramas en vuelo y se perdiera una, la siguiente avanzaría el contador anti-replay y la retransmisión de la perdida tendría un IV más antiguo, con lo que sería rechazada. Con una trama cada vez se evita sin complicar el anti-replay.
- **Límite de eventos:** la telemetría es un recurso escaso (86 bytes útiles por trama). Sin límite, 300 tramas falsas generarían 300 TM y enterrarían el housekeeping y las confirmaciones legítimas. Con el resumen no se pierde información: el total exacto sigue en el HK.

## Alternativas descartadas

- **FARM antes que SDLS:** es más eficiente, pero abre la denegación de servicio descrita arriba.
- **Ventana anti-replay deslizante (bitmap):** permitiría varias tramas en vuelo, a cambio de más estado y complejidad. Con el ritmo de un operador humano no compensa.
- **Desbloquear el lockout automáticamente:** oculta un síntoma que debe investigarse, como un reinicio inesperado del satélite o una desalineación.
- **Descartar los eventos que sobran sin contarlos:** el operador perdería la magnitud del ataque.

## Consecuencias

- **El FARM no es un control de seguridad:** N(S) tiene 8 bits y da la vuelta. Esto queda documentado en el código para que nadie lo trate como tal.
- **Tras reiniciarse, el satélite arranca con V(R) = 0:** el primer TC de la tierra provoca un lockout y hay que ejecutar `sync`. Es el comportamiento esperado y sirve como aviso de que el satélite se ha reiniciado.
- **La inundación sigue consumiendo CPU y Wi-Fi:** el límite protege la telemetría y la pantalla, no el canal radio. En un sistema real, la mitigación del canal sería física (antena, espectro), fuera del alcance del proyecto.
- **El CLCW no está protegido por la MAC**, como se indicó en ADR-008. Un atacante en posición de intermediario podría falsear el estado del FARM que ve la tierra. Queda en el threat model de la fase 4.
