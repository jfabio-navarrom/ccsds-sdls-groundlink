# ADR-009: Anti-replay con el IV y contadores que sobreviven a reinicios

- **Estado:** aceptada
- **Fecha:** 2026-11-07

## Contexto

Con AES-GCM, el IV cumple dos papeles:

1. No puede repetirse nunca con la misma clave (ver ADR-008).
2. Puede servir como número de secuencia anti-replay (ARSN en SDLS).

Un replay es una trama legítima reenviada tal cual: la MAC es válida, así que solo la detecta un contador. Hay tres casos que lo complican: la estación de tierra se cierra y se vuelve a abrir, el satélite se reinicia, y un atacante envía tramas falsas con un IV enorme.

## Decisión

- **IV = 4 bytes a cero + contador de 64 bits.** El IV va en claro en la Security Header y hace de ARSN, sin campo de secuencia aparte.
- **Satélite, recepción de TC:** acepta un TC solo si su IV es **estrictamente mayor** que el último aceptado, y lo comprueba **después** de verificar la MAC. El último IV aceptado se guarda en la NVS (flash) en cada TC válido.
- **Tierra, envío de TC:** el contador es `max(último_guardado + 1, reloj_en_µs)` y se guarda en `ground/state_f2.json`.
- **Satélite, envío de TM:** reserva bloques de 1024 IV en la NVS y, al arrancar, empieza por encima del último bloque reservado.
- **Tierra, recepción de TM:** también rechaza TM con un IV no creciente.

## Por qué

- **Comprobar la MAC antes del contador:** si el contador se actualizara antes, un atacante sin clave podría enviar un IV de 2^63 y bloquear para siempre a la tierra legítima (denegación de servicio). El ataque `forge` lo prueba.
- **NVS en el satélite:** sin ella, tras un reinicio el contador volvería a 0 y aceptaría cualquier trama capturada antes. La flash del ESP32 aguanta unos 100 000 ciclos por sector y la NVS reparte el desgaste: suficiente para un laboratorio, no para una misión.
- **Reloj en tierra:** si se borra el archivo de estado, el reloj del PC sigue por delante del último IV usado, así que la tierra no queda bloqueada como si fuera un atacante.
- **Bloques de IV para TM:** evita una escritura en flash por cada trama de telemetría, y un reinicio solo «salta» IV, nunca los repite.

## Alternativas descartadas

- **Ventana deslizante (aceptar desorden dentro de N tramas):** útil con pérdidas y reordenación. Aquí la tierra envía de uno en uno, así que se deja para FARM-1 en la fase 3.
- **Usar el N(S) de la trama como contador:** solo tiene 8 bits, da la vuelta cada 256 tramas y no es secreto ni está pensado para esto.
- **Reiniciar contadores al rotar la clave:** es correcto con claves nuevas, pero la rotación llega en la fase 3.

## Consecuencias

- Si el reloj del PC se atrasa y además se pierde `state_f2.json`, la tierra podría quedar por debajo del último IV del satélite. Sus TC se rechazarán como replay hasta que el reloj supere ese valor (se ve en los eventos de seguridad).
- Tras un reinicio, el satélite no conoce la dirección de la tierra hasta el primer TC autenticado. Los rechazos anteriores se cuentan en el HK, pero no generan evento.
- Borrar la flash del C5 («Erase All Flash» en Arduino) borra el estado anti-replay. Es aceptable en el laboratorio y queda documentado.
