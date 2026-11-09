# ADR-010: Rotación de claves en vuelo (OTAR) con una clave maestra

- **Estado:** aceptada
- **Fecha:** 2026-11-09

## Contexto

En la fase 2 las claves de tráfico (TC y TM) se compilan en el firmware. Si una clave se filtra (por ejemplo, porque alguien la pega en un chat), la única forma de cambiarla es regenerarla y reflashear la placa. En un satélite real eso no es posible: no se puede subir a cambiarle el firmware. Hace falta poder cambiar las claves por el propio enlace, de forma segura.

## Decisión

Seguir el esquema de jerarquía de claves de SDLS Extended Procedures (CCSDS 355.1-B), simplificado:

- **KEK (clave maestra):** se instala en tierra. Solo sirve para envolver claves nuevas y nunca cifra tráfico normal.
- **Claves de tráfico (TC y TM):** llevan un **ID** creciente. Las iniciales tienen el ID 1.
- **Subida (servicio 24,1):** `[ID][IV 12][claves TC+TM cifradas 64][MAC 16]`, con AES-256-GCM bajo la KEK y AAD = `"OTAR" + SCID + ID`. El TC que la transporta va además protegido con las claves de tráfico actuales.
- **Activación (servicio 24,2):** es un paso separado. A partir de su confirmación, que ya sale cifrada con la clave TM nueva, tierra y satélite usan las claves nuevas.
- **Anti-rollback:** el satélite rechaza cualquier ID que no sea mayor que el activo.
- **Destrucción:** el satélite borra de la RAM las copias de las claves pendientes. En tierra, las claves retiradas se eliminan del almacén y solo se conserva su ID.
- **Persistencia:** el satélite guarda las claves activas en la NVS junto a una huella de la KEK. Si se reflashea con otra KEK, descarta las guardadas y vuelve a las de `secrets.h`.

## Por qué

- **Separar KEK y claves de tráfico** limita el daño: la clave que más se usa (y más se expone) no es la que permite instalar claves nuevas.
- **El ID dentro del AAD** impide reetiquetar un bloque OTAR capturado como si fuera de otro ID.
- **Subir y activar por separado** deja comprobar que las claves llegaron antes de cambiar. Si la activación falla, el enlace sigue funcionando con las claves antiguas.
- **Anti-rollback:** sin él, un atacante con una clave antigua filtrada y un bloque OTAR antiguo capturado podría devolver el satélite a una clave comprometida.
- **Conservar los contadores anti-replay al rotar:** los IV siguen creciendo, así que no hay ventana de replay durante el cambio.

## Alternativas descartadas

- **Reflashear para cada cambio:** imposible en vuelo, y es justo el problema que se quiere resolver.
- **Derivar claves nuevas de la anterior (ratchet con HKDF):** no necesita KEK, pero si se filtra una clave, se pueden calcular todas las siguientes.
- **Intercambio de claves asimétrico (ECDH):** es más robusto, porque no hay un secreto de larga duración que proteja todo. Pero es más complejo y no forma parte del baseline SDLS. Se deja como mejora para la fase 4.
- **AES Key Wrap (RFC 3394):** es el estándar clásico para envolver claves. Usar GCM permite reutilizar la misma primitiva y su implementación ya probada.

## Consecuencias

- **La KEK pasa a ser el secreto crítico.** Si se filtra, un atacante que además pueda enviar TC autenticados podría instalar sus propias claves. Cambiar la KEK sí requiere reflashear.
- La KEK y las claves activas están en claro en la flash del ESP32, sin flash encryption ni secure boot. Queda como riesgo aceptado del laboratorio en el threat model de la fase 4.
- Si se pierde la confirmación de la activación, la tierra lo detecta al recibir la siguiente TM cifrada con la clave nueva y completa el cambio entonces.
