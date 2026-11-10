# ADR-012: La configuración de seguridad del enlace como código, con riesgos aceptados versionados

- **Estado:** aceptada
- **Fecha:** 2026-11-10

## Contexto

En las fases 1 a 3, los parámetros de seguridad del enlace estaban repartidos por el código: SPI, algoritmo, longitudes de IV y MAC, anti-replay y referencias de claves. Nadie podía responder de un vistazo a «¿cumple este enlace el baseline CCSDS?». Si un cambio en el código degradaba un parámetro, no fallaba nada.

Existe un proyecto propio, `ccsds-policy-as-code`, con 24 políticas Rego trazadas a CCSDS 355.0-B-2 y 352.0-B-2 que evalúan una base de datos de Security Associations (SA) en YAML.

## Decisión

1. **Documentar las SA reales** en `docs/arquitectura/groundlink.sdls.yaml`, en el formato de `ccsds-policy-as-code`, describiendo lo implementado y no lo ideal.
2. **Atar el documento al código:** `tests/test_sa_database.py` compara el YAML con las constantes de Python y C++. Si se cambia uno sin el otro, el CI falla.
3. **Escanear en el CI** con Conftest y las políticas de `ccsds-policy-as-code` (job `politicas`).
4. **Gestionar las desviaciones como código:** `riesgos-aceptados.yaml` recoge cada hallazgo aceptado con justificación, controles compensatorios, remediación, responsable y fecha de revisión. `tools/check_policy.py` hace fallar el CI si aparece un hallazgo nuevo, si una aceptación ya no corresponde a ningún hallazgo o si ha vencido su revisión.

## Por qué

- **Honestidad del modelo:** documentar el enlace como «ideal» habría dado un escaneo limpio y engañoso. El escaneo encontró tres desviaciones reales en mi propia implementación: el ARSN es el IV, no hay ventana anti-replay y las claves no están en un HSM.
- **El riesgo aceptado no es un riesgo olvidado:** con fecha de revisión y un CI que la hace cumplir, una excepción no puede quedarse para siempre. Es la diferencia entre GRC en hoja de cálculo y GRC continuo.
- **Las aceptaciones caducadas también fallan:** si alguien corrige un problema, el registro se limpia. No quedan excepciones fantasma.

## Alternativas descartadas

- **Desactivar las reglas que fallan:** oculta la desviación a cualquier revisor.
- **Ajustar el YAML para que pase:** sería documentación falsa.
- **Copiar las políticas en este repo:** duplica el código y lo desincroniza. Se usa el repo de políticas como fuente única.

## Consecuencias

- El job `politicas` necesita que `ccsds-policy-as-code` sea accesible desde GitHub Actions. Si no lo es, el job avisa y se salta, pero `test_sa_database` se sigue ejecutando.
- Cambiar un parámetro de seguridad obliga a tocar tres sitios: el código, el YAML y, si cambia el resultado del escaneo, el registro de riesgos. Es intencionado.
