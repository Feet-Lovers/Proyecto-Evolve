# Evidencia · RNF-06 — el clasificador antes y después del apartado 3 (9-oct-2026)

Prueba automática de los tres estados (`ia/tests/test_tres_estados.py`), con un cliente de mentira:
sin clave de API, sin red y a coste cero. Se ejecutó **sobre una copia**, nunca en producción (R1).

## Antes — el código que hay hoy en `develop`

```
FALLA  A · packet degradado dice «no analizado» y por qué  → AttributeError: 'RespuestaFalsa' object has no attribute 'get'
FALLA  B · packet vulnerable se marca «analizado»  → AttributeError: 'RespuestaFalsa' object has no attribute 'get'
FALLA  C · packet analizado y limpio sigue devolviendo None  → AttributeError: 'RespuestaFalsa' object has no attribute 'get'
FALLA  D · intruder degradado dice «no analizado»  → AttributeError: 'RespuestaFalsa' object has no attribute 'get'
FALLA  E · console degradado dice «no analizado»  → AttributeError: 'RespuestaFalsa' object has no attribute 'get'
FALLA  F · fingerprint degradado dice «no analizado»
FALLA  G · fingerprint correcto devuelve los datos del modelo
FALLA  H · se le pasa un schema al cliente (lo exige client.analyze)  → AttributeError: 'RespuestaFalsa' object has no attribute 'get'

0/8 pasan
```

**Qué significa el `AttributeError`.** La reescritura del cliente (apartado 1, 9-oct) hizo que
`analyze()` devuelva un objeto `RespuestaIA` en vez de un `dict`. Los cuatro métodos del clasificador
siguen haciendo `result.get(...)` sobre lo que reciben. Es decir: **hoy no es que el fallo de la IA sea
silencioso — es que la fase de análisis se cae entera a la primera llamada.** El módulo está a propósito
a media secuencia desde el apartado 1, pero conviene que conste medido y no supuesto.

## Después — con el apartado 3 aplicado

```
PASA   A · packet degradado dice «no analizado» y por qué
PASA   B · packet vulnerable se marca «analizado»
PASA   C · packet analizado y limpio sigue devolviendo None
PASA   D · intruder degradado dice «no analizado»
PASA   E · console degradado dice «no analizado»
PASA   F · fingerprint degradado dice «no analizado»
PASA   G · fingerprint correcto devuelve los datos del modelo
PASA   H · se le pasa un schema al cliente (lo exige client.analyze)

8/8 pasan
```

## Un hallazgo que corrige el plan (R9: se declara, no se cambia en silencio)

El §3 del `PLAN-RF08-MODULO-IA.md` da por supuesto que cada módulo de prompts expone un `ESQUEMA`
(`network_packet.ESQUEMA`). **No existe en ninguno de los cuatro**: `grep -c ESQUEMA` devuelve 0, 0, 0 y 0.
Como `client.analyze()` declara `schema: dict` **sin valor por defecto**, aplicar el plan tal cual habría
dado un `TypeError` en la primera llamada.

Solución adoptada: un módulo nuevo `ia/esquemas.py`, generado a partir de las claves que el propio
clasificador lee, en vez de escribir los esquemas dentro de los prompts. Motivo añadido: los prompts están
en la lista de ficheros que no se vuelcan a la conversación, así que no se pueden editar con los ojos.

## Cómo reproducirlo

```
python3 ia/tests/test_tres_estados.py
```
Sin argumentos usa el clasificador que tiene al lado. Devuelve 0 si pasan los ocho.
