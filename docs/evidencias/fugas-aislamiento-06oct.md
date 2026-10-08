# Evidencia · Fase 2 — cuatro fugas de aislamiento entre usuarios (estado ANTES de arreglar)

> 2026-10-06, cocina del mediaserver (R1). Terminal guardada como texto (R6), sin secretos (R7):
> los valores de cookie son **inventados a propósito**.
> Peticiones a través de Nginx (`:8880` → backend), igual que las haría un cliente.
>
> **Qué muestra:** que el modelo de sesión actual no aísla nada — el token no es una credencial,
> la cookie de sesión que captura un auditor la puede leer cualquiera, y los hallazgos de un
> cliente aparecen en el panel de los demás.
>
> **A qué requisito corresponde:** **RF-12** (login individual con JWT + *aislamiento de
> historial/auditorías por usuario*), hoy «Pendiente / mejora». También respalda el apartado 7
> («Lo que todavía no cubre») y el apartado 8 (pruebas que han fallado, con su explicación).
>
> **Por qué se captura AHORA:** R6 — los arreglos de la Fase 2 destruyen esta evidencia y es
> irrepetible. Las cuatro pruebas se lanzaron antes de tocar una sola línea de código.

## Captura íntegra de la terminal

```
######################################################################
# EVIDENCIA Fase 2 — estado ANTES de arreglar. Cocina del mediaserver.
# Fecha: 2026-10-06 10:54:12 CEST   Base: http://127.0.0.1:8880 (nginx -> backend)
# Valores de cookie INVENTADOS a proposito (R7: ningun secreto real).
######################################################################

== PRUEBA 1 — Nginx protege /health pero deja /api abierta ==========
  GET /health            -> HTTP 401
  GET /api/session/new   -> HTTP 200
  VEREDICTO: la API completa es alcanzable SIN credencial.

== PRUEBA 2 — el token no es una credencial ========================
  Uso un token que NO ha emitido el servidor: token-inventado-por-un-atacante-2688988
  GET /api/spider/status/token-inventado-por-un-atacante-2688988 -> HTTP 200
  Respuesta:
    {"running":false}
  VEREDICTO: get_session() ha CREADO una sesion para un token inventado.

== PRUEBA 3 — FUGA DE COOKIES entre usuarios =======================
  Usuario A, token ...722fc778
  Usuario B, token ...d21225f9   (sesion DISTINTA)

  [A] guarda la cookie de sesion que ha capturado auditando victima.example:
    {"stored":true,"host":"victima.example"}

  [B] pide la cookie de ese mismo host — es OTRO usuario, otra sesion:
    {"host":"victima.example","phpsessid":"COOKIE-FALSA-DE-USUARIO-A-0001"}

  >>> FUGA CONFIRMADA: B ha leido la cookie de sesion de A. <<<

  [sin token alguno] cualquiera en la red puede pedirla igual:
    {"host":"victima.example","phpsessid":"COOKIE-FALSA-DE-USUARIO-A-0001"}
  CAUSA: network.py:12 — session_cookies es un dict global indexado SOLO por host.
  IMPACTO: secuestro de sesion. El PHPSESSID de la victima que captura un
           auditor queda legible para cualquiera que alcance la API.

== PRUEBA 4 — FUGA DE BROADCAST (difusion a todas las sesiones) =====
  Auditor C, token ...4e466720
  Auditor D, token ...6c5780c9   (cliente ajeno, sesion distinta)

  Un tercero publica UNA vulnerabilidad SIN token (POST /api/vulnerabilities):
    {"received":true,"id":"EVID-BROADCAST-06OCT"}

  Sesion de C (...4e466720) contiene el hallazgo ajeno: SI  <-- FUGA
  Sesion de D (...6c5780c9) contiene el hallazgo ajeno: SI  <-- FUGA

  CAUSA: vulnerabilities.py:21 y network.py:14 recorren session_manager.sessions
         y ESCRIBEN + emiten en TODAS. Mas emit_all en redis_consumer.py:15 y
         mitm_proxy.py:49.
  IMPACTO: el hallazgo del cliente de un auditor aparece en el panel de otro.
           Para una herramienta de auditoria es una fuga de datos de cliente.

######################################################################
# FIN DE LA EVIDENCIA — 4 pruebas, 4 confirmadas.
######################################################################
```

## Resumen de causas, con fichero y línea

| # | Fuga | Causa en el código | Impacto |
|---|---|---|---|
| 1 | La API entera es alcanzable sin credencial | Nginx protege `/health` pero deja pasar `/api`; ningún `Depends()` en el backend | Cualquiera en la red lanza auditorías |
| 2 | El token no es una credencial | `session_service.py:60-66` — `get_session()` **crea** sesión para cualquier token inventado | No hay frontera de usuario que violar: basta inventarse una cadena |
| 3 | Fuga de cookies entre usuarios | `network.py:12` — `session_cookies` es un dict **global indexado solo por host**; lo importa además `intruder_service.py:8` | Secuestro de sesión: el `PHPSESSID` de la víctima que captura un auditor queda legible para todos |
| 4 | Fuga de broadcast | `vulnerabilities.py:21` y `network.py:14` recorren `session_manager.sessions` y **escriben + emiten en todas**; más `emit_all` en `redis_consumer.py:15` y `mitm_proxy.py:49` | El hallazgo del cliente de un auditor aparece en el panel de otro auditor |

**Matiz honesto (R9):** la fuga nº 4 es más amplia de lo que la hoja de ruta anotaba. No son solo
las dos llamadas a `emit_all`: los dos endpoints **sin token** (`POST /api/vulnerabilities` y
`POST /api/network/packet`) hacen la misma difusión *y además persisten* el dato en la sesión de
todos, que es peor que emitirlo. Son cuatro puntos de difusión, no dos.
