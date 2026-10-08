# Evidencia · Las fugas de aislamiento, confirmadas VIVAS en producción (antes de desplegar la Fase 2)

**Fecha:** 2026-10-07, 17:31 CEST · **Entorno:** `www.hooksuite.de` (caja `91.98.143.219`), **solo lectura**
· **Requisito:** RF-12, y apartado 8 (pruebas) · **Quién:** Claude

**Qué muestra:** que las fugas documentadas el 6-oct en la cocina **no son teóricas ni pasadas**: el código
que las contiene es exactamente el que sirve hoy a internet. Es lo que convierte el despliegue de la Fase 2
de trámite documental en **el tapón de un agujero abierto**.

**Por qué se captura ahora:** el despliegue destruye esta evidencia en minutos y es irrepetible (R6).

**Cómo se hizo, y qué NO se hizo (R1):** solo peticiones **GET**. La caja no recibe comandos de prueba, así
que **no se reprodujo** el guion del 6-oct, que necesita dos `POST` (guardar una cookie, publicar una
vulnerabilidad). Lo que un `POST` habría demostrado se deja marcado como **inferido del código desplegado**,
no como comprobado.

**R7:** no se imprime ningún cuerpo que pueda contener un secreto ajeno — solo código HTTP, longitud y
`sha256` truncado. El host consultado en la sonda C es **inexistente a propósito**, para no leer ninguna
cookie real capturada por nadie.

---

## Punto de partida verificado

- La caja corre `main@485a22ec`. Los tres commits que cierran las fugas (`9e710225`, `c0101f65`, `0df23509`)
  **no son ancestros de ese `main`** y no están en **ninguna** rama remota (`git branch -r --contains` → vacío).
- Es decir: lo que atiende las peticiones de abajo es el código **anterior** al arreglo, línea por línea.

## Captura íntegra de la terminal

```
######################################################################
# CONFIRMACION EN VIVO — fugas de aislamiento en PRODUCCION
# Fecha: 2026-10-07 17:31:56 CEST   Base: http://www.hooksuite.de
# Solo peticiones GET (R1: ni un POST de prueba en la caja).
# Desplegado: main@485a22ec (Fase 1). Los 3 commits de auth NO estan en main.
######################################################################

== SONDA A — asimetria del Basic Auth (fuga 1) ======================
  GET /                              -> HTTP 401   len=178  sha256=e1fb48eb5d3d…
  GET /health                        -> HTTP 401   len=178  sha256=e1fb48eb5d3d…
  GET /api/spider/status/<inv>       -> HTTP 200   len=17  sha256=a0b2bcfcde77…
      cuerpo: {"running":false}
  VEREDICTO: si / y /health dan 401 y /api da 200 -> la API entera es
             alcanzable SIN credencial. Fuga 1 CONFIRMADA en vivo.

== SONDA B — el token no es una credencial (fuga 2) =================
  Token inventado, jamas emitido por el servidor: token-inventado-confirmacion-07oct
  GET /api/vulnerabilities/<inv>     -> HTTP 200   len=2  sha256=4f53cda18c2b…
      cuerpo: []
  VEREDICTO: un 200 significa que get_session() ha CREADO sesion para un
             token inventado (session_service.py:60-66). Fuga 2 CONFIRMADA.

== SONDA C — puerta de la fuga de cookies (fuga 3, PARCIAL) =========
  Host inexistente a proposito, para NO leer ninguna cookie real (R7).
  GET /api/network/session_cookie/   -> HTTP 200   len=51  sha256=1b7816310441…
  VEREDICTO: un 200 prueba que el endpoint responde SIN credencial, que es
             la puerta de la fuga. NO prueba el trasvase A->B: eso exige un
             POST previo y R1 lo prohibe en la caja. Queda como INFERIDA.

== FUGA 4 (broadcast) — NO SONDEADA ================================
  Exige POST /api/vulnerabilities en produccion. R1 lo prohibe. INFERIDA
  del codigo desplegado (vulnerabilities.py:21, network.py:14 en 485a22ec).

######################################################################
```

## Qué queda probado y qué no — sin redondear

| # | Fuga | En producción | Cómo |
|---|---|---|---|
| 1 | La API entera alcanzable sin credencial | ✅ **COMPROBADA en vivo** | `/` y `/health` → 401, pero `/api/…` → 200 |
| 2 | El token no es una credencial | ✅ **COMPROBADA en vivo** | Un token inventado obtiene `200` en dos routers distintos: `get_session()` le crea sesión |
| 3 | Fuga de cookies entre usuarios | 🟠 **PARCIAL** | Comprobado que el endpoint de lectura responde **sin token**; el trasvase A→B se **infiere** de `network.py:12` (dict global por host), no se reprodujo |
| 4 | Fuga de broadcast | ⚪ **INFERIDA del código** | Exige `POST`; no se ejecutó. `vulnerabilities.py:21` y `network.py:14` recorren todas las sesiones en el commit desplegado |

**La asimetría de la sonda A es el hallazgo de fondo:** la autenticación básica protege la portada y hasta
`/health`, pero **no** `/api`. Da la impresión de que el servicio está cerrado —el navegador pide credencial—
mientras la superficie que de verdad importa está abierta a cualquiera.

## Efecto secundario declarado

Las sondas A y B **crearon dos sesiones vacías** en la memoria del backend de producción, porque ese es
justamente el defecto que demuestran: pedir por un token inventado lo crea. No se escribió nada en disco y
las recoge `cleanup_old_sessions()` (más los topes de memoria de la Fase 1). Se declara porque es la única
huella que han dejado estas comprobaciones.
