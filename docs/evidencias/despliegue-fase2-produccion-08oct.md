# Evidencia · La Fase 2, desplegada en producción (y las fugas tapadas)

**Fecha:** 2026-10-08, 06:52–06:55 UTC (08:52–08:55 CEST) · **Entorno:** caja `91.98.143.219`
· **Requisito:** RF-12, RNF-07, apartado 8 · **Quién:** josemax ejecuta, Claude arma y verifica

**Qué muestra:** que el código de la Fase 2 **está sirviendo en producción**, no solo mergeado. Es el cierre
real de la fase: ayer quedó comprobado que las fugas estaban vivas en la caja (`fugas-vivas-en-produccion-07oct.md`)
y esta evidencia muestra el mismo sistema con la autenticación por usuario puesta.

---

## Secuencia completa del despliegue

| # | Bloque | Qué hizo | Evidencia |
|---|---|---|---|
| 1 | punto de retorno (R8) | `485a22ec` guardado, `.env.pre-fase2` (600), 4 imágenes `prefase2/*:07oct` | `punto-retorno-fase2-08oct.md` |
| 2 | PR #6 | mergeado por josemax → `origin/main` = `3d3baba8` | — |
| 2a | comprobación previa | `bcrypt` en el host, 4 claves ausentes del `.env` | `preflight-credenciales-fase2-08oct.md` |
| 3 | código + secretos | `reset --hard` a `3d3baba8`, `JWT_SECRET` y `REGISTRO_CODIGO` generados, **0 usuarios** | esta |
| 4 | build + recreate | `up -d --build backend frontend` + `--force-recreate nginx`, `chmod 600 .env` | esta |
| 5 | verificación | bloque 3b, solo lectura | esta |

## Verificación en vivo (bloque 3b, 06:55:17 UTC)

```
-- 1) Codigo y permisos --
   HEAD:          3d3baba8   (esperado: 3d3baba8)
   .env:          600            (esperado: 600)
   .env.pre-fase2:600  (la vuelta atras, 600)

-- 2) Contenedores: cuando se crearon? --
   backend      creado 2026-10-08T06:52  estado running   reinicios 0
   frontend     creado 2026-10-08T06:52  estado running   reinicios 0
   nginx        creado 2026-10-08T06:52  estado running   reinicios 0
   playwright   creado 2026-05-21T14:44  estado running   reinicios 0
   ia           creado 2026-05-21T14:44  estado running   reinicios 0
   redis        creado 2026-05-21T14:44  estado running   reinicios 0
   dvwa         creado 2026-05-21T14:44  estado running   reinicios 0

-- 3) El backend tiene de verdad la Fase 2 dentro? --
   bcrypt en el contenedor: 4.1.3
   JWT_SECRET: presente en el entorno del contenedor (valor NO mostrado, R7)
   REGISTRO_CODIGO: presente en el entorno del contenedor (valor NO mostrado, R7)
   volumen de usuarios: 1 encontrado(s)

-- 4) Sondas HTTP desde la caja (GET, solo codigos) --
   /                  -> 200
   /api/auth/yo       -> 401
```

### Lo que prueba cada dato

- **`reinicios 0` en el backend.** El riesgo real de este despliegue era un backend en bucle de reinicio: el
  código de la Fase 2 **se niega a arrancar** si faltan `JWT_SECRET` o `REGISTRO_CODIGO` (sin valor por
  defecto, a propósito: preferimos no arrancar a arrancar sin autenticación pareciendo correcto). Cero
  reinicios con el contenedor `running` prueba que las variables llegaron.
- **Los tres contenedores de 06:52 y los otros cuatro de mayo.** El `--force-recreate` hizo su trabajo en
  nginx —imagen descargada, que `--build` no habría tocado (lección del 7-oct)— y playwright, ia, redis y
  dvwa quedaron **deliberadamente intactos**.
- **`/` → 200.** El panel carga **sin pedir Basic Auth**: la contraseña compartida está retirada y el código
  de invitación es la única puerta de alta.
- **`/api/auth/yo` → 401.** La API **exige token**. Es la fuga nº 1 de ayer («la API entera alcanzable sin
  credencial», comprobada en vivo con `/api/...` → 200) **tapada**.
- **`bcrypt 4.1.3` dentro del contenedor.** Resuelve el `ModuleNotFoundError` que el bloque 2a encontró en la
  imagen vieja: el `--build` instaló la dependencia, como estaba previsto.

## Comprobación desde fuera (desde el mediaserver, 08:57 CEST)

```
  IPv4  /            -> 200
  IPv4  /api/auth/yo -> 401
  IPv6  /            -> 000   (sin conectividad IPv6 desde el mediaserver)
  IPv6  /api/auth/yo -> 000
  DNS:  91.98.143.219  +  2a01:4f8:d0a:27bd::2
```

## ⚠️ Lo que esta evidencia NO prueba (y no se disfraza de verde)

**No está comprobado qué ve un visitante que llegue por IPv6.** El dominio publica `AAAA` además de `A`, y
desde **dentro** de la caja la petición al dominio —que resuelve a su propia IPv6— devolvió **404**, no un
rechazo de conexión: algo responde ahí y **no es nuestro nginx**. Desde el mediaserver no se puede confirmar
porque no tiene salida IPv6 (`000` = no conectó, que no es lo mismo que «falla»).

**Por qué importa:** muchas redes (móviles, bastantes ISP) prefieren IPv6. Un visitante así podría recibir un
404 en lugar del panel — incluido el equipo evaluador. **Pendiente de comprobar desde una red con IPv6** (p.
ej. datos móviles) antes de dar la disponibilidad por buena.

**Hipótesis a verificar, sin darla por cierta:** `ports: "80:80"` del compose publica en IPv4 y, sin IPv6
habilitado en el daemon de Docker, el `[::]:80` de la caja queda servido por otra cosa. Las salidas posibles
serían habilitar IPv6 en Docker o **retirar el registro `AAAA`** si no se va a servir.
