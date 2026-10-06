# Evidencia · Fase 1 — cierre de :8000/:3000 + DVWA solo interno

> 2026-10-05, cocina del mediaserver (R1). Tras `docker compose up -d --build frontend backend nginx`
> (lo lanzó josemax desde la bandeja). Todo por terminal (R6), ningún secreto en texto (R7).

## Antes
```
backend  :8800/health         -> 200 (sin auth)   <- API abierta
backend  :8800/api/session/new-> 200 (sin auth)
frontend :8830/               -> 200 (sin auth)   <- saltaba el Basic Auth
nginx    :8880/               -> 401 (Basic Auth)
```

## Después
```
# Puertos directos CERRADOS (ya no se publican al host):
backend  :8800  -> conexión rechazada (Couldn't connect to port 8800)
frontend :8830  -> conexión rechazada (Couldn't connect to port 8830)
nginx    :8880/ -> 401 (único puerto publicado: 0.0.0.0:8880->80)

# Contenedores: backend expone 8000/tcp y frontend 80/tcp SOLO en la red interna (sin 0.0.0.0).

# El frontend sigue funcionando a mismo origen, vía Nginx:
:8880/api/session/new      -> 200  (token emitido)
:8880/api/proxy/check/alive-> 200
:8880/ws/<token>           -> 101  (WebSocket upgrade a mismo origen)

# Bundle del frontend horneado: 0 ocurrencias de ':8000' y ninguna de la IP vieja
# (antes VITE_API_URL=http://«IP-de-la-caja»:8000) -> confirma same-origin.
```

## Qué cambió
- `frontend/src/services/api.js`: `API_BASE` → `''` (relativo, mismo origen).
- `frontend/src/AppContext.jsx` y `frontend/src/hooks/useWebSocket.js`: WS a `ws(s)://location.host/ws`.
- `frontend/Dockerfile`: `ARG VITE_API_URL=` vacío (ya no hornea la IP de la caja).
- `docker-compose.yml`: sin `ports` en backend ni frontend; solo Nginx publica.
- `infra/nginx.conf`: retirado el bloque de DVWA → DVWA queda solo en la red interna (accesible por
  backend/playwright para pruebas, nunca a internet) y Nginx deja de depender de resolver 'dvwa' al arrancar
  (se cae el crash-loop).

## Nota pendiente (Fase 2)
`/api` y `/ws` aún NO están tras autenticación en Nginx (hoy accesibles sin credencial a través del :8880).
La auth de `/api` y `/ws` la trae el login nuevo de la Fase 2 (puntos 4+5). El cierre de puertos de HOY quita
la exposición DIRECTA (bypass del proxy) y unifica la entrada por Nginx; la autenticación es el paso siguiente.

## Requisitos
RNF-07 / endurecimiento de exposición · RF (unificación de entrada por Nginx). Evidencia de pantalla (producto)
tras la Fase 3 (R6), cuando el login cambie las pantallas.
