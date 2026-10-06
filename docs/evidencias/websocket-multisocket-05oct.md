# Evidencia · Fase 1 — WebSocket: varios sockets por token (fin del last-wins)

> 2026-10-05, cocina (R1). Terminal (R6), sin secretos (R7).

## Causa (R9)
`backend/services/session_service.py` guardaba `self.websockets: Dict[str, WebSocket]` = **un socket por token**.
`register_websocket` hacía `self.websockets[token] = ws` → el 2º socket sobrescribía al 1º (last-wins). El
frontend abre DOS consumidores con el mismo token (`AppContext.jsx` y `hooks/useWebSocket.js`), así que uno
dejaba de recibir eventos. Además `emit`/`unregister` operaban sobre ese único socket.

## Fix
`Dict[str, List[WebSocket]]`: `register` añade (sin duplicar), `emit` manda a TODOS los sockets del token y poda
los muertos, `unregister(token, ws)` quita solo el socket que se va (`ws=None` → compat: quita todos).
`emit_all` reusa `emit` por token. `main.py` llama `unregister_websocket(token, websocket)`.

## Prueba unitaria (importación fresca del código nuevo)
```
sockets registrados para el token: 2
tras emit      -> A recibio: 1 | B recibio: 1
tras quitar A y re-emit -> A: 1 | B: 2
RESULTADO: OK - ambos reciben; unregister quita solo el suyo
```

## Prueba end-to-end (backend reconstruido, 2 WS reales al mismo token)
Disparador seguro (no ataca a nadie): `POST /api/vulnerabilities/{token}` con un registro de prueba.
```
confirmación del contenedor: List[WebSocket] presente (1 coincidencia)
POST vuln -> 200
recibieron el evento: ['A', 'B']
RESULTADO: OK - ambos sockets reciben
```

## Nota (Fase 2)
Este arreglo no cambia que `emit_all` siga difundiendo a TODAS las sesiones (fuga de datos entre usuarios),
que es otro pendiente que cierra el login/aislamiento de la Fase 2. Aquí solo se corrige el last-wins por token.

## Requisito
RNF (tiempo real / WebSocket). Material de demostración para el vídeo (post-Fase-3).
