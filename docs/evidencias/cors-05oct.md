# Evidencia · Fase 1 — CORS restringido a orígenes legítimos

> 2026-10-05, cocina (R1), tras rebuild del backend. Terminal (R6), sin secretos (R7).
> Peticiones a través del proxy (`:8880` → backend).

## Antes (`allow_origins=["*"]` + `allow_credentials=True`)
```
GET  /api/session/new   (Origin: https://evil.example)
  access-control-allow-origin: *
  access-control-allow-credentials: true
OPTIONS /api/intruder/start (Origin: https://evil.example)
  access-control-allow-origin: https://evil.example   <- REFLEJA cualquier origen
  access-control-allow-credentials: true
```
→ Cualquier web podía hacer peticiones autenticadas contra la API.

## Después (lista cerrada vía env ALLOWED_ORIGINS, sin "*")
```
# Origen MALICIOSO (https://evil.example):
GET      -> (sin access-control-allow-origin)      <- bloqueado
OPTIONS  -> (sin access-control-allow-origin)      <- bloqueado
# (aparece 'allow-credentials: true' suelto; sin ACAO el navegador deniega igual)

# Origen LEGÍTIMO (http://127.0.0.1:8880):
GET      -> access-control-allow-origin: http://127.0.0.1:8880
OPTIONS  -> access-control-allow-origin: http://127.0.0.1:8880

# App viva:
GET /api/session/new -> 200
```

## Qué cambió
`backend/main.py`: `allow_origins=["*"]` → lista cerrada configurable por env `ALLOWED_ORIGINS`
(default: dominio hooksuite.de + IP de la caja + localhost + cocina). Se mantiene `allow_credentials=True`
(ahora válido por spec, con orígenes concretos). El frontend es mismo origen, así que el CORS solo afecta a
llamadas cross-origin legítimas.

## Requisito
Endurecimiento (apartado 7). Prueba cross-origin negativa/positiva.
