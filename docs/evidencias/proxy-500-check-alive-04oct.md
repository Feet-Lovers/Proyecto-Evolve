# Evidencia · 500 en /api/proxy/check/alive (y endpoint duplicado) — 2026-10-04

## ANTES (capturado por Claude, terminal)
`GET http://localhost:8800/api/proxy/check/alive` -> **HTTP 500** ("Internal Server Error").
Causa: en `backend/routes/proxy.py` los `return {{...}}` (líneas 26 y 31) NO son f-strings, así que
`{{ "k": v }}` construye un *set que contiene un dict* -> `TypeError: unhashable type: 'dict'` -> 500.

## Endpoint duplicado
`/check/alive` existe dos veces: `backend/main.py:25` (ruta raíz, devuelve dict correcto) y
`backend/routes/proxy.py:24` (prefijo `/api/proxy`, el que estaba roto). Nginx enruta `/check/` al del
router. El de main.py es redundante pero inofensivo -> se deja; limpiarlo es cosmético.

## FIX
Quitadas las llaves dobles -> `return {"status": ...}` y `return {"filtered": True}` (dicts normales).
Commit a nombre de Macarena. Verificación end-to-end (200) en el pase de arranque del backend al cerrar la Fase 1.
