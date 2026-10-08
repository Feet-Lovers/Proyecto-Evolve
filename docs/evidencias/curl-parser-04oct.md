# Evidencia · Parser curl del Repeater (regex rompía en 'https') — 2026-10-04

## Causa
`backend/routes/repeater.py`: la clase `[^'\"\\s]+` tenía DOBLE backslash → excluía el backslash y la
**letra `s` literal** (no los espacios `\s`). Rompía en `https` y además no paraba en espacios.

## ANTES (regex original)
- `curl https://example.com/path`        -> url=`http`           (se come todo desde la 's')
- `curl -X POST https://api.test/x`      -> url=`POST http`       (junta método + para en la 's')

## DESPUÉS (captura por esquema: `https?://[^\s'\"]+`)
- `curl https://example.com/path`        -> `https://example.com/path`
- `curl http://example.com`              -> `http://example.com`
- `curl -X POST https://api.test/x -d '{}'` -> `https://api.test/x`  (ignora flags)
