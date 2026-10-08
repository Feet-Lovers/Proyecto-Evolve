# Evidencia · Pase end-to-end de la Fase 1 (sobre imagen RECONSTRUIDA)

> 2026-10-05, cocina del mediaserver (R1). Tras `docker compose up -d --build backend` (lo lanzó josemax
> desde la bandeja; el guardian frena el lifecycle a Claude). El rebuild hornea el código **commiteado**;
> un `restart` previo solo recargaba la capa de escritura y daba un end-to-end FALSO (ver más abajo).
> Objetivos de prueba: `/forward` contra web propia autorizada `web.academyx.es` (R1/RNF-07); nada contra terceros.
> Ningún secreto en texto (R7).

## Confirmación de que el contenedor corre el código commiteado
```
proxy.py en contenedor: 0 ocurrencias de 'return {{'   (antes 2 -> bug del 500)
intruder_service.py: def cancel -> 1
spider_service.py: get("spider_running") en run() -> 1
```

## Resultados (todos sobre http://127.0.0.1:8800)
| Endpoint | Antes | Ahora | Cuerpo |
|---|---|---|---|
| `GET /health` | — | 200 | — |
| `POST /api/intruder/cancel/{tok}` | 500 (AttributeError) | **200** | `{"status":"cancelled"}` |
| `GET /api/proxy/check/alive` | 500 (`{{...}}`) | **200** | `{"status":"proxy_active",...}` |
| `POST /api/proxy/forward` | 500 (`{{...}}`) | **200** | reenvía a web.academyx.es, status 200, 39216 B |
| `POST /api/spider/stop/{tok}` | seguía crawleando | **200** | `{"status":"stopped"}` (corte real probado en unitario: `intruder-spider-async-05oct.md`) |
| `POST /api/repeater/parse` (curl https + flags) | rompía `https`→`http` | **200** | `url: https://web.academyx.es/tienda?id=5` correcta |

## Lección operativa (para no repetirla)
En la cocina, un `docker compose restart` **NO** aplica el código commiteado: recarga solo la capa de escritura
del contenedor. Las pruebas de sesiones previas se hacían copiando ficheros en caliente o en unitario, nunca
sobre la imagen reconstruida → daban por buenos arreglos que en la imagen seguían rotos (se vio hoy: tras el
restart, Intruder cancel iba a 200 pero proxy seguía 500 porque `proxy.py` de la imagen aún tenía `{{...}}`).
**Verificar end-to-end = rebuild (`--build`), no restart.**

## Requisitos cubiertos
RF-04/RF-06 (Intruder) · RF-02 (proxy) · RF-03 (Spider) · RF-05 (repeater/curl) · RNF-07.
