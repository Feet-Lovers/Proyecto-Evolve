# Evidencia · Fase 1 — topes de memoria del estado de sesión

> 2026-10-05, cocina (R1). Terminal (R6), sin secretos (R7). Martilleo contra la propia cocina
> (localhost), nunca contra terceros (RNF-07).

## Hallazgo (R9) — el pendiente estaba mal planteado
El pendiente decía «sesiones solo en memoria: un reinicio borra todo». El problema real y más grave es otro:
**el estado de sesión crecía SIN LÍMITE**.

- `SessionManager.cleanup_old_sessions` estaba **definido pero NUNCA se llamaba** (ninguna referencia en todo
  el backend), y aun invocándolo descartaba **una sola** sesión por llamada.
- `get_session(token)` **crea una sesión para cualquier token inventado**.
- Cada petición guardada arrastra hasta **50 KB** de cuerpo de respuesta
  (`spider_service.py:184`, `proxy_service.py:111`).

Combinado con que `/api` no tiene autenticación (hasta la Fase 2), **cualquiera podía agotar la memoria del
backend** llamando a la API con tokens nuevos.

## Fix
- `MAX_SESSIONS` (50) y `MAX_REQUESTS_PER_SESSION` (1000), configurables por entorno.
- Recolector **real**: descarta en bucle hasta volver al tope y **prefiere las sesiones sin WebSocket vivo**,
  para no tumbar a quien está trabajando. Se invoca al crear sesión y en el camino del token inventado.
- `BoundedList`: lista auto-podada (conserva las últimas) para `requests`, `network_packets` y
  `vulnerabilities` → el tope se aplica solo, sin tocar las decenas de `.append()` repartidos por el backend.
- Corregido que *clear*/*reset* del Spider hacían `session["requests"] = []`: **reasignar perdía el tope**;
  ahora se vacía en el sitio con `.clear()`.

## Prueba unitaria (MAX_SESSIONS=5, MAX_REQUESTS_PER_SESSION=3)
```
20 tokens distintos        -> 5 sesiones (tope respetado)
10 peticiones en 1 sesion  -> 3 guardadas, y son las ULTIMAS: [7, 8, 9]
sesion con socket vivo     -> sobrevive a la recoleccion (True)
RESULTADO: OK
```

## Prueba end-to-end (backend reconstruido, defaults 50/1000)
Método black-box: se guarda un dato en una sesión, se martillea con 120 tokens inventados y se comprueba si
la sesión fue desalojada.
```
A (sin socket) antes           -> 1 vuln
A (sin socket) tras 120 tokens -> 0 vuln   (DESALOJADA: el tope actua)
B (con socket vivo) tras 120   -> 1 vuln   (PROTEGIDA: no se tumba a quien trabaja)
RESULTADO: OK
```

## Decisión sobre la persistencia (josemax, 5-oct)
**No se persisten las sesiones; se justifica como limitación consciente** (apartado 10). Motivos:
1. ~decenas de puntos del backend obtienen el dict de sesión y lo mutan en memoria → persistir de verdad
   obliga a escritura-a-través en cada mutación (reescritura amplia).
2. La Fase 2 (login/usuarios) ata las sesiones a usuarios → lo que se persistiera ahora habría que rehacerlo.
3. En una herramienta de auditoría, la sesión es un **espacio de trabajo efímero**; es una decisión defendible
   si se declara, y el enunciado valora las decisiones justificadas.
Alternativa registrada como trabajo futuro: Redis ya está levantado y el backend ya lo usa para el consumidor
de tráfico, así que persistir es factible **después** de la Fase 2.

## Requisitos
RNF-07 (robustez/abuso) · apartado 7 (endurecimiento) · apartado 10 (limitaciones y trabajo futuro).
