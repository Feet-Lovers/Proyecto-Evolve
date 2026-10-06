# Evidencia · Fase 1 — dos bugs async: Intruder `cancel()` y Spider `stop`

> Capturada el **2026-10-05** en la cocina del mediaserver (R1, nada en producción).
> Las dos pruebas se hacen **sin lanzar ataques a terceros** (R1/RNF-07): el 500 del Intruder es una
> llamada que solo invoca un método ausente, y el Spider se demuestra con una **reproducción unitaria**
> (su `crawl_page` se sustituye por un stub que no hace ninguna petición de red).
> Ningún secreto en texto (R7).

## Bug A · `POST /api/intruder/cancel/{token}` → 500

**Causa (R9):** `routes/intruder.py:38` llama a `intruder_engine.cancel(token)`, pero `IntruderEngine`
(`services/intruder_service.py`) solo definía `pause()` y `resume()`. No existía `cancel()`.

### ANTES
```
GET /api/session/new            -> {"token":"3bcf6f07-…"}
POST /api/intruder/cancel/<tok> -> HTTP 500  (cuerpo: "Internal Server Error")
```
Traceback del backend (confirma la causa exacta):
```
  File "/app/routes/intruder.py", line 38, in cancel_attack
    intruder_engine.cancel(token)
AttributeError: 'IntruderEngine' object has no attribute 'cancel'
```

### FIX
Añadido a `IntruderEngine`, simétrico a `pause()`:
```python
def cancel(self, session_token: str):
    session = session_manager.get_session(session_token)
    session["intruder_status"] = "cancelled"
```
El bucle `test_payload` ya corta todo lo que no esté en estado `"running"`
(`intruder_service.py:43`), así que los payloads pendientes abortan y la corrida no se marca `complete`.

### DESPUÉS (verificación unitaria, importación fresca del código nuevo en el contenedor)
```
¿existe cancel()? -> True
cancel() ejecutado sin error
intruder_status -> cancelled
```
> Pendiente del pase end-to-end: reiniciar el backend y comprobar el `200` real por HTTP
> (hoy la imagen tiene el código horneado y no recarga en caliente; el reinicio va en el pase
> end-to-end planificado).

## Bug B · `POST /api/spider/stop/{token}` no detiene el crawl

**Causa (R9):** `routes/spider.py:53` pone `session["spider_running"] = False`, pero `SpiderService.run()`
(`services/spider_service.py:237`) hacía `while self.queue and len(self.visited) < self.max_pages:` —
**nunca leía `spider_running`**. La bandera se ponía, pero el bucle seguía hasta agotar la cola o el máximo.

### ANTES (reproducción unitaria; `crawl_page` stubbeado, cero peticiones de red)
Cola sembrada con 20 URLs del mismo dominio; se pide STOP tras procesar unas pocas:
```
Paginas visitadas cuando se pidio STOP: 3
Paginas visitadas al terminar run():     20
RESULTADO: FALLO - el Spider SIGUIO tras el stop (bandera ignorada)
```

### FIX
`run()` consulta la bandera en cada iteración y distingue "detenido" de "completado"/"límite":
```python
detenido = False
while self.queue and len(self.visited) < self.max_pages:
    session = session_manager.get_session(self.session_token)
    if not session.get("spider_running", True):
        detenido = True
        break
    current_url = self.queue.pop(0)
    await self.crawl_page(current_url)
```
El evento `spider_completed` refleja la parada manual (`completo` pasa a `False` y mensaje propio).

### DESPUÉS (misma reproducción, código nuevo)
```
Paginas visitadas cuando se pidio STOP: 3
Paginas visitadas al terminar run():     3
RESULTADO: OK - el Spider se detuvo al pedir stop
```

## Scripts de reproducción
- `/tmp/.../repro_intruder_cancel.py` y `/tmp/.../repro_spider_stop.py` (temporales de la sesión).
  Ambos stubbean `session_manager` y, en el Spider, `crawl_page` → no sale ni una petición a la red.

## Requisitos tocados
- **RF-06 (Intruder)** · **RF-03 (Spider)** · **RNF-07** (operación controlada: parada efectiva de un ataque en curso).
