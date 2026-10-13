# De dónde salieron los 5 € de saldo de la P1, y qué tope sigue faltando

> Evidencia de lectura de código e historial. Capturada el **2026-10-08** (tarde) por Claude.
> Origen: josemax recordaba el incidente («metimos 5 € en la API y volaron en muy poco tiempo»)
> pero no qué parte del código se tocó para arreglarlo. Se reconstruyó del historial de git,
> **no de los logs de conversación**. Ningún valor de clave aparece aquí (R7).

## 1. La causa: el módulo de IA auditaba al arrancar, y Docker lo reiniciaba

Antes del 17-may, `ia/main.py` llamaba directamente a la auditoría completa en el arranque:

```python
async def main():
    orchestrator = AttackOrchestrator(session_token=SESSION_TOKEN)
    await orchestrator.run_full_audit(
        target_url=TARGET_URL,
        field_selector=FIELD_SELECTOR,
    )
```

El servicio `ia` del compose lleva `restart: unless-stopped`. Como `main()` **termina** cuando acaba la
auditoría, el contenedor salía y **Docker lo volvía a levantar** → otra auditoría completa contra la API.
Bucle de auditorías mientras el contenedor estuviera arriba. Eso es lo que vació el saldo.

## 2. Los dos arreglos, los dos del 17-may-2026, autor JoSeMhack

| Commit | Qué hizo |
|---|---|
| `99b656a2` | `fix(ia): arrancar en modo polling de instrucciones en lugar de ejecutar auditoría al inicio` |
| `058e9763` | `fix(infra): cambiar MOCK_PLAYWRIGHT a true en docker-compose para evitar consumo de API al arrancar` |

- **`99b656a2` es el arreglo de raíz.** `main.py` pasa a un `while True` que consulta
  `GET /api/playwright/instruction/<token>` cada `POLL_INTERVAL` (5 s por defecto) y **solo audita si
  recibe una instrucción `full_audit`**. Dos efectos: el proceso ya no termina (Docker deja de
  reiniciarlo) y no se llama a la API sin que alguien lo pida.
- **`058e9763` es el freno de mano**, no la cura: puso `MOCK_PLAYWRIGHT=true` en los servicios `backend`
  e `ia`.

## 3. Lo que hay HOY (verificado en la cocina, 8-oct)

- ✅ El modo polling **sigue puesto**: `ia/main.py:10` `poll_for_instructions()`. Arrancar no gasta API.
- ⚠️ **El freno de mano está quitado**: `docker-compose.yml:24` y `:74` dicen `MOCK_PLAYWRIGHT=false`.
  Hoy es inofensivo —lo que gastaba era el arranque automático, ya curado— pero la red de seguridad
  del 17-may ya no está.
- ✅ Topes que sí existen en `ia/client.py`: `max_tokens=1000` por defecto, `MAX_RETRIES = 3` con
  espera exponencial, modelo `claude-sonnet-4-20250514`.
- ✅ El contrato backend↔IA **encaja** (se comprobó por si acaso): el backend devuelve
  `{"instructions": [...]}` (`backend/routes/playwright.py:30`) y `main.py:23` lee `instructions` en
  plural y toma el primero. No hay desajuste.

## 4. El tope que NO existe: una auditoría no tiene techo de llamadas

`run_full_audit` (`ia/orchestrator.py:299`) encadena tres bucles anidados:

```
run_full_audit
 └── for page_url in target_pages          # orchestrator.py:323 → hasta 5 páginas (objetivo + 4 del spider, :320)
      └── for attack_type in attack_priorities   # :194 → los tipos que priorice el fingerprint
           └── for payload in payloads           # :198
                └── classifier.analyze_packet()  # :221 → UNA llamada a la API por payload
```

El número de llamadas de una sola auditoría es **páginas × tipos de ataque × payloads**, sin ningún
límite superior en el código. El arreglo del 17-may quitó el **disparo automático**; nunca puso techo
al **tamaño** de una auditoría.

## 5. Por qué esto importa justo ahora (RF-08)

El pendiente de RF-08 es «**disparador en la UI** (hoy no hay ni botón)» y «**subir el modelo a Claude 5**».
Añadir ese botón pone el triple bucle **a un clic de distancia**, en producción, detrás de un login con
usuarios, y con un modelo más caro que el de mayo. Es la misma aritmética que vació los 5 €, con la única
diferencia de que ahora hace falta pulsar.

**Recomendación (decide josemax):** antes de montar el disparador, poner un techo explícito por auditoría
— tope de llamadas, o de páginas × payloads — y dejarlo visible en el panel. Tiene premio doble: evita
repetir el incidente y es material directo del apartado 10 (limitaciones) y del 8 (lo aprendido de un
fallo real de la P1).
