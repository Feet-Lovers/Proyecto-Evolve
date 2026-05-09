# Documentación técnica — HookSuite Módulo de IA

## Stack tecnológico

- **Python 3.14**
- **Anthropic Claude API** — modelo `claude-sonnet-4-20250514`
- **httpx** — cliente HTTP asíncrono para comunicación con el backend
- **asyncio** — gestión de concurrencia y ejecución asíncrona
- **python-dotenv** — gestión de variables de entorno

### Dependencias (`requirements.txt`)
```
anthropic==0.25.0
python-dotenv==1.0.0
```

---

## Estructura del módulo

```
ia/
├── client.py                          ← Cliente Anthropic con reintentos exponenciales
├── orchestrator.py                    ← Orquestador del ciclo completo de auditoría
├── main.py                            ← Punto de entrada
├── analyzers/
│   └── vulnerability_classifier.py   ← Clasificador con umbral de confianza
├── prompts/
│   ├── network_packet.py              ← Prompt de análisis de paquetes de red
│   ├── intruder.py                    ← Prompt de análisis de resultados del Intruder
│   ├── console.py                     ← Prompt de análisis de logs de consola
│   └── fingerprint.py                 ← Prompt de fingerprint y priorización de ataques
├── tests/
│   └── test_standalone.py             ← Test standalone validado contra la API real
├── results/
│   └── vulnerabilities.json           ← Salida de la auditoría con hallazgos reales
├── .env                               ← Variables de entorno (no subido al repo)
└── .env.example                       ← Plantilla de configuración
```

---

## Variables de entorno

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| `ANTHROPIC_API_KEY` | API Key de Anthropic | — (obligatoria) |
| `BACKEND_URL` | URL del backend (Macarena Rogerio) | `http://localhost:8000` |
| `DVWA_URL` | URL del entorno de pruebas | `http://localhost:8888` |
| `MOCK_PLAYWRIGHT` | Activa el modo mock sin automatización | `true` |

Para pasar a modo real una vez Macarena Rogerio tenga los endpoints listos: cambiar `MOCK_PLAYWRIGHT=false` en `.env`. Sin tocar código.

---

## Módulos

### `client.py` — Cliente Anthropic

Encapsula todas las llamadas a la API de Anthropic. Implementa reintentos exponenciales para gestionar errores de rate limit y fallos de red.

**Parámetros fijos:**
- Modelo: `claude-sonnet-4-20250514`
- Reintentos máximos: 3
- Delay base entre reintentos: 1 segundo (se dobla en cada intento: 1s, 2s, 4s)

**Comportamiento:**
- Llama a la API con un `system_prompt` y un `user_message`
- Parsea automáticamente la respuesta como JSON (limpia los bloques de código markdown si están presentes)
- En caso de `RateLimitError` o `APIError` aplica backoff exponencial
- Devuelve siempre un `dict` — nunca lanza excepciones al caller

---

### `analyzers/vulnerability_classifier.py` — Clasificador

Orquesta las llamadas a los 4 prompts especializados y filtra los resultados por umbral de confianza.

**Umbral de confianza: 60%** — por debajo de este valor, el resultado se descarta y se devuelve `None`.

**Métodos disponibles:**

| Método | Entrada | Qué analiza | Devuelve |
|--------|---------|-------------|----------|
| `analyze_packet(packet)` | Paquete HTTP de red | Tráfico interceptado por el proxy | Vulnerabilidad o `None` |
| `analyze_intruder(results, url, param)` | Resultados del Intruder | Resultados de fuzzing | Vulnerabilidad o `None` |
| `analyze_console(logs, url)` | Logs de consola del navegador | Información sensible expuesta | Hallazgo o `None` |
| `fingerprint(headers, url, body)` | Headers HTTP y URL | Tecnologías y superficie de ataque | Dict con prioridades siempre |

**Formato de salida de `analyze_packet`:**
```json
{
  "origen": "proxy",
  "url": "http://objetivo.com/pagina",
  "tipo": "SQL Injection",
  "severidad": "critical",
  "confianza": 0.95,
  "descripcion": "...",
  "evidencia": "...",
  "recomendacion": "..."
}
```

---

### `prompts/` — Prompts especializados

Cuatro prompts independientes, cada uno especializado en un tipo de análisis distinto:

**`network_packet.py`** — Analiza paquetes HTTP capturados por el proxy o por CDP. Detecta patrones de inyección, headers anómalos y comportamientos sospechosos en el tráfico.

**`intruder.py`** — Analiza los resultados del módulo Intruder tras un ataque de fuzzing. Compara respuestas para determinar si algún payload logró explotar una vulnerabilidad.

**`console.py`** — Analiza los logs de consola del navegador capturados por el módulo CDP de Carlos Bañuelos Fernández. Detecta API keys expuestas, paths sensibles, errores de SQL y otros patrones de 11 tipos de información sensible.

**`fingerprint.py`** — Analiza los headers HTTP y la URL del target para identificar el stack tecnológico (servidor, lenguaje, framework) y generar una lista priorizada de ataques a lanzar.

---

### `orchestrator.py` — Orquestador

El componente central del módulo. Coordina las tres fases de la auditoría y gestiona la comunicación con el backend de Macarena Rogerio y el módulo de automatización de Nacho García Monge.

**Ciclo completo de auditoría (`run_full_audit`):**

```
FASE 1 — Fingerprinting
  → Playwright navega al target y devuelve headers y tecnologías
  → Claude analiza y genera lista de ataques priorizados
         ↓
FASE 2 — Spider
  → Playwright descubre todas las URLs del target (BFS)
  → Se construye la lista de páginas a atacar
         ↓
FASE 3 — Ataques (por cada URL descubierta)
  → Para cada tipo de ataque priorizado (SQLi, XSS, fuzzing):
    → Se lanza cada payload contra el selector configurado
    → Claude analiza la respuesta como paquete de red
    → Si confianza ≥ 60%: se confirma con 2 pases adicionales
    → Si se confirma: se clasifica, se construye la ficha y se envía al backend
```

**Sistema de confirmación:** antes de registrar una vulnerabilidad como real, el orquestador lanza el mismo payload 2 veces más de forma independiente. Solo si las 3 ejecuciones son positivas se clasifica como vulnerabilidad confirmada. Esto elimina falsos positivos.

**Payload map integrado:**

| Tipo | Payloads incluidos |
|------|--------------------|
| SQLi | `' OR '1'='1`, `' OR '1'='1'--`, `1 UNION SELECT null--`, Blind SQLi time-based |
| XSS | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, variantes encoded |
| Fuzzing | Path traversal, null bytes, SSTI, command injection |

**Comunicación con el backend (Macarena Rogerio):**
- `POST /api/playwright/instruction/{session_token}` — envía instrucciones al módulo de automatización a través del backend
- `POST /api/vulnerabilities` — registra vulnerabilidades confirmadas en el backend

**Modo mock (`MOCK_PLAYWRIGHT=true`):** el orquestador simula las respuestas de Playwright internamente sin necesitar el backend ni el módulo de automatización. Permite desarrollo y testing independiente del resto del equipo.

---

### `main.py` — Punto de entrada

Lanza la auditoría completa contra el target configurado en `.env`.

```python
TARGET_URL = os.getenv("DVWA_URL", "http://localhost:8888")
FIELD_SELECTOR = "input[name='id']"
SESSION_TOKEN = "ia_session_default"
```

**Ejecución:**
```bash
cd ~/Proyecto-Evolve
source ia/venv/Scripts/activate   # Windows
python -m ia.main
```

---

### `results/vulnerabilities.json` — Salida de la auditoría

El orquestador guarda los resultados en este archivo al finalizar cada auditoría.

**Formato:**
```json
{
  "total_analyses": 42,
  "vulnerabilities_found": 3,
  "vulnerabilities": [
    {
      "id": "uuid",
      "tipo": "SQL Injection",
      "severidad": "critical",
      "titulo": "SQL Injection en http://objetivo.com/...",
      "descripcion": "...",
      "url": "http://objetivo.com/vulnerabilities/sqli/",
      "payload": "' OR '1'='1",
      "recomendacion": "...",
      "confianza": 0.95,
      "source_type": "sqli",
      "timestamp": "2026-05-09T10:30:00"
    }
  ]
}
```

---

## Flujo de datos completo

```
Carlos Bañuelos Fernández (CDP) captura paquete de red
         ↓
Macarena Rogerio recibe paquete → POST /api/network/packet
         ↓
Jose María López Ausín (IA) → VulnerabilityClassifier.analyze_packet()
         ↓
Claude API analiza con prompt especializado
         ↓
Si confianza ≥ 60%:
  AttackOrchestrator._confirm_vulnerability() → 2 pases adicionales
         ↓
Si confirmada:
  _build_vulnerability() → ficha completa con clasificación OWASP
  send_vulnerability_to_backend() → POST /api/vulnerabilities
         ↓
Macarena Rogerio emite evento WebSocket → Ivan Medina Castro muestra alerta en el dashboard
```

---

## Decisiones de diseño

**Por qué `claude-sonnet-4-20250514` y no un modelo más pequeño:** el análisis de vulnerabilidades requiere razonamiento profundo sobre el contexto de la petición, no solo detección de patrones. Sonnet ofrece el equilibrio adecuado entre capacidad analítica y coste por llamada.

**Por qué umbral de 60% y no más alto:** por debajo de 60% hay demasiado ruido (falsos positivos). Por encima de 75% se pierden vulnerabilidades reales en aplicaciones con respuestas poco informativas. El sistema de doble confirmación compensa el umbral más permisivo.

**Por qué modo mock con variable de entorno:** permite desarrollo completamente independiente sin necesitar que Macarena Rogerio o Nacho García Monge estén listos. Un solo cambio en `.env` activa el modo real sin modificar código.

---

## Limitaciones conocidas

- Las capturas en modo real dependen de que Macarena Rogerio implemente `POST /api/playwright/instruction/{token}` y `POST /api/vulnerabilities`
- El Blind SQLi time-based puede generar falsos positivos en servidores con alta latencia
- El módulo no procesa aplicaciones con autenticación de dos factores
- El coste estimado por auditoría completa de 30 minutos es ~0.15$ con el modelo actual

---

*Documentación técnica del módulo IA — Proyecto HookSuite — Módulo de Ciberseguridad Avanzada 2026*
