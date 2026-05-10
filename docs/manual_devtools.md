# Documentación técnica — HookSuite Chrome DevTools (P4)

## Stack tecnológico

- Python 3.11
- Chrome DevTools Protocol (CDP) via WebSocket
- websockets 12.0
- httpx 0.27.0
- python-dotenv 1.0.1

---

## Qué es el CDP

El Chrome DevTools Protocol es una API interna de Google Chrome que se activa
arrancando el navegador con el flag `--remote-debugging-port=9222`. Una vez activo,
cualquier cliente externo puede conectarse via WebSocket y acceder en tiempo real a
los dominios de red, consola, DOM y rendimiento del navegador.

Nuestro módulo Python se conecta a ese WebSocket y se suscribe a los eventos del
dominio `Network.*` y `Console.*`, recibiendo cada petición HTTP y cada mensaje de
consola que genera el navegador mientras navega por la aplicación objetivo.

### Por qué CDP nativo en vez de una librería de alto nivel

Librerías como Playwright o Puppeteer abstraen el CDP y no exponen todos los eventos
de red necesarios para un análisis de seguridad detallado. Usando CDP directamente
tenemos control total sobre qué eventos escuchamos, cómo construimos los paquetes y
qué filtramos. Esto nos permite acceder al body completo de las respuestas, detectar
headers de seguridad ausentes y marcar peticiones sospechosas con criterios propios.

---

## Módulos

### `core/chrome_launcher.py` — Lanzador de Chrome

Arranca Google Chrome con el flag `--remote-debugging-port=9222` mediante
`subprocess.Popen`. Detecta automáticamente la ruta del ejecutable en macOS, Windows
y Linux. Expone también `verify_cdp_connection()`, que consulta
`http://localhost:9222/json` para confirmar que el protocolo está activo y listar
las pestañas disponibles.

### `core/cdp_client.py` — Cliente CDP via WebSocket

Gestiona la conexión WebSocket con el CDP. Sus responsabilidades principales son:

- Conectarse a la pestaña correcta obteniendo su `webSocketDebuggerUrl`
- Enviar comandos CDP con `send(method, params)` y esperar su respuesta via futures
- Distribuir los eventos entrantes (`Network.requestWillBeSent`,
  `Network.responseReceived`, etc.) a los handlers registrados con `on(event, handler)`
- Activar los dominios necesarios: `Network.enable`, `Console.enable`, `Page.enable`

### `core/packet_builder.py` — Constructor de paquetes

Transforma los eventos CDP en objetos paquete con formato unificado. Mantiene un
diccionario de peticiones pendientes indexado por `requestId`. Cuando llega el evento
`Network.loadingFinished`, combina los datos de request y response en un objeto con
esta estructura:

```json
{
  "id": "uuid",
  "method": "GET",
  "url": "http://...",
  "status": 200,
  "size": 1024,
  "time": 145,
  "timestamp": "ISO-8601",
  "request_headers": {},
  "request_body": null,
  "response_headers": {},
  "response_body": "...",
  "suspicious": false,
  "vulnerable": false
}
```

Incluye filtrado de tráfico irrelevante: imágenes, CSS, fuentes, CDNs conocidos
(Google Analytics, Cloudflare, etc.) y tipos de recurso no relevantes para el
análisis de seguridad. Esto reduce el ruido en aproximadamente un 70%.

### `analyzers/network_analyzer.py` — Analizador de tráfico

Se suscribe a los eventos CDP a través del `CDPClient` y delega la construcción de
paquetes al `PacketBuilder`. Sobre cada paquete completado aplica dos análisis:

**Detección de paquetes sospechosos** (`_check_suspicious`):
- Respuestas HTTP 5xx
- Patrones de error SQL en el body de la respuesta
- Caracteres de inyección en la URL o en el body de la petición (`'`, `"`,
  `<script`, `UNION SELECT`, `--`, `1=1`)
- Tiempos de respuesta superiores a 5000ms

**Análisis de headers de seguridad** (`_check_security_headers`):
- Detecta ausencia de `Content-Security-Policy`, `X-Frame-Options`,
  `Strict-Transport-Security`, `X-Content-Type-Options` y `Referrer-Policy`
- Detecta cookies de sesión sin los flags `HttpOnly` y `Secure`

### `analyzers/console_analyzer.py` — Analizador de consola

Escucha los eventos `Console.messageAdded` del CDP y analiza el texto de cada mensaje
de error o warning con expresiones regulares. Detecta:

- Rutas de servidor expuestas (`/var/www/`, `C:\`, `/home/usuario/`)
- API keys y tokens expuestos en consola
- Contraseñas en texto plano
- Errores de base de datos (MySQL, Oracle, SQLite)
- Stack traces y direcciones IP internas

Clasifica cada hallazgo con severidad `high` (credenciales) o `medium` (resto).

### `utils/reporter.py` — Reporter hacia P2 Backend

Gestiona el envío de paquetes al backend de P2 via `POST
/api/network/packet/{session_token}`. Si el backend no está disponible, almacena los
paquetes en un buffer local y los escribe en `results/captured_packets.json` cada 10
paquetes. Esto garantiza que no se pierde ningún dato aunque P2 no esté operativo.

---

## Flujo de datos

```
Chrome (navegador)
    │
    │  --remote-debugging-port=9222
    ▼
chrome_launcher.py  →  lanza el proceso Chrome
    │
    ▼
cdp_client.py  →  conexión WebSocket al CDP
    │
    │  eventos Network.* y Console.*
    ▼
packet_builder.py  →  construye objeto paquete unificado
    │
    ▼
network_analyzer.py  →  detecta patrones sospechosos y headers ausentes
console_analyzer.py  →  detecta información sensible en consola
    │
    ▼
reporter.py  →  envía a P2 Backend (POST /api/network/packet/)
                o guarda en results/captured_packets.json si P2 no está disponible
    │
    ├──▶  P2 Backend  →  P1 Frontend (dashboard en tiempo real)
    └──▶  P5 IA  →  análisis de vulnerabilidades con Claude
```

---

## Decisiones de diseño

**CDP nativo en vez de librería de alto nivel.** Playwright y Puppeteer abstraen el
protocolo e impiden el acceso directo a ciertos eventos de red. Usando CDP
directamente tenemos control total sobre los eventos que escuchamos y cómo
procesamos los datos.

**Filtrado de tráfico irrelevante en origen.** El `PacketBuilder` descarta imágenes,
CSS, fuentes y CDNs conocidos antes de construir el paquete. Esto reduce el volumen
de datos en un ~70% y hace que los análisis de P5 sean más eficientes.

**Buffer local como fallback.** El `PacketReporter` guarda todos los paquetes en
disco independientemente de si el backend está disponible. Esto permite desarrollar
y probar el módulo de forma completamente independiente antes de la integración con P2.

**Formato de paquete acordado con P2.** El objeto paquete tiene un formato fijo
definido en `PacketBuilder.build_packet()`. Cualquier campo adicional que requiera P2
se añade en ese único punto, lo que mantiene la interfaz entre módulos limpia y
predecible.

---

## Limitaciones conocidas

- Solo captura el tráfico del Chrome controlado por el módulo, no el de otras
  aplicaciones ni el del proxy de P2.
- Algunas respuestas pueden tener el body vacío si Chrome libera la memoria del
  recurso antes de que el módulo lo solicite con `Network.getResponseBody`.
- Requiere que Google Chrome esté instalado en la misma máquina que ejecuta el módulo.
- El CDP no expone el body de respuestas en streaming o chunked transfer en todos
  los casos.
