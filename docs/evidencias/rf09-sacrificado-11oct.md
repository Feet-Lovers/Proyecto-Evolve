# RF-09 (Red/DevTools) — qué había de verdad antes de sacrificarlo

**Fecha:** 2026-10-11 · **Capturado por:** Claude, en la cocina del mediaserver (R1), antes de retirar nada.
**Para qué:** justificar en la memoria el sacrificio de RF-09 **sin repetir el enunciado del pendiente**, que
estaba mal en dos de sus tres puntos. Evidencia de terminal, guardada como texto y no como foto (R3/R7).

## 1. El enunciado del pendiente, contrastado contra el código (R9)

| Lo que afirmaba el pendiente | Lo que dice el código |
|---|---|
| «dos llamadas a endpoints que no existen (404)» | **Una, no dos** — ver §2 |
| «rutas de Windows» | **No es un defecto, es un detector** — ver §3 |
| «IP hardcodeada» | **No hay ninguna IP fija**; lo que hay es `localhost` en 4 ficheros de `devtools/` |

## 2. Las dos llamadas de `devtools/utils/reporter.py` contra los endpoints que existen

Lo que **llama** el capturador:

    reporter.py:45   POST {BACKEND_URL}/api/network/packet/{session_token}
    reporter.py:63   POST {BACKEND_URL}/api/network/console_finding/{session_token}

Lo que **existe** en `backend/routes/network.py` (montado en `main.py:150` con prefijo `/api/network`):

    network.py:33    POST  /packet
    network.py:51    POST  /packet/{session_token}      <-- la llamada de :45 SI existe
    network.py:62    GET   /packets/{session_token}
    network.py:68    POST  /session_cookie
    network.py:74    GET   /session_cookie/{host:path}

**Resultado: 1 de 2.** `/api/network/packet/{token}` existe y responde; `/api/network/console_finding/{token}`
**no existe** — los hallazgos de consola que el capturador envía se pierden contra un 404.

## 3. La supuesta «ruta de Windows»

`devtools/analyzers/console_analyzer.py:8` contiene:

    (r'C:\\', "SERVER_PATH_EXPOSED")

No es una ruta hardcodeada que rompa nada: es un **patrón de detección** que marca como hallazgo las rutas de
servidor expuestas en la consola del navegador. Es una característica del analizador, no un defecto.

## 4. La pestaña del front era pasiva

`frontend/src/pages/network/NetworkPage.jsx` (113 líneas) importaba solo `useSession`, `useWebSocket` y
`Badge`: **ni un `fetch`, ni un `axios`, ni una URL**. Solo pintaba los paquetes que llegaban por WebSocket.
Los 404 nunca salieron de la pestaña, sino del capturador CDP, que es un proceso aparte.

## 5. Lo que queda vivo detrás, y por qué no se toca

- `backend/routes/network.py` **se queda**: sus endpoints los consumen `ia/orchestrator.py` y `playwright/`
  (declarado en `main.py:158`). Quitarlos rompería RF-08, que empezó a funcionar el 10-oct.
- `networkPackets` en `AppContext.jsx` y `hooks/useWebSocket.js` **se queda** por ahora: vive en la vía del
  WebSocket que alimenta las cinco pestañas restantes, y no se toca en mitad del pulido.
- `devtools/` **se queda en el repo**: es el trabajo hecho, va al apartado de trabajo futuro, no se borra.

## 6. Hallazgo colateral

`AppContext.jsx` y `hooks/useWebSocket.js` tienen **la misma lógica de WebSocket duplicada** (ambos declaran
`networkPackets`, llaman a `normalizePacket` y manejan `network_packet`). Dos fuentes de verdad para el mismo
canal: candidato a explicar comportamientos distintos según qué componente lea de cuál.
