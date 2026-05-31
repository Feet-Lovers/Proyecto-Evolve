// ============================================================
// HookSuite — Informe técnico de la Práctica 1
// Módulo de Ciberseguridad Avanzada | Curso 2026
// Compilar: typst compile main.typ informe_hooksuite.pdf --root docs
// ============================================================

#let azul = rgb("#0F1B2D")
#let azul-acento = rgb("#1A6FBF")
#let azul-claro = rgb("#EBF3FB")
#let gris-texto = rgb("#444444")
#let gris-borde = rgb("#CCCCCC")

#set document(
  title: "HookSuite — Herramienta de auditoría de seguridad web con IA",
  author: "Jose María López Ausín, Ivan Medina Castro, Macarena Rogerio, Nacho García Monge, Carlos Bañuelos Fernández",
)

#set page(
  paper: "a4",
  margin: (top: 0cm, bottom: 0cm, left: 0cm, right: 0cm),
  numbering: none,
)

#set text(
  font: "Arial",
  size: 11pt,
  lang: "es",
  fill: rgb("#1a1a1a"),
)

#set par(justify: true, leading: 0.75em)

// ============================================================
// PORTADA
// ============================================================

#block(width: 100%, height: 100%, fill: azul)[
  #block(width: 100%, height: 2cm, fill: azul-acento)[]

  #pad(left: 3cm, right: 3cm, top: 1.5cm)[
    #v(1.5cm)

    #text(size: 52pt, weight: "bold", fill: white)[Hook]#text(
      size: 52pt, weight: "bold", fill: azul-acento,
    )[Suite]

    #v(0.4cm)

    #text(size: 14pt, fill: rgb("#8FA8C0"))[
      Herramienta de auditoría de seguridad web con Inteligencia Artificial
    ]

    #v(1cm)
    #block(width: 60pt, height: 2pt, fill: azul-acento)[]
    #v(1cm)

    #text(size: 11pt, fill: rgb("#8FA8C0"))[
      *#text(fill: rgb("#C8D8E8"))[Módulo]* · Ciberseguridad Avanzada | Curso 2026 \
      *#text(fill: rgb("#C8D8E8"))[Práctica]* · Práctica 1 — Red Team
    ]

    #v(1.5cm)
    #line(length: 100%, stroke: 0.5pt + rgb("#1E3A5F"))
    #v(0.8cm)

    #text(size: 9pt, fill: rgb("#5B8DB8"), tracking: 1.5pt)[EQUIPO DE DESARROLLO]
    #v(0.6cm)

    #let miembro(rol, nombre, modulo) = {
      grid(
        columns: (1.2cm, 5cm, 1fr),
        gutter: 0.5cm,
        align: left,
        block(fill: rgb("#1E3A5F"), inset: (x: 6pt, y: 4pt), radius: 3pt)[
          #text(size: 9pt, weight: "bold", fill: azul-acento)[#rol]
        ],
        text(size: 11pt, fill: rgb("#C8D8E8"), weight: "bold")[#nombre],
        text(size: 10pt, fill: rgb("#8FA8C0"))[#modulo],
      )
      v(0.4cm)
    }

    #miembro("P1", "Ivan Medina Castro", "Frontend — React + Vite + Tailwind")
    #miembro("P2", "Macarena Rogerio", "Backend — FastAPI + Python")
    #miembro("P3", "Nacho García Monge", "Playwright — Automatización")
    #miembro("P4", "Carlos Bañuelos Fernández", "DevTools — Chrome DevTools Protocol")
    #miembro("P5", "Jose María López Ausín", "IA + GitHub — Claude API")

    #v(1cm)
    #line(length: 100%, stroke: 0.5pt + rgb("#1E3A5F"))
    #v(0.6cm)

    #grid(
      columns: (1fr, auto),
      text(size: 10pt, fill: azul-acento)[#link("https://github.com/Feet-Lovers/Proyecto-Evolve")[github.com/Feet-Lovers/Proyecto-Evolve]],
      text(size: 10pt, fill: rgb("#8FA8C0"))[Entrega · 31 de Mayo de 2026],
    )
  ]
]

// ============================================================
// CONFIGURACIÓN PÁGINAS INTERIORES
// ============================================================

#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2.5cm, left: 3cm, right: 2.5cm),
  numbering: "1",
  number-align: center,
  header: [
    #grid(
      columns: (1fr, auto),
      align: (left, right),
      text(size: 9pt, fill: rgb("#888888"))[HookSuite — Ciberseguridad Avanzada | Curso 2026],
      text(size: 9pt, fill: azul-acento)[Práctica 1],
    )
    #line(length: 100%, stroke: 0.5pt + gris-borde)
  ],
  footer: [
    #line(length: 100%, stroke: 0.5pt + gris-borde)
    #v(4pt)
    #align(center)[
      #context text(size: 9pt, fill: rgb("#888888"))[#counter(page).display("1")]
    ]
  ],
)

#set text(size: 11pt, fill: rgb("#1a1a1a"))
#set heading(numbering: "1.1.")

#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  v(0.5em)
  block[
    #text(size: 9pt, fill: azul-acento, tracking: 1.5pt, weight: "regular")[
      #upper[Sección #counter(heading).display("1")]
    ]
    #v(0.2em)
    #text(size: 20pt, weight: "bold", fill: azul)[#it.body]
    #v(0.2em)
    #block(width: 50pt, height: 2pt, fill: azul-acento)[]
  ]
  v(0.8em)
}

#show heading.where(level: 2): it => {
  v(0.8em)
  grid(
    columns: (3pt, 1fr),
    gutter: 8pt,
    block(width: 3pt, height: 16pt, fill: azul-acento, radius: 1pt)[],
    text(size: 13pt, weight: "bold", fill: azul)[#it.body],
  )
  v(0.3em)
}

#show heading.where(level: 3): it => {
  v(0.5em)
  text(size: 11pt, weight: "bold", fill: gris-texto)[#it.body]
  v(0.2em)
}

#show raw.where(block: true): it => {
  block(fill: azul, inset: 12pt, radius: 4pt, width: 100%)[
    #text(font: "Courier New", size: 9pt, fill: rgb("#8FA8C0"))[#it]
  ]
}

#set table(stroke: none, inset: (x: 10pt, y: 8pt))

// ============================================================
// ÍNDICE
// ============================================================

#page(header: none, footer: none, numbering: none)[
  #v(2cm)
  #text(size: 20pt, weight: "bold", fill: azul)[Índice de contenidos]
  #v(0.3cm)
  #block(width: 50pt, height: 2pt, fill: azul-acento)[]
  #v(1cm)
  #outline(title: none, indent: auto)
]

// ============================================================
// 1. RESUMEN EJECUTIVO
// ============================================================

= Resumen ejecutivo

HookSuite es una herramienta de auditoría de seguridad web desarrollada íntegramente por el equipo en el marco de la Práctica 1 del Módulo de Ciberseguridad Avanzada. Su objetivo es automatizar el proceso de detección de vulnerabilidades web combinando análisis de tráfico HTTP en tiempo real, fuzzing automatizado de parámetros y análisis inteligente mediante inteligencia artificial.

Funcionalmente, HookSuite opera de forma similar a Burp Suite pero con tres diferencias clave: está construida desde cero, es accesible desde cualquier navegador sin instalación de software adicional en el cliente, e incorpora inteligencia artificial para clasificar y priorizar vulnerabilidades según el estándar OWASP.

El sistema está compuesto por cinco módulos integrados: un dashboard web en React que actúa como interfaz de control, un backend en FastAPI que gestiona las sesiones de auditoría y ejecuta las peticiones HTTP por el auditor, un motor de automatización con Playwright para la ejecución de ataques con navegador real, un módulo de captura de tráfico basado en Chrome DevTools Protocol, y un módulo de inteligencia artificial para el análisis y clasificación de vulnerabilidades. Los módulos de Playwright, DevTools e IA están integrados en la arquitectura del sistema y su activación completa está planificada para la Práctica 2.

La herramienta está desplegada en un servidor Hetzner Cloud CX22 y es accesible desde cualquier navegador a través de su URL pública. En su estado actual, el Spider, el Repeater, el Intruder y las Utilidades están completamente operativos y han sido validados contra DVWA (Damn Vulnerable Web Application). El desarrollo completo, incluyendo el historial de commits, está disponible en el repositorio público de la organización Feet-Lovers en GitHub.

// ============================================================
// 2. DESCRIPCIÓN DEL PROBLEMA Y JUSTIFICACIÓN
// ============================================================

= Descripción del problema y justificación

== El ecosistema actual de herramientas de auditoría web

Las herramientas de auditoría de seguridad web más utilizadas en la industria —Burp Suite, OWASP ZAP, Nikto— comparten un patrón común: requieren instalación local, generan grandes volúmenes de tráfico fácilmente detectable, y delegan en el analista la mayor parte del trabajo de interpretación de resultados. Son herramientas potentes pero con tres limitaciones estructurales que HookSuite aborda directamente.

La primera es la dependencia del analista humano. Herramientas como Burp Suite interceptan el tráfico y presentan los datos en bruto, pero la interpretación —determinar qué es una vulnerabilidad, qué severidad tiene, qué ataque ejecutar a continuación— recae íntegramente en el criterio del analista. Esto convierte la auditoría en un proceso que escala mal: más tráfico equivale a más tiempo de análisis manual.

La segunda es la accesibilidad. La mayoría de herramientas profesionales requieren configuración local del sistema operativo, instalación de certificados de seguridad y conocimientos técnicos previos para operar. Esto eleva la barrera de entrada y dificulta su uso en entornos educativos o en equipos con perfiles heterogéneos.

La tercera es la trazabilidad. Las auditorías realizadas con herramientas tradicionales generan logs dispersos, difícilmente exportables y sin estructura estandarizada. Integrar los resultados en un flujo de trabajo moderno —CI/CD, ticketing, informes automáticos— requiere desarrollo adicional específico para cada herramienta.

== La propuesta de HookSuite

HookSuite nace como respuesta a estas tres limitaciones. Su arquitectura combina tecnologías modernas para construir una solución que es a la vez accesible, inteligente y trazable.

La accesibilidad se resuelve mediante un dashboard web accesible desde cualquier navegador sin instalación ni configuración adicional. El analista dirige el proceso —introduce la URL objetivo, define el scope, lanza el spider, selecciona peticiones para el Repeater y configura los ataques en el Intruder— mientras el servidor ejecuta las operaciones pesadas sin intervención adicional del cliente.

La automatización del análisis se resuelve mediante un módulo de inteligencia artificial integrado en el sistema. Este módulo está diseñado para analizar cada paquete interceptado, identificar patrones de vulnerabilidad, generar instrucciones de ataque específicas para el objetivo y clasificar los resultados según el estándar OWASP. El analista recibirá vulnerabilidades clasificadas y priorizadas, no datos en bruto.

La trazabilidad se resuelve mediante un sistema de registro estructurado. Cada vulnerabilidad detectada genera una ficha completa con identificador único, tipo, severidad, URL afectada, payload utilizado y recomendación de mitigación, exportable en formato JSON estándar.

== Relevancia en el contexto académico

Este proyecto desarrolla competencias en cinco áreas simultáneamente: desarrollo web full-stack, seguridad ofensiva, integración de APIs de inteligencia artificial, trabajo con protocolos HTTP a bajo nivel e infraestructura en la nube. La naturaleza distribuida del sistema —cinco módulos integrados desarrollados en paralelo por cinco personas— añade una dimensión de ingeniería de software que va más allá del ejercicio técnico individual.

// ============================================================
// 3. ARQUITECTURA TÉCNICA
// ============================================================

= Arquitectura técnica

== Visión general del sistema

HookSuite está compuesto por cinco módulos independientes que se comunican a través de una capa de backend centralizada. Cada módulo fue desarrollado por un miembro del equipo de forma autónoma y se integra con el resto a través de contratos de API definidos previamente.

// TODO: Sustituir el diagrama ASCII por la imagen definitiva del diagrama de arquitectura
// #figure(image("../capturas/arquitectura.png", width: 100%), caption: "Arquitectura técnica de HookSuite")

```
P1 — Frontend React (dashboard web)
         │ WebSocket + REST
         ▼
P2 — Backend FastAPI + httpx
    ┌────┴────┬─────────────┐
    ▼         ▼             ▼
P3            P5            P4
Playwright    IA            DevTools
(ataques)     (análisis)    (captura red)
```

_Los módulos P3, P4 y P5 están integrados en la arquitectura y su activación completa está planificada para la Práctica 2._

== Proceso de decisión arquitectónica

El diseño de HookSuite partió de una pregunta técnica concreta: ¿cómo construir una herramienta de auditoría web accesible desde el navegador sin instalar software adicional en el cliente?

La investigación inicial identificó tres limitaciones fundamentales del navegador que condicionaron toda la arquitectura. El modelo de seguridad del navegador impide interceptar el tráfico de otras pestañas y aplicaciones por la política de mismo origen, actuar como proxy TCP al no tener acceso a sockets TCP arbitrarios, y modificar headers protegidos como Host, Origin o Cookie en las peticiones fetch y XHR. La conclusión fue que la función central de una herramienta de auditoría es técnicamente imposible si toda la lógica reside en el frontend. La solución pasaba por mover el proxy al servidor.

Con esa premisa, el equipo evaluó cinco opciones para gestionar la interceptación del tráfico:

#table(
  columns: (1fr, auto),
  fill: (_, y) => if y == 0 { azul } else if calc.odd(y) { azul-claro } else { white },
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Opción]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Resultado]],
  [Extensión de navegador], [❌ Descartada — rompe el concepto de web app],
  [Certificado CA propio], [❌ Descartada — requiere instalar certificado en el cliente],
  [Proxy SOCKS5], [❌ Descartada — configuración manual compleja],
  [Electron híbrido], [❌ Descartada — requiere instalar aplicación de escritorio],
  [Archivo PAC + WebSockets], [✅ Seleccionada],
)

La opción seleccionada combinaba dos elementos. Un archivo PAC (Proxy Auto-Configuration) alojado en el servidor — un fichero JavaScript que el navegador lee antes de cada petición para decidir si enrutar el tráfico a través del proxy. Y WebSockets como canal de comunicación bidireccional en tiempo real entre el frontend y el backend. Esta combinación ofrecía compatibilidad con todos los navegadores modernos, sin instalaciones en el cliente, y soporte nativo para múltiples usuarios simultáneos mediante tokens de sesión UUID.

La validez de esta arquitectura fue confirmada por Caido — una herramienta de seguridad web profesional con arquitectura cliente-servidor idéntica que también requiere configuración manual del proxy, lo que confirmó que no existe ninguna alternativa técnica viable que evite ese paso sin instalar una extensión o aplicación.

Esta arquitectura inicial fue posteriormente descartada cuando al exponerla al exterior los bots saturaron el servidor. El equipo pivotó hacia un modelo donde el servidor realiza las peticiones HTTP directamente por el auditor — eliminando la necesidad de configuración del proxy en el navegador y resolviendo el problema de saturación. Esta decisión redefinió el rol de cada módulo y condicionó la fase de integración del proyecto.

== Stack tecnológico

#table(
  columns: (auto, 1fr, auto),
  fill: (_, y) => if y == 0 { azul } else if calc.odd(y) { azul-claro } else { white },
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Módulo]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Tecnologías]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Responsable]],
  [Frontend], [React 19 + Vite + Tailwind CSS], [P1 — Ivan],
  [Backend], [Python 3.11 + FastAPI + httpx + WebSockets], [P2 — Macarena],
  [Playwright], [Python + Playwright + httpx], [P3 — Nacho],
  [DevTools], [Python + WebSockets + httpx], [P4 — Carlos],
  [IA], [Claude Code], [P5 — Jose María],
  [Infraestructura], [Docker + Hetzner Cloud CX22 + Nginx], [Todos],
)

== Contratos de integración activos — Práctica 1

#table(
  columns: (1fr, 1fr, auto),
  fill: (_, y) => if y == 0 { azul } else if calc.odd(y) { azul-claro } else { white },
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Integración]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Canal]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Estado]],
  [P1 ↔ P2 (Frontend — Backend)], [WebSocket + REST], [✅ Activo],
)

_Los contratos de integración de P3, P4 y P5 con el Backend se definirán y documentarán durante la Práctica 2._

// ============================================================
// 4. PROCESO DE DESARROLLO
// ============================================================

= Proceso de desarrollo

// ============================================================
// 4.1 PROCESO INDIVIDUAL
// ============================================================

== Proceso individual

El desarrollo de HookSuite arrancó con cada miembro construyendo su módulo de forma autónoma. Durante esta fase el equipo trabajó en paralelo — cada uno contra su propio entorno local con DVWA como objetivo de pruebas — siguiendo los contratos de integración definidos al inicio del proyecto. El resultado fue cinco módulos independientes y validados en local, listos para conectarse entre sí.

=== P1 — Frontend (Ivan Medina Castro)

==== Fase 0 — Investigación y decisiones de arquitectura

Antes de que Ivan iniciara el desarrollo, el equipo realizó una investigación técnica para definir la arquitectura de la herramienta. La conclusión fue que HookSuite operaría como un proxy en el navegador del usuario — el tráfico del auditor pasaría a través del servidor antes de llegar al objetivo, permitiendo interceptarlo y analizarlo. Esta arquitectura requería que el usuario configurara su navegador apuntando a un archivo PAC que el servidor generaba dinámicamente.

Para minimizar la fricción de esa configuración, el equipo diseñó un asistente de onboarding que detectaba automáticamente el navegador y sistema operativo del usuario y mostraba instrucciones paso a paso personalizadas. El asistente verificaba cada dos segundos si el proxy estaba activo y cerraba el modal automáticamente cuando lo detectaba. Como alternativa para usuarios que no quisieran configurar el proxy, se diseñó también un importador de peticiones que permitía pegar peticiones en formato raw HTTP o cURL directamente en el Repeater. Estas decisiones definieron el alcance inicial del módulo y los componentes que Ivan debía construir.

==== Fase 1 — Construcción con mock mode y validación con proxy PAC

Ivan construyó el Frontend completo siguiendo su manual de desarrollo, entregando la primera versión funcional con toda la estructura base del proyecto: layout con sidebar de navegación, sistema de componentes UI reutilizables, hooks de WebSocket y sesión, las seis páginas principales, el asistente de configuración del proxy con detección automática de navegador y sistema operativo, el importador de peticiones, y un sistema completo de mock data.

El sistema de mock data fue una de las decisiones técnicas más relevantes del módulo. Dado que el Frontend se desarrollaba en paralelo al Backend, Ivan construyó un conjunto de datos simulados que replicaban exactamente el formato que emitiría el WebSocket real. Esto permitió desarrollar y validar toda la interfaz de forma completamente independiente, sin bloqueos por dependencias entre módulos.

Con la interfaz validada en mock, Ivan configuró el proxy PAC en local y conectó el Frontend contra DVWA. En esta fase la herramienta funcionó como estaba diseñada originalmente: el proxy interceptaba el tráfico del navegador del auditor, las peticiones aparecían en el panel Proxy en tiempo real, el auditor podía enviarlas al Repeater para modificarlas y reenviarlas, y el Intruder ejecutaba payloads SQLi reales contra los formularios de DVWA.

=== P2 — Backend (Macarena Rogerio)

==== Fase 1 — Construcción del servidor base

Macarena comenzó configurando el entorno Python en Windows, donde encontró el primer obstáculo técnico del módulo: al intentar instalar las dependencias del proyecto, la versión de Python disponible en el sistema era incompatible con `pydantic-core`, que requería compilar extensiones nativas con Rust y Cargo — una cadena de herramientas que no estaba disponible en el entorno. Lo resolvió instalando Python 3.12 mediante el gestor oficial y creando un entorno virtual específico para esa versión.

#figure(
  image("../capturas/backend/backend_error_instalacion.png", width: 90%),
  caption: "Error de compilación de pydantic-core durante la instalación de dependencias"
)

Con el entorno configurado, definió la estructura de carpetas del módulo — `routes/`, `services/`, `models/`, `middleware/` — que organizaría todos los bloques funcionales del backend.

#figure(
  image("../capturas/backend/backend_estructura_carpetas.png", width: 80%),
  caption: "Estructura de carpetas del Backend planificada al inicio de la construcción"
)

Con la estructura en su sitio, construyó el servidor FastAPI base con los endpoints de salud, la gestión de sesiones con tokens UUID y el canal WebSocket en `/ws/{token}`. Verificó el funcionamiento del servidor consultando `/health` desde el navegador y comprobando que el Swagger UI en `/docs` mostraba los endpoints registrados.

#figure(
  image("../capturas/backend/backend_health_respondiendo.png", width: 70%),
  caption: "Endpoint /health respondiendo correctamente — servidor base operativo"
)

#figure(
  image("../capturas/backend/backend_swagger_base.png", width: 90%),
  caption: "Swagger UI con los primeros endpoints registrados"
)

Una vez verificado el servidor base, añadió la gestión de sesiones con el endpoint `/api/session/new` — el punto de coordinación con el Frontend: en cuanto el WebSocket estuvo operativo, Ivan pudo conectar el Frontend al Backend real y validar el contrato de comunicación.

#figure(
  image("../capturas/backend/backend_swagger_session.png", width: 90%),
  caption: "Swagger UI con el endpoint /api/session/new añadido — gestión de sesiones operativa"
)

==== Fase 2 — Implementación del proxy TCP con mitmproxy

Con el servidor base operativo, Macarena implementó la arquitectura de proxy TCP usando mitmproxy — una librería que escucha en el puerto 8080 y procesa cada petición HTTP a través de un addon personalizado que extrae los datos relevantes y los emite por WebSocket al Frontend en tiempo real. En paralelo implementó los modelos Pydantic en `schemas.py` y la función `forward_request` en el servicio de proxy HTTP, que gestiona el reenvío de peticiones con manejo de timeouts, filtrado de headers protegidos y análisis de respuestas sospechosas.

La integración de mitmproxy presentó cuatro errores encadenados que Macarena resolvió de forma sistemática: la librería no estaba instalada correctamente, una dependencia de gestión de contraseñas tenía una versión incompatible, los bloques de excepción del `proxy_service` estaban mal colocados y al corregirlos se perdieron funciones del fichero. Cada error llevó al siguiente hasta tener el servidor arrancando limpiamente con mitmproxy y FastAPI como procesos independientes.

#figure(
  image("../capturas/backend/backend_swagger_proxy.png", width: 90%),
  caption: "Swagger UI con el grupo proxy y los schemas Pydantic definidos — arquitectura de proxy interceptor operativa"
)

=== P3 — Playwright (Nacho García Monge)

==== Fase 1 — Setup y optimización de velocidad

Nacho arrancó el módulo configurando el entorno Playwright con Chromium y levantando DVWA en Docker como entorno de pruebas local.

#figure(
  image("../capturas/playwright/docker_dvwa.png", width: 90%),
  caption: "DVWA levantándose en Docker — entorno de pruebas local operativo"
)

Antes de construir los componentes principales, verificó el entorno con dos scripts de prueba: uno que comprobó que Playwright arrancaba correctamente navegando a example.com, y otro que confirmó el login automático en DVWA. Ambos se eliminaron tras la verificación.

#figure(
  image("../capturas/playwright/test_playwright.png", width: 90%),
  caption: "Verificación de Playwright — instalación de Chromium, Firefox y WebKit completada"
)

#figure(
  image("../capturas/playwright/test_playwright_ok.png", width: 90%),
  caption: "Script de prueba ejecutándose correctamente — Playwright funciona, título de la página verificado"
)

#figure(
  image("../capturas/playwright/test_dvwa_ok.png", width: 90%),
  caption: "Login automático en DVWA verificado — autenticación con Playwright funcionando"
)

La primera decisión técnica fue la optimización de velocidad: verificó la diferencia real entre `page.type()` y `page.fill()` mediante un script de benchmark sobre el formulario de login de DVWA. La mejora medida — hasta 60 veces más rápido — confirmó que `page.fill()` debía usarse de forma sistemática en todo el módulo. Nacho verificó también que ningún módulo utilizara `page.type()`, confirmando que la optimización se aplicaba de forma consistente en toda la base de código.

#figure(
  image("../capturas/playwright/verificacion_pagetype.png", width: 90%),
  caption: "Verificación sistemática — ningún uso de page.type() en el código, comentario de optimización visible en browser.py"
)

Con esa decisión tomada, construyó el `BrowserManager` con `asyncio.Semaphore` para el control de paralelismo, que actúa como base para todos los demás componentes.

==== Fase 2 — Reconocimiento automático

Con la infraestructura base operativa, Nacho construyó los tres módulos de reconocimiento: el sistema de autenticación para DVWA y la variante genérica parametrizable, el spider con BFS y filtrado de extensiones estáticas, y el fingerprinter con detección de nueve tecnologías y generación de prioridades de ataque.

En la primera ejecución contra DVWA el spider descubrió 20 URLs — la totalidad de la superficie de ataque de la aplicación — guardando los resultados en `results/spider_results.json`.

#figure(
  image("../capturas/playwright/spider_output.png", width: 90%),
  caption: "Spider ejecutándose contra DVWA — 20 URLs descubiertas en la primera ejecución"
)

#figure(
  image("../capturas/playwright/spider_results_json.png", width: 90%),
  caption: "Fichero spider_results.json generado automáticamente — 20 URLs descubiertas en formato JSON"
)

Durante el desarrollo del fingerprinter apareció un bug que no llegó a resolverse antes de la entrega: en determinadas condiciones al procesar los headers de respuesta, el módulo lanza un error `not enough values to unpack`. El bug no bloquea el funcionamiento — cuando ocurre el fingerprinter devuelve igualmente los resultados parciales disponibles — pero es una deuda técnica identificada para la Práctica 2.

==== Fase 3 — Automatización de ataques y validación del flujo completo

Con los módulos de reconocimiento operativos, Nacho implementó el motor de ataques con cuatro variantes: inyección de payloads en formularios con detección de anomalías en la respuesta, Blind SQLi boolean-based con comparación de longitudes de respuesta ante condiciones verdaderas y falsas, Blind SQLi time-based con medición de tiempos de respuesta ante payloads con `SLEEP()` y `WAITFOR DELAY`, y captura automática de screenshots como evidencia de cada ataque. El descubridor de formularios recibió también en esta fase la capacidad de detectar endpoints AJAX mediante interceptación de eventos de red.

Para validar la integración entre los módulos de reconocimiento y ataque, Nacho desarrolló `test_full_flow.py` — un test que ejecuta de forma encadenada fingerprinting, spider y ataque SQLi verificando que el receptor de instrucciones coordina correctamente los tres módulos. Los tres tests completaron correctamente: PHP detectado, 5 URLs descubiertas, SQLi vulnerable.

#figure(
  image("../capturas/playwright/test_full_flow.png", width: 90%),
  caption: "test_full_flow.py — los tres tests completados: fingerprinting PHP, spider 5 URLs, SQLi vulnerable: True"
)

Con todos los módulos construidos, Nacho los integró en el orquestador `main.py` y ejecutó el flujo completo contra DVWA: autenticación, fingerprinting, reconocimiento con el spider, descubrimiento de formularios y ataques automatizados. La auditoría completó las cinco fases descubriendo 15 URLs, analizando 7 formularios y detectando 1 vulnerabilidad de SQL Injection.

#figure(
  image("../capturas/playwright/auditoria_fases.png", width: 90%),
  caption: "Orquestador main.py ejecutando las cinco fases — autenticación, fingerprinting, spider, formularios y ataques"
)

#figure(
  image("../capturas/playwright/auditoria_completada.png", width: 90%),
  caption: "AUDITORÍA COMPLETADA — 15 URLs descubiertas, 7 formularios analizados, 1 vulnerabilidad encontrada"
)

Desarrolló también `demo.py` como script de demostración del flujo completo, que confirmó la detección de SQLi mediante el error `SQL_ERROR: you have an error in your sql syntax` en la respuesta.

#figure(
  image("../capturas/playwright/demo_completada.png", width: 90%),
  caption: "demo.py — flujo completo en 7 pasos, SQL Injection detectada con error SQL real en la respuesta"
)

=== P4 — DevTools (Carlos Bañuelos Fernández)

==== Fase 1 — Construcción del módulo

Carlos construyó el módulo de forma completamente autónoma. La primera decisión técnica fue usar el CDP de forma nativa mediante WebSocket en lugar de una librería de alto nivel — necesitaba control total sobre qué eventos capturar y cuándo recuperar el body de la respuesta. Con esa decisión tomada construyó los cinco componentes del módulo: el lanzador de Chrome con detección multiplataforma, el cliente CDP con su sistema de comandos asíncronos, el constructor de paquetes con filtrado de tráfico irrelevante, los analizadores de red y consola, y el reporter con buffer local como fallback.

#figure(
  image("../capturas/devtools/devtools_terminal_captura.png", width: 90%),
  caption: "Módulo DevTools en ejecución — capturando peticiones HTTP de DVWA vía Chrome DevTools Protocol"
)

==== Fase 2 — Validación contra DVWA

Con el módulo construido, Carlos lo validó contra DVWA verificando que el CDP capturaba correctamente las peticiones HTTP, que el filtrado eliminaba el tráfico irrelevante — imágenes, fuentes, CDNs — dejando únicamente las peticiones relevantes, y que los analizadores detectaban correctamente los patrones sospechosos al provocar errores SQL en los formularios de DVWA.

En esta fase apareció el bug más relevante del módulo: Chrome ignoraba los flags de debugging cuando ya había una instancia abierta en el sistema. Carlos lo identificó y lo resolvió añadiendo `--user-data-dir` con un directorio de perfil separado, garantizando que el Chrome lanzado por DevTools arranque siempre con los flags correctos independientemente del estado del sistema. También añadió `--remote-allow-origins=*` para evitar restricciones de origen en la conexión WebSocket al CDP.

#figure(
  image("../capturas/devtools/cdp_conectado.png", width: 90%),
  caption: "Arranque del módulo DevTools — Chrome lanzado, CDP activo y analizadores inicializados"
)

#figure(
  image("../capturas/devtools/paquetes_tiempo_real.png", width: 90%),
  caption: "Captura de tráfico en tiempo real — petición marcada como sospechosa con SQL_ERROR_IN_RESPONSE"
)

#figure(
  image("../capturas/devtools/hallazgo_consola.png", width: 90%),
  caption: "Analizador de consola detectando PASSWORD_EXPOSED en los logs de DVWA"
)

#figure(
  image("../capturas/devtools/json_paquete.png", width: 70%),
  caption: "Objeto paquete generado por el constructor — cinco headers de seguridad ausentes detectados"
)

=== P5 — IA (Jose María López Ausín)

==== Fase 1 — Construcción del módulo

El módulo arrancó con la construcción del cliente, los cuatro prompts especializados y el clasificador. La primera decisión técnica fue el formato JSON obligatorio en todos los prompts — la alternativa era parsear texto libre, pero eso introduce fragilidad que no tiene cabida en una herramienta de auditoría donde la precisión es crítica.

Con la estructura base lista, se validó el ciclo completo contra la API real mediante un test standalone sobre DVWA en local: el prompt de paquetes de red detectó una inyección SQL con un 95% de confianza en el primer intento, sin necesidad de que el Backend ni Playwright estuvieran activos.

#figure(
  image("../capturas/ia/api_funcionando.png", width: 90%),
  caption: "Test standalone — detección de SQLi con 95% de confianza y fingerprint con vectores priorizados"
)

Durante esta fase apareció una incidencia de seguridad: la API key se expuso accidentalmente en el fichero `.env.example` subido al repositorio. GitHub Secret Scanning la detectó y revocó automáticamente. La versión `0.25.0` de la librería de Anthropic era además incompatible con Python 3.14 del sistema, lo que se resolvió actualizando a `>=0.97.0`.

==== Fase 2 — Orquestador y modo mock

Con el clasificador validado, se construyó el orquestador con las tres fases de auditoría y el modo mock controlado por variable de entorno. El modo mock fue una decisión de diseño deliberada: permitía desarrollar y probar el ciclo completo IA→Playwright→Backend sin depender de que los otros módulos estuvieran operativos. Durante la construcción del orquestador aparecieron dos bugs que se resolvieron antes del primer commit: algunos métodos síncronos del clasificador se llamaban con `await`, y la firma del método `fingerprint` era incorrecta.

#figure(
  image("../capturas/ia/orquestador_mock.png", width: 90%),
  caption: "Orquestador en modo mock — las tres fases ejecutadas, 4 URLs descubiertas, 0 vulnerabilidades confirmadas (comportamiento esperado en mock)"
)

// ============================================================
// 4.2 INTEGRACIÓN
// ============================================================

== Integración

=== Integración en local

Con los cinco módulos construidos y validados de forma independiente, el equipo se reunió para conectarlos por primera vez. La integración en local se realizó con el sistema completo corriendo en los equipos de desarrollo — Backend, Frontend, módulo IA, Playwright y DevTools levantados simultáneamente, con DVWA como objetivo de pruebas.

La integración fue fluida. Los contratos de API definidos al inicio del proyecto habían eliminado la mayoría de los problemas de compatibilidad — cuando el Frontend conectó al WebSocket real del Backend los datos fluían con el formato esperado, el módulo IA operaba en modo mock coordinándose con el Backend, Playwright respondía en modo polling y DevTools capturaba tráfico y lo enviaba al panel Red. Los ajustes necesarios fueron menores: correcciones de puerto, apuntado de conexiones entre servicios y pequeños ajustes de configuración. Al cierre de esta fase el sistema funcionaba end-to-end en local con todos los módulos activos: el proxy interceptaba el tráfico del navegador del auditor, las peticiones aparecían en el panel Proxy en tiempo real, el Repeater reenviaba peticiones modificadas, el Intruder ejecutaba ataques SQLi contra DVWA con resultados visibles en el panel de Vulnerabilidades, el panel Red mostraba el tráfico capturado por DevTools y el módulo IA analizaba los paquetes en modo mock.

#figure(
  image("../capturas/frontend/frontend_proxy_local.jpeg", width: 90%),
  caption: "Panel Proxy interceptando tráfico real de DVWA en local — peticiones con status codes reales"
)

#figure(
  image("../capturas/frontend/frontend_repeater_local.jpeg", width: 90%),
  caption: "Panel Repeater en local — editor de peticiones con soporte de headers y body"
)

#figure(
  image("../capturas/frontend/frontend_intruder_local.jpeg", width: 90%),
  caption: "Panel Intruder en local — URL objetivo, punto de inyección y tipo de ataque configurados"
)

#figure(
  image("../capturas/frontend/frontend_utilidades_local.jpeg", width: 90%),
  caption: "Panel Utilidades en local — Encoder/Decoder con todos los formatos disponibles"
)

#figure(
  image("../capturas/frontend/frontend_vulnerabilidades_local.jpeg", width: 90%),
  caption: "Panel Vulnerabilidades en local — SQL Injection crítica detectada en DVWA"
)

#figure(
  image("../capturas/frontend/frontend_red_local.jpeg", width: 90%),
  caption: "Panel Red en local — tráfico clasificado como limpio, sospechoso y vulnerable"
)

=== Despliegue en Hetzner

Con el sistema validado en local, el equipo preparó el repositorio para producción y creó el servidor. Macarena generó los Dockerfiles de todos los módulos y el `docker-compose.yml` de producción, añadió el `.env.example` con todas las variables del sistema y configuró los endpoints de integración. Nacho adaptó el modo de arranque del contenedor de Playwright a polling pasivo para que el sistema pudiera desplegarse sin bloquear el arranque del resto de servicios. Ivan corrigió los nombres de ficheros con mayúsculas incorrectas en Linux y el bug de `crypto.randomUUID` no disponible en HTTP.

Con el repositorio listo, se aprovisionó el servidor — un CX22 con Ubuntu 24.04 en Hetzner Cloud, IP `91.98.143.219` — se instaló Docker y se ejecutó `docker compose up -d --build`. El despliegue presentó cinco bugs que se resolvieron en tiempo real: `node_modules` subido al repositorio, el `docker-compose.yml` malformado, nombres de ficheros con mayúsculas incorrectas en Linux, `crypto.randomUUID` no disponible en HTTP y la URL del PAC apuntando a `localhost` en lugar de a la IP pública del servidor. Con los cinco resueltos, HookSuite quedó accesible desde internet en `http://91.98.143.219` con el dashboard funcionando y el proxy conectado.

#figure(
  image("../capturas/frontend/hooksuite_dashboard.png", width: 90%),
  caption: "Dashboard de HookSuite accesible desde internet — sistema desplegado en Hetzner"
)

#figure(
  image("../capturas/frontend/hooksuite_onboarding.png", width: 90%),
  caption: "Asistente de configuración del proxy PAC apuntando a la IP pública del servidor"
)

#figure(
  image("../capturas/frontend/proxy_interceptando_real.png", width: 90%),
  caption: "Panel Proxy interceptando tráfico real en el servidor de producción"
)

#figure(
  image("../capturas/frontend/proxy_detalle_headers.png", width: 90%),
  caption: "Detalle de headers — cookie PHPSESSID de sesión autenticada visible"
)

#figure(
  image("../capturas/frontend/repeater_vacio.png", width: 90%),
  caption: "Panel Repeater operativo en producción"
)

#figure(
  image("../capturas/frontend/repeater_editor_sqli.png", width: 90%),
  caption: "Repeater con petición SQLi cargada — headers completos y cookie de sesión activa"
)

#figure(
  image("../capturas/frontend/repeater_preview.png", width: 90%),
  caption: "Vista Preview del Repeater — DVWA renderizado con datos reales extraídos por inyección SQL"
)

#figure(
  image("../capturas/frontend/intruder_vacio.png", width: 90%),
  caption: "Panel Intruder operativo en producción"
)

#figure(
  image("../capturas/frontend/intruder_configurado.png", width: 90%),
  caption: "Intruder ejecutando 13 payloads SQLi contra DVWA — resultados en tiempo real"
)

#figure(
  image("../capturas/frontend/vulnerabilidades_detalle.png", width: 90%),
  caption: "Panel Vulnerabilidades — SQL Injection crítica detectada con payload ' OR '1'='1 y recomendación de mitigación"
)

#figure(
  image("../capturas/devtools/devtools_red_tiempo_real.png", width: 90%),
  caption: "Panel Red de HookSuite recibiendo tráfico capturado por DevTools en el servidor de producción"
)

=== El error de los bots

Al abrir el puerto 8080 al exterior para que el proxy TCP fuera accesible desde internet, el servidor recibió inmediatamente tráfico automatizado externo. Los bots entraron de forma descontrolada a través del proxy, generando un volumen de peticiones que el servidor no estaba dimensionado para absorber. El resultado fue la saturación completa del servicio — el proxy dejó de responder y el sistema quedó inutilizable como herramienta de auditoría.

El problema era estructural: un proxy TCP abierto en internet sin autenticación a nivel de conexión es un recurso que cualquier bot puede explotar. Cerrar el puerto resolvía la saturación pero eliminaba la funcionalidad central de la herramienta.

=== Intento de solución

Antes de descartar la arquitectura, Carlos trabajó en un intento de salvarla. La propuesta fue convertir el proxy en un servicio por usuario con aislamiento completo: cada login generaría un UID único que arrancaría una instancia de mitmproxy en un puerto aleatorio del rango 10000–60000, abriría ese puerto en el firewall exclusivamente para la IP del usuario mediante un firewall agent desplegado como servicio del sistema, y lo cerraría automáticamente al hacer logout o tras cuatro horas de inactividad. El tráfico interceptado se enviaría a Redis en lugar de directamente al WebSocket — desacoplando la captura del envío y añadiendo resiliencia al sistema — y el Backend consumiría Redis para emitirlo al Frontend.

La solución era técnicamente sólida pero no resolvió el problema en el tiempo disponible. La gestión dinámica del firewall introducía complejidad operacional que se sumaba a la ya existente en la coordinación entre módulos, y el tiempo necesario para estabilizarla comprometía el resto de la entrega.

=== Cambio de planteamiento

Fue en una sesión con el profesor donde se definió el camino definitivo. El profesor detectó el problema, planteó varias alternativas y el equipo eligió la que resolvía la saturación de raíz: eliminar el proxy TCP del flujo de auditoría y hacer que el servidor realizara las peticiones HTTP directamente por el auditor. Sin proxy abierto al exterior, sin superficie de ataque para los bots.

Con el nuevo planteamiento definido, el equipo tomó también la decisión de concentrar el tiempo restante hasta la entrega en estabilizar el núcleo de la herramienta — Frontend y Backend. Los módulos de Playwright, DevTools e IA, que habían funcionado en local y estaban desplegados en el servidor en modo polling, quedarían en segundo plano. Su activación completa pasaría a ser el objetivo principal de la Práctica 2.

=== Nueva arquitectura

Con la decisión tomada, Jose María reconvirtió el sistema a la nueva arquitectura. Eliminó el modelo de proxy interceptor y lo sustituyó por el nuevo planteamiento: el servidor audita directamente por el auditor, realizando las peticiones HTTP de forma activa en lugar de interceptar el tráfico pasivamente. La pieza técnica central fue el cliente httpx persistente por sesión — un `AsyncClient` compartido por todos los módulos bajo el mismo token que acumula automáticamente las cookies de la sesión de auditoría. Esta decisión resolvió de raíz el problema de la autenticación compartida: el auditor hace login desde el Repeater y el Spider y el Intruder heredan automáticamente esa sesión sin configuración adicional. Sobre esa base completó el spider httpx, el motor de fuzzing del Intruder y los parsers de raw HTTP y cURL del Repeater. mitmproxy se mantuvo en el código sin eliminarlo, con vistas a su posible uso en auditorías de aplicaciones móviles en la Práctica 2.

Macarena realizó en paralelo una mejora visual del Frontend — navegación horizontal en topbar en lugar del sidebar vertical, sistema de variables CSS con modo claro y modo oscuro, y nuevos componentes de UI con paneles redimensionables. El nuevo diseño se desplegó en el servidor manteniendo toda la lógica funcional intacta.

Al cierre de esta fase el núcleo de HookSuite estaba operativo con la nueva arquitectura: el panel Proxy mostraba las peticiones que el servidor realizaba por el auditor en tiempo real, el Repeater reenviaba peticiones con gestión automática de cookies, el Intruder ejecutaba ataques con paralelismo controlado y el panel de Vulnerabilidades recibía alertas por WebSocket. El flujo completo de auditoría — spider sin autenticación, login desde el Repeater, spider autenticado, Intruder detectando SQLi — fue validado end-to-end contra DVWA antes de la entrega.

// ============================================================
// 4.3 ESTADO ACTUAL DE LA HERRAMIENTA
// ============================================================

== Estado actual de la herramienta

=== Frontend

El Frontend es la interfaz visual de HookSuite — un dashboard web accesible desde cualquier navegador sin instalación adicional. Construido sobre React 19, Vite y Tailwind CSS, con JetBrains Mono como tipografía de código, se comunica con el Backend exclusivamente mediante WebSocket para recibir eventos en tiempo real y REST para enviar las acciones del auditor. La gestión del estado compartido entre paneles se centraliza en un contexto global que mantiene la conexión WebSocket activa, el identificador de sesión UUID del auditor y los datos que fluyen entre los distintos módulos de la interfaz. El diseño incorpora un sistema de variables CSS con soporte de modo oscuro y modo claro, navegación horizontal en topbar y paneles redimensionables.

El Frontend se organiza en seis paneles accesibles desde el topbar:

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_vacio.png", width: 90%),
  caption: "Panel Proxy con el nuevo diseño — topbar horizontal, WebSocket conectado y spider listo para lanzar"
)

El *panel Proxy* es el centro de operaciones de la auditoría. El auditor introduce la URL objetivo, selecciona la velocidad del análisis — rápido, normal o completo, que determina el número máximo de páginas que el spider visitará — y lanza el proceso. Las peticiones que el servidor realiza por el auditor aparecen en tiempo real agrupadas por URL. Los formularios detectados en cada página se muestran como subelementos desplegables bajo su URL correspondiente, lo que permite identificar de un vistazo los vectores de ataque disponibles. El panel de estado muestra las cookies de sesión activas en verde cuando el auditor está autenticado, y ofrece tres acciones: liberar la sesión activa sin perder el historial de peticiones, limpiar el panel manteniendo la sesión, o iniciar una nueva auditoría completa reseteando todo el estado.

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_interceptando.png", width: 90%),
  caption: "Panel Proxy interceptando peticiones en tiempo real — petición de login de DVWA capturada con formulario detectado"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_formulario.png", width: 90%),
  caption: "Formulario POST desplegado en el panel Proxy — botones de envío al Repeater y al Intruder visibles"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_headers.png", width: 90%),
  caption: "Pestaña Headers del detalle de petición — headers de petición y respuesta con cookie PHPSESSID visible"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_autenticado.png", width: 90%),
  caption: "Panel Proxy con sesión autenticada — spider navegando DVWA con todas las páginas descubiertas y formularios detectados"
)

El *Repeater* permite modificar y reenviar cualquier petición manualmente. El auditor puede enviar al Repeater cualquier petición interceptada en el panel Proxy con un solo clic, y desde ahí modificar el método HTTP, la URL, los headers y el body antes de reenviarla. La respuesta se muestra en cuatro vistas: Raw muestra la respuesta tal como llega del servidor; Pretty formatea automáticamente el JSON para facilitar su lectura; Preview renderiza el HTML de la respuesta en un iframe reescribiendo las URLs relativas para que los recursos del objetivo se carguen correctamente; y Headers muestra los headers de respuesta con las cookies resaltadas en verde para identificarlas fácilmente.

#figure(
  image("../capturas/frontend/frontend_nuevo_repeater_raw.png", width: 90%),
  caption: "Repeater — vista Raw con la respuesta de login exitoso en DVWA"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_repeater_preview.png", width: 90%),
  caption: "Repeater — vista Preview con DVWA renderizado tras autenticación exitosa"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_repeater_headers.png", width: 90%),
  caption: "Repeater — vista Headers con los headers de respuesta del servidor"
)

El *Intruder* automatiza el fuzzing de parámetros al estilo Burp Suite. Al recibir una petición detecta automáticamente todos los parámetros GET y POST presentes. El auditor selecciona el parámetro que quiere atacar marcándolo con el símbolo `*` — el marcado se resalta en naranja en tiempo real tanto en la URL como en el body. El sistema sustituye ese marcador por cada payload de la lista seleccionada y envía todas las peticiones de forma automatizada. Soporta cuatro tipos de ataque con sus respectivas listas de payloads: SQL Injection, Blind SQLi, XSS y fuzzing genérico. Los resultados se muestran en una tabla en tiempo real donde las peticiones que reciben una respuesta identificada como vulnerable se marcan en rojo.

#figure(
  image("../capturas/frontend/frontend_nuevo_intruder_configurado.png", width: 90%),
  caption: "Intruder — parámetro id marcado con * y ataque SQL Injection configurado"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_intruder_resultados.png", width: 90%),
  caption: "Intruder — 13 payloads ejecutados contra DVWA SQLi, 12 vulnerables detectados en tiempo real"
)

Las *Utilidades* agrupan cuatro herramientas auxiliares de uso frecuente en auditorías web. El Encoder/Decoder transforma texto entre los formatos más comunes — Base64, URL encoding, HTML encoding y decodificación de tokens JWT. El Hash Generator calcula los hashes MD5, SHA1, SHA256 y SHA512 de cualquier texto. El Regex Tester permite probar expresiones regulares contra texto de prueba con resaltado visual de los matches en tiempo real. El Payload Generator organiza colecciones de payloads por tipo de ataque — SQLi, Blind SQLi, XSS y fuzzing genérico — con opción de copiar payloads individuales o la lista completa.

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_encoder.png", width: 90%),
  caption: "Utilidades — Encoder/Decoder con texto 'admin' transformado a Base64, URL encoding y HTML encoding"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_hash.png", width: 90%),
  caption: "Utilidades — Hash Generator con hashes MD5, SHA1, SHA256 y SHA512 de 'administrator'"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_regex.png", width: 90%),
  caption: "Utilidades — Regex Tester con patrón \\d+ y match resaltado en 'administrator123'"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_payload.png", width: 90%),
  caption: "Utilidades — Payload Generator con lista de payloads XSS listos para copiar"
)

El *panel Vulnerabilidades* y el *panel Red* están completamente construidos e integrados en la interfaz. El panel Vulnerabilidades está diseñado para recibir las detecciones del módulo de IA clasificadas por severidad — crítica, alta, media y baja — con descripción de la vulnerabilidad, payload utilizado y recomendación de mitigación. El panel Red está diseñado para mostrar el tráfico capturado por el módulo DevTools en tiempo real, con código de colores para identificar peticiones limpias, sospechosas y vulnerables. Ambos paneles permanecen inactivos en esta entrega porque los módulos que los alimentan están pendientes de integración completa en la Práctica 2.

#figure(
  image("../capturas/frontend/frontend_nuevo_vulnerabilidades.png", width: 90%),
  caption: "Panel Vulnerabilidades — construido e integrado, pendiente de activación con el módulo IA en la Práctica 2"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_red.png", width: 90%),
  caption: "Panel Red — construido e integrado, pendiente de activación con el módulo DevTools en la Práctica 2"
)

=== Backend

El Backend es el núcleo del sistema — el único módulo que habla con todos los demás y el que hace posible que HookSuite funcione como una herramienta de auditoría real. Construido sobre Python 3.11 y FastAPI, gestiona las sesiones de auditoría, ejecuta todas las peticiones HTTP por el auditor, emite los resultados al Frontend en tiempo real mediante WebSockets y expone la API REST que coordina el resto de módulos.

El módulo se organiza en seis bloques funcionales:

El *servidor FastAPI* es el punto de entrada del sistema. Arranca con CORS habilitado para aceptar peticiones desde cualquier origen, registra todos los routers de la aplicación bajo el prefijo `/api/`, e inicia al arranque dos tareas asíncronas en segundo plano: un consumidor Redis y un gestor de limpieza de sesiones expiradas. La documentación interactiva de la API — generada automáticamente por FastAPI — está disponible en `/docs` y lista todos los endpoints con sus modelos de entrada y salida.

El *sistema de sesiones y WebSockets* es la pieza que permite que múltiples auditores trabajen simultáneamente sin interferirse. Cada auditor recibe un token UUID único al conectarse. El `SessionManager` mantiene en memoria el estado completo de cada sesión — historial de peticiones, estado del Intruder, paquetes de red, vulnerabilidades detectadas — y registra la conexión WebSocket asociada a cada token. El canal WebSocket en `/ws/{token}` mantiene la conexión viva mediante pings cada 30 segundos y emite eventos tipados con la estructura `{type, payload}` cada vez que ocurre algo relevante en el servidor. El método `emit_all()` permite difundir eventos a todas las sesiones activas simultáneamente.

El *spider httpx* es el módulo de reconocimiento activo. Dado un punto de entrada y un token de sesión, navega la aplicación objetivo de forma autónoma usando un cliente httpx persistente que comparte con el Repeater y el Intruder. Esta persistencia es lo que permite el flujo de auditoría autenticada: el auditor hace login desde el Repeater, y el spider hereda automáticamente esa sesión y navega autenticado sin configuración adicional. El spider implementa un algoritmo BFS con scope restringido al dominio objetivo, filtra extensiones estáticas irrelevantes y varía los User-Agent de forma aleatoria entre peticiones. Para cada página visitada extrae mediante expresiones regulares todos los formularios HTML — método, acción y campos — y los emite al Frontend como peticiones independientes con status `FORM`. La velocidad es configurable en tres presets — rápido, normal y completo — que determinan el número máximo de páginas a visitar.

El *cliente httpx persistente por sesión* es la decisión técnica más importante del módulo. En lugar de crear un cliente HTTP nuevo para cada petición, el backend mantiene un diccionario que asocia cada token de sesión con un `AsyncClient` de httpx configurado con seguimiento de redirects y verificación SSL desactivada. Este cliente acumula automáticamente las cookies que el servidor objetivo va devolviendo a lo largo de la auditoría. El resultado es que el Repeater, el Spider y el Intruder comparten implícitamente la misma sesión HTTP — incluyendo las cookies de autenticación — sin que el auditor tenga que copiar ni gestionar nada manualmente. Cuando el backend detecta nuevas cookies, emite un evento WebSocket al Frontend para mostrarlas en el panel de estado de auditoría.

El *motor de fuzzing del Intruder* ejecuta ataques automatizados contra parámetros específicos. Recibe del Frontend la URL objetivo con el punto de inyección marcado con `*`, el tipo de ataque y la configuración de paralelismo. Sustituye el marcador por cada payload de la lista correspondiente y lanza todas las peticiones de forma concurrente usando `asyncio.Semaphore` con un límite de cinco peticiones simultáneas — elegido para no sobrecargar el servidor de producción. Soporta cuatro tipos de ataque con sus respectivas listas de payloads: SQL Injection con trece vectores, Blind SQLi con nueve variantes incluyendo time-based, XSS con diez payloads, y fuzzing genérico con diecisiete entradas que cubren path traversal, null bytes, templates y cadenas extremadamente largas. La detección de vulnerabilidades SQLi se basa en la búsqueda de patrones de confirmación en la respuesta — `First name:`, `Surname:`, errores de base de datos — que indican que el payload ha producido una respuesta anómala. Los resultados se emiten al Frontend en tiempo real a medida que cada payload completa su ejecución.

Las *utilidades* exponen tres endpoints auxiliares implementados con la librería estándar de Python sin dependencias externas. El generador de hashes calcula MD5, SHA1, SHA256 y SHA512 de cualquier texto. El encoder/decoder transforma texto entre Base64, URL encoding y HTML encoding en ambas direcciones. El regex tester compila y ejecuta expresiones regulares con soporte de flags — case insensitive, multiline, dotall — y devuelve todos los matches con sus posiciones.

El *receptor de paquetes de red* y los *endpoints de integración con Playwright e IA* están completamente implementados en el Backend. El receptor de paquetes expone dos endpoints para recibir los paquetes capturados por el módulo DevTools y distribuirlos a las sesiones activas por WebSocket. Los endpoints de instrucciones y resultados de Playwright permiten al módulo de IA enviar órdenes de ataque y recibir los resultados de su ejecución. El endpoint de vulnerabilidades recibe las detecciones del módulo de IA y las emite al panel correspondiente del Frontend. Estos tres bloques permanecen inactivos en esta entrega porque los módulos que los alimentan están pendientes de integración completa en la Práctica 2.

=== Playwright, DevTools e IA

Los módulos de Playwright, DevTools e IA están construidos y validados en sus entornos locales, y desplegados en el servidor como contenedores Docker en modo polling pasivo. El pivote de arquitectura que ocurrió a mitad del desarrollo redefinió el rol de los tres módulos y el tiempo disponible se concentró en estabilizar el núcleo operativo de la herramienta. Los tres módulos, sus componentes y su lógica interna están descritos en detalle en el apartado de Proceso individual de esta sección. Su integración completa con el Frontend y el Backend es el objetivo principal de la Práctica 2.

// ============================================================
// 5. GUÍA DE DESPLIEGUE
// ============================================================

= Guía de despliegue

== Entorno de producción

HookSuite está desplegado en un servidor Hetzner Cloud CX22 con las siguientes especificaciones:

#table(
  columns: (auto, 1fr),
  fill: (_, y) => if y == 0 { azul } else if calc.odd(y) { azul-claro } else { white },
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Parámetro]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Valor]],
  [Proveedor], [Hetzner Cloud],
  [Plan], [CX22],
  [vCPUs], [2 vCPUs compartidas],
  [RAM], [4 GB],
  [Almacenamiento], [40 GB NVMe SSD],
  [Tráfico incluido], [20 TB/mes],
  [Sistema operativo], [Ubuntu 24.04 LTS],
  [Kernel], [6.8.0-117-generic],
  [IP pública], [91.98.143.219],
  [Docker], [29.5.0],
  [Docker Compose], [v5.1.3],
)

== Arquitectura de contenedores

El sistema se compone de siete contenedores Docker orquestados con Docker Compose y comunicados a través de la red interna `hooksuite-net` de tipo bridge:

#table(
  columns: (auto, 1fr, auto, auto),
  fill: (_, y) => if y == 0 { azul } else if calc.odd(y) { azul-claro } else { white },
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Servicio]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Imagen base]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Puerto externo]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Estado P1]],
  [nginx], [nginx:alpine], [80], [✅ Activo],
  [frontend], [node:20-alpine + nginx:alpine], [—], [✅ Activo],
  [backend], [python:3.11-slim], [8000], [✅ Activo],
  [redis], [redis:7-alpine], [—], [✅ Activo],
  [dvwa], [vulnerables/web-dvwa], [—], [✅ Activo],
  [playwright], [imagen propia], [—], [⏳ Práctica 2],
  [ia], [imagen propia], [—], [⏳ Práctica 2],
)

== Construcción de los contenedores

=== Backend

El contenedor de backend usa Python 3.11-slim como imagen base. Durante la construcción instala `redis-tools`, `iptables` y `build-essential` — necesarios para la gestión dinámica del firewall por sesión. Expone los puertos 8000 (API) y 8080 (mitmproxy). Arranca con `NET_ADMIN` para poder manipular reglas de iptables, y monta el socket del agente de firewall desde el host.

El `entrypoint.sh` implementa el siguiente flujo de arranque:

```bash
# 1. Espera a que Redis esté disponible
until redis-cli -h redis -p 6379 ping; do sleep 1; done

# 2. Levanta mitmproxy en segundo plano en el puerto 8080
mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
    --set block_global=false \
    --proxyauth hooksuite:audit2026 \
    -s /app/services/mitm_addon.py &

# 3. Arranca el servidor FastAPI en el puerto 8000
uvicorn main:app --host 0.0.0.0 --port 8000
```

mitmproxy está presente en la infraestructura aunque no forma parte del flujo de auditoría principal en esta entrega — el sistema opera con httpx directo. Está disponible para un posible uso futuro sin necesidad de cambios en la infraestructura.

=== Frontend

El contenedor de frontend usa un proceso de construcción multietapa. En la primera etapa, Node 20 Alpine compila la aplicación React con Vite inyectando la URL del backend como variable de entorno en tiempo de compilación:

```bash
ARG VITE_API_URL=http://91.98.143.219:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build
```

En la segunda etapa, Nginx Alpine sirve los ficheros estáticos compilados. El resultado es una imagen final ligera sin dependencias de Node en producción.

=== Módulos Playwright e IA

Ambos contenedores están desplegados en el servidor en modo polling pasivo — operativos como infraestructura pero sin integración activa con el núcleo del sistema. Su activación completa está planificada para la Práctica 2.

== Enrutamiento Nginx

Nginx actúa como punto de entrada único en el puerto 80 y distribuye el tráfico según la ruta:

#table(
  columns: (auto, 1fr),
  fill: (_, y) => if y == 0 { azul } else if calc.odd(y) { azul-claro } else { white },
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Ruta]],
  table.cell(fill: azul)[#text(fill: white, weight: "bold")[Destino y notas]],
  [`/api/`], [Backend FastAPI — endpoints REST con cabeceras de proxy],
  [`/ws/`], [Backend WebSockets — upgrade HTTP/1.1 a WS],
  [`/proxy.pac`], [Backend — fichero PAC de configuración del proxy],
  [`/check/`], [Backend — endpoint de verificación del proxy activo],
  [`/dvwa/`], [DVWA — protegido con autenticación básica Nginx],
  [`/`], [Frontend React — protegido con autenticación básica Nginx],
)

El acceso al dashboard y a DVWA requiere autenticación HTTP básica gestionada por Nginx mediante fichero `htpasswd`. El puerto 8080 de mitmproxy no está expuesto al exterior.

== Despliegue desde cero

=== Requisitos previos

- Servidor Linux con Ubuntu 24.04 LTS
- Docker 24+ y Docker Compose v2+
- Acceso SSH con usuario root o sudo
- Mínimo 2 vCPUs y 4 GB de RAM recomendados

=== Pasos

```bash
# 1. Instalar Docker
curl -fsSL https://get.docker.com | sh

# 2. Clonar el repositorio
git clone https://github.com/Feet-Lovers/Proyecto-Evolve.git
cd Proyecto-Evolve

# 3. Configurar variables de entorno
cp .env.example .env
# Editar .env con los valores del entorno

# 4. Generar fichero htpasswd para autenticación Nginx
apt-get install -y apache2-utils
htpasswd -c infra/htpasswd hooksuite

# 5. Construir y arrancar todos los contenedores
docker compose up -d --build

# 6. Verificar estado
docker compose ps
```

== Operación y mantenimiento

=== Ver estado de los contenedores

```bash
docker compose ps
```

=== Ver logs de un servicio

```bash
docker compose logs backend --tail=50
docker compose logs frontend --tail=50
```

=== Reiniciar un servicio

```bash
docker compose restart backend
```

=== Actualizar el código y redesplegar

```bash
git pull origin main
docker compose up -d --build backend
# o para redesplegar todos los servicios:
docker compose up -d --build
```

=== Parar el sistema completo

```bash
docker compose down
```

=== Verificar accesibilidad

```bash
curl -s -o /dev/null -w "%{http_code}" http://91.98.143.219
```

// ============================================================
// 6. MANUAL DE USO
// ============================================================

= Manual de uso

== Acceso a la herramienta

HookSuite es accesible desde cualquier navegador sin instalación adicional. La herramienta está desplegada en `http://91.98.143.219`. Al acceder, Nginx solicita autenticación básica — introducir las credenciales proporcionadas para acceder al dashboard.

Una vez autenticado, el navegador muestra el panel Proxy directamente. La navegación entre los seis paneles se realiza desde el topbar superior. El indicador verde *conectado* en el panel Proxy confirma que el WebSocket con el Backend está activo y la herramienta lista para operar.

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_vacio.png", width: 90%),
  caption: "Dashboard de HookSuite — panel Proxy con WebSocket conectado y listo para iniciar una auditoría"
)

== Flujo de auditoría completo

=== Paso 1 — Lanzar el spider

En el campo *URL objetivo* del panel Proxy, introducir la URL de la aplicación a auditar. Seleccionar la velocidad de análisis según el alcance deseado — *Rápido* visita hasta 50 páginas, *Normal* hasta 200 y *Completo* hasta 500. Pulsar *Iniciar spider*.

El spider navega la aplicación de forma autónoma realizando peticiones HTTP por el auditor. Cada petición descubierta aparece en tiempo real en la tabla del panel Proxy con su método, URL, status code, tamaño y tiempo de respuesta. Los formularios detectados en cada página aparecen como subelementos desplegables bajo su URL correspondiente, identificados con el indicador *[N FORM ▼]*.

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_interceptando.png", width: 90%),
  caption: "Spider en ejecución — petición de login de DVWA capturada con formulario detectado"
)

=== Paso 2 — Login desde el Repeater

Cuando el spider detecta el formulario de login de la aplicación objetivo, aparece como subelemento desplegable bajo la URL del login. Desplegar el formulario pulsando *[N FORM ▼]* y seleccionar el formulario POST. Hacer clic en él para ver su detalle en el panel derecho y pulsar *enviar al repeater →*.

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_formulario.png", width: 90%),
  caption: "Formulario de login detectado — botones de envío al Repeater y al Intruder visibles"
)

El Repeater recibe la petición con el método POST ya configurado, los headers correctos — incluyendo `Content-Type: application/x-www-form-urlencoded` — y el body con todos los campos del formulario rellenos con sus valores por defecto, incluido el token CSRF si la aplicación lo requiere.

#figure(
  image("../capturas/frontend/frontend_nuevo_repeater_form_post.png", width: 90%),
  caption: "Repeater con el formulario POST recibido — body con campos del formulario y token CSRF incluidos"
)

Modificar los campos de credenciales en el body con los valores correctos y pulsar *enviar*. Si el login es exitoso, la vista Preview mostrará el dashboard de la aplicación autenticada. La cookie de sesión queda automáticamente acumulada en el cliente httpx del Backend — el Spider y el Intruder la heredan sin configuración adicional.

#figure(
  image("../capturas/frontend/frontend_nuevo_repeater_preview.png", width: 90%),
  caption: "Vista Preview del Repeater — DVWA autenticado tras login exitoso"
)

#figure(
  image("../capturas/frontend/frontend_nuevo_repeater_headers.png", width: 90%),
  caption: "Vista Headers del Repeater — headers de respuesta del servidor"
)

=== Paso 3 — Spider autenticado

Con la sesión activa, volver al panel Proxy y lanzar el spider de nuevo. Esta vez navega con las cookies de sesión acumuladas — descubre todas las páginas internas de la aplicación que requieren autenticación. El indicador de cookies en verde confirma que el spider opera autenticado.

#figure(
  image("../capturas/frontend/frontend_nuevo_proxy_autenticado.png", width: 90%),
  caption: "Panel Proxy con sesión autenticada — todas las páginas de DVWA descubiertas con formularios detectados"
)

=== Paso 4 — Enviar al Intruder y configurar el ataque

Desplegar el formulario de la página objetivo pulsando *[N FORM ▼]*. Seleccionar el formulario que se quiere atacar y pulsar *enviar al intruder →*. El Intruder recibe automáticamente la URL con los parámetros detectados.

En el Intruder, pulsar *→ marcar* junto al parámetro que se quiere atacar — el marcador `*` se resalta en naranja en la URL. Seleccionar el tipo de ataque en el desplegable: *SQL Injection*, *Blind SQLi*, *XSS* o *Fuzzing genérico*. Pulsar *iniciar ataque*.

#figure(
  image("../capturas/frontend/frontend_nuevo_intruder_configurado.png", width: 90%),
  caption: "Intruder configurado — parámetro id marcado con * y tipo de ataque SQL Injection seleccionado"
)

=== Paso 5 — Resultados del ataque

El Intruder ejecuta todos los payloads de forma concurrente y muestra los resultados en tiempo real. Las peticiones que producen una respuesta identificada como vulnerable se marcan en rojo en la columna *Resultado*.

#figure(
  image("../capturas/frontend/frontend_nuevo_intruder_resultados.png", width: 90%),
  caption: "Resultados del Intruder — 12 de 13 payloads SQLi marcados como vulnerables en DVWA"
)

== Utilidades

Las Utilidades agrupan cuatro herramientas auxiliares accesibles desde el topbar, útiles durante cualquier fase de la auditoría.

El *Encoder/Decoder* transforma texto entre Base64, URL encoding, HTML encoding y decodificación de JWT en tiempo real — útil para preparar payloads o analizar respuestas codificadas.

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_encoder.png", width: 90%),
  caption: "Encoder/Decoder — transformación de 'admin' a los distintos formatos de codificación"
)

El *Hash Generator* calcula los hashes MD5, SHA1, SHA256 y SHA512 de cualquier texto — útil para verificar integridad de datos o preparar ataques de fuerza bruta con hashes conocidos.

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_hash.png", width: 90%),
  caption: "Hash Generator — hashes de 'administrator' en los cuatro algoritmos"
)

El *Regex Tester* compila y ejecuta expresiones regulares contra texto de prueba con resaltado visual de los matches en tiempo real — útil para construir patrones de extracción de datos de respuestas HTTP.

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_regex.png", width: 90%),
  caption: "Regex Tester — patrón \\d+ con match resaltado en 'administrator123'"
)

El *Payload Generator* organiza colecciones de payloads por tipo de ataque con opción de copiar individualmente o todos a la vez — útil para preparar listas de payloads personalizadas antes de lanzar el Intruder.

#figure(
  image("../capturas/frontend/frontend_nuevo_utilidades_payload.png", width: 90%),
  caption: "Payload Generator — lista de payloads XSS listos para copiar"
)

== Paneles pendientes de activación

El panel *Vulnerabilidades* está construido e integrado en la interfaz. Está diseñado para recibir las detecciones del módulo de IA clasificadas por severidad — crítica, alta, media y baja — con descripción de la vulnerabilidad, payload utilizado y recomendación de mitigación. Su activación completa está planificada para la Práctica 2.

#figure(
  image("../capturas/frontend/frontend_nuevo_vulnerabilidades.png", width: 90%),
  caption: "Panel Vulnerabilidades — construido e integrado, pendiente de activación en la Práctica 2"
)

El panel *Red* está construido e integrado en la interfaz. Está diseñado para mostrar el tráfico capturado por el módulo DevTools en tiempo real, con código de colores para identificar peticiones limpias, sospechosas y vulnerables. Su activación completa está planificada para la Práctica 2.

#figure(
  image("../capturas/frontend/frontend_nuevo_red.png", width: 90%),
  caption: "Panel Red — construido e integrado, pendiente de activación en la Práctica 2"
)

// ============================================================
// 7. CONCLUSIONES Y LECCIONES APRENDIDAS
// ============================================================

= Conclusiones y lecciones aprendidas

== Lo que funcionó mejor de lo esperado

La integración entre módulos fue más fluida de lo que el equipo anticipaba. Definir los contratos de API al inicio del proyecto —antes de que cada miembro arrancara su desarrollo— eliminó la mayoría de los problemas de compatibilidad que suelen aparecer en proyectos distribuidos de este tipo. Cuando P4 terminó el módulo de captura CDP y P2 ya tenía el endpoint receptor implementado, la integración se completó sin fricción.

El uso de variables de entorno para controlar el modo de operación del módulo de IA resultó ser una decisión especialmente acertada. El modo mock (`MOCK_PLAYWRIGHT=true`) permitió desarrollar y validar el ciclo completo de análisis de forma independiente, sin depender de que P2 y P3 tuvieran sus módulos listos. Esto desbloqueó el desarrollo en paralelo real y redujo los tiempos de espera entre módulos.

La elección de Claude como motor de análisis superó las expectativas iniciales en términos de precisión. La detección de inyecciones SQL en DVWA alcanzó niveles de confianza superiores al 90% con prompts relativamente sencillos, lo que confirma que la calidad del prompt es más determinante que la complejidad del código de análisis.

== Lo que fue más difícil de lo previsto

La coordinación entre cinco módulos con dependencias cruzadas generó cuellos de botella que no estaban completamente previstos en el diseño inicial. El módulo de backend actúa como nexo central del sistema, lo que convirtió a P2 en el punto de mayor presión del proyecto: cualquier endpoint pendiente en el backend bloqueaba simultáneamente a varios módulos. En retrospectiva, haber paralelizado más agresivamente el desarrollo del backend desde el inicio habría reducido estos bloqueos.

La gestión del entorno Python en Windows presentó más fricción de la esperada. La incompatibilidad entre la versión inicial de la librería `anthropic` y Python 3.14, la exposición accidental de una API key en el repositorio o la configuración del entorno virtual en distintos sistemas operativos fueron incidencias menores que, sumadas, consumieron tiempo de desarrollo que no estaba previsto en el plan inicial.

== Qué haríamos diferente si empezáramos de nuevo

Estableceríamos la convención de commits desde el primer commit del repositorio, no como corrección posterior. La convención de commits es un estándar de calidad que penaliza directamente la nota cuando no se aplica, y su adopción tardía en un historial ya creado es costosa de corregir sin reescribir el historial.

Definiríamos un entorno de integración compartido desde el inicio. Durante el desarrollo, cada módulo se probó de forma aislada contra DVWA en local. Un entorno de integración compartido en Hetzner desde la primera semana habría permitido detectar antes los problemas de integración real entre módulos y habría dado más tiempo para resolverlos.

== Aprendizajes sobre integración de sistemas complejos

Este proyecto confirma que la dificultad de un sistema distribuido no está en la complejidad de cada módulo individual, sino en la gestión de sus interfaces. Un módulo técnicamente excelente que no cumple el contrato de API acordado bloquea a todos los módulos que dependen de él. La disciplina en la definición y el respeto de los contratos de integración es tan importante como la calidad del código.

La inteligencia artificial como componente de un sistema mayor introduce un tipo de incertidumbre diferente al del código determinista. Los tiempos de respuesta variables, los costes por llamada y la naturaleza probabilística de las clasificaciones requieren diseñar el sistema de forma que pueda operar de forma degradada cuando la IA no está disponible o cuando su respuesta no supera el umbral de confianza requerido.

// ============================================================
// 8. ROAD MAP DE MEJORA — PRÁCTICA 2
// ============================================================

= Road map de mejora para la Práctica 2

#rect(fill: azul-claro, stroke: 1pt + azul-acento, inset: 12pt, width: 100%, radius: 4pt)[
  _Sección pendiente — en espera de roadmap_tabla.png de P4_
]
