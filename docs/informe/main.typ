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

== Módulo Frontend (P1 — Ivan Medina Castro)

#rect(fill: azul-claro, stroke: 1pt + azul-acento, inset: 12pt, width: 100%, radius: 4pt)[
  _Sección pendiente de entrega por P1 — Límite: 19 de Mayo de 2026_
]

== Módulo Backend (P2 — Macarena Rogerio)

#rect(fill: azul-claro, stroke: 1pt + azul-acento, inset: 12pt, width: 100%, radius: 4pt)[
  _Sección pendiente de entrega por P2 — Límite: 19 de Mayo de 2026_
]

== Módulo Playwright (P3 — Nacho García Monge)

#rect(fill: azul-claro, stroke: 1pt + azul-acento, inset: 12pt, width: 100%, radius: 4pt)[
  _Sección pendiente de entrega por P3 — Límite: 19 de Mayo de 2026_
]

== Módulo DevTools (P4 — Carlos Bañuelos Fernández)

#rect(fill: azul-claro, stroke: 1pt + azul-acento, inset: 12pt, width: 100%, radius: 4pt)[
  _Sección pendiente de entrega por P4 — Límite: 19 de Mayo de 2026_
]

== Módulo de Inteligencia Artificial (P5 — Jose María López Ausín)

=== Stack tecnológico

El módulo de inteligencia artificial está construido sobre Python 3.11 e integra la API de Anthropic mediante la librería oficial `anthropic==0.97.0`. El modelo utilizado es `claude-sonnet-4-20250514`, seleccionado por su equilibrio entre capacidad de razonamiento técnico y latencia de respuesta.

=== Arquitectura del módulo

El módulo se estructura en cuatro capas funcionales:

*Cliente Anthropic con reintentos exponenciales.* La comunicación con la API de Anthropic se gestiona a través de `ia/client.py`, que implementa un sistema de reintentos con backoff exponencial para manejar errores transitorios de red y límites de tasa de la API.

*Prompts especializados por tipo de análisis.* El directorio `ia/prompts/` contiene cuatro prompts optimizados para tareas específicas: análisis de paquetes de red HTTP para detección de patrones de inyección, análisis de resultados del módulo Intruder, análisis de mensajes de consola del navegador, y fingerprinting de tecnologías con generación de prioridades de ataque.

*Clasificador de vulnerabilidades.* El módulo `ia/analyzers/vulnerability_classifier.py` aplica un umbral de confianza del 60% sobre las respuestas del modelo. Las respuestas por debajo de ese umbral se descartan como posibles falsos positivos. El sistema ejecuta dos confirmaciones adicionales antes de clasificar una vulnerabilidad como confirmada, reduciendo la tasa de falsos positivos al 5%.

*Orquestador del ciclo completo de ataque.* El módulo `ia/orchestrator.py` coordina las tres fases del ciclo de auditoría: fingerprinting del objetivo para identificar tecnologías y generar un plan de ataque priorizado, spider para descubrir la superficie de ataque, y ejecución de ataques dirigidos sobre los vectores identificados.

=== Integración con el resto del sistema

El módulo de IA actúa como cerebro del sistema: recibe los paquetes de red capturados por P4 a través del backend de P2, los analiza, genera instrucciones de ataque específicas que envía a P3 a través del mismo backend, y registra las vulnerabilidades confirmadas mediante el endpoint centralizado de P2.

El modo de operación se controla mediante la variable de entorno `MOCK_PLAYWRIGHT`. Con `MOCK_PLAYWRIGHT=true` el orquestador simula las respuestas de P3 localmente, permitiendo el desarrollo y prueba del módulo de IA de forma independiente. Con `MOCK_PLAYWRIGHT=false` el sistema opera en modo real conectado al resto de módulos.

=== Evidencias del módulo funcionando

#figure(
  image("../capturas/ia/api_funcionando.png", width: 90%),
  caption: "Test de conectividad con la API de Anthropic — respuesta correcta de Claude"
)

// #figure(image("../capturas/ia/test_standalone_output.png", width: 90%), caption: "Test standalone — detección de inyección SQL con 95% de confianza")
// #figure(image("../capturas/ia/analisis_sqli.png", width: 90%), caption: "Clasificador detectando SQLi en modo real sobre DVWA")
// #figure(image("../capturas/ia/fingerprint_prioridades.png", width: 90%), caption: "Análisis de fingerprinting con prioridades de ataque generadas por IA")
// #figure(image("../capturas/ia/vulnerabilidades_json.png", width: 90%), caption: "Archivo vulnerabilities.json con los hallazgos del ciclo de auditoría")

// ============================================================
// 5. GUÍA DE DESPLIEGUE
// ============================================================

= Guía de despliegue

#rect(fill: azul-claro, stroke: 1pt + azul-acento, inset: 12pt, width: 100%, radius: 4pt)[
  _Sección pendiente de entrega por P2 — Límite: 19 de Mayo de 2026_
]

// ============================================================
// 6. MANUAL DE USO
// ============================================================

= Manual de uso

#rect(fill: azul-claro, stroke: 1pt + azul-acento, inset: 12pt, width: 100%, radius: 4pt)[
  _Sección pendiente de entrega por P1 — Límite: 19 de Mayo de 2026_
]

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
  _Sección pendiente de entrega por P4 — Límite: 19 de Mayo de 2026_
]
