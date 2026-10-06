// ============================================================
// HookSuite — Memoria técnica de la Práctica 3
// FUENTE ÚNICA (R4). Dos salidas:
//   typst compile --root . docs/informe/P3-memoria.typ docs/informe/P3-memoria.pdf   -> PDF
//   ~/.venvs/hooksuite-tools/bin/python tools/typ2html.py                            -> artefacto HTML
//   (--root . porque las imágenes viven en docs/capturas/, fuera de docs/informe/;
//    el venv aporta Pillow para reducir las capturas en el artefacto, R6)
// El HTML se REGENERA de este fichero; nunca se edita a mano.
// Dialecto usado (para que typ2html.py lo soporte 100%):
//   = / == / ===  encabezados | párrafos | listas con "- " | *negrita* | `codigo`
//   #hueco("responsable", "qué falta")   #estado("rojo|ok|info|curso", "texto")
//   #tabla((anchos), "cab|cab\nfila|fila")  -> 1ª línea = cabecera; una línea por fila
//   #imagen("../capturas/ruta.png|.svg", "pie con qué muestra y a qué requisito toca")
// ============================================================

#let azul = rgb("#0F1B2D")
#let azul-acento = rgb("#1A6FBF")
#let rojo = rgb("#C0392B")
#let verde = rgb("#1E8449")
#let ambar = rgb("#B9770E")

#let estado(tipo, txt) = {
  let c = if tipo == "rojo" { rojo } else if tipo == "ok" { verde } else if tipo == "curso" { ambar } else { azul-acento }
  box(fill: c, inset: (x: 6pt, y: 2pt), radius: 3pt, text(fill: white, size: 8pt, weight: "bold", txt))
}
#let hueco(responsable, que) = block(
  width: 100%, inset: 8pt, radius: 4pt, above: 8pt, below: 8pt,
  fill: rgb("#FFF4E5"), stroke: 0.5pt + ambar,
  [⚠️ *HUECO* — responsable: *#responsable*. #que],
)
#let tabla(cols, datos) = {
  let filas = datos.split("\n").map(l => l.trim()).filter(l => l != "")
  let celdas = filas.map(l => l.split("|").map(c => c.trim()))
  let cab = celdas.first()
  let cuerpo = celdas.slice(1)
  block(above: 10pt, below: 10pt, table(
    columns: cols,
    stroke: 0.4pt + rgb("#C9CFD8"),
    inset: (x: 5pt, y: 4pt),
    fill: (_, y) => if y == 0 { azul-acento.lighten(85%) } else { none },
    ..cab.map(c => table.cell(text(weight: "bold", size: 8pt, eval(c, mode: "markup")))),
    ..cuerpo.flatten().map(c => table.cell(text(size: 8pt, eval(c, mode: "markup")))),
  ))
}
#let imagen(ruta, pie) = figure(image(ruta, width: 92%), caption: eval(pie, mode: "markup"))

#set document(title: "HookSuite — Memoria técnica (Práctica 3)")
#set page(paper: "a4", margin: 2.2cm, numbering: "1")
#set text(font: "Liberation Sans", size: 10pt, fill: rgb("#222222"), lang: "es")
#set heading(numbering: none)
#show heading.where(level: 1): it => block(above: 18pt, below: 10pt, text(size: 15pt, fill: azul, weight: "bold", it.body))
#show heading.where(level: 2): it => block(above: 12pt, below: 6pt, text(size: 12pt, fill: azul-acento, weight: "bold", it.body))
#show figure.caption: set text(size: 8.5pt, fill: rgb("#5B6675"), style: "italic")

// Portada
#align(center)[
  #v(3cm)
  #text(size: 26pt, fill: azul, weight: "bold")[HookSuite]
  #v(0.2cm)
  #text(size: 14pt, fill: azul-acento)[Memoria técnica · Práctica 3 — «Del prototipo al producto»]
  #v(0.5cm)
  #text(size: 11pt)[Máster en Ciberseguridad & IA · Evolve Academy]
  #v(2cm)
]
#hueco("José María", "Portada: nº de grupo definitivo, integrantes, fecha de entrega, enlace al repo y enlace al vídeo (apartado 1).")
#pagebreak()

// === CUERPO ===

= 1. Portada
Producto: *HookSuite* — herramienta web de auditoría de seguridad «tipo Burp Suite», con IA.
Grupo: #estado("curso", "nº por confirmar"). Entrega: *16 de octubre de 2026*.
#hueco("José María", "Integrantes con rol, enlace al repositorio público y enlace al vídeo (≥10 min). Se rellena al congelar.")

= 2. Resumen ejecutivo
HookSuite resuelve la auditoría web asistida por IA desde el navegador: interceptar y repetir peticiones, fuzzing, utilidades (hash/encoder/regex), análisis de vulnerabilidades y un módulo de IA que prioriza hallazgos. La P3 parte del prototipo de la P1 y lo lleva a un estado ejecutable, seguro y reproducible.
#hueco("José María + Claude", "Cerrar a 1 página cuando el producto esté congelado: qué hace, para quién, y en qué estado final se entrega.")

= 3. Punto de partida
HookSuite nació en la Práctica 1 como prototipo funcional de una suite de auditoría web «tipo Burp Suite» operada desde el navegador y asistida por IA. Quedó desplegado en un servidor Hetzner (`www.hooksuite.de`) con Docker Compose y, desde la entrega de mayo de 2026, *nadie volvió a tocarlo*: el máster encadenó otras actividades y la Práctica 3 lo retoma tal como quedó.

== Qué nos encontramos (verificación en vivo, 29-sep y 4-oct)
- La herramienta *seguía en pie* desde mayo, sin cambios: DNS → Hetzner, `nginx/1.31.0`, `uvicorn` y los 36 endpoints de la API respondiendo.
- Núcleo funcional sólido: Spider, Repeater, Intruder, Utilidades (hash/encoder/regex), sesiones por token UUID y WebSocket operativos.
- Dos hallazgos que *reorientan* la Práctica 3 (detalle en el apartado 7):
- La API `:8000` estaba *abierta a internet sin ninguna autenticación*, incluidos los endpoints que lanzan tráfico contra terceros.
- En el historial de git había claves de API reales (secretos expuestos).
- El módulo de IA (RF-08), que es lo que da sentido al «con IA» del producto, *nunca llegó a operar* salvo pruebas muy iniciales de la P1: panel construido pero inactivo.

== Numeración de requisitos
La P1 *no numeraba* los requisitos. El enunciado de la P3 (apartado 3) obliga a numerarlos ahora (RF-xx / RNF-xx) y a usar esa numeración en toda la práctica. La lista de abajo (apartado 4) está *derivada del informe de la P1* —de lo que el producto prometía y hace— y #estado("curso", "PENDIENTE DE VALIDAR POR EL GRUPO") en la reunión antes de darla por firme.

== Clasificación inicial de requisitos
Usando las cinco categorías del enunciado. El recuento es provisional, a validar por el grupo junto con la numeración.
#tabla(
  (auto, 6fr, 2fr),
  "
  Estado | Qué significa | Requisitos
  *Cumplido* | Implementado en la P1 y funciona; en la P3 se verifica con prueba y evidencia | RF-01, RF-03, RF-04, RF-05, RF-06, RF-07, RF-11 · RNF-01, RNF-02, RNF-03, RNF-05, RNF-08 *(12)*
  *Parcial* | Existe algo, pero incompleto o con fallos; hay que terminarlo y probarlo | RF-08 · RNF-04, RNF-07 *(3)*
  *Pendiente* | Definido, pero sin implementar; se hace desde cero | RF-09, RF-10, RF-12 · RNF-09 *(4)*
  *A revisar* | El feedback o la experiencia indican que estaba mal planteado; se reformula con justificación | RF-02 · RNF-06 *(2)*
  *Descartado* | Se decide no implementarlo (debe ser la excepción y justificarse) | — ninguno de momento
  ",
)
#hueco("José María", "Feedback docente de la P1: la calificación y los comentarios del equipo evaluador NO constan en el material de la línea. El enunciado los pide expresamente en este apartado. Conseguirlos (José María / portavoz) y resumir aquí qué se nos señaló y cómo lo aborda la P3.")

= 4. Requisitos
Lista completa y numerada. Numeración fijada en la P3 (la P1 no la tenía) a partir del informe de la P1; #estado("curso", "PENDIENTE DE VALIDAR POR EL GRUPO"). El estado es el de partida (apartado 3); se actualiza a medida que la P3 avanza.

== Requisitos funcionales (RF)
#tabla(
  (auto, 7fr, auto),
  "
  ID | Requisito | Estado P1
  RF-01 | Dashboard web accesible desde cualquier navegador, sin instalar nada en el cliente | Cumplido
  RF-02 | El servidor ejecuta las peticiones HTTP en nombre del auditor (proxy del lado servidor) | A revisar
  RF-03 | Spider: rastreo automático del objetivo (BFS, scope al dominio, extrae formularios), velocidad configurable | Cumplido
  RF-04 | Auditoría autenticada: sesión `httpx` persistente compartida por Spider/Repeater/Intruder que hereda las cookies del login | Cumplido
  RF-05 | Repeater: modificar y reenviar cualquier petición; respuesta en 4 vistas (Raw/Pretty/Preview/Headers) | Cumplido
  RF-06 | Intruder: fuzzing de parámetros marcados con `*`; 4 tipos (SQLi, Blind SQLi, XSS, genérico); resultados en tiempo real | Cumplido
  RF-07 | Utilidades: Encoder/Decoder (Base64/URL/HTML/JWT), Hash (MD5/SHA1/SHA256/SHA512), Regex Tester, Payload Generator | Cumplido
  RF-08 | *Análisis y clasificación de vulnerabilidades con IA (Claude) según OWASP* → panel Vulnerabilidades | Parcial
  RF-09 | Captura de tráfico HTTP en tiempo real (DevTools / CDP) → panel Red con código de colores | Pendiente
  RF-10 | Ejecución de ataques con navegador real (Playwright) | Pendiente
  RF-11 | Soporte multi-usuario simultáneo mediante tokens de sesión UUID | Cumplido
  RF-12 | Registro y login individual con JWT + aislamiento de historial/auditorías por usuario | Pendiente (mejora)
  ",
)

== Requisitos no funcionales (RNF)
#tabla(
  (auto, 7fr, auto),
  "
  ID | Requisito | Estado P1
  RNF-01 | Accesible desde navegador sin instalar software en el cliente | Cumplido
  RNF-02 | Actualización en tiempo real vía WebSocket (pings cada 30 s, eventos `{type,payload}`) | Cumplido
  RNF-03 | Desplegado en servidor Hetzner con contenedores Docker | Cumplido
  RNF-04 | Código en GitHub con historial de commits que refleje el trabajo del grupo | Parcial
  RNF-05 | Estabilidad ante carga: límite de concurrencia para no saturar producción | Cumplido
  RNF-06 | Operación degradada cuando la IA no responde o no supera el umbral de confianza | A revisar
  RNF-07 | *Seguridad del propio producto*: secretos fuera del repo, control de acceso, validación de entradas, dependencias sin CVEs | Parcial
  RNF-08 | Firewall dinámico por sesión (abre un puerto por sesión, lo cierra al logout o tras 4 h) | Cumplido (a verificar)
  RNF-09 | TLS/HTTPS en los endpoints públicos (Let's Encrypt) | Pendiente
  ",
)

== Requisitos modificados o descartados (con justificación)
El enunciado pide que todo requisito modificado o descartado lleve su versión original, la nueva y el motivo.

=== RF-02 — proxy del lado servidor (*modificado*)
- *Versión original (P1):* interceptación del tráfico del navegador mediante archivo de autoconfiguración de proxy (PAC) + WebSockets.
- *Versión nueva:* el servidor ejecuta las peticiones directamente con `httpx`, sin interponerse en el navegador del auditor.
- *Motivo:* en la P1, el modelo PAC quedó expuesto y se saturó con tráfico de bots. El pivote a `httpx` directo elimina esa superficie y simplifica el flujo. Es el caso de libro de «requisito reformulado con justificación».

=== RNF-06 — operación degradada (*a revisar*)
- *Original:* enunciado como principio en la P1, sin demostrar.
- *Nuevo:* se demostrará con un umbral sobre el campo `confianza` que devuelve el clasificador de IA: por debajo del umbral, el hallazgo se marca como no concluyente en vez de descartarse. Encaja con el criterio P3 «se comporta razonablemente ante errores».

=== RF-12 — login individual con JWT (*mejora, no requisito P1*)
- No era requisito de la P1 (venía del road map de mejoras). En la P3 cuenta como *mejora*: suma, pero no compensa un requisito original sin cumplir. Se abordará por su valor de seguridad (cierra la fuga de datos entre sesiones).

> *Descartados:* ninguno por ahora. El enunciado pide que sean la excepción; si alguno se descarta (candidato: RF-09/DevTools si aprieta el tiempo) se justificará aquí por escrito.

= 5. Arquitectura y decisiones técnicas
HookSuite se despliega como un conjunto de contenedores Docker coordinados por `docker-compose`, todos en una red interna `hooksuite-net`, con Nginx como única puerta de entrada. Arquitectura verificada fichero a fichero en la cocina local el 4-oct (`docker-compose.yml` + `infra/nginx.conf`).

#imagen("../capturas/arquitectura-p3.svg", "Arquitectura de contenedores de HookSuite: Nginx es la única entrada (Basic Auth); el backend FastAPI orquesta Spider/Repeater/Intruder/IA/Playwright y sale al objetivo auditado con `httpx`. En rojo, el estado actual a corregir (apartado 7).")

== Componentes
#tabla(
  (auto, 3fr, 5fr, auto),
  "
  Componente | Tecnología | Rol | Puerto (prod.)
  *nginx* | `nginx:alpine` | Proxy inverso y único punto de entrada; Basic Auth; enruta a frontend, backend y DVWA | `80→80`
  *frontend* | React + Vite (build propio) | Dashboard web (SPA) servido como estático | `3000→80`
  *backend* | FastAPI + uvicorn (build propio) | API de auditoría: proxy `httpx`, Spider, Repeater, Intruder, utilidades, vulnerabilidades y WebSocket | `8000→8000`
  *redis* | `redis:7-alpine` | Bus de eventos y estado efímero entre servicios | interno
  *ia* | Python + SDK Anthropic (build propio) | Clasificador de vulnerabilidades con Claude (RF-08) | interno
  *playwright* | Python + Playwright (build propio) | Navegador real para ataques dirigidos (RF-10) | interno
  *dvwa* | `vulnerables/web-dvwa` | Laboratorio de pruebas, solo accesible por la red interna | interno
  ",
)

== Enrutado (Nginx)
Toda petición entra por Nginx, que reparte por ruta (`infra/nginx.conf`):
- `/` → *frontend* (protegido con Basic Auth).
- `/api/` y `/ws/` → *backend* (API y WebSocket).
- `/check/` y `/proxy.pac` → *backend* (utilidades del proxy).

Desde la Fase 1, Nginx es además la *única* entrada: `backend` y `frontend` dejaron de publicar puerto propio, y la ruta hacia el laboratorio vulnerable se retiró del proxy (apartado 7).

== Decisiones técnicas
=== Proxy del lado servidor: pivote PAC → httpx (RF-02)
La decisión arquitectónica de más peso heredada de la P1. En origen, HookSuite interceptaba el tráfico del navegador con un archivo de autoconfiguración (PAC) + WebSockets; ese modelo quedó expuesto y se saturó con tráfico de bots. Se pivotó a que *el servidor ejecute las peticiones directamente con `httpx`*: menos superficie y un flujo más simple, a cambio de perder la captura pasiva del tráfico del navegador —justo lo que retoman después DevTools (RF-09) y Playwright (RF-10)—. Versión original/nueva/justificación detalladas en el apartado 4.

=== Frontend: reescritura a Tailwind (cambio respecto a la P1)
La interfaz que corría en producción (`www.hooksuite.de`) se había reescrito al framework de estilos *Tailwind*, abandonando el sistema de variables CSS propio de la P1. Esa versión —la desplegada y en uso— es la que se toma como *base del frontend en la P3*. En la Fase 0 se reconcilió al repositorio (vivía solo en la caja, sin commitear); el detalle del proceso está en el apartado 8.

=== Puntos a corregir, detectados al montar la cocina
- *CORS abierto a cualquier origen* en el backend (FastAPI) → *corregido en la Fase 1*: lista cerrada de orígenes, configurable por entorno (apartado 7).
- *Verificación SSL desactivada* en el cliente `httpx`: justificable en una herramienta de auditoría (objetivos con certificados autofirmados), pero se documenta expresamente como decisión, no como descuido.
- *Acoplamiento Nginx ↔ DVWA*: `infra/nginx.conf` hacía del laboratorio un requisito de arranque del proxy (`host not found in upstream`) → *resuelto en la Fase 1* al retirar su ruta del proxy: el laboratorio queda solo en la red interna y Nginx ya no depende de él.
- *Playwright fuera de la red*: en el `docker-compose.yml` el servicio `playwright` no declara `networks: hooksuite-net`, así que queda aislado y no habla con el backend (causa raíz de RF-10/RF-08 sin operar; se corrige con una línea).

> *Nota de reproducibilidad (cocina).* En el mediaserver los puertos `80/3000/8000` ya los ocupan otros servicios, así que la cocina los remapea a `8880/8830/8800` mediante un override local que no toca el compose versionado. Es solo del entorno de pruebas; la arquitectura de producción es la de la tabla.
#hueco("José María + Claude", "Añadir, si procede, un diagrama de secuencia del ciclo IA↔Playwright↔Backend cuando RF-08/RF-10 estén operativos.")

= 6. Funcionalidades implementadas
Cada funcionalidad con capturas: qué hace, cómo se usa y qué requisitos cubre.
- Proxy interceptor, Repeater, Intruder, Utilidades (hash/encoder/regex), Vulnerabilidades, Red/DevTools, módulo IA.

== Defectos corregidos en la Fase 1
Diez defectos del prototipo, todos reproducidos antes de corregirlos y verificados después en producción. El detalle de cada uno (causa raíz, prueba y autoría) está en el diario del repositorio.

#tabla(
  (5fr, 6fr, auto),
  "
  Qué fallaba | Causa | Requisito
  El Spider entraba en bucle y martilleaba el objetivo | No canonicalizaba las direcciones: el mismo recurso generaba variantes infinitas | RF-03
  El Spider podía dirigirse a servicios internos del propio servidor | Faltaba filtrar destinos no legítimos | RNF-07
  El botón de detener el Spider no existía en la interfaz | El servidor aceptaba la orden, pero la pantalla no ofrecía forma de darla | RF-03
  Detener el Spider no detenía nada | El bucle de rastreo no consultaba la señal de parada | RF-03
  Un mismo formulario aparecía decenas de veces | No se agrupaban: se emitía uno por página visitada | RF-03
  Cancelar el Intruder devolvía un error del servidor | La operación invocaba un método inexistente | RF-06
  Dos operaciones del proxy devolvían error del servidor | Un error de sintaxis construía un tipo de dato equivocado | RF-02
  Importar un comando `curl` rompía las direcciones seguras | Una expresión regular mal escapada recortaba el esquema | RF-05
  Los avisos de error no decían qué había fallado | Se mostraba el texto crudo de la librería de red | RF-05
  Dos pantallas no recibían avisos en tiempo real | El servidor guardaba una sola conexión por sesión y la segunda desplazaba a la primera | RNF-04
  El agente del cortafuegos era manipulable por cualquiera | Su canal se creaba con permisos para todo el sistema y no validaba lo recibido | RNF-08
  El estado de sesión podía crecer sin límite | El recolector existía pero nunca se ejecutaba, y cualquier identificador nuevo creaba una sesión | RNF-07
  "
)

*Nota sobre el último:* no era el defecto que teníamos anotado. El pendiente decía «las sesiones no se conservan al reiniciar»; al abrirlo resultó que el problema real era el contrario y más grave —podían crecer sin límite desde fuera—. La volatilidad se justifica en el apartado 10; lo que se corrigió fue el crecimiento.
#hueco("José María + Claude", "Documentar cada funcionalidad (qué hace, cómo se usa, qué requisitos cubre) con capturas de producto; las de pantalla las saca José María (R6), tras la Fase 3, cuando el login nuevo cambie las pantallas. El commit de cada módulo se firma a nombre de su responsable cuando toque (R2): Ivan/frontend, Macarena/backend, Nacho/playwright, Carlos/DevTools, José María/IA.")

= 7. Seguridad del producto
Modelo de amenazas, secretos, autenticación, validación de entradas, dependencias y datos personales. (Base en `REQUISITOS.md` §3.) Contenido ya verificado en esta práctica:

== Secretos: el incidente de las claves
En el historial de git había claves de API de Anthropic. Verificado el 4-oct: *las cuatro están muertas* (la API responde `401 / "API key is invalid."`). Aun así, el enunciado (§7) obliga a limpiarlas del historial, no basta con borrarlas en un commit nuevo.
- El 4-oct se *reescribió el historial* con `git-filter-repo`: se redactaron las claves por patrón y se eliminaron los `.env` rastreados y la basura (node_modules, venv de Windows), conservando el código, las 7 ramas y el `.env.example` (con la clave ya redactada).
- *Ejecutado en GitHub el 4-oct* (force-push de las 7 ramas, con copia de seguridad previa). Verificado sobre un clon nuevo: *0 claves en todo el historial* de las ramas. El repositorio público queda sin secretos.
- Salvedad: GitHub conserva un tiempo los refs internos de los *pull requests* antiguos apuntando a los commits viejos; los purga por su cuenta. Como las claves están muertas, no supone riesgo.
#estado("ok", "LIMPIEZA EJECUTADA Y VERIFICADA")

== Exposición de la caja: cómo estaba
Estado de partida, verificado en vivo el 29-sep y el 4-oct (evidencia fotográfica en el apartado 8):
- La API `:8000` *no tenía autenticación*: lo declaraba su propia `openapi.json` (40 operaciones sin seguridad) y `/health` respondía sin credenciales.
- El Basic Auth del `:80` se *evitaba* sirviendo el frontend directamente por `:3000`.
- El servidor *no tenía cortafuegos* (política de aceptación por defecto) ni protección contra fuerza bruta, y acumulaba unos *127.000 intentos de acceso en 7 días*.
- DVWA *no* estaba expuesto a internet (solo red interna) — corrige un supuesto previo nuestro.

== Endurecimiento aplicado en la Fase 1 (5-oct)
=== Cierre de la exposición
La API y el frontend dejaron de publicar puerto propio: *la única entrada es el proxy*. No bastaba con retirarlos del `docker-compose.yml`, porque el frontend llevaba la dirección del servidor incrustada en tiempo de compilación y hablaba directamente con la API; hubo que *reconstruirlo para que use el mismo origen* y que sus llamadas (incluido el WebSocket) pasen por el proxy.
Comprobado desde fuera tras el despliegue: los puertos directos *rechazan la conexión*, el proxy responde, y el paquete del frontend ya no contiene ninguna referencia a la dirección antigua.

=== Orígenes permitidos (CORS)
El backend aceptaba *cualquier* origen con credenciales, combinación además inválida por especificación: en la práctica, el servidor *reflejaba el origen de quien preguntara*, de modo que cualquier web podía hacerle peticiones autenticadas. Se sustituyó por una *lista cerrada* configurable por entorno. Comprobado: un origen arbitrario ya no recibe permiso; uno legítimo sí.

=== El laboratorio vulnerable, solo interno
Se retiró del proxy la ruta que lo publicaba. Queda accesible únicamente desde la red interna, para las pruebas del propio producto.

=== Endurecimiento del servidor
- *Cortafuegos* activo, con política de denegación por defecto y únicamente el acceso remoto y el proxy permitidos.
- *Bloqueo automático de fuerza bruta* contra el acceso remoto: en su primer minuto ya registraba 148 intentos fallidos y había bloqueado dos direcciones.
- *Acceso remoto solo por clave*: se desactivó la autenticación por contraseña. La prueba más limpia es el propio mensaje del servidor, que pasó de ofrecer «clave o contraseña» a admitir *solo clave*.
- *Limpieza de reglas abandonadas*: siete reglas heredadas de la P1 —una de ellas con la dirección pública de un integrante y otra con un valor de ejemplo— se retiraron tras comprobar que ningún servicio escuchaba en esos puertos.
- *Agente de firewall duplicado*: se encontró un segundo proceso del agente, lanzado a mano en mayo y fuera del gestor de servicios, con permisos de administración del cortafuegos. Se terminó; queda uno solo, gestionado por el sistema.
- *Sistema operativo*: se estrenó el núcleo ya instalado pero sin aplicar desde mayo. Antes de reiniciar se corrigió una condición de carrera en el arranque que habría dejado el agente del cortafuegos en bucle (ver apartado 8).

=== Dos matices honestos, para no atribuirnos de más
- *El acceso de administrador por contraseña ya estaba bloqueado* por la configuración por defecto del sistema: los 127.000 intentos registrados nunca tuvieron ninguna posibilidad. Lo que se cerró fue la autenticación por contraseña *a nivel general*. Se hizo igual porque deja de depender de un valor por defecto que una actualización podría cambiar, y porque cierra la puerta a cualquier usuario futuro.
- *El cortafuegos del sistema no filtra los puertos que publica Docker*, cuyas reglas se evalúan antes. Quien cerró de verdad la API y el frontend fue el despliegue, al dejar de publicarlos. El cortafuegos protege el resto del servidor, no esos puertos.

#estado("ok", "EXPOSICIÓN CERRADA Y SERVIDOR ENDURECIDO")

== Lo que todavía no cubre
La API y el WebSocket siguen *sin autenticación* por detrás del proxy: hoy el único control es el Basic Auth de la entrada, que además no distingue usuarios. Eso lo resuelve el sistema de acceso por usuario de la Fase 2, que es también lo que cierra el aislamiento entre sesiones.

Conviene ser concretos, porque «sin autenticación» suena a una sola carencia y en realidad son cuatro fallos distintos, los cuatro medidos en la cocina el 6-oct antes de tocar código:

- *La API entera responde sin credencial.* La asimetría lo delata: `GET /health` devuelve `401` por el Basic Auth de la entrada, pero `GET /api/session/new` devuelve `200` y entrega un token. El proxy protege unas rutas y deja `/api` abierta.
- *El token de sesión no es una credencial, es un nombre.* El backend *crea* una sesión para cualquier cadena inventada, así que no existe frontera que un atacante tenga que violar: basta con escribir un token cualquiera en la URL.
- *La cookie de sesión de la web auditada se comparte entre todos.* Se guarda en una tabla global indexada *solo por el dominio*, sin dueño. En la prueba, un segundo usuario leyó la cookie que había capturado el primero, y también se obtiene sin presentar token alguno. Dicho sin rodeos: la herramienta filtra el identificador de sesión de la víctima a cualquiera que alcance la API.
- *Los hallazgos se difunden a todos los paneles.* Una vulnerabilidad publicada sin token apareció en la sesión de dos auditores distintos. En una herramienta de auditoría eso es una fuga de datos del cliente de otro.

Los dos últimos son los que convierten la falta de login en algo más que una incomodidad, y son la razón por la que la Fase 2 figura como innegociable. La evidencia completa está en el apartado 8.
#hueco("José María", "Completar el modelo STRIDE, validación de entradas, dependencias y tratamiento de datos personales.")

= 8. Pruebas y evidencias
Plan de pruebas, casos ejecutados, resultados y las pruebas que fallaron con su explicación. El detalle caso a caso (PR-01…PR-20) se mantiene en la matriz del apartado 9 y en el diario del repo.

== Evidencia de exposición (RNF-07 / PR-16), capturada el 4-oct
La prueba PR-16 —llamar a la API sin credenciales— y la verificación del frontend confirman que, antes de endurecer, el producto quedaba accesible sin autenticación. Capturas obtenidas antes de cualquier arreglo (R6: la evidencia de un fallo se captura antes de corregirlo, porque el propio arreglo la destruye):

#imagen("../capturas/exposicion/RNF07-api-health-sin-login.png", "RNF-07 / PR-16 — `GET /health` de la API responde `200` sin credenciales ni cabecera `WWW-Authenticate`: la API no exige autenticación.")

#imagen("../capturas/exposicion/RNF07-api-swagger-abierto.png", "RNF-07 / PR-16 — la documentación Swagger (`/docs`) queda abierta a cualquiera, exponiendo las 40 operaciones de la API, incluidas las que lanzan tráfico contra terceros.")

#imagen("../capturas/exposicion/RNF07-frontend-3000-sin-auth.png", "RNF-07 — el frontend servido directamente por `:3000` carga `200` sin Basic Auth, evitando por completo el login de Nginx del `:80`.")

#imagen("../capturas/exposicion/RNF07-nginx-80-pide-auth.png", "RNF-07 — por contraste, la entrada «correcta» (`:80` tras Nginx) sí pide Basic Auth: el control existe, pero se puede rodear por el puerto directo.")

#imagen("../capturas/exposicion/RNF07-credencial-p1-no-abre.png", "RNF-07 — la credencial documentada en el informe de la P1 es rechazada con `401` por `nginx/1.31.0`: la credencial publicada ya no sirve, lo que refuerza el cambio de modelo de acceso en la Fase 2.")

== Defectos corregidos: antes y después (RF-03)

Dos pares de capturas tomadas sobre el producto desplegado, antes y después de corregir. El objetivo de las pruebas es una web propia del equipo, autorizada para ello.

#imagen("../capturas/fase1/RF-03-antes-sin-boton-detener.png", "RF-03 — ANTES: el Spider está rastreando («Spider en ejecucion…») y el único botón del panel aparece bloqueado como «Ejecutando…». No existe ninguna forma de detener el rastreo desde la interfaz.")

#imagen("../capturas/fase1/RF-03-despues-con-boton-detener.png", "RF-03 — DESPUÉS: en la misma situación aparece el botón «Detener» junto al de ejecución. Obsérvese además el contador «1 FORM» en cada petición, frente a las decenas de la captura siguiente.")

#imagen("../capturas/fase1/RF-03-antes-formularios-repetidos.png", "RF-03 — ANTES: una sola petición (`/tienda?page=1&sort=newest`) arrastra *52 entradas de formulario idénticas*, que inundan el panel de resultados.")

#imagen("../capturas/fase1/RF-03-despues-formularios-unicos.png", "RF-03 — DESPUÉS: la misma petición de la misma página queda en *una sola entrada*. Solo cambia el contador: 52 → 1.")

> *Nota de tratamiento de las capturas (R7).* Las dos del estado anterior mostraban un identificador de sesión de la web de pruebas en la franja superior; se publican con esa franja tapada, y los originales no salen del almacén interno. Las del estado posterior no lo contienen porque la sesión no estaba autenticada.

== Condición de carrera detectada antes de reiniciar el servidor
El agente del cortafuegos y el servicio de contenedores no tenían orden de arranque entre sí. Si el segundo ganaba la carrera, *creaba una carpeta donde debía ir el canal de comunicación del agente* —comportamiento normal al montar un fichero que no existe— y el agente quedaba en un bucle de reinicios. El servidor llevaba sin reiniciarse desde mayo, así que nunca se había puesto a prueba. Se corrigió fijando el orden de arranque antes de reiniciar; tras el reinicio, el contador de reinicios del agente marcaba *cero*: la carrera no llegó a producirse.

== Otras evidencias ya en mano
- *Incidente de las claves y limpieza del historial:* ensayo de reescritura verificado antes/después (3 → 0 claves), detallado en el apartado 7.
- *Salidas de terminal* (health sin login, `openapi.json` sin seguridad, cierre de puertos, mensajes de error) guardadas como texto en el repo, no como foto (R7: así ninguna captura publica por error un secreto).

== Evidencia de las fugas de aislamiento (RF-12), capturada el 6-oct
Cuatro pruebas lanzadas contra la cocina a través del proxy, como las haría un cliente, *antes de tocar una sola línea de código de la Fase 2*: el propio arreglo borra esta evidencia, y el apartado pide las pruebas que fallaron con su explicación. Los valores de cookie empleados son inventados a propósito, de modo que la captura no contiene ningún identificador real (R7).

Las cuatro confirmaron el fallo: la API responde `200` sin credencial mientras `/health` responde `401`; un token inventado obtiene sesión propia; un segundo usuario lee la cookie de sesión capturada por el primero —y también se obtiene sin token—; y una vulnerabilidad publicada sin token aparece en la sesión de dos auditores distintos.

La captura íntegra, con la causa en fichero y línea de cada una, está en `evidencias/fugas-aislamiento-06oct.md`. Una corrección respecto a lo que teníamos anotado: la difusión no ocurre solo en las dos llamadas que emiten a todas las sesiones, sino también en los dos endpoints que admiten peticiones sin token, que además *persisten* el dato en la sesión de todos los usuarios. Son cuatro puntos de difusión, no dos.

#estado("rojo", "FUGAS DE AISLAMIENTO DOCUMENTADAS Y ABIERTAS — LAS CIERRA LA FASE 2")
#estado("ok", "EVIDENCIA DE EXPOSICIÓN Y DE LA FASE 1 COMPLETA")
#hueco("José María + Claude", "Plan de pruebas formal y capturas de PRODUCTO de los bugs (500 de `check/alive`, trampa del Spider) reproducidos en la cocina. Las de pantalla las saca José María (R6), tras la Fase 3, cuando el login nuevo cambie las pantallas. Las pruebas las hacen José María y Claude (R2).")

= 9. Matriz de trazabilidad
La pieza con la que se corrige la práctica: requisito por requisito, dónde está implementado, qué prueba lo verifica y dónde se ve. Las rutas están comprobadas en el código (cocina local, 4-oct). La columna de evidencia enlaza la figura de la memoria y el *minuto exacto del vídeo*; se rellena al grabar.
#tabla(
  (auto, 4fr, auto, 4fr, auto, 3fr),
  "
  Req. | Descripción | Estado | Implementación (ruta) | Prueba | Evidencia
  RF-01 | Dashboard web sin instalación | Cumplido | `frontend/src/App.jsx` + `Layout.jsx` | PR-01 | fig. — · vídeo —:—
  RF-02 | Proxy del lado servidor (`httpx`) | Modificado (2 errores de servidor corregidos en F1) | `backend/services/proxy_service.py` | PR-19 | justif. apdo. 4 · apdo. 6
  RF-03 | Spider / rastreo | Cumplido (4 defectos corregidos en F1) | `backend/services/spider_service.py`, `frontend/.../ProxyPage.jsx` | PR-03 | figs. apdo. 8 · vídeo —:—
  RF-04 | Auditoría autenticada (sesión compartida) | Cumplido | `backend/services/session_service.py` | PR-04 | fig. — · vídeo —:—
  RF-05 | Repeater | Cumplido (parser y avisos de error corregidos en F1) | `backend/routes/repeater.py`, `backend/services/proxy_service.py` | PR-05 | apdo. 6 · vídeo —:—
  RF-06 | Intruder / fuzzing | Cumplido (cancelación corregida en F1) | `backend/services/intruder_service.py` | PR-06 | apdo. 6 · vídeo —:—
  RF-07 | Utilidades (incl. JWT) | Cumplido | `frontend/src/pages/utilities/` | PR-07 | fig. — · vídeo —:—
  RF-08 | IA → panel Vulnerabilidades | según alcance | `ia/analyzers/vulnerability_classifier.py` + `backend/routes/vulnerabilities.py` | PR-08 | fig. — · vídeo —:—
  RF-09 | DevTools → panel Red | según alcance | `devtools/` + `backend/routes/network.py` | PR-09 | fig. — · vídeo —:—
  RF-10 | Playwright | según alcance | `playwright/` + `backend/routes/playwright.py` | PR-10 | fig. — · vídeo —:—
  RF-11 | Multi-usuario (tokens UUID) | Cumplido | `backend/main.py` (`/api/session/new`) | PR-11 | fig. — · vídeo —:—
  RF-12 | Login JWT + aislamiento | mejora opcional | (por implementar, Fase 2) | PR-12 | fig. — · vídeo —:—
  RNF-02 | WebSocket en tiempo real | Cumplido | `backend/main.py` (`/ws/{token}`) | PR-17 | vídeo —:—
  RNF-03 | Despliegue Docker en Hetzner | Cumplido | `docker-compose.yml` + `infra/nginx.conf` | PR-13 | fig. — · vídeo —:—
  RNF-05 | Límite de concurrencia | Cumplido | `backend/services/intruder_service.py` (`asyncio.Semaphore`) | PR-20 | apdo. 8
  RNF-07 | Seguridad del producto | Cumplido en F1 (exposición cerrada y servidor endurecido); auth de API pendiente de F2 | ver apartado 7 | PR-14, PR-16 | apdo. 7-8
  RNF-08 | Firewall dinámico por sesión | Operativo y endurecido en F1 (permisos del canal y validación de entradas) | `firewall_agent.py` | PR-15 | apdo. 7-8
  RNF-09 | TLS/HTTPS | Pendiente | (por configurar en Nginx) | PR-18 | apdo. 8
  ",
)
#estado("curso", "RUTAS VERIFICADAS EN CÓDIGO · PRUEBAS Y MINUTOS DE VÍDEO POR COMPLETAR")

El estado de cada prueba (PR-xx) y su resultado detallado están en el apartado 8. Al arreglar cada fallo se reejecuta la prueba y se actualiza la fila. La numeración RF/RNF es la fijada en el apartado 4 y #estado("curso", "PENDIENTE DE VALIDAR POR EL GRUPO").
#hueco("José María + Claude", "Al revisar el vídeo grabado, anotar el minuto exacto donde se demuestra cada requisito y el número de figura de su captura (R6: el nombre de la captura va atado al ID del requisito, p. ej. `RF-08-panel-ia.png`, para que esta columna se rellene sola).")

= 10. Limitaciones y trabajo futuro
Qué no funciona, qué funciona con condiciones y qué se haría con más tiempo. Este apartado recibe material hasta el último día.

== El estado de sesión es volátil, por diseño
El estado de una sesión de auditoría —tráfico capturado, resultados del Intruder, vulnerabilidades— vive *en memoria del backend*: al reiniciarlo, se pierde. Es una *decisión consciente*, no un olvido, y se sostiene en tres razones:

1. *El patrón de acceso del backend no lo soporta sin reescribirlo.* Una treintena de puntos obtienen el diccionario de la sesión y lo mutan en memoria (`session["requests"].append(...)`). Persistir de verdad obligaría a escritura-a-través en cada mutación, es decir, a tocar todo el backend a pocos días de la entrega.
2. *El modelo de sesión cambia en la Fase 2.* El login por usuario ata las sesiones a identidades; lo que se persistiera con el modelo anterior habría que rehacerlo.
3. *Una sesión de auditoría es un espacio de trabajo efímero.* El operador lanza un rastreo, examina los resultados y exporta lo que importa; no espera que la herramienta recuerde una sesión de hace tres días.

Lo que *sí* se hizo, porque era el riesgo real detrás de «todo en memoria»: *poner topes*. El recolector de sesiones existía en el código pero nunca se invocaba, y cualquier llamada a la API con un identificador nuevo creaba una sesión más —con la API sin autenticación, eso permitía agotar la memoria del servidor desde fuera—. Ahora hay un tope de sesiones y de peticiones por sesión (configurables por entorno), el recolector se ejecuta de verdad y, al desalojar, *prefiere las sesiones que no tienen conexión en tiempo real abierta*, para no interrumpir a quien está trabajando. Verificado con prueba de abuso: 120 identificadores inventados dejan el número de sesiones en el tope, y la sesión con conexión viva sobrevive.

*Trabajo futuro.* La persistencia es viable sin cambiar la arquitectura: el despliegue ya incluye Redis y el backend ya lo usa para otro flujo. El momento correcto es *después* del modelo de usuarios, para persistir sesiones ya asociadas a su propietario.

#hueco("José María + Claude", "Acumular el resto de limitaciones conforme aparezcan durante las Fases 1-4; este apartado recibe material hasta el último día.")

= 11. Reparto del trabajo
Quién hizo qué, con estimación de horas por persona.
#hueco("José María", "Consolidar las horas por persona al congelar (13-oct). El reparto real del trabajo queda trazado por los commits firmados por cada responsable (R2); José María cierra el recuento.")

= 12. Uso de herramientas de IA
Declaración obligatoria de qué herramientas de IA se usaron y para qué.
- *Claude Code* (modelo Claude de Anthropic): asistencia en diagnóstico, montaje de la cocina, ensayo de limpieza del historial y redacción de esta memoria, bajo revisión humana.
#hueco("José María", "Detallar por fase qué aportó la IA y qué fue decisión/revisión humana; distinguir generado de verificado.")

= 13. Anexos
Manual de instalación ampliado, credenciales de prueba (ficticias), glosario y referencias.
#hueco("José María", "Manual de despliegue, usuarios de prueba del login nuevo (sustituyen a la credencial de Nginx), glosario y referencias.")
