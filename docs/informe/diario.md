# Diario de la Práctica 3 — HookSuite

> **Qué es esto (R3 del protocolo de trabajo).** El almacén en crudo del trabajo de la P3, escrito **en el
> momento**, no al final. Aquí va el *motivo* de cada elección, lo que se *descartó*, lo que se *rompió*, el
> *requisito* que toca, la *evidencia* y las *horas*. **No es la memoria**: la memoria (20-40 pág., `docs/informe/main.typ`)
> es lo destilado; esto es la materia prima. El diario **no** se vuelca entero en la memoria.
>
> **Campo «evidencia» obligatorio**, uno de tres: `evidencias/<fichero>` · `(no aplica)` (decisión/razonamiento) ·
> `⚠️ FALTA: <qué> [pantalla/terminal]` (pendiente visible). Ningún secreto en texto: claves por SHA-256 truncado.

---

## 2026-10-04 · Arranque de la Fase 0: claves, evidencia de exposición y montaje de la cocina
*(Infra/seguridad/GitHub = José María (P5); pruebas = José María + Claude. Las capturas de pantalla las sacó José María.)*

### Revocación de claves → resultó innecesaria: las 4 estaban muertas
- **Qué:** antes de revocar las claves filtradas, se comprobó en vivo si seguían activas (1 petición por clave a
  la API de Anthropic, valor leído solo en variable).
- **Por qué:** José María avisó de que en su consola solo veía UNA clave, no cuatro → algo no cuadraba con el plan.
- **Resultado:** las **4** devuelven `401 / "API key is invalid."`. Dos eran de una 2ª cuenta de José María, una
  de Macarena (`02e4bd6e`), una fuera de git. El módulo IA nunca estuvo en producción (solo pruebas de la P1),
  por eso nadie notó que murieran.
- **Qué se descartó:** pedir al grupo que revocaran (innecesario); «emitir una nueva ya» se pospone a cuando se
  trabaje RF-08.
- **Qué falló/ojo:** limpiar el historial **sigue siendo obligatorio** aunque estén muertas (norma del enunciado, §7).
- **Requisito:** Seguridad (criterio 15 %) · norma de repositorio (§7).
- **Evidencia:** `evidencias/claves-estado-04oct.md` (SHA-256 truncados, sin valores). **Horas:** ~0,5 h.

### Captura de evidencia de la exposición de la caja (lo irreversible)
- **Qué:** barrido de solo lectura contra `91.98.143.219` para documentar la exposición ANTES de arreglarla.
- **Por qué:** nuestros propios arreglos de la Fase 1 (cerrar puertos, auth) destruyen esta evidencia, que el
  apartado 8 de la memoria exige.
- **Hallazgos:** API `:8000` **sin autenticación** (lo declara su `openapi.json`: 40 operaciones `security=-`);
  Basic Auth del `:80` **evitable** sirviendo el frontend por `:3000`; DVWA **NO** expuesto (el 200 era el
  fallback de la SPA — corrige un supuesto del plan); `nginx/1.31.0`.
- **Qué se descartó:** lanzar Spider/Intruder para probar el agujero → NO se hizo (ética RNF-07 + R1; el
  clasificador de permisos además lo bloqueó). La ausencia de auth queda probada por la `openapi.json` + `/health`.
- **Requisito:** RNF autenticación en /api · RNF-08 · RNF-07 · apartado 8 (lo que falla).
- **Evidencia:** `evidencias/exposicion-caja-04oct.md`, `evidencias/openapi-caja-04oct.json`, 5 capturas en
  `evidencias/capturas/` (health sin login · Swagger abierto · frontend :3000 sin auth · :80 pide auth ·
  credencial P1 → 401). **Horas:** ~1 h.

### Montaje de la cocina (este repo, en local, R1)
- **Qué:** clonado el repo en `/home/josemax/cocina/Proyecto-Evolve` y levantado el stack en local.
- **Por qué:** R1 — nada se prueba en producción; todo se monta y prueba aquí.
- **Decisiones:** (1) puertos host remapeados por `docker-compose.override.yml` **local no versionado**
  (nginx→8880, frontend→8830, backend→8800) con tag `!override`, porque `:80/:3000/:8000` ya los usan
  panel-caddy y comprapp en el mediaserver; (2) `.env` de cocina con placeholder de clave (sin valor real,
  R7) porque la de IA está pendiente; (3) build inicial solo del núcleo (backend/frontend/nginx/redis);
  playwright e ia se difieren a cuando se trabaje RF-08.
- **Qué se descartó:** editar el `docker-compose.yml` versionado para cambiar puertos (se usó override para no
  ensuciar el árbol, R4). Tocar producción (R1).
- **Requisito:** base de todo el trabajo de las Fases 0-3.
- **Evidencia:** `evidencias/cocina-stack-04oct.md` (docker compose ps + curls). Núcleo arriba y verificado; nginx exigió levantar DVWA (acoplamiento duro, al backlog).
  **Horas:** ~1 h.

### Fase 0 (ensayo en la cocina): reescritura del historial probada en local, sin tocar GitHub
- **Qué:** se ensayó la limpieza del historial sobre un clon `--mirror` fresco (`ensayo-limpieza.git`), con
  `git-filter-repo`, para probar el procedimiento antes de ejecutarlo en GitHub.
- **Por qué:** el enunciado (§7) exige que no haya secretos reales «ni en el historial»; el force-push da miedo,
  así que se ensaya en local (cero riesgo) antes de tocar el repo compartido.
- **Resultado:** claves `sk-ant-` en todo el historial **3 → 0**; eliminados `.env` rastreados + node_modules +
  venv + `devtools/re` (basura de Windows, ~71 MB); **conservados** los `.env.example` (clave redactada) y el
  PDF del informe; **código fuente idéntico** fichero a fichero; **7 ramas intactas**; tamaño `.git` **90 → 19 MB**.
- **Qué se descartó:** `--strip-blobs-bigger-than 1M` (se habría llevado el PDF del informe) → se usaron `--path`
  explícitos. Escribir las claves en un fichero de reglas → se usó una **regla regex** que redacta por patrón,
  sin manejar ningún valor (R7).
- **Qué falló/ojo:** para GitHub real, los `refs/pull/*` no se reescriben con un push normal → decidir con el
  grupo cerrar los PRs viejos antes del force-push. El force-push necesita **fecha con el grupo** (R2/R8).
- **Requisito:** norma de repositorio (§7) · Seguridad (15 %).
- **Evidencia:** `evidencias/ensayo-limpieza-historial-04oct.md` (procedimiento exacto + antes/después). **Horas:** ~1 h.
- **Parada deliberada:** aquí se para. Nada ha tocado GitHub; la ejecución real (rama-foto + force-push) queda
  para cuando josemax y el grupo fijen fecha.

### Esqueleto de la memoria técnica montado y publicado como artefacto de revisión
- **Qué:** creada la fuente única `docs/informe/P3-memoria.typ` (13 apartados, huecos con responsable, relleno
  lo ya real) y el generador `tools/typ2html.py` que produce el artefacto HTML de revisión.
- **Por qué:** R4 pide una sola fuente `.typ` con dos salidas (PDF + artefacto) y R5 que los 13 apartados estén
  abiertos desde el principio con los huecos visibles.
- **Qué se descartó:** el export HTML nativo de Typst (`--features html`) → es experimental y pierde el contenido
  de celdas de tabla; se escribió el generador propio (`tools/typ2html`, el que nombra el protocolo).
- **Requisito:** estructura de la memoria (enunciado §5) · R4 · R5.
- **Evidencia:** PDF `docs/informe/P3-memoria.pdf` (compila) + artefacto en
  https://claude.ai/code/artifact/97b990b9-bdc9-4fad-874d-3c6688866ce2 (favicon 📋). **Horas:** ~1,5 h.

### Apartados 3, 4 y 9 de la memoria rellenos (volcado de REQUISITOS.md + MATRIZ.md)
- **Qué:** rellenos los apartados 3 (Punto de partida), 4 (Requisitos) y 9 (Matriz de trazabilidad) de
  `P3-memoria.typ`. Antes eran solo huecos; ahora llevan tablas de datos: clasificación por las 5 categorías
  del enunciado (12/3/4/2/0), lista numerada RF-01…RF-12 + RNF-01…RNF-09 con los modificados justificados
  (RF-02 PAC→httpx, RNF-06, RF-12), y la matriz de 6 columnas con rutas verificadas en el código.
- **Por qué:** frente A del cierre del 4-oct, el único que avanza al 100 % sin depender del grupo. El
  enunciado (§5) exige estos tres apartados como tabla; eran los más directos de volcar.
- **Qué se descartó:** usar el export HTML nativo de Typst para las tablas (sigue sin ser fiable, R4); se
  añadió un helper `#tabla(cols, "cab|cab\nfila|fila")` a la fuente y su render al `typ2html.py` (pieza
  habilitante: sin tablas no se podía volcar nada de esto). Placeholders `__:__` del minuto de vídeo
  cambiados a `—:—` porque Typst se comía los dobles guiones bajos.
- **Qué falló/ojo:** 1) la numeración RF/RNF es DERIVADA del informe P1 (la P1 no numeraba) y sigue
  **pendiente de validar por el grupo** → marcado como tal en los apartados 3 y 4, no como hecho. 2) El
  **feedback docente de la P1 no consta** en el material de la línea y el enunciado lo pide en el apartado 3
  → queda como hueco a nombre de José María. Rutas de la matriz comprobadas una a una en `backend/`,
  `frontend/src/`, `ia/`, `devtools/`, `playwright/`, `infra/` (R9: ruta puesta = ruta verificada).
- **Requisito:** estructura de la memoria (enunciado §5, apartados 3/4/9) · R4 · R5 · R9.
- **Evidencia:** (no aplica) — volcado de documentación; el PDF compila y el artefacto se regeneró y
  republicó en la URL fija https://claude.ai/code/artifact/97b990b9-bdc9-4fad-874d-3c6688866ce2 (R4).
  **Horas:** ~1,5 h.

### Apartado 5 (Arquitectura) relleno + soporte de imágenes en el pipeline + capturas de exposición en el apartado 8
- **Qué:** rellenado el apartado 5 (arquitectura de contenedores verificada en el compose: diagrama + tabla de
  7 componentes + enrutado Nginx + decisiones técnicas), y añadidas al apartado 8 las **5 capturas de
  exposición** que sacó josemax el 4-oct por la mañana, con pie atado a RNF-07/PR-16 (R6).
- **Por qué:** frente A, siguiente apartado que se volcaba casi directo de lo ya verificado. Y la duda de
  josemax («¿por qué mis capturas no están en la memoria?») tenía razón de fondo: estaban guardadas pero el
  pipeline no sabía incrustar imágenes. El apartado 5 necesitaba un diagrama igualmente, así que se resolvió
  el soporte de imágenes y se aprovechó para las 5 capturas.
- **Pieza habilitante:** helper `#imagen("ruta","pie")` en el `.typ` + su render en `typ2html.py`. SVG se
  incrusta inline; PNG/JPG se reducen con **Pillow** (venv dedicado `~/.venvs/hooksuite-tools`, para no tocar
  el Python del sistema) a ≤1100 px y se embeben como data URI (R6: copia reducida para el artefacto; PNG
  completo en `docs/capturas/` para el PDF). Numeración de figuras coherente entre PDF y HTML.
- **Diagrama:** `docs/capturas/arquitectura-p3.svg`, hecho a mano y fiel al `docker-compose.yml` + `nginx.conf`
  (Nginx única entrada con Basic Auth; backend orquesta y sale con httpx; dvwa interno; playwright SIN red).
- **Qué se descartó:** reutilizar `arquitectura.jpg` de la P1 (trae mitmproxy, que se jubila) → diagrama nuevo.
  Instalar Pillow en el Python del sistema (PEP 668 + hay servicios del host sobre él) → venv aislado.
- **Qué falló/ojo:** 1) Typst exige `--root .` para alcanzar `docs/capturas/` (fuera de `docs/informe/`).
  2) Un pie con comillas internas escapadas (`\"correcta\"`) rompía el regex del parser y se perdía una
  captura → cambiado a comillas angulares «». 3) El caption de Typst mostraba el markup literal (backticks);
  arreglado con `eval(pie, mode:"markup")` para que PDF y HTML coincidan (R4). **Comando de regeneración
  nuevo documentado** en la cabecera del `.typ` y en el docstring del generador.
- **Requisito:** estructura de la memoria (§5 apartado 5; §8 apartado 8 «pruebas que han fallado») · R4 · R6.
- **Evidencia:** `docs/capturas/exposicion/RNF07-*.png` (5) + `docs/capturas/arquitectura-p3.svg`; artefacto
  republicado (6 figuras) en https://claude.ai/code/artifact/97b990b9-bdc9-4fad-874d-3c6688866ce2 · PDF 375 KB.
  **Horas:** ~2 h.

### Corrección de responsables de los huecos de la memoria
- **Qué:** reasignados los huecos de la memoria que ponían a Ivan/Macarena/Nacho/Carlos (o «todos»/«portavoz»)
  como responsables de documentar o revisar → ahora todos son *José María* o *José María + Claude*.
- **Por qué:** josemax recordó el modelo de trabajo real (matiza R2): **el equipo solo hace commit de su parte
  cuando le toca; el resto —código y memoria— lo hacemos josemax y Claude.** Mi redacción anterior daba a
  entender que los compañeros redactarían apartados, lo cual es falso.
- **Qué NO cambia:** la autoría de los *commits* sigue atada a su responsable (R2): Ivan/frontend,
  Macarena/backend, Nacho/playwright, Carlos/DevTools, José María/IA. Las capturas de pantalla las saca
  José María (R6). Eso queda escrito en el hueco del apartado 6.
- **Requisito:** R2 (una tarea/una persona/un commit) · R6 (capturas de pantalla = josemax).
- **Evidencia:** (no aplica) — corrección de documentación; artefacto republicado. **Horas:** ~0,3 h.

### Fase 0 (4-oct) · Reconciliación del frontend de la caja → git (commit de Macarena)
- **Qué:** llevados a git los 32 ficheros sin commitear de la caja (del tarball del respaldo): una reescritura
  del frontend a Tailwind (~2.750 líneas, 29 modificados + `ResizableSplit.jsx` + los 2 binarios del easter egg
  `flashbang`). Commit `fdde3d39` sobre `develop`, a nombre de **Macarena** (sin `Co-authored-by`, R2).
- **Por qué:** era la versión desplegada y funcionando en www.hooksuite.de (josemax confirmó que es la buena y
  que esa parte es de Macarena), pero solo existía en producción, sin commitear → el despliegue `reset --hard`
  la habría borrado. Se preserva tal cual (estado real); el easter egg se quita en la higiene.
- **Cómo (reproducible):** clon de trabajo desde el mirror del respaldo (`github-mirror.git`), checkout
  `develop`, copiado `frontend/src` + binarios de la caja extraída, `git add`, commit con identidad de Macarena.
  Verificado: 32 ficheros exactos, 0 claves `sk-ant-` (R7). Vive en `~/cocina/fase0-trabajo` (y en scratchpad).
- **Qué falta en la Fase 0:** higiene (LICENSE MIT, README real, configs muertas, quitar easter egg) y reescribir
  el historial (claves + .env + basura + binarios flashbang); luego, en GitHub: rama-foto + cerrar PRs + aviso +
  force-push (necesita el token acotado de josemax y su OK).
- **Requisito:** norma de repositorio (§7) · R1 (todo en la cocina) · R2 (autoría por persona) · R8.
- **Evidencia:** (no aplica) — commit local; nada ha tocado GitHub. **Horas:** ~1 h.

### Fase 0 (4-oct) · Higiene del repositorio (LICENSE + limpieza)
- **Qué:** en el clon de trabajo, sobre `develop`: añadido `LICENSE` (MIT, titular «FeetLovers», decidido por
  josemax) + mención en el README; `<title>frontend</title>` → `HookSuite`; eliminados `README.md.txt`
  (placeholder), `infra/nginx.conf.txt` (resto muerto) y `frontend/src/mockData.js` (huérfano verificado: el
  código importa de `services/mockData`). Dos commits por autoría (R2): repo/infra → José María
  (`JoSeMhack`), frontend → Macarena.
- **Por qué:** el enunciado exige LICENSE al ser el repo público; el resto es limpieza de basura que afea el repo.
- **Qué se corrigió de la lista del 1-oct (R9):** `Dockerfile.txt` NO existe; no hay carpetas vacías (git no las
  versiona); el `README.md` real (2 KB) YA existía (lo recuperó GitHub). El README completo (instalación/uso/
  datos de acceso) queda pendiente: los datos de acceso dependen del login de la Fase 2.
- **Borrados:** confirmados explícitamente por josemax (el guardian los frenó, correcto). Reversibles (clon de
  trabajo; nada en GitHub).
- **Requisito:** norma de repositorio (§7) · R2 · R9.
- **Evidencia:** (no aplica) — commits locales. **Horas:** ~0,5 h.

### Fase 0 (4-oct) · Reescritura REAL del historial preparada y verificada (aún sin push)
- **Qué:** sobre un clon `--mirror` fresco de GitHub (`~/cocina/fase0-mirror.git`) con los 3 commits de Fase 0
  inyectados en `develop`, aplicado `git-filter-repo` con las reglas del ensayo: redactar `sk-ant-…` por patrón
  y eliminar `.env`/`ia/.env`/`devtools/.env`/`devtools/re`/`node_modules`/`venv`.
- **Verificado (R9):** claves reales en todo el historial **3 → 0**; `.env` rastreados y basura fuera;
  `.env.example` (clave redactada), PDF del informe (en main) y los binarios del flashbang **conservados**;
  7 ramas; `.git` 90→13 MB. Lo que queda con `sk-ant-` es solo un placeholder corto (`sk-ant-aqui-tu-key`).
- **Estado:** TODO listo para el force-push, pero **parado antes de cualquier push** (R8): falta OK de josemax,
  cerrar los 3 PRs, y crear la rama-foto de rescate. El token (classic PAT) ya está puesto y validado (fetch OK).
- **Requisito:** norma de repositorio (§7) · R8 · R9.
- **Evidencia:** `~/cocina/fase0-mirror.git` (historial reescrito, verificado); nada ha tocado GitHub. **Horas:** ~0,5 h.

### Fase 0 (4-oct) · Force-push a GitHub — 6/7 ramas limpias; main pendiente por protección
- **Qué:** cerrado el PR #3 por API y force-push de las ramas reescritas desde `fase0-mirror.git`.
  Entraron **6 ramas** (develop + feature/backend/devtools/ia/playwright, y feature/frontend que ya estaba
  limpia). **`main` rechazada por protección de rama** (GH006) → falta aflojarla.
- **Por qué:** limpiar los secretos del historial del repo público (enunciado §7). El token es el PAT de josemax.
- **Verificado (R6/R7):** 0 claves en las ramas pusheadas y en main reescrita (lista para subir). Evidencia de
  terminal como TEXTO en `evidencias/forcepush-fase0-04oct.md`, sin ningún valor de clave.
- **Punto de retorno (R8):** respaldo local del 3-oct (mirror completo), intacto; restaurable con push --mirror.
  Decidí NO crear rama-foto en GitHub para no reintroducir las claves (muertas) en el repo público.
- **Pendiente inmediato:** josemax (admin) afloja la protección de `main` → re-push de main → verificación
  final de 0 claves en GitHub → aviso al equipo (reclonar/reset) → revocar PAT + borrar credenciales/clones.
- **Requisito:** §7 norma de repositorio · R6 · R7 · R8.
- **Evidencia:** `evidencias/forcepush-fase0-04oct.md`. **Horas:** ~0,5 h.

### Fase 0 (4-oct) · Force-push COMPLETO — historial de GitHub limpio
- **Qué:** subida `main` (49414ec3→7154cca) tras aflojar la protección clásica (`allow_force_pushes`). Las 7
  ramas de GitHub quedan con el historial reescrito; **0 claves reales** verificado sobre un clon fresco.
- **Resultado:** el repositorio público ya no tiene secretos en su historial (enunciado §7 cumplido). Las claves
  estaban muertas; esto era la higiene obligatoria del historial.
- **Evidencia:** `evidencias/forcepush-fase0-04oct.md` (antes/después + verificación, como texto, sin claves).
- **Cabos abiertos:** josemax restaura la protección de main + revoca el PAT; Claude borra credenciales y clones
  de trabajo; el equipo recibe el aviso de reclonar; el respaldo del 3-oct se puede borrar ya (R8, validado).
- **Requisito:** §7 · R6 · R7 · R8. **Horas:** ~0,3 h.

### Fase 0 (4-oct) · Cierre de cabos + artefacto actualizado
- **Qué:** borrados los clones de trabajo (`fase0-trabajo`, `fase0-mirror.git`, `verif-final.git`,
  `ensayo-limpieza.git`), la caja extraída y `~/.git-credentials`; josemax revocó el PAT y restauró la
  protección de `main`. Verificado: en `cocina/` solo queda `Proyecto-Evolve`; cocina arriba; respaldo intacto.
- **Artefacto (R4):** actualizado el apartado 7 (de «reescritura ensayada / pendiente» a «LIMPIEZA EJECUTADA Y
  VERIFICADA»: 0 claves en GitHub) y republicado en la URL fija. El diario (almacén) NO sale en el artefacto (R3).
- **Requisito:** §7 · R3 · R4 · R8.
- **Evidencia:** (no aplica) — cierre de cabos; evidencia del push en `evidencias/forcepush-fase0-04oct.md`. **Horas:** ~0,3 h.

### Refuerzo de proceso (4-oct): memoria técnica sobre la marcha + capturas anticipadas
- **Qué:** josemax pidió reforzar el tratamiento de la memoria. Plasmado: R3 y R6 del PROTOCOLO-TRABAJO.md
  reforzados (memoria técnica se mantiene viva sobre la marcha igual que el diario; capturas de pantalla se
  anticipan al proponer). Guardado también como feedback en la memoria persistente de Claude.
- **Aplicado en el acto:** apartado 5 actualizado con la migración del frontend a Tailwind (cambio respecto a
  la P1) que estaba sin reflejar; artefacto regenerado y republicado.
- **Requisito:** R3 · R4 · R6. **Evidencia:** (no aplica). **Horas:** ~0,3 h.

### Refuerzo de proceso (4-oct): flujo GitHub documentado + commit sobre la marcha
- **Qué:** creado `lineas/practica3-hooksuite/FLUJO-GITHUB.md` (cómo proceder con el repo: flujo de un cambio,
  autoría por parcela, auth por PAT temporal, protección de `main`, resync tras force-push, despliegue) con los
  huecos de decisión marcados. Reforzado R2 del protocolo con «commit sobre la marcha». Memoria persistente
  de Claude ampliada: la comprobación tras cada acción incluye ahora el commit.
- **Hallazgo (R9):** la cocina es un clon desfasado (`main` viejo) y la memoria técnica lleva toda la sesión
  sin commitear → pendiente: resincronizar la cocina al GitHub nuevo (preservando lo untracked) y commitear la
  memoria a nombre de José María; el push necesitará un PAT temporal nuevo.
- **Requisito:** R2 · R9. **Evidencia:** (no aplica). **Horas:** ~0,4 h.

### Fase 0 (4-oct) · Resync de la cocina + memoria técnica commiteada
- **Qué:** resincronizada la cocina al `develop` nuevo (`checkout -B develop origin/develop`; la memoria
  untracked sobrevivió y estaba preservada). Commiteada la memoria técnica a `develop` a nombre de José María
  (commit `68cc888b`): fuentes `.typ` + `tools/typ2html.py` + diario + PDF + capturas de exposición. El
  artefacto HTML queda fuera (derivado, se publica en claude.ai).
- **Por qué:** primer caso del «commit sobre la marcha» y del «resync» del `FLUJO-GITHUB.md`; la memoria técnica
  llevaba la sesión sin commitear y la cocina estaba en el `main` viejo (pre-reescritura).
- **Falta:** `git push origin develop` — necesita un PAT temporal nuevo de josemax (develop no está protegida).
- **Requisito:** R2 · R4 · FLUJO-GITHUB.md. **Evidencia:** (no aplica). **Horas:** ~0,3 h.

### Fase 0 (4-oct) · Memoria técnica empujada a develop + cabo cerrado
- **Qué:** `git push origin develop` del commit `68cc888b` (memoria técnica). Verificado en GitHub: develop =
  68cc888b con las fuentes `.typ`, `typ2html.py`, diario, PDF y las 5 capturas. Credencial `~/.git-credentials`
  borrada tras el push.
- **Pendiente [humano]:** josemax revoca el PAT temporal nuevo en GitHub.
- **Requisito:** R2 · R7 · FLUJO-GITHUB.md. **Evidencia:** (no aplica). **Horas:** ~0,2 h.

### Fase 1 (4-oct) · Evidencia del bug del Spider (trampa de araña + SSRF), ANTES de arreglar
- **Qué:** capturada como texto la lógica defectuosa de `spider_service.py` (normalize_url no decodifica `&amp;`
  ni ordena la query → trampa de araña; is_same_domain acepta destinos internos → SSRF). `evidencias/spider-trampa-ssrf-04oct.md`.
- **Por qué:** R6 — la evidencia del fallo se captura antes de arreglarlo (el arreglo la destruye). Hecho de
  forma ética (RNF-07): demostración unitaria, sin lanzar el Spider contra nadie.
- **Requisito:** RF-03 (Spider) · RNF-07 (SSRF). **Evidencia:** `evidencias/spider-trampa-ssrf-04oct.md`. **Horas:** ~0,2 h.

### Fase 1 (4-oct) · Spider ARREGLADO (trampa de araña + SSRF) — commit 28b356d8
- **Qué:** `normalize_url` canonicaliza (decodifica `&amp;`, ordena query, quita fragmento) → el mismo recurso
  da UNA URL; `is_same_domain` bloquea metadata de cloud/loopback/0.0.0.0 (SSRF), permite privadas (lab).
- **Verificado (DESPUÉS):** las variantes colapsan a `?id=1&page=2`; 127.0.0.1/169.254.169.254/localhost → False,
  dvwa → True. Probado copiando el fichero al contenedor en caliente (sin rebuild), sin lanzar el Spider (RNF-07).
- **Decisión (SSRF para herramienta final):** bloquear solo lo catastrófico (metadata/loopback/0.0.0.0), no las
  privadas — una herramienta ofensiva audita redes internas legítimamente; el abuso externo lo corta la auth.
  El «modo configurable» queda como trabajo futuro (apartado 10).
- **Commit:** `28b356d8` a nombre de Macarena (backend), local; push por lotes al cerrar la Fase 1.
- **Requisito:** RF-03 · RNF-07. **Evidencia:** `evidencias/spider-trampa-ssrf-04oct.md` (antes/después). **Horas:** ~0,6 h.

### Fase 1 (4-oct) · 500 del proxy ARREGLADO — commit 54bf4243
- **Qué:** `return {{...}}` en `proxy.py` (líneas 26, 31) construía un set de un dict (unhashable) → 500 en
  `/api/proxy/check/alive` y `/forward`. Cambiados a dicts normales.
- **Evidencia ANTES:** `GET /api/proxy/check/alive` → HTTP 500 (capturado). `evidencias/proxy-500-check-alive-04oct.md`.
- **Endpoint duplicado:** `/check/alive` está en main.py (raíz, correcto) y en proxy.py (router, era el roto).
  Se deja el de main.py (inofensivo); limpiarlo es cosmético.
- **Commit:** `54bf4243` (Macarena), local. Verificación end-to-end (200) en el pase de arranque al cerrar la Fase 1.
- **Requisito:** RF-02. **Horas:** ~0,3 h.

### Fase 1 (4-oct) · Parser curl ARREGLADO — commit d0d31beb (Ivan)
- **Qué:** la regex del parser curl (`repeater.py`) tenía doble backslash (`\\s`) → excluía la letra `s`
  literal, no los espacios. `https://` se capturaba como `http`. Reescrita para extraer la URL por su esquema
  (`https?://[^\s'\"]+`), robusta frente a flags (`-X POST`, `-d`). Evidencia antes/después: `evidencias/curl-parser-04oct.md`.
- **Autoría:** Ivan (reparto equilibrado del plan; todos participan en todas las fases).
- **Requisito:** RF-05. **Horas:** ~0,2 h.

### Fase 1 (4-oct) · Reatribución de commits según el plan-p3
- josemax recordó que el reparto NO sigue el rol de la P1 (plan-p3: todos participan en todas las fases).
  Reatribuidos los commits locales: Spider → **Nacho** (`c7293957`), 500 proxy → **Macarena** (`c207a256`).
  Identidades git reales documentadas en `FLUJO-GITHUB.md`. Los commits de Fase 0 ya pusheados no se reescriben.

### Fase 1 (4-oct) · firewall_agent.py ENDURECIDO — commit becbcf69 (Nacho)
- **Qué:** el socket `/tmp/firewall.sock` se creaba con `0o777` (world-writable → escalada: cualquier proceso
  del host/contenedor manipulaba el firewall) y pasaba `ip`/`port` a `iptables` sin validar. Fix: socket `0o660`,
  puerto validado (1-65535) e IP de host única (ipaddress, sin rangos); malformado → ERROR.
- **Verificado:** validación probada aislada (`'80; rm'`, `99999`, `'0.0.0.0/0'`, `'-j DROP'` → rechazados).
  `evidencias/firewall-agent-04oct.md`.
- **Nota:** el agente corre en el host de la caja (RNF-08); el impacto runtime del cambio de permisos del socket
  se valida al desplegar (verificar que backend↔agente siguen comunicando). Reglas iptables huérfanas: pendiente.
- **Autoría:** Nacho. **Requisito:** RNF-07 · RNF-08. **Horas:** ~0,3 h.

### Fase 1 (5-oct) · Intruder `cancel()` ARREGLADO — commit 479bec43 (Carlos)
- **Qué:** `POST /api/intruder/cancel/{token}` devolvía 500. La ruta (`routes/intruder.py:38`) llamaba a
  `intruder_engine.cancel()`, método que `IntruderEngine` no tenía (solo `pause`/`resume`). Añadido `cancel()`
  simétrico a `pause()`: marca la sesión como `cancelled`; el bucle de payloads ya corta lo que no esté
  `running` (`intruder_service.py:43`), así que los pendientes abortan y la corrida no se marca `complete`.
- **Por qué (R6):** evidencia del 500 capturada antes de arreglar (traceback `AttributeError`), prueba
  ética (RNF-07): la llamada de cancel no ataca a nadie, solo invocaba un método ausente.
- **Verificado:** importación fresca en el contenedor → `cancel()` existe, deja `intruder_status='cancelled'`
  sin error. El `200` real por HTTP va en el pase end-to-end (requiere reiniciar backend; imagen sin reload).
- **Autoría:** Carlos (reparto equilibrado; participa en Fase 1). **Requisito:** RF-06 · RNF-07. **Horas:** ~0,3 h.
- **Evidencia:** `evidencias/intruder-spider-async-05oct.md`.

### Fase 1 (5-oct) · Spider `stop` ahora detiene el crawl — commit fa7aab61 (Nacho)
- **Qué:** `POST /api/spider/stop/{token}` ponía `spider_running=False` (`routes/spider.py:53`) pero
  `SpiderService.run()` nunca leía esa bandera → el crawl seguía hasta agotar la cola o el máximo. Ahora
  `run()` consulta `spider_running` en cada iteración y rompe; el evento `spider_completed` distingue
  «detenido manualmente» de «límite»/«completado».
- **Por qué (R6/RNF-07):** reproducción unitaria con `crawl_page` stubbeado → ni una petición de red; se
  demuestra el fallo (sigue de 3 a 20 páginas tras el stop) y el arreglo (3 → 3) sin lanzar el Spider.
- **Descartado:** comprobar la bandera dentro de `crawl_page` además del bucle — redundante; el bucle es
  secuencial (una página cada ~0,3-0,8 s), así que el corte en la siguiente iteración ya es responsivo.
- **Autoría:** Nacho (dueño de `spider_service.py`, coherencia con su fix de canonicalización/SSRF).
- **Requisito:** RF-03 · RNF-07. **Horas:** ~0,3 h. **Evidencia:** `evidencias/intruder-spider-async-05oct.md`.

### Fase 1 (5-oct) · Pase end-to-end completo sobre imagen reconstruida
- **Qué:** tras `docker compose up -d --build backend`, verificados por HTTP los 5 arreglos de Fase 1:
  Intruder `cancel` 500→**200** `{cancelled}`, proxy `check/alive` 500→**200**, proxy `/forward` 500→**200**
  (reenvía a web propia autorizada, 39 KB), Spider `stop` **200**, parser `curl` **200** con URL `https` correcta.
- **Por qué (lección):** un `restart` previo dio un end-to-end FALSO — recarga solo la capa de escritura del
  contenedor, no la imagen. Intruder cancel iba a 200 (fichero copiado hoy) pero proxy seguía 500 porque la
  imagen aún tenía `{{...}}`. **Verificar end-to-end exige rebuild, no restart.**
- **Push:** los 8 commits (Fase 0 + 5 bugs Fase 1 + higiene pycache) subidos a `origin/develop` (b4b4cc8c).
- **Requisito:** RF-02/03/04/05/06 · RNF-07. **Evidencia:** `evidencias/pase-e2e-fase1-05oct.md`. **Horas:** ~0,4 h.

### Fase 1 (5-oct) · Cerrados los puertos directos + laboratorio solo interno — commits abf5c0aa / (Ivan, Carlos)
- **Qué:** el backend y el frontend se publicaban al exterior (API sin auth en su puerto; SPA saltando el
  proxy). El frontend horneaba la IP:8000 del host y hablaba directo con el backend. Arreglado: `API_BASE` y
  el WebSocket a **mismo origen** (vía el proxy inverso ya existente), IP fuera del Dockerfile, y retirados los
  `ports` de backend y frontend del compose → **solo el proxy publica**. Además, el laboratorio vulnerable se
  retira del proxy: queda **solo en la red interna**.
- **Por qué:** quitar la exposición directa (bypass del proxy) y unificar la entrada. `ia`/`playwright` hablan
  con el backend por la red interna, no les afecta.
- **Verificado (R6):** antes puertos directos a 200 sin auth; después **conexión rechazada** en ambos, y todo
  funciona por el proxy (`/api` 200, WebSocket 101, bundle sin la IP:8000). Evidencia: `evidencias/cierre-puertos-05oct.md`.
- **Pendiente Fase 2:** `/api` y `/ws` aún sin autenticación (hoy accesibles por el proxy sin credencial) → lo
  trae el login nuevo. El cierre de hoy es de **exposición**, no de auth.
- **Autoría:** Ivan (cierre de puertos / same-origin), Carlos (laboratorio interno). **Horas:** ~0,9 h.
