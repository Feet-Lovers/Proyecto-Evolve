# RNF-06: el estado degradado no llega al panel porque nadie lo consume

**Fecha:** 2026-10-09, 17:36-17:40 · **Capturado por:** Claude (salida de terminal, como texto, R3)
**Contexto:** destilado del 2º rescate del día. El pendiente vigente decía que lo que impedía ver RNF-06
en el panel era el defecto (b) del orquestador. Esta evidencia demuestra que (b) estaba cerrado y que el
bloqueo real es otro.

## 1. El defecto (b) ya estaba arreglado (4 h antes de que la memoria dijera lo contrario)

```
$ git log -1 --format='%h %ad %an %s' --date=iso ea317969
ea317969 2026-10-09 13:03:46 +0200 JoSeMhack fix(rnf-06): el orquestador anulaba el umbral de confianza y habria tapado el estado degradado

$ git show --stat --format='' ea317969
 docs/evidencias/rf08-filtro-confianza-09oct.md | 44 ++++++++++++++++++++++++++
 docs/informe/diario.md                         | 28 ++++++++++++++++
 ia/orchestrator.py                             | 17 ++++++++--
 3 files changed, 87 insertions(+), 2 deletions(-)
```

Estado del fichero hoy, medido **sin volcarlo** (protocolo de contexto limpio, regla 2):

```
$ wc -l ia/orchestrator.py
348 ia/orchestrator.py

$ grep -c 'CONFIDENCE_THRESHOLD' ia/orchestrator.py
2
$ grep -n 'CONFIDENCE_THRESHOLD' ia/orchestrator.py | cut -d: -f1
10 234

$ grep -c '0\.6' ia/orchestrator.py
1
$ grep -n '0\.6' ia/orchestrator.py | cut -d: -f1
226

$ git status --short ia/orchestrator.py
(sin salida -> ningun cambio sin commitear)
```

Lectura: el umbral se **importa** (línea 10) y se **usa** (línea 234); la única mención restante de `0.6`
está en la 226 y es el comentario que explica el defecto corregido. Árbol limpio: no hubo ninguna edición
perdida que explicara el código, solo el commit de las 13:03.

## 2. El bloqueo real: no hay consumidor del estado degradado

```
$ grep -rc 'no_analizado' frontend/src backend
(ninguna coincidencia: 0 en los dos arboles)

$ grep -rl 'no_analizado' --include='*.py' --include='*.jsx' --include='*.js' .
ia/analyzers/vulnerability_classifier.py
ia/orchestrator.py
ia/tests/test_tres_estados.py
```

Lectura: el estado degradado se **calcula** (clasificador), **sobrevive al filtro** (orquestador) y se
**publica** (`save_results` → `no_analizados` y `no_analizados_detalle`), pero **ningún consumidor lo lee**:
cero menciones en `frontend/src` y en `backend`. RNF-06 está cumplido **dentro del módulo de IA** y lo que
falta es el tramo **IA → backend → panel**.

## 3. El tramo de sesión perdido no dejó efectos en el servidor

```
$ find . -newermt '2026-10-09 17:19' -not -path './.git/*' -type f
(sin salida)

$ git rev-parse --short HEAD
952f0cba

$ git ls-remote origin refs/heads/develop
88f8d99e79936a8e1b79e4f2e92928893bfc285b	refs/heads/develop

$ git rev-list --count origin/develop..HEAD
21
```

Lectura: nada se tocó en la cocina después del último commit (17:18). El estado de git se leyó de la fuente
real con `git ls-remote` (R9), no de refs locales.

## Qué prueba y qué no

- **Prueba** que (b) está cerrado y que la memoria lo contradecía en cuatro sitios a la vez.
- **Prueba** que nadie consume `no_analizados`, por conteo sobre los dos árboles completos.
- **No prueba** cómo debe pintarse ese estado en la interfaz: es una decisión de producto, abierta.
- **No prueba** que la API acepte los esquemas generados: sigue sin clave válida.
