# Evidencia · ENSAYO de reescritura del historial (en la cocina, NADA tocó GitHub)

- **Tomada:** 2026-10-04 por Claude, Fase 0 en la cocina.
- **Dónde:** clon `--mirror` FRESCO de ensayo en `/home/josemax/cocina/ensayo-limpieza.git` (no es el stack que
  corre, ni el `--mirror` del respaldo, que es la red de seguridad y no se toca).
- **Qué NO se hizo:** ni un push, ni un fetch de escritura. `git-filter-repo` **quita el remote `origin`** por
  diseño → es imposible empujar por accidente desde este clon. El estado de GitHub quedó **idéntico**
  (7 heads sin cambios respecto al manifiesto del 3-oct).
- **Objetivo:** demostrar que la limpieza deja el historial **sin ninguna clave** y sin basura, conservando
  todo el código y las 7 ramas, ANTES de ejecutarla de verdad en GitHub.

## Herramienta
`git-filter-repo` (script único en `~/.local/bin`, sin sudo). Es la herramienta recomendada por GitHub para
reescribir historial (sucesora de `filter-branch`/BFG).

## Alcance (inventariado sobre el mirror fresco, R9)
- **3 blobs** con clave `sk-ant-` en el historial (en `ia/.env`, `ia/.env.example`, `.env.example` raíz).
- **`.env` rastreados** a eliminar: `ia/.env`, `devtools/.env`, `.env` (raíz). Los `.example` se CONSERVAN.
- **Basura grande (~71 MB):** `node_modules/`, `frontend/node_modules/`, `venv/` (binarios de Windows `.pyd`),
  y `devtools/re` (un PostScript de 10 MB). El PDF del informe (`docs/informe/informe_hooksuite.pdf`, 6,4 MB)
  **se conserva**.

## Procedimiento exacto (reproducible en la ejecución real)
Regla de redacción por PATRÓN (no contiene ninguna clave real; redacta cualquier `sk-ant-…` del historial):
```
regex:sk-ant-[A-Za-z0-9_-]{20,}==>***CLAVE-ANTHROPIC-ELIMINADA***
```
Comando (sobre un `--mirror` fresco):
```
git-filter-repo --force \
  --replace-text replace-rules.txt \
  --invert-paths \
  --path .env --path ia/.env --path devtools/.env \
  --path devtools/re \
  --path node_modules --path frontend/node_modules --path venv
```

## Resultado verificado (antes → después)
| Comprobación | Antes | Después |
|---|---|---|
| Claves `sk-ant-` en TODO el historial | 3 | **0** |
| `ia/.env` · `devtools/.env` · `node_modules` · `venv` · `devtools/re` | presentes | **0 (eliminados)** |
| `ia/.env.example` · `.env.example` · PDF del informe | presentes | **conservados** |
| Clave de `.env.example` | visible | **redactada** (`***CLAVE-ANTHROPIC-ELIMINADA***`) |
| Código fuente (backend 27 · frontend/src 37 · ia 13 · playwright 77 · devtools 14 · infra 2 · docs 81) | — | **idéntico, fichero a fichero** |
| Ramas | 7 | **7 intactas** |
| Tamaño `.git` | 90 MB | **19 MB** |

## Avisos para la ejecución REAL en GitHub (cuando haya fecha con el grupo)
1. **El force-push necesita fecha acordada** (R2/R8) y afecta al repo compartido de los cinco → no se hace sin
   OK de josemax y aviso al grupo. Tras él, cada uno reclona o hace `reset --hard`.
2. **refs/pull/* **: GitHub mantiene 4 refs de PR (`pull/1..3`) que **no se reescriben con un push normal**
   (los deriva GitHub de los PRs). Quedarán apuntando a commits viejos con las claves hasta que esos PRs se
   cierren/rehagan. A decidir con el grupo: cerrar los PRs viejos antes del force-push. *(En el ensayo local el
   mirror sí reescribe esos refs; en GitHub real no basta un push.)*
3. **Las claves ya están muertas** (verificado 4-oct), así que esto es higiene exigida por el enunciado (§7),
   no contención de una fuga activa.
4. El punto de retorno (`«ruta-del-respaldo»/`) se borra **solo** tras validar que la
   limpieza en GitHub quedó bien (cerco R8).

## Lo que ESTE ensayo NO cubre (queda para la Fase 0 con el equipo)
- **Reconciliar los 32 ficheros divergentes** de la caja (viven en el tarball del respaldo, no en git) →
  commits a nombre de las personas (R2), trabajo con el grupo.
- **Higiene de repo** (README, LICENSE MIT, borrar configs muertas): en `main` el README ya es real y no hay
  `Dockerfile.txt`/`nginx.conf.txt` (esos estaban en lo desplegado/develop) → revisar por rama al reconciliar.
