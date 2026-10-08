# Evidencia · Force-push de la Fase 0 (limpieza del historial) — 2026-10-04

Ejecutado por Claude con el PAT de josemax (classic, en `~/.git-credentials`, valor nunca expuesto, R7).
Origen: `~/cocina/fase0-mirror.git` (historial reescrito con git-filter-repo; 0 claves verificado).
Captura de terminal como TEXTO (R6). Sin ningún valor de clave (R7).

## PR cerrado antes del push
- #3 `feature/devtools -> main` → **closed** por API. (#1 y #2 ya estaban cerrados/merged.)

## Estado ANTES → DESPUÉS (SHAs)
| Rama | ANTES (con secretos) | DESPUÉS (reescrita) | En GitHub |
|---|---|---|---|
| develop            | 7af4f252 | 694c333 | ✅ pusheada |
| feature/backend    | d6a18786 | 33f1a31 | ✅ pusheada |
| feature/devtools   | 59c14226 | bb740e4 | ✅ pusheada |
| feature/ia         | 0428bd14 | c1f1546 | ✅ pusheada |
| feature/playwright | 4faf534f | 902470f | ✅ pusheada |
| feature/frontend   | 6e33c592 | 6e33c592 | ✅ (su historia no tenía secretos → hash sin cambiar, 0 claves verificado) |
| main               | 49414ec3 | 7154cca | ⏳ **PENDIENTE: rama protegida (GH006), falta aflojar la protección** |

## Verificación de claves (blobs con `sk-ant-` real)
- feature/frontend: **0** · main reescrita: **0** · historial global del mirror: **3 → 0**.
- Lo único que queda con el prefijo `sk-ant-` es un placeholder corto de ejemplo (no es un secreto).

## Salvedad (refs de PR)
- GitHub conserva `refs/pull/1..3/head` apuntando a commits viejos; son de solo lectura y los purga con el
  tiempo. Las claves están MUERTAS (verificado 4-oct) → higiene formal, sin riesgo real.

## Punto de retorno (R8)
- `«ruta-del-respaldo»/github-mirror.git` (estado viejo completo; restaurable con
  `git push --mirror`). NO se borra hasta validar que la limpieza en GitHub quedó completa (incluida main).

## CIERRE (main subida, verificación final) — 2026-10-04
- `main`: 49414ec3 → **7154cca** (forced update OK, tras aflojar `allow_force_pushes` en la protección clásica).
- Las **7 ramas** en GitHub coinciden con las reescritas.
- **0 blobs con clave real** en todo el historial de `refs/heads` de GitHub (clon `--mirror` fresco + escaneo).
- ✅ **LIMPIEZA DEL HISTORIAL COMPLETA.** Queda la higiene formal de los refs `pull/*` (los purga GitHub; claves muertas).
