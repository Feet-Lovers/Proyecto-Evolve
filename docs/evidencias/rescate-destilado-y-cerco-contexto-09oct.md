# Evidencia · 2026-10-09 (tarde) · Destilado del primer rescate: dos fallos del cerco de contexto y una vía de análisis muerta

Salida de terminal capturada **como texto** (R3, R7: ningún valor de clave sale por pantalla).
Contexto: la salvaguarda del modelo partió la sesión de tarde; se recuperó con `/rescate` + `/destilar`.

---

## 1. Verificación de que el servidor NO fue por delante de la conversación

El rebobinado del 9-oct por la mañana dejó una imagen Docker de 719 MB que el Rewind listaba como «sin
cambios de código». Por eso el destilado **verifica en vivo** cada efecto, en vez de creerse el borrador.

```
$ find /home/josemax/cocina/Proyecto-Evolve -newermt "2026-10-09 13:20" -type f \
       -not -path "*/.git/*" -not -path "*/node_modules/*"
--- fin cocina ---          (sin resultados)

$ find /home/josemax/claude-workspace -newermt "2026-10-09 13:20" -type f -not -path "*/bitacora/*"
/home/josemax/claude-workspace/memoria/BORRADOR-RESCATE.md
--- fin workspace ---       (solo el propio borrador del rescate)
```

Imagen más reciente, sin novedad respecto al cierre de las 13:20:

```
$ docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}} {{.Size}}' | head -3
proyecto-evolve-ia:latest        2026-10-09 08:48:03 +0200 CEST  719MB
proyecto-evolve-frontend:latest  2026-10-08 10:23:50 +0200 CEST  94.4MB
proyecto-evolve-backend:latest   2026-10-06 19:45:38 +0200 CEST  955MB
```

Contenedores: **14**, los mismos (9 del servidor + 5 de la cocina); sigue sin existir contenedor `ia`.

Git leído de la **fuente real** y no de refs locales (R9):

```
$ git ls-remote origin develop main
88f8d99e79936a8e1b79e4f2e92928893bfc285b   refs/heads/develop
3d3baba88720096dcaa71b81862a0d47b87eb332   refs/heads/main

$ git status --porcelain=v1 -b
## develop...origin/develop [ahead 15]
?? docker-compose.yml.bak-20261009-122912
?? docs/informe/P3-memoria.typ.bak-20261009-123124
```

**Conclusión: 15 commits sin empujar, ni uno más que a las 13:20. La sesión de tarde fue de solo lectura.**
El único efecto del incidente fue en el **contexto** de la conversación, no en el servidor.

---

## 2. Fallo nº 1 del hook `contexto-limpio.sh` — falso NEGATIVO (mecanismo, no inventario)

Leído **en el código del hook**, no deducido del comportamiento:

```
$ grep -n "grep -qF\|continue" .claude/hooks/contexto-limpio.sh
62:    if printf '%s' "$t" | grep -qF -- "$p"; then printf '%s' "$p"; return 0; fi
108:  if [ -z "$SEG_PATRON" ] && [ "$HAY_CD" = "0" ]; then continue; fi
```

La detección es una comparación de **cadena fija contra el texto crudo del comando**. Si ninguna ruta de
`.claude/sensibles.txt` aparece escrita en el comando y este no lleva `cd`, el segmento **se salta**.

**Consecuencia, ocurrida de verdad en la sesión de tarde:** un `grep -rn <patrón> --include=*.py .` lanzado
desde un directorio padre no nombra el fichero —la ruta la resuelve el `-r`—, así que **pasó el hook** e
imprimió 4 líneas de un fichero de la lista, que entraron en el contexto. El comando siguiente, que **sí**
nombraba el fichero, fue **bloqueado correctamente** por el mismo hook.

🔵 **Es un fallo distinto del que se cerró a las 12:58**, que era de *inventario* (faltaban los cuatro
ficheros de prompts en la lista). Este es del *mecanismo*: **ampliar la lista no lo arregla.**

## 3. Fallo nº 2 del mismo hook — falso POSITIVO, cazado durante este destilado

```
🔒 CONTEXTO LIMPIO — bloqueado: 'bitacora/' está en .claude/sensibles.txt.
   'grep' sin -c/-l/-L/-q imprime las líneas que casan.
```

El comando bloqueado era de **solo lectura** y usaba la cadena para **excluir** la bitácora del listado
(`find … | grep -v '^./bitacora/'`). Misma raíz que el nº 2: se mira texto crudo sin distinguir lo que un
comando **lee** de lo que **filtra o rotula**. Se resolvió sin insistir con un equivalente (regla 5),
reformulando con `find -not -path`.

---

## 4. Hallazgo del producto: dos de las cuatro vías de análisis no tienen llamador

```
$ grep -rl "analyze_intruder\|analyze_console" --include=*.py .
ia/analyzers/vulnerability_classifier.py

$ grep -rl "analyze_intruder\|analyze_console" .
ia/analyzers/vulnerability_classifier.py
docs/manual_ia.md
docs/evidencias/rf08-paso1-cliente-y-techo-09oct.md
docs/informe/diario.md

$ grep -n "classifier\." ia/orchestrator.py
158:            analysis = self.classifier.fingerprint(
222:                analysis = self.classifier.analyze_packet(fake_packet)
```

Los dos métodos solo aparecen donde se definen y en tres documentos: **en código, cero llamadas**.
El orquestador invoca únicamente `fingerprint` y `analyze_packet`.

**Por qué importa:** el umbral de confianza de RNF-06 está aplicado en `analyze_packet` **y en
`analyze_intruder`**; esa segunda mitad es **código muerto hoy**. La prueba de RNF-06 que pide el apartado 8
(apagar la clave y capturar «no analizado») **tiene que recorrer `analyze_packet` o `fingerprint`**.

**No falsea la memoria técnica:** `P3-memoria.typ:490` sitúa el techo en el cliente «por donde pasan las
cuatro vías de análisis». Es una afirmación sobre por dónde **pasan** —cierta— y no sobre que las cuatro se
**invoquen**. Se leyó antes de decidir no tocarla (R9).

---

## Nota de método

Todo lo de arriba se obtuvo **sin volcar** ningún fichero de la lista de rutas sensibles: `find`, `wc -l`,
`grep -c`, `grep -rl` (solo nombres) y `bin/estructura.sh`. El apartado 3 de RF-08 sigue **bloqueado
esperando el visto bueno de josemax** para leer el clasificador, o que dicte él los cambios.
