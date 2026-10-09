# Un tramo de trabajo desaparecido del contexto, y el rastro que sí quedó — 9-oct-2026

> Evidencia de terminal capturada como **texto** (R3) a las ~09:05 del 9-oct, desde la propia sesión
> afectada. No contiene ningún valor de clave (R7).

## Qué pasó, en una línea

La salvaguarda de seguridad del modelo se disparó, josemax eligió en el menú la opción de **volver a un
mensaje anterior**, y el contexto de Claude **perdió el tramo 08:40–08:48:49** — en el que se había
trabajado la Fase 3 (RF-08) y se había **construido una imagen Docker**. El trabajo desapareció de la
conversación, pero **el cambio en el servidor se quedó hecho**, sin registrar en ninguna memoria.

Lo cazó el **CERCO 2** (hook `Stop`, `cerco-memoria.sh`) a las 09:01, señalando el comando exacto.

## Lo que el log de la sesión registra y el contexto de Claude NO tenía

Sesión `5265e13b-f0ae-4723-9e62-5b846f64c48e`, log `bitacora/2026-10-09-0832.log` (arranque 08:32:32).
Tramo ausente del contexto:

```
[2026-10-09 08:40:14] COMANDO | cat lineas/practica3-hooksuite/PROTOCOLO-TRABAJO.md
[2026-10-09 08:40:15] COMANDO | bin/cerco.sh practica3-hooksuite 2>&1 | tail -60
[2026-10-09 08:40:35] COMANDO | cat lineas/practica3-hooksuite/PLAN-RF08-MODULO-IA.md
[2026-10-09 08:40:40] COMANDO | (6 líneas, 596 chars)
[2026-10-09 08:41:37] COMANDO | (5 líneas, 556 chars)
[2026-10-09 08:46:16] COMANDO | (4 líneas, 446 chars)
[2026-10-09 08:47:31] COMANDO | cd /home/josemax/cocina/Proyecto-Evolve && docker compose build ia 2>&1 | tail -25
[2026-10-09 08:47:33] RESULTADO Bash | (sin salida)
[2026-10-09 08:47:34] COMANDO | (4 líneas, 350 chars)
    cd /home/josemax/cocina/Proyecto-Evolve
    echo "=== client.py actual (el que se reescribe) ==="; cat -n ia/client.py 2>/dev/null
    echo; echo "=== orchestrator.py:265-275 (el bug de justificacion) ==="; sed -n '265,275p' ia/orchestrator.py
    echo; echo "=== vulnerability_classifier.py cabecera ==="; sed -n '1,30p' ia/analyzers/vulnerability_classifier.py
[2026-10-09 08:48:32] COMANDO | (4 líneas, 220 chars)
[2026-10-09 08:48:49] COMANDO | (3 líneas, 292 chars)
```

Después, silencio hasta las **09:00:45**, que es ya la sesión rebobinada.

**Dato clave:** el rótulo *«client.py actual (el que se reescribe)»* dice que ese tramo **iba a reescribir**
`ia/client.py` (el pendiente de subir el modelo a Claude 5). Se quedó en la intención.

## Qué dejó hecho de verdad — verificado en vivo, no supuesto (R9)

| Comprobación | Resultado | Lectura |
|---|---|---|
| `docker images` | `proyecto-evolve-ia:latest` — **creada 2026-10-09 08:48:03**, 719 MB | ✅ el build **SÍ se ejecutó** |
| `docker ps -a` | **no existe contenedor `ia`** | solo imagen; nada arrancado |
| `git status --porcelain` (cocina) | **vacío** | ✅ **no quedó ningún cambio a medias en disco** |
| `ia/client.py` | mtime **04-oct 10:24:20**; `MODEL = "claude-sonnet-4-20250514"` | ❌ la reescritura **NO se aplicó** |
| `git log -1` | `335eb27e` — **8-oct 15:58** | no hubo commits hoy |
| `origin/develop...HEAD` | `88f8d99e`, **8 commits por empujar** | sin cambios hoy |
| `docs/informe/diario.md` | mtime **08-oct 15:57:31** | ❌ el build **no estaba en el diario** (R3 roto por el corte) |

**Saldo:** el único rastro material es una imagen Docker de 719 MB. No hay código tocado, ni contenedor
levantado, ni commit, ni gasto de API (no se llegó a ejecutar nada contra Anthropic). `/` sigue al 71 %, así
que los 719 MB no aprietan.

## Por qué esto importa más allá del incidente

1. **La reescritura de `client.py` no está hecha.** Si alguien lee «se construyó la imagen `ia`» y asume que
   el módulo quedó al día, se equivoca: la imagen se construyó **con el código viejo** (`claude-sonnet-4`).
2. **El motivo exacto de ese tramo no consta y no se va a inventar** (R9). Lo que se puede afirmar es qué
   ficheros miró y qué construyó; **por qué** en ese orden, se perdió con el contexto.
3. **El CERCO 2 se ganó el sueldo.** Una hora antes, en esta misma sesión, ese mismo cerco había dado dos
   falsos positivos y Claude había propuesto **aflojarlo**. Acto seguido cazó la única mutación real del día,
   que además nadie habría registrado porque quien la hizo perdió la memoria de haberla hecho. Cualquier
   arreglo del cerco tiene que seguir cazando esto.

---

## ⚠️ CORRECCIÓN DECLARADA (9-oct, 09:30) — este documento contaba mal el mecanismo

Lo de arriba dice que «la salvaguarda se disparó y josemax eligió en el menú de pausa volver a un mensaje
anterior». **Eso es inexacto y se corrige en vez de reescribirse (R9).** Con las cinco capturas que sacó
josemax en el momento delante:

- La salvaguarda **no ofrece menú**: devuelve un **error de API** («*Opus 5's safeguards flagged this
  message … Claude Code can't respond to this message with Opus 5*») y sugiere editar el último mensaje
  o cambiar de modelo. Confirma además que `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` **funciona**: no hubo
  cambio automático a Opus 4.8.
- El **Rewind es otra función de Claude Code** (doble `Esc`) que josemax abrió para desatascarse, con
  **cuatro** opciones. Eligió la 1 (`Restore conversation`), que descarta lo posterior. Las opciones 2 y 3
  habrían conservado el trabajo.
- Y el dato que más importa: el turno del build figuraba en el Rewind como **«No code changes»**, porque
  **cuenta ficheros, no efectos en el servidor**.

**Transcripción completa de las capturas y qué hacer la próxima vez:**
`salvaguarda-y-rebobinado-09oct.md` (en el repo: `evidencias/salvaguarda-y-rebobinado-09oct.md`).
