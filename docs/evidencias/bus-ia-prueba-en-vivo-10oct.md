# Prueba en vivo del bus IA↔backend — 10-oct-2026, 12:26–12:33

Medido tras el corte de la sesión por la salvaguarda. **Todo son recuentos, no volcados**: el stdout del
contenedor `ia` es la salida en ejecución del orquestador (fichero protegido en `.claude/sensibles.txt`), y
leerlo fue justamente lo que disparó el clasificador. Se mide con `grep -c` / `wc -l` / `docker inspect`,
nunca con `logs` a pantalla. Protocolo de contexto limpio, reglas 1 y 2.

## 1. El bus está cableado en los dos sentidos

```
$ docker exec hooksuite-redis-1 redis-cli pubsub numsub ia:instrucciones ia:hallazgos
ia:instrucciones   1
ia:hallazgos       1
$ docker exec hooksuite-redis-1 redis-cli dbsize
0
```

Un suscriptor en cada canal (el módulo `ia` en instrucciones, el backend en hallazgos). `dbsize 0`: el
bus es pub/sub puro, no deja estado en Redis.

## 2. La auditoría de prueba SÍ terminó, y no reventó

```
$ docker inspect proyecto-evolve-ia-1 --format '...'
Running=true ExitCode=0 RestartCount=0 Started=2026-10-10T09:58:11Z Finished=0001-01-01T00:00:00Z
$ docker stats --no-stream proyecto-evolve-ia-1
proyecto-evolve-ia-1   0.00%   71.49MiB / 7.695GiB
```

Contenedor vivo, **sin reinicios**, **sin código de salida** y a **0 % de CPU**: la auditoría que estaba en
curso cuando se cortó la sesión ya había acabado. Recuentos sobre sus 192 líneas de log:

| Patrón | Veces |
|---|---|
| `Traceback` | **0** |
| `Error` / `ERROR` | **0** |
| `401` / `Unauthorized` | **0** |
| `completad` | 2 |
| `hallazgos` | 2 |
| `analiz` | 100 |
| **`techo`** | **96** |

## 3. 🔴 EL DATO QUE FALTABA: una auditoría completa son ~96 llamadas, no 40

El techo corría a 0 (`HOOKSUITE_IA_MAX_LLAMADAS=0` verificado con `printenv` dentro del contenedor), así que
**cada intento de llamada se cortó y devolvió la vía degradada**: 0 € de API. El mensaje que los cuenta es
`ia/client.py:94` (`"techo de N llamadas por auditoria alcanzado"`), y sale **96 veces**.

Es decir: **el triple bucle de una auditoría completa contra DVWA intenta ~96 llamadas al modelo.** El techo
por defecto es **40** (`ia/client.py:51`), declarado provisional precisamente a falta de este dato
(`HOJA-DE-RUTA`: *«se fija con el dato de `ia_llamadas` de la primera auditoría real, no a ojo»*).

**40 cortaría una auditoría real al 42 % de sus llamadas.** Subirlo o no es decisión de josemax.

> ⚠️ Matiz honesto: con el techo a 0 ninguna llamada produce hallazgos, y un hallazgo podría ramificar el
> recorrido. 96 es la medida del bucle en vía degradada, no necesariamente la de una auditoría con clave
> viva. Sirve como orden de magnitud y como cota inferior; no como número exacto.

## 4. Al backend NO llegó nada de la prueba

```
$ docker logs proyecto-evolve-backend-1 | wc -l
34
```

| Patrón en el log del backend | Veces |
|---|---|
| `prueba-bus-10oct` | **0** |
| `espacio` | **0** |
| `no_analizado` | **0** |
| `hallazgo` | 1 (la línea de suscripción del arranque) |
| `WARNING` / `ERROR` | 5 — **ninguna** menciona `redis`, `bus`, `ia:` ni `hallazgo` |

El backend **no registra por mensaje**, así que esto no prueba que el mensaje no llegara: prueba que **no
hay constancia de que llegara** y que **el bus no está dando errores** en ese lado. Queda como lo único
pendiente de la prueba extremo a extremo.

## 5. El espacio ficticio no dejó rastro — nada que limpiar

```
$ grep -rl 'prueba-bus-10oct' ~/cocina/Proyecto-Evolve
(sin resultados)
$ docker exec hooksuite-redis-1 redis-cli dbsize
0
```

Ni en disco, ni en Redis, ni en el log del backend. El almacén de vulnerabilidades del backend es en
proceso (`backend/models/` solo tiene `schemas.py`; el único volumen es `usuarios`, de RF-12), así que un
reinicio lo vacía de todos modos. **El pendiente «limpiar `prueba-bus-10oct`» se cierra sin acción.**

## 6. Por qué NO hubo la interrupción que se había predicho

Se predijo que las **7 llamadas HTTP** del orquestador al backend (`BACKEND_URL`, medido el 10-oct con
`grep -c`) fallarían contra el guardián de la Fase 2 e interrumpirían la auditoría. **No pasó, y la
explicación ya estaba escrita en este mismo diario**, en la entrada del bus:

> *«el código comprueba `status_code == 200`; un 401 **no lanza excepción**»*

Un 401 **falla en silencio**: no interrumpe nada y no escribe nada en el log — coherente con los **0**
aciertos de `401`, `Unauthorized` y `Error` en las 192 líneas. La predicción era errónea: el modo de fallo
de ese camino es silencioso, que es exactamente el defecto que el bus vino a arreglar.

**Declarado por R9:** la predicción de la sesión anterior queda corregida aquí, no cambiada en silencio.

## 7. Vía de fuga NUEVA, no cubierta por la lista de protección

El clasificador se disparó con **un solo comando encadenado** que publicaba la orden en el bus, esperaba 12 s y terminaba en `docker compose logs --since 30s ia | tail -20`. **El fichero no se leyó**:
se leyó su *salida en ejecución*, que lleva la misma clase de contenido (nombres de fase de ataque,
recuentos de intentos). `.claude/sensibles.txt` (48 líneas) protege **rutas de ficheros**, y un log de
contenedor no es una ruta → el hook `contexto-limpio.sh` no lo frena.

Decisión pendiente de josemax: si la lista debe cubrir también `docker logs` / `docker compose logs` del
servicio `ia`. Mientras no se decida, la norma de trabajo es la de este documento: **medir, nunca volcar**.

### 7b. 🔴 CORRECCIÓN (12:45, con la captura del comando delante): fue UN comando, no dos

El borrador del rescate decía que el disparo fue un `docker compose logs` **«inmediatamente después de»** el
publish —es decir, **dos** comandos—. **Es falso.** La captura
(`lineas/practica3-hooksuite/evidencias/capturas/Salto1_Salvaguarda.png`, aportada por josemax) enseña que
fue **una sola llamada encadenada**:

```
cd …/Proyecto-Evolve ; echo "=== publico una orden de prueba en el bus ===" ;
docker compose exec -T redis redis-cli publish ia:instrucciones '{"type":"full_audit",…}' 2>&1 ;
echo " (el número = suscriptores que la oyeron; debe ser 1)" ;
sleep 12 ; echo ; echo "=== qué hizo el módulo IA ===" ;
docker compose logs --no-color --since 30s ia 2>&1 | tail -20
```

**Y eso cambia la lección.** El problema no fue «leer un log»: fue **arrancar algo ofensivo y leer su salida
en la misma llamada**, lo que elimina el único punto donde se podía parar. El `sleep 12` le da tiempo a
producir material y el `| tail -20` lo mete en el contexto sin que nadie llegue a mirar qué era. Visto como
dos comandos parece un descuido; visto como uno es **un diseño que no podía salir bien**.

**Regla que queda:** disparar y observar van en **llamadas separadas**, y la observación empieza siempre
midiendo. Si entre arrancar algo y mirarlo hace falta un `sleep`, eso ya indica que son dos pasos.

> ✅ **La captura está vetada y es publicable:** revisada entera antes de citarla (norma de que ninguna
> captura se publica sin abrirla). Muestra el comando, el `restart` de nginx y las dos comprobaciones
> (`frontend HTTP 200`, `api no-analizados HTTP 401`). **No lleva ningún secreto**: ni claves, ni tokens, ni
> cabeceras de sesión. Solo nombres de host internos, el puerto local y el espacio de usar y tirar.
