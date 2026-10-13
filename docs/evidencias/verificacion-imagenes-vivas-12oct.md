# Evidencia · ¿Las imágenes que están corriendo llevan los arreglos del 11-oct?

**Fecha:** 2026-10-12, mañana. **Quién:** Claude. **Requisitos:** RF-05, RNF-07.
**Para qué:** cerrar (o confirmar vivos) los dos pendientes de «recrear backend y frontend»
que quedaron a nombre de josemax al cerrar la sesión del 11-oct.

**Método, y por qué este y no otro:** se verifica por el **código que hay dentro del
contenedor**, nunca por el fuente del disco ni por la hora de arranque. Dos motivos
registrados: (1) un contenedor recién arrancado imita al arreglo —el reloj no dice qué
código lleva la imagen—, y la nota del cierre advertía de que las imágenes se habían
construido con una **versión intermedia** porque el primer script abortó a mitad;
(2) mis propios comentarios falsean el `grep` sobre el fuente (ya había pasado tres veces
en dos días).

---

## 1. Hora de arranque de los dos contenedores (indicio, NO prueba)

```
$ docker inspect -f '{{.Name}} {{.State.StartedAt}}' proyecto-evolve-backend-1 proyecto-evolve-frontend-1
/proyecto-evolve-backend-1 2026-10-11T19:04:41.97986449Z
/proyecto-evolve-frontend-1 2026-10-11T19:19:54.246069735Z
```

En hora local (CEST, +2): **21:04:41** y **21:19:54**, los dos **posteriores** a sus commits
(21:02 y 21:19). Es compatible con que josemax los recreara al cerrar, pero por sí solo no
demuestra qué código llevan dentro. De ahí los dos apartados siguientes.

## 2. Backend · normalización de cabeceras a lista de pares

```
$ docker exec proyecto-evolve-backend-1 sh -c 'grep -rn "forward_request" /app --include=*.py'
/app/services/proxy_service.py:71:async def forward_request(
/app/routes/repeater.py:20:    result = await forward_request(
/app/routes/proxy.py:34:    result = await forward_request(method=request.method, ...)
```

```
$ docker exec proyecto-evolve-backend-1 sh -c 'sed -n "71,112p" /app/services/proxy_service.py'
...
    pares = list(headers.items()) if isinstance(headers, dict) else [(k, v) for k, v in headers]
    clean_headers = [(k, v) for k, v in pares if k.lower() not in protected_headers]
...
                headers=clean_headers,
```

**Resultado: el arreglo SÍ está en la imagen viva.** Acepta diccionario (Spider y proxy) o
lista de pares (Repeater), trabaja siempre con pares y los pasa como lista a `httpx`, que
envía las dos cabeceras repetidas. Es lógica ejecutable, no un comentario.

**Lo que este apartado NO cubre:** el schema de entrada de `/send`. Si declarara un
diccionario, aplastaría la lista antes de llegar aquí. La prueba de extremo a extremo del
11-oct (contra servidor de eco dentro del contenedor, con control negativo) cubría ese
camino completo, así que no se repite; queda dicho que aquí no se ha vuelto a medir.

## 3. Frontend · vista previa sin ejecución de JavaScript

```
$ docker exec proyecto-evolve-frontend-1 sh -c 'f=$(ls -S /usr/share/nginx/html/assets/*.js | head -1); \
    echo "BUNDLE: $f"; for p in sandbox allow-scripts allow-same-origin "no se ejecuta"; \
    do echo "$p = $(grep -ao "$p" "$f" | wc -l)"; done'
BUNDLE: /usr/share/nginx/html/assets/index-BJ_zfD0P.js
sandbox = 1
allow-scripts = 0
allow-same-origin = 0
no se ejecuta = 1
```

**Resultado: 0/0/1/1 sobre el bundle realmente servido**, el mismo recuento que quedó
anotado el 11-oct al commitear.

**Dos cautelas del método, porque son el valor de esta medición:**
- Se cuenta con `grep -ao … | wc -l` y **no** con `grep -c`: el bundle minificado es *una
  sola línea*, así que `grep -c` devolvería `1` para cualquier cadena presente y `0` para
  las ausentes sin distinguir cuántas veces aparece — un contador que parece funcionar.
- Antes de aceptar los dos ceros se comprobó que **el detector sabe dar distinto de cero**:
  el mismo comando devuelve `1` dos veces (`sandbox` y el aviso). Un cero solo vale si el
  medidor ha demostrado que sabría cantar otra cosa.

---

## Conclusión

| Pendiente del 11-oct | Estado tras esta verificación |
|---|---|
| Recrear `backend` | ✅ hecho — la imagen viva lleva la normalización a pares |
| Recrear `frontend` | ✅ hecho — el bundle servido da 0/0/1/1 |
| Probar en pantalla (botón limpiar · dos cabeceras · aviso de la vista previa) | ⏳ sigue a nombre de josemax (R6: pantalla) |
| Panel de detalle muestra **una sola** cabecera repetida | ⏳ sigue vivo → apdo. 10 |

**Inferencia declarada como tal:** el botón `limpiar` venía del commit *anterior* al que se ha
confirmado en el bundle, así que el bundle debería llevarlo. Se deduce por el orden de los
commits; **no se ha contado**.
