# Evidencia · El canal entre el módulo IA y el backend está muerto desde la Fase 2 (10-oct-2026)

Capturada **ANTES de arreglarlo** (R6). Medida en la cocina, con la pila levantada.

## Qué hace el módulo IA, y con qué se encuentra

`ia/main.py:19` hace `GET {BACKEND_URL}/api/playwright/instruction/{SESSION_TOKEN}` **sin cabecera de
autorización**, cada 5 segundos. Desde la Fase 2 eso es un 401:

```
$ curl -i http://localhost:8880/api/playwright/instruction/ia_session
HTTP/1.1 401 Unauthorized
www-authenticate: Bearer
{"detail":"Token ausente o invalido"}

$ # el sondeo de arranque de ia/main.py:43, que espera un 200
HTTP 401

$ # y el POST que usaria el boton, sin token
POST HTTP 401
```

## Por qué, y por qué son DOS muros y no uno

`backend/main.py:143` monta el router de instrucciones con `dependencies=PROTEGIDO`, es decir
`Depends(usuario_actual)`. Y `backend/services/guardia.py` hace dos cosas distintas:

1. **Autenticación** (`:34-46`): exige un Bearer firmado válido. El módulo IA no manda ninguno → **401**.
2. **Autorización** (`:48-58`): `session_token` está en `PARAMETROS_DE_ESPACIO`, así que el valor de la ruta
   tiene que coincidir con el espacio del token. El módulo IA pollea con `ia_session`, que no es el espacio
   de ningún usuario → **403 incluso con un token válido**.

El guardián se aplica **por router** en FastAPI, no en Nginx, así que el muro es el mismo venga la petición
de internet o de la red interna. No se esquiva cambiando de camino.

## Alcance real: no es solo el polling

El orquestador del módulo IA (348 líneas) usa `BACKEND_URL` **7 veces**, y su esqueleto —obtenido con
`bin/estructura.sh`, sin leer el fichero, que está en la lista protegida— muestra al menos tres puntos de
contacto más: `check_backend` (:52), `send_instruction_to_playwright` (:65) y
`send_vulnerability_to_backend` (:94). **El camino de vuelta de los resultados tiene el mismo problema que
el de ida.**

## El modo de fallo, que es lo peor de todo

`ia/main.py` comprueba `if response.status_code == 200`. Un 401 no lanza excepción: simplemente la condición
es falsa y el bucle vuelve a dormir 5 segundos. Y `wait_for_backend` (:40) ignora su propio valor de retorno,
así que tras 30 intentos fallidos **arranca igual** y escribe «Esperando instrucciones del backend...».
**El módulo parece sano y no puede hacer nada.** Es el mismo patrón que RNF-06 vino a cerrar dentro del
clasificador, un nivel más arriba: un fallo que no se distingue de la normalidad.

## Nota de estado

En la cocina no hay contenedor `ia` ni `playwright` levantados (`docker compose ps`: redis, backend, dvwa,
frontend, nginx). Y el puerto 8800 no escucha: el backend dejó de publicar puerto propio en la Fase 1, que
es el endurecimiento funcionando como se diseñó.
