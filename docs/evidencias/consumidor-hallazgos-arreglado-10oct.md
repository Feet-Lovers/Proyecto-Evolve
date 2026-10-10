# RF-08 · El consumidor de hallazgos deja de morir — evidencia de terminal (10-oct-2026)

Captura en TEXTO (R3: las de terminal las guarda Claude, no se fotografían).

## Antes del arreglo — backend de las 18:52 (imagen sin `db6d40c1`)

    oyentes por canal
      ia:instrucciones   1
      ia:hallazgos       0     <-- el modulo publicaba aqui y NADIE escuchaba
      traffic            0

    registro del backend
      "Redis consumer escuchando"          1    <-- arranco
      "Task exception was never retrieved" 1    <-- y murio
      RuntimeError: aclose(): asynchronous generator is already running

Consecuencia: cada auditoria gastaba llamadas reales (techo 10) y el resultado se tiraba.

## Despues del arreglo — backend recreado por josemax a las ~20:30

    $ docker compose up -d --force-recreate --no-deps backend
     ✔ Container proyecto-evolve-backend-1  Started
    $ docker compose exec -T redis redis-cli PUBSUB NUMSUB ia:instrucciones ia:hallazgos traffic
    ia:instrucciones
    1
    ia:hallazgos
    1
    traffic
    1

    registro del backend
      "Redis consumer escuchando"          1
      "Redis consumer caido"               0
      "Task exception was never retrieved" 0

## Que lo arreglo (commit `db6d40c1`)

1. `redis_consumer.py`: `async for ... in pubsub.listen()` -> `get_message(timeout=1.0)`.
   `listen()` es un generador asincrono y revienta al cerrarse mientras espera.
2. `main.py`: las tareas de fondo pasan a `app.state.tareas_fondo`. `asyncio.create_task()`
   solo guarda una referencia DEBIL: el recolector de basura podia llevarse la tarea a
   media ejecucion, que es lo que producia esa excepcion.
3. Supervisor con reintento (1s -> 30s) que anuncia cada caida con su tipo de error.

El contraste 0 -> 1 oyentes, con el mismo comando antes y despues, es la prueba.

---

## 🔴 RECTIFICACION (20:4x, el mismo dia): ESTA EVIDENCIA ERA FALSA

Lo de arriba da por probado un arreglo que **nunca llego a ejecutarse**. Se conserva entero, sin borrar
nada, porque el error de metodo vale mas que el resultado.

**Que fallo.** El backend se recreo con `--force-recreate --no-deps` **y sin `--build`**: eso recrea el
contenedor pero **no reconstruye la imagen**, asi que siguio corriendo el codigo anterior.

**Por que la prueba parecia buena, que es lo importante.** El `ia:hallazgos: 1` se midio **justo despues**
de recrear. El consumidor VIEJO tambien se suscribe al arrancar — y muere despues. O sea: **el contraste
0 -> 1 era real, pero no probaba lo que se creia**. Medido a las 20:4x, con el mismo comando: `ia:hallazgos`
de vuelta a **0**, y el registro con el mismo `RuntimeError: aclose(): asynchronous generator is already
running` que el arreglo elimina.

**La comprobacion que SI distingue** (y que ya estaba documentada en `memoria/ESTADO.md`, sin aplicarse):

    $ docker compose exec -T backend sh -c 'sha256sum /app/services/redis_consumer.py'
    $ sha256sum backend/services/redis_consumer.py        # deben coincidir
    $ docker compose exec -T backend sh -c "grep -c 'pubsub.listen()' /app/..."   # 0 = codigo nuevo

Resultado real: hashes distintos (`b620d1e1…` vs `7a1db8bb…`) y **1** ocurrencia de `pubsub.listen()`
dentro del contenedor.

**Leccion, en una linea: un efecto observado justo despues de recrear no distingue codigo nuevo de codigo
viejo recien arrancado.** Se verifica el CODIGO dentro del contenedor, no el sintoma.
