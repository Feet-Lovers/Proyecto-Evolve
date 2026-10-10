import asyncio
import json

import redis.asyncio as aioredis

from services import bus_ia
from services.session_service import session_manager


async def _repartir_hallazgo(data: dict):
    """Mete un hallazgo de la IA en la sesion de SU DUEÑO, y en ninguna otra.

    El `espacio` lo pone el backend al publicar la orden (bus_ia.publicar_instruccion),
    tomandolo del guardian, y el modulo de IA lo devuelve tal cual. Aqui NO se deduce ni
    se adivina: si falta, el mensaje se descarta.

    Descartar es deliberado y es la leccion de la Fase 2. La version anterior de la ruta
    de vulnerabilidades recorria TODAS las sesiones y emitia el hallazgo en cada una; se
    comprobo que un hallazgo publicado sin token aparecia en el panel de dos auditores
    distintos (docs/evidencias/fugas-aislamiento-06oct.md, prueba 4). En una herramienta
    de auditoria eso es filtrar los datos del cliente de otro. Un mensaje sin dueño se
    tira; no se reparte «por si acaso».
    """
    espacio = data.get("espacio")
    if not espacio:
        print("Bus IA: hallazgo SIN espacio, descartado (no se reparte a ciegas)")
        return

    session = session_manager.get_session(espacio)

    # Sello del objetivo: el hallazgo se queda con el objetivo que estaba auditandose cuando
    # llego. Sin esto el panel no puede distinguir lo de ESTA auditoria de lo que quedo de
    # otra anterior, que es lo que confundia al leerlo. `setdefault` para no pisar el valor
    # si algun dia el modulo lo manda por su cuenta.
    data.setdefault("objetivo", session.get("objetivo_actual"))

    # RNF-06. «No analizado» no es «no hay vulnerabilidad», y tampoco encaja en el modelo
    # VulnerabilityReport (no tiene id, tipo, severidad ni confianza). Va por su propio
    # camino para que el panel pueda decirlo en voz alta en vez de callar.
    # Resumen de la auditoria: no es un hallazgo, es el recibo de lo que se hizo. Va a su
    # propia casilla para que el panel pueda decir «N analisis» aunque no haya encontrado
    # nada, que es justo lo que distingue «no habia nada» de «no se ejecuto».
    if data.get("estado") == "resumen_auditoria":
        session["resumen_ia"] = data
        await session_manager.emit(espacio, "ia_resumen", data)
        return

    if data.get("estado") == "no_analizado":
        session.setdefault("no_analizados", []).append(data)
        await session_manager.emit(espacio, "ia_no_analizado", data)
        return

    session.setdefault("vulnerabilities", []).append(data)
    await session_manager.emit(espacio, "vulnerability_detected", data)


async def _cerrar(recurso):
    """Cierra un recurso de redis sin importar como se llame el metodo en esta version."""
    cerrar = getattr(recurso, "aclose", None) or getattr(recurso, "close", None)
    if cerrar is None:
        return
    try:
        resultado = cerrar()
        if hasattr(resultado, "__await__"):
            await resultado
    except Exception:
        pass


async def _bucle_consumidor():
    """Una vida del consumidor: se suscribe y reparte hasta que algo falle.

    Usa `get_message(timeout=...)` y NO `pubsub.listen()`. El 10-oct el consumidor murio
    con `RuntimeError: aclose(): asynchronous generator is already running`: `listen()` es
    un generador asincrono y, cuando se cierra mientras esta suspendido esperando, revienta.
    El modulo de IA siguio analizando y publicando en `ia:hallazgos` con NADIE escuchando
    al otro lado — gastando API y tirando el resultado. `get_message` es un await normal,
    sin generador que cerrar.
    """
    r = aioredis.Redis(host='redis', port=6379)
    pubsub = r.pubsub()
    try:
        await pubsub.subscribe("traffic", bus_ia.CANAL_HALLAZGOS)
        print(f"✓ Redis consumer escuchando 'traffic' y '{bus_ia.CANAL_HALLAZGOS}'")
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message is None or message.get("type") != "message":
                continue
            canal = message["channel"]
            if isinstance(canal, bytes):
                canal = canal.decode()
            try:
                data = json.loads(message["data"])
                if canal == bus_ia.CANAL_HALLAZGOS:
                    await _repartir_hallazgo(data)
                else:
                    await session_manager.emit_all("request_intercepted", data)
            except Exception as e:
                print(f"Error procesando mensaje Redis ({canal}): {e}")
    finally:
        await _cerrar(pubsub)
        await _cerrar(r)


async def start_redis_consumer():
    """Supervisor: mantiene vivo el consumidor pase lo que pase.

    Antes, si el bucle moria, no lo reemplazaba nadie y no se enteraba nadie: el backend
    seguia contestando 200, el panel seguia en verde y el producto estaba roto por dentro.
    Arreglar solo la excepcion del 10-oct dejaria ese modo de fallo intacto para la
    siguiente, asi que el bucle se reintenta con espera creciente (1s -> 30s) y cada caida
    se anuncia en el registro con el tipo de error, que es lo que permitio diagnosticarlo.
    """
    espera = 1
    while True:
        try:
            await _bucle_consumidor()
            print("⚠ Redis consumer: el bucle termino solo; reintentando")
        except asyncio.CancelledError:
            print("Redis consumer: cancelado, saliendo")
            raise
        except Exception as e:
            print(f"⚠ Redis consumer caido ({type(e).__name__}: {e}); reintento en {espera}s")
        await asyncio.sleep(espera)
        espera = min(espera * 2, 30)
