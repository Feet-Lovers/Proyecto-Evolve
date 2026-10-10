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

    # RNF-06. «No analizado» no es «no hay vulnerabilidad», y tampoco encaja en el modelo
    # VulnerabilityReport (no tiene id, tipo, severidad ni confianza). Va por su propio
    # camino para que el panel pueda decirlo en voz alta en vez de callar.
    if data.get("estado") == "no_analizado":
        session.setdefault("no_analizados", []).append(data)
        await session_manager.emit(espacio, "ia_no_analizado", data)
        return

    session.setdefault("vulnerabilities", []).append(data)
    await session_manager.emit(espacio, "vulnerability_detected", data)


async def start_redis_consumer():
    r = aioredis.Redis(host='redis', port=6379)
    pubsub = r.pubsub()
    await pubsub.subscribe("traffic", bus_ia.CANAL_HALLAZGOS)
    print(f"✓ Redis consumer escuchando 'traffic' y '{bus_ia.CANAL_HALLAZGOS}'")
    async for message in pubsub.listen():
        if message["type"] != "message":
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
