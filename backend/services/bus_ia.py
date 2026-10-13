"""Bus entre el backend y el modulo de IA, sobre el Redis que ya existe.

POR QUE ESTE MODULO EXISTE (10-oct-2026). Hasta hoy el modulo de IA hablaba con el
backend por HTTP, contra `/api/playwright/instruction/...`. Desde la Fase 2 ese router
lleva `dependencies=PROTEGIDO`, asi que el guardian lo cortaba por dos sitios a la vez:

  1. 401 — el modulo no manda ningun Bearer firmado.
  2. 403 — `session_token` esta en PARAMETROS_DE_ESPACIO, asi que su `ia_session` fijo
     no coincidiria con el espacio de ningun usuario ni con un token valido.

Y lo peor era el modo de fallo: el polling comprobaba `status_code == 200`, un 401 no
lanza excepcion, y el bucle volvia a dormir. El modulo parecia sano sin poder hacer nada.
Evidencia: docs/evidencias/canal-ia-backend-muerto-10oct.md

Se descartaron dos alternativas:

  - Un TOKEN DE SERVICIO que el guardian aceptara. Abre una excepcion en el unico sitio
    del que el apartado 7 presume justo por lo contrario: que una ruta nueva nace
    protegida. Lo que hay que acordarse de poner, se olvida.
  - EXENTAR los endpoints de instruccion. Peor: estan bajo `/api`, que Nginx publica, asi
    que cualquiera desde internet podria encolar una auditoria contra cualquier objetivo
    — el riesgo exacto que el codigo de invitacion existe para evitar.

Redis no esta publicado y vive en la red interna, asi que el salto no necesita
autenticacion: la frontera la pone la red, no una credencial que haya que custodiar. Y el
compose ya lo declara como bus de eventos, con un consumidor en marcha desde antes.

EL DUEÑO VIAJA CON LA ORDEN, y eso es lo que deshace el enredo de los cuatro tokens: cada
mensaje lleva `espacio`, el identificador del usuario que pidio la auditoria, tomado del
guardian. Los resultados vuelven a la sesion de quien la pidio y no a una sesion fija
compartida.
"""

import json
import os

import redis.asyncio as aioredis

# Ordenes del backend hacia el modulo de IA.
CANAL_INSTRUCCIONES = "ia:instrucciones"
# Hallazgos del modulo de IA hacia el backend (vulnerabilidades y «no analizado»).
CANAL_HALLAZGOS = "ia:hallazgos"

_REDIS_HOST = os.getenv("REDIS_HOST", "redis")
_REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

_cliente = None


def cliente():
    """Una sola conexion para todo el proceso, creada al primer uso."""
    global _cliente
    if _cliente is None:
        _cliente = aioredis.Redis(host=_REDIS_HOST, port=_REDIS_PORT)
    return _cliente


async def publicar_instruccion(espacio: str, instruccion: dict) -> int:
    """Publica una orden para el modulo de IA. Devuelve cuantos suscriptores la oyeron.

    El numero importa: si es 0, el modulo de IA no esta escuchando (contenedor caido, o
    no levantado). Quien llama puede decirlo en voz alta en vez de dejar al usuario
    esperando un resultado que no va a llegar — la misma idea que RNF-06.
    """
    mensaje = dict(instruccion)
    mensaje["espacio"] = espacio
    return await cliente().publish(CANAL_INSTRUCCIONES, json.dumps(mensaje))
