from fastapi import APIRouter, Depends
from models.schemas import NetworkPacket
from services.session_service import session_manager
from services.guardia import usuario_actual
from pydantic import BaseModel

router = APIRouter()


class SessionCookie(BaseModel):
    host: str
    phpsessid: str


#  FUGA CERRADA (Fase 2, 6-oct) — aqui vivia `session_cookies: dict = {}`.
#
#  Era un diccionario GLOBAL del modulo indexado SOLO por dominio, sin dueno. La cookie
#  de sesion que un auditor capturaba de la web auditada quedaba legible para cualquiera
#  que pidiera ese dominio — y se obtenia incluso SIN presentar token. Verificado antes
#  de arreglarlo: un segundo usuario leyo la cookie guardada por el primero
#  (`docs/evidencias/fugas-aislamiento-06oct.md`, prueba 3). Es secuestro de sesion de la
#  victima auditada, que es de lo mas grave que podia filtrar esta herramienta.
#
#  Ahora las cookies viven DENTRO de la sesion de cada usuario, asi que el aislamiento lo
#  da la misma estructura que el resto de sus datos y no hay un segundo sitio que
#  recordar. `intruder_service` las lee de ahi.


def _cookies_de(espacio: str) -> dict:
    return session_manager.get_session(espacio).setdefault("session_cookies", {})


@router.post("/packet")
async def receive_network_packet(
    packet: NetworkPacket,
    espacio: str = Depends(usuario_actual),
):
    """Registra un paquete en la sesion de QUIEN LLAMA.

    FUGA CERRADA (Fase 2, 6-oct): esto recorria `session_manager.sessions` y escribia y
    emitia el paquete en TODAS. Peor que difundirlo, porque lo PERSISTIA en los datos de
    todos los usuarios.
    """
    packet_dict = packet.model_dump()
    session = session_manager.get_session(espacio)
    session.setdefault("network_packets", []).append(packet_dict)
    await session_manager.emit(espacio, "request_intercepted", packet_dict)
    return {"received": True, "id": packet.id}


@router.post("/packet/{session_token}")
async def receive_packet_for_session(session_token: str, packet: NetworkPacket):
    # El guardian del router ya ha comprobado que `session_token` es el espacio propio,
    # asi que llegar aqui con el de otro es imposible.
    packet_dict = packet.model_dump()
    session = session_manager.get_session(session_token)
    session.setdefault("network_packets", []).append(packet_dict)
    await session_manager.emit(session_token, "network_packet", packet_dict)
    return {"received": True, "id": packet.id}


@router.get("/packets/{session_token}")
async def get_packets(session_token: str):
    session = session_manager.get_session(session_token)
    return session.get("network_packets", [])[-500:]


@router.post("/session_cookie")
async def store_session_cookie(cookie: SessionCookie, espacio: str = Depends(usuario_actual)):
    _cookies_de(espacio)[cookie.host] = cookie.phpsessid
    return {"stored": True, "host": cookie.host}


@router.get("/session_cookie/{host:path}")
async def get_session_cookie(host: str, espacio: str = Depends(usuario_actual)):
    return {"host": host, "phpsessid": _cookies_de(espacio).get(host, "")}
