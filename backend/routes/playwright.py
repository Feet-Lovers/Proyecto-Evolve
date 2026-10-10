from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
from services.session_service import session_manager
from services import bus_ia

router = APIRouter()

pending_instructions: Dict[str, list] = {}

class PlaywrightInstruction(BaseModel):
    type: str
    url: str
    selector: Optional[str] = None
    payload: Optional[str] = None
    verify: Optional[str] = None
    session_token: str

@router.post("/instruction/{session_token}")
async def receive_instruction(session_token: str, instruction: PlaywrightInstruction):
    """Encola una orden y, si es para la IA, la publica en el bus interno.

    `session_token` ES el espacio de quien llama: el guardian ya lo ha comprobado antes de
    entrar aqui (`services/guardia.py`, PARAMETROS_DE_ESPACIO incluye "session_token", y
    responde 403 si no coincide con el del Bearer). Por eso se puede usar como dueño sin
    volver a validarlo — y por eso NO se lee del cuerpo, que el cliente si controla.
    """
    if session_token not in pending_instructions:
        pending_instructions[session_token] = []
    pending_instructions[session_token].append(instruction.model_dump())
    await session_manager.emit(session_token, "playwright_instruction", instruction.model_dump())

    # El modulo de IA ya no pollea esta ruta: desde la Fase 2 el guardian se lo impedia en
    # silencio (ver services/bus_ia.py). Ahora la orden le llega por el bus, con el dueño
    # dentro, de modo que los hallazgos vuelven a la sesion de quien pidio la auditoria.
    oyentes = None
    if instruction.type == "full_audit":
        try:
            oyentes = await bus_ia.publicar_instruccion(session_token, instruction.model_dump())
        except Exception as e:
            # Que falle el bus no debe tumbar la peticion, pero TAMPOCO puede pasar por
            # exito: el usuario tiene que saber que su auditoria no ha salido.
            return {
                "queued": True,
                "session_token": session_token,
                "ia_avisada": False,
                "motivo": f"el bus no acepto la orden: {type(e).__name__}",
            }
        if oyentes == 0:
            return {
                "queued": True,
                "session_token": session_token,
                "ia_avisada": False,
                "motivo": "nadie escucha el canal: el modulo de IA no esta en marcha",
            }

    respuesta = {"queued": True, "session_token": session_token}
    if oyentes is not None:
        respuesta["ia_avisada"] = True
        respuesta["oyentes"] = oyentes
    return respuesta

@router.get("/instruction/{session_token}")
async def get_pending_instructions(session_token: str):
    instructions = pending_instructions.get(session_token, [])
    pending_instructions[session_token] = []
    return {"instructions": instructions}

@router.post("/result/{session_token}")
async def receive_result(session_token: str, result: Dict[str, Any]):
    session = session_manager.get_session(session_token)
    session.setdefault("playwright_results", []).append(result)
    await session_manager.emit(session_token, "playwright_result", result)
    return {"received": True}

@router.get("/result/{session_token}")
async def get_playwright_results(session_token: str):
    session = session_manager.get_session(session_token)
    results = session.get("playwright_results", [])
    session["playwright_results"] = []
    return results
