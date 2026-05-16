from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
from services.session_service import session_manager

router = APIRouter()

# Cola de instrucciones pendientes por sesión
pending_instructions: Dict[str, list] = {}

class PlaywrightInstruction(BaseModel):
    type: str
    url: str
    selector: Optional[str] = None
    payload: Optional[str] = None
    verify: Optional[str] = None
    session_token: str

class VulnerabilityReport(BaseModel):
    id: str
    tipo: str
    severidad: str
    titulo: str
    descripcion: str
    url: str
    payload: Optional[str] = None
    recomendacion: Optional[str] = None
    confianza: float
    source_type: Optional[str] = None
    timestamp: str

@router.post("/instruction/{session_token}")
async def receive_instruction(session_token: str, instruction: PlaywrightInstruction):
    if session_token not in pending_instructions:
        pending_instructions[session_token] = []
    pending_instructions[session_token].append(instruction.model_dump())
    await session_manager.emit(session_token, "playwright_instruction", instruction.model_dump())
    return {"queued": True, "session_token": session_token}

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

@router.post("/vulnerabilities")
async def receive_vulnerability(vulnerability: VulnerabilityReport):
    vuln_dict = vulnerability.model_dump()
    for token in session_manager.sessions:
        session = session_manager.get_session(token)
        session.setdefault("vulnerabilities", []).append(vuln_dict)
        await session_manager.emit(token, "vulnerability_detected", vuln_dict)
    return {"received": True, "id": vulnerability.id}

@router.post("/vulnerabilities/{session_token}")
async def receive_vulnerability_for_session(session_token: str, vulnerability: VulnerabilityReport):
    vuln_dict = vulnerability.model_dump()
    session = session_manager.get_session(session_token)
    session.setdefault("vulnerabilities", []).append(vuln_dict)
    await session_manager.emit(session_token, "vulnerability_detected", vuln_dict)
    return {"received": True, "id": vulnerability.id}

@router.get("/vulnerabilities/{session_token}")
async def get_vulnerabilities(session_token: str):
    session = session_manager.get_session(session_token)
    return session.get("vulnerabilities", [])
