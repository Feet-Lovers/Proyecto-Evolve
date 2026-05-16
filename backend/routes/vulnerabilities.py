from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from services.session_service import session_manager

router = APIRouter()

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

@router.post("")
async def receive_vulnerability(vulnerability: VulnerabilityReport):
    vuln_dict = vulnerability.model_dump()
    for token in session_manager.sessions:
        session = session_manager.get_session(token)
        session.setdefault("vulnerabilities", []).append(vuln_dict)
        await session_manager.emit(token, "vulnerability_detected", vuln_dict)
    return {"received": True, "id": vulnerability.id}

@router.post("/{session_token}")
async def receive_vulnerability_for_session(session_token: str, vulnerability: VulnerabilityReport):
    vuln_dict = vulnerability.model_dump()
    session = session_manager.get_session(session_token)
    session.setdefault("vulnerabilities", []).append(vuln_dict)
    await session_manager.emit(session_token, "vulnerability_detected", vuln_dict)
    return {"received": True, "id": vulnerability.id}

@router.get("/{session_token}")
async def get_vulnerabilities(session_token: str):
    session = session_manager.get_session(session_token)
    return session.get("vulnerabilities", [])
