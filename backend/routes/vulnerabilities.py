from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from services.session_service import session_manager
from services.guardia import usuario_actual

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
async def receive_vulnerability(
    vulnerability: VulnerabilityReport,
    espacio: str = Depends(usuario_actual),
):
    """Registra un hallazgo en la sesion de QUIEN LLAMA.

    FUGA CERRADA (Fase 2, 6-oct). Esto recorria `session_manager.sessions` y escribia y
    emitia el hallazgo en TODAS las sesiones. Verificado antes de arreglarlo: una
    vulnerabilidad publicada sin token aparecia en el panel de dos auditores distintos
    (`docs/evidencias/fugas-aislamiento-06oct.md`, prueba 4). En una herramienta de
    auditoria eso es filtrar los datos del cliente de otro.
    """
    vuln_dict = vulnerability.model_dump()
    session = session_manager.get_session(espacio)
    session.setdefault("vulnerabilities", []).append(vuln_dict)
    await session_manager.emit(espacio, "vulnerability_detected", vuln_dict)
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
