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

@router.get("/{session_token}/no-analizados")
async def get_no_analizados(session_token: str):
    """RNF-06: lo que la IA NO pudo analizar, con su motivo.

    Existe porque hasta el 10-oct el estado degradado se calculaba, sobrevivia al filtro
    de confianza y se publicaba... y NADIE lo leia: `no_analizado` aparecia 4 veces en
    `ia/` y CERO en `backend` y `frontend`. O sea, RNF-06 estaba cumplido en el modulo e
    invisible en el producto, que para el operador es lo mismo que no estar.

    Va aparte de las vulnerabilidades y no mezclado con ellas por una razon: un fallo de
    analisis no es un hallazgo. Mezclarlos obligaria a inventarle severidad y confianza a
    algo que precisamente no se ha podido valorar.

    El aislamiento es automatico: `session_token` esta en PARAMETROS_DE_ESPACIO, asi que
    el guardian responde 403 si no es el espacio de quien llama.
    """
    session = session_manager.get_session(session_token)
    return session.get("no_analizados", [])


@router.delete("/{session_token}")
async def limpiar_panel(session_token: str):
    """Vacia el panel de vulnerabilidades de ESTA sesion, a peticion del usuario.

    Hace falta porque la limpieza automatica al lanzar una auditoria no cubre el caso que
    se dio el 10-oct: josemax limpio el proxy, vacio el campo de objetivo, y los 39 avisos
    de "no analizado" seguian ahi sin forma de quitarlos. Lanzar otra auditoria para poder
    limpiar la pantalla seria pedirle que gaste llamadas de API para borrar algo.

    El aislamiento es automatico: `session_token` esta en PARAMETROS_DE_ESPACIO, asi que el
    guardian ya ha comprobado que es el espacio de quien llama (403 si no coincide).
    """
    session = session_manager.get_session(session_token)
    borrados = len(session.get("vulnerabilities", [])) + len(session.get("no_analizados", []))
    session["vulnerabilities"] = []
    session["no_analizados"] = []
    session["resumen_ia"] = None
    session["objetivo_actual"] = None
    await session_manager.emit(session_token, "panel_limpiado", {"borrados": borrados})
    return {"borrados": borrados}


@router.get("/{session_token}/resumen")
async def get_resumen_ia(session_token: str):
    """El recibo de la ultima auditoria: cuantos analisis se hicieron de verdad.

    Existe porque «0 detectadas» es ambiguo: significa lo mismo si la IA examino 48
    elementos y ninguno era vulnerable que si no examino ninguno. Sin este dato la
    herramienta no es creible, que es lo que hizo notar josemax el 10-oct.

    Devuelve `null` si no ha habido auditoria en esta sesion.
    """
    session = session_manager.get_session(session_token)
    return session.get("resumen_ia")
