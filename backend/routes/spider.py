from fastapi import APIRouter, Depends
from pydantic import BaseModel
from services.spider_service import SpiderService
from services.session_service import session_manager
from services.guardia import usuario_actual
import asyncio

router = APIRouter()

class SpiderRequest(BaseModel):
    url: str
    # IGNORADO a proposito: se conserva porque el frontend lo sigue enviando, pero el
    # espacio de datos NO sale de aqui. Ver la nota de la ruta.
    session_token: str = ''
    speed: str = 'normal'
    cookie: str = ''

@router.post("/start")
async def start_spider(request: SpiderRequest, espacio: str = Depends(usuario_actual)):
    """Arranca el rastreo en el espacio de datos de QUIEN LLAMA.

    HUECO DE AUTORIZACION CERRADO (6-oct). El espacio salia de `request.session_token`,
    es decir del CUERPO de la peticion, y el guardian del router solo valida los
    parametros de la RUTA. Un usuario autenticado podia escribir en el espacio de otro
    poniendo su nombre en el cuerpo: la autenticacion estaba, la autorizacion se
    escapaba por ahi.

    Es el mismo error que tenia el codigo anterior y que esta Fase vino a corregir
    —dejar que el cliente elija donde escribe— solo que escondido un nivel mas abajo.
    Ahora el espacio viene del token firmado y lo que llegue en el cuerpo se descarta.
    """
    session = session_manager.get_session(espacio)
    if session.get("spider_running"):
        return {"status": "error", "message": "Ya hay un spider en ejecución para esta sesión"}

    session["spider_running"] = True

    async def run_spider():
        try:
            spider = SpiderService(
                base_url=request.url,
                session_token=espacio,
                speed=request.speed,
                cookie=request.cookie
            )
            await spider.run()
        finally:
            session["spider_running"] = False
    
    asyncio.create_task(run_spider())
    
    return {
        "status": "started",
        "url": request.url,
        "speed": request.speed
    }

@router.get("/status/{token}")
async def spider_status(token: str):
    session = session_manager.get_session(token)
    return {
        "running": session.get("spider_running", False)
    }

@router.post("/stop/{token}")
async def stop_spider(token: str):
    session = session_manager.get_session(token)
    session["spider_running"] = False
    return {"status": "stopped"}

@router.post("/clear/{token}")
async def clear_spider(token: str):
    from services.session_service import session_manager
    session = session_manager.get_session(token)
    session["requests"].clear()  # vaciar EN EL SITIO: reasignar perdia el tope de memoria
    session["spider_running"] = False
    return {"status": "cleared"}

@router.post("/release-session/{token}")
async def release_session(token: str):
    from services.proxy_service import _session_clients
    import httpx
    if token in _session_clients:
        await _session_clients[token].aclose()
        del _session_clients[token]
    return {"status": "session_released"}

@router.post("/reset/{token}")
async def reset_session(token: str):
    from services.proxy_service import _session_clients
    import httpx
    if token in _session_clients:
        await _session_clients[token].aclose()
        del _session_clients[token]
    session = session_manager.get_session(token)
    session["requests"].clear()  # vaciar EN EL SITIO: reasignar perdia el tope de memoria
    session["spider_running"] = False
    return {"status": "reset"}
