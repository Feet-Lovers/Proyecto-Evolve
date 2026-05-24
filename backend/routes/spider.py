from fastapi import APIRouter
from pydantic import BaseModel
from services.spider_service import SpiderService
from services.session_service import session_manager
import asyncio

router = APIRouter()

class SpiderRequest(BaseModel):
    url: str
    session_token: str
    speed: str = 'normal'
    cookie: str = ''

@router.post("/start")
async def start_spider(request: SpiderRequest):
    session = session_manager.get_session(request.session_token)
    if session.get("spider_running"):
        return {"status": "error", "message": "Ya hay un spider en ejecución para esta sesión"}
    
    session["spider_running"] = True
    
    async def run_spider():
        try:
            spider = SpiderService(
                base_url=request.url,
                session_token=request.session_token,
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
    session["requests"] = []
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
    session["requests"] = []
    session["spider_running"] = False
    return {"status": "reset"}
