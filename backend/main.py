from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
import asyncio
load_dotenv()
from services.session_service import session_manager
from services.redis_consumer import start_redis_consumer
from services.proxy_manager import proxy_manager
app = FastAPI(
    title="HookSuite API",
    description="Backend del sistema de pentesting HookSuite",
    version="1.0.0",
)
# Orígenes permitidos: lista cerrada (config por env ALLOWED_ORIGINS, coma-separada).
# Se quita el "*": con credenciales es inválido por spec y, de hecho, reflejaba cualquier
# origen -> cualquier web hacía peticiones autenticadas. El frontend ya es mismo origen (via
# proxy), así que el CORS solo aplica a llamadas cross-origin legítimas.
_default_origins = (
    "https://www.hooksuite.de,http://www.hooksuite.de,http://91.98.143.219,"
    "http://localhost,http://localhost:8880,http://127.0.0.1:8880,http://localhost:5173"
)
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.get("/health")
async def health():
    return {"status": "ok", "service": "HookSuite Backend"}
@app.get("/check/alive")
async def check_alive():
    return {"status": "proxy_active"}
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    await websocket.accept()
    session_manager.get_session(token)
    session_manager.register_websocket(token, websocket)
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        session_manager.unregister_websocket(token)
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(start_redis_consumer())
    asyncio.create_task(proxy_manager.cleanup_expired())

@app.get("/api/session/new")
async def new_session():
    token = session_manager.create_session()
    return {"token": token}
from routes import proxy, repeater, intruder, utils, network, playwright, vulnerabilities, auth, spider
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(proxy.router, prefix="/api/proxy", tags=["proxy"])
app.include_router(repeater.router, prefix="/api/repeater", tags=["repeater"])
app.include_router(intruder.router, prefix="/api/intruder", tags=["intruder"])
app.include_router(utils.router, prefix="/api/utils", tags=["utils"])
app.include_router(network.router, prefix="/api/network", tags=["network"])
app.include_router(playwright.router, prefix="/api/playwright", tags=["playwright"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(spider.router, prefix="/api/spider", tags=["spider"])
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=True
    )
