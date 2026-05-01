from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from services.session_service import session_manager
import os
import asyncio

load_dotenv()

app = FastAPI(
    title="HookSuite API",
    description="Backend del sistema de pentesting HookSuite",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        session_manager.unregister_websocket(token)

@app.get("/api/session/new")
async def new_session():
    token = session_manager.create_session()
    return {"token": token}

from routes import proxy, repeater, intruder, utils, network
app.include_router(proxy.router, prefix="/api/proxy", tags=["proxy"])
app.include_router(repeater.router, prefix="/api/repeater", tags=["repeater"])
app.include_router(intruder.router, prefix="/api/intruder", tags=["intruder"])
app.include_router(utils.router, prefix="/api/utils", tags=["utils"])
app.include_router(network.router, prefix="/api/network", tags=["network"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=True
    )