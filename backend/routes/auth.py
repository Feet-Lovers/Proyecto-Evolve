from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from services.proxy_manager import proxy_manager

router = APIRouter()

USERS = {
    "admin": "hooksuite2026",
    "profesor": "hooksuite2026",
}

class LoginRequest(BaseModel):
    username: str
    password: str

class LogoutRequest(BaseModel):
    uid: str

@router.post("/login")
async def login(request: Request, body: LoginRequest):
    if body.username not in USERS or USERS[body.username] != body.password:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    client_ip = request.headers.get("X-Real-IP", request.client.host)
    uid = f"{body.username}_{id(body)}"
    port = proxy_manager.start_proxy(uid, client_ip)
    return {"uid": uid, "proxy_port": port, "message": "Proxy arrancado"}

@router.post("/logout")
async def logout(body: LogoutRequest):
    proxy_manager.stop_proxy(body.uid)
    return {"message": "Proxy parado"}

@router.get("/session/{uid}")
async def get_session(uid: str):
    port = proxy_manager.get_port(uid)
    if not port:
        raise HTTPException(status_code=404, detail="Sesion no encontrada")
    return {"uid": uid, "proxy_port": port}
