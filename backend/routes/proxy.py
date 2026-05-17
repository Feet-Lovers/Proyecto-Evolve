from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from services.proxy_service import forward_request, should_filter
from services.session_service import session_manager
from models.schemas import ProxyRequest
import os

router = APIRouter()

PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))

@router.get("/proxy.pac", response_class=PlainTextResponse)
async def get_pac_file(request: Request):
    host = request.headers.get("host", "localhost").split(":")[0]
    pac_content = f"""function FindProxyForURL(url, host) {{
    if (shExpMatch(host, "localhost")) return "DIRECT";
    if (isInNet(host, "127.0.0.1", "255.255.255.255")) return "DIRECT";
    return "PROXY {host}:{PROXY_PORT}";
}}"""
    return PlainTextResponse(content=pac_content, media_type="application/x-ns-proxy-autoconfig")

@router.get("/check/alive")
async def check_proxy_alive():
    return {"status": "proxy_active", "message": "HookSuite proxy is running"}

@router.post("/forward")
async def forward_proxy_request(request: ProxyRequest):
    if should_filter(request.url):
        return {"filtered": True}
    result = await forward_request(method=request.method, url=request.url, headers=request.headers, body=request.body)
    session = session_manager.get_session(request.session_token)
    session["requests"].append(result)
    await session_manager.emit(request.session_token, "request_intercepted", result)
    return result
