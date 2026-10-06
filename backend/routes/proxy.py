from fastapi import APIRouter, Depends
from services.proxy_service import forward_request, should_filter
from services.session_service import session_manager
from services.guardia import usuario_actual
from models.schemas import ProxyRequest
import os

router = APIRouter()

PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))

# El fichero PAC se ha MOVIDO a main.py, fuera del guardian de /api. Motivo: lo pide el
# propio navegador al configurar el proxy, y un navegador no manda cabecera de
# autenticacion al buscarlo, asi que protegerlo romperia la configuracion del proxy sin
# ganar nada — no contiene secretos, solo el host y el puerto que el usuario ya conoce.
# Se sirve en la misma ruta de antes (`/api/proxy/proxy.pac`), para no tocar el
# `proxy_pass` de Nginx.

@router.get("/check/alive")
async def check_proxy_alive():
    return {"status": "proxy_active", "message": "HookSuite proxy is running"}

@router.post("/forward")
async def forward_proxy_request(request: ProxyRequest, espacio: str = Depends(usuario_actual)):
    """Ejecuta la peticion en nombre del auditor y la guarda en SU espacio.

    HUECO DE AUTORIZACION CERRADO (6-oct): el espacio salia de `request.session_token`,
    o sea del CUERPO, y el guardian del router solo valida los parametros de la RUTA.
    Un usuario autenticado podia meter trafico en el historial de otro poniendo su
    nombre en el cuerpo. Ahora sale del token firmado y el cuerpo se descarta.
    """
    if should_filter(request.url):
        return {"filtered": True}
    result = await forward_request(method=request.method, url=request.url, headers=request.headers, body=request.body)
    session = session_manager.get_session(espacio)
    session["requests"].append(result)
    await session_manager.emit(espacio, "request_intercepted", result)
    return result
