from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import json
import os
import asyncio
load_dotenv()
from services import auth_service
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
@app.websocket("/ws/")
async def websocket_endpoint(websocket: WebSocket):
    """Canal de eventos del usuario autenticado.

    Antes era `/ws/{token}`: aceptaba la conexion y registraba el socket SIN validar
    nada, con un identificador que el navegador se inventaba. Cualquiera podia abrir el
    canal y, como los eventos se difundian a todas las sesiones, recibir el trabajo de
    los demas.

    Ahora la credencial llega en el PRIMER MENSAJE y no en la ruta. Motivo: un
    WebSocket del navegador no admite cabeceras, y poner el token en la URL lo deja
    escrito en los registros de acceso de Nginx — un token en un log es un token
    regalado. La barra final del path es intencionada: Nginx proxea `location /ws/`.
    """
    await websocket.accept()

    # Ventana corta para presentar la credencial. Sin tope, un cliente que se conecta
    # y calla retendria la conexion indefinidamente sin identificarse.
    espacio = None
    try:
        primero = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        sobre = json.loads(primero)
        if sobre.get("type") == "auth":
            cuerpo = auth_service.decodificar_token(sobre.get("token") or "")
            if cuerpo is not None:
                espacio = auth_service.espacio_de_datos(cuerpo)
    except (asyncio.TimeoutError, WebSocketDisconnect, json.JSONDecodeError, TypeError, AttributeError):
        espacio = None

    if espacio is None:
        # 1008 = violacion de politica. Se cierra sin decir por que: el cliente
        # legitimo ya sabe que tenia que autenticarse.
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
        return

    session_manager.get_session(espacio)
    session_manager.register_websocket(espacio, websocket)
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
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
        session_manager.unregister_websocket(espacio, websocket)
@app.on_event("startup")
async def startup_event():
    # Referencia FUERTE a proposito. `asyncio.create_task()` solo guarda una referencia
    # debil: si nadie se queda con la tarea, el recolector de basura puede llevarsela a
    # media ejecucion. Con un generador asincrono dentro, eso es exactamente como murio
    # el consumidor de hallazgos el 10-oct ("aclose(): asynchronous generator is already
    # running"), dejando el canal `ia:hallazgos` sin nadie escuchando mientras el modulo
    # de IA seguia gastando API. Guardarlas en `app.state` las mantiene vivas.
    app.state.tareas_fondo = [
        asyncio.create_task(start_redis_consumer()),
        asyncio.create_task(proxy_manager.cleanup_expired()),
    ]

#  RETIRADO: GET /api/session/new
#
#  Repartia un UUID como «token de sesion», pero no era una credencial: el backend
#  abria una sesion para cualquier cadena que llegara, asi que el UUID solo nombraba un
#  espacio de datos, no lo protegia. Ademas estaba MUERTO — el frontend nunca lo llamo:
#  se fabricaba su propio identificador en el navegador con Math.random().
#
#  Lo sustituye el token firmado de /api/auth/login, que SI es una credencial y del que
#  el espacio de datos se deriva. Se deja constancia aqui porque la matriz de
#  trazabilidad de la memoria citaba esta ruta como implementacion de RF-11.
from fastapi import Depends
from services.guardia import usuario_actual
from routes import proxy, repeater, intruder, utils, network, playwright, vulnerabilities, auth, spider

#  RETIRADO: GET /api/proxy/proxy.pac — el fichero de autoconfiguracion de proxy.
#
#  Pertenecia al modelo ABANDONADO de RF-02. La memoria tecnica lo cuenta: «en origen,
#  HookSuite interceptaba el trafico del navegador con un archivo de autoconfiguracion
#  (PAC) + WebSockets; ese modelo quedo expuesto y se saturo con trafico de bots. Se
#  pivoto a que el servidor ejecute las peticiones directamente con httpx». Lo confirmo
#  el repaso del 6-oct: su unico consumidor en el frontend era `PacOnboarding.jsx`, un
#  componente que NADIE importaba (codigo muerto, eliminado), y `devtools/core/
#  chrome_launcher.py`, que no esta integrado (RF-09) y ademas apunta a una IP de
#  produccion fija y al puerto 8000 que se cerro en la Fase 1.
#
#  Beneficio colateral para la seguridad: el PAC era la UNICA excepcion al guardian,
#  porque un navegador no manda cabecera de autenticacion al pedirlo. Al retirarlo,
#  TODAS las rutas de /api exigen token, sin carveouts que explicar ni mantener.


# El guardian se aplica POR ROUTER, no ruta por ruta: asi una ruta nueva nace protegida.
# Lo contrario —acordarse de ponerlo en cada una— es exactamente como se colaron los dos
# endpoints sin token que escribian en las sesiones de todos los usuarios.
PROTEGIDO = [Depends(usuario_actual)]

# `auth` queda fuera: login y registro tienen que ser alcanzables sin token, por
# definicion. Sus otras rutas (`/logout`, `/yo`) validan el token ellas mismas.
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

app.include_router(proxy.router, prefix="/api/proxy", tags=["proxy"], dependencies=PROTEGIDO)
app.include_router(repeater.router, prefix="/api/repeater", tags=["repeater"], dependencies=PROTEGIDO)
app.include_router(intruder.router, prefix="/api/intruder", tags=["intruder"], dependencies=PROTEGIDO)
app.include_router(utils.router, prefix="/api/utils", tags=["utils"], dependencies=PROTEGIDO)
app.include_router(network.router, prefix="/api/network", tags=["network"], dependencies=PROTEGIDO)
app.include_router(playwright.router, prefix="/api/playwright", tags=["playwright"], dependencies=PROTEGIDO)
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"], dependencies=PROTEGIDO)
app.include_router(spider.router, prefix="/api/spider", tags=["spider"], dependencies=PROTEGIDO)

#  ⚠️ PENDIENTE QUE ESTO CREA PARA LA FASE 3 (RF-08 / RF-10), anotado aqui para que no
#  se descubra como un 401 misterioso:
#  Los servicios internos `ia` y `playwright` publican en `/api/vulnerabilities` y
#  `/api/network/packet/...` sin credencial (ia/orchestrator.py, playwright/utils/
#  reporter.py). Ahora esas rutas exigen token, asi que cuando la Fase 3 los active
#  habra que darles una credencial de servicio y un espacio de datos propio. Ninguno de
#  los dos contenedores esta en marcha hoy, por lo que no rompe nada todavia.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=True
    )
