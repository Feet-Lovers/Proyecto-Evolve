from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from services.proxy_manager import proxy_manager
from services import auth_service

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class RegistroRequest(BaseModel):
    username: str
    password: str
    codigo: str


def _token_de(request: Request) -> dict:
    """Saca el token del encabezado y lo valida, o corta con 401.

    Centralizado para que ninguna ruta de este fichero vuelva a fiarse de un
    identificador que venga en el cuerpo de la peticion.
    """
    cabecera = request.headers.get("Authorization", "")
    crudo = cabecera[7:] if cabecera[:7].lower() == "bearer " else ""
    cuerpo = auth_service.decodificar_token(crudo)
    if cuerpo is None:
        raise HTTPException(status_code=401, detail="Token ausente o invalido")
    return cuerpo


@router.post("/registro", status_code=201)
async def registro(body: RegistroRequest):
    """Alta de usuario con codigo de invitacion (RF-12: *registro* y login).

    Por que con codigo y no abierto: HookSuite lanza trafico contra terceros. Con el
    registro abierto, cualquiera se da de alta y usa el Spider y el Intruder contra
    quien quiera desde nuestra infraestructura. El codigo lo reparte el grupo; el
    usuario elige su propia contrasena, que es el punto del requisito — nadie mas la
    conoce, ni siquiera quien administra.

    El codigo se comprueba ANTES que cualquier otra cosa y con el mismo error para
    todos los fallos de codigo, para no dar pistas sobre su longitud ni su forma.
    """
    if not auth_service.codigo_registro_valido(body.codigo):
        raise HTTPException(status_code=403, detail="Codigo de invitacion incorrecto")

    ok, motivo = auth_service.registrar(body.username, body.password)
    if not ok:
        # 409 cuando el nombre esta cogido, 400 cuando el dato es invalido.
        codigo_http = 409 if "ya esta en uso" in motivo else 400
        raise HTTPException(status_code=codigo_http, detail=motivo)

    return {"usuario": body.username.strip(), "mensaje": "Usuario creado. Ya puedes entrar."}


@router.post("/login")
async def login(request: Request, body: LoginRequest):
    """Verifica credenciales y emite un token firmado.

    Cambios respecto a la version anterior:
      - Las contrasenas se comparaban EN CLARO contra un diccionario escrito en este
        mismo fichero, y el repositorio es publico. Ahora se comparan contra un hash
        de bcrypt que vive en el entorno.
      - El identificador de sesion era `username + id(objeto_peticion)`: la direccion
        de memoria del cuerpo de la peticion, que no es aleatoria y que CPython
        reutiliza, de modo que dos sesiones podian coincidir. Ahora lo emite y firma
        el servidor.
      - El error no distingue «usuario desconocido» de «contrasena incorrecta», para
        no confirmarle a nadie que un nombre existe.
    """
    # Se normaliza igual que en el registro, que guarda el nombre sin espacios al
    # borde: si aqui no se hiciera, «  ana» no encontraria a «ana» y el usuario veria
    # un 401 sin entender por que.
    nombre = (body.username or "").strip()

    if not auth_service.verificar_credenciales(nombre, body.password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    token = auth_service.crear_token(nombre)

    # El proxy por usuario sigue arrancando igual, pero atado al usuario autenticado
    # en vez de a una direccion de memoria.
    #
    # OJO: aqui se pasa el NOMBRE, no `token`. `crear_token` devuelve la respuesta de
    # la API ({access_token, token_type, usuario, …}), mientras que `espacio_de_datos`
    # espera los *claims* decodificados del JWT. Pasarle la respuesta provocaba
    # `KeyError: 'sub'` y un 500 en cada inicio de sesion — el registro funcionaba, asi
    # que parecia que todo iba bien hasta el primer login real.
    client_ip = request.headers.get("X-Real-IP", request.client.host)
    puerto = proxy_manager.start_proxy(nombre, client_ip)

    return {**token, "proxy_port": puerto}


@router.post("/logout")
async def logout(request: Request):
    """Cierra la sesion del portador del token.

    Antes recibia el `uid` en el cuerpo: cualquiera podia parar el proxy de otro
    simplemente nombrandolo. Ahora el usuario sale del token firmado, asi que solo
    se puede cerrar la propia.
    """
    cuerpo = _token_de(request)
    proxy_manager.stop_proxy(auth_service.espacio_de_datos(cuerpo))
    return {"message": "Sesion cerrada"}


@router.get("/yo")
async def quien_soy(request: Request):
    """Quien es el portador del token.

    El frontend la usa al cargar para saber si el token guardado sigue vivo, en vez
    de suponerlo. Sustituye a `GET /session/{uid}`, que aceptaba el identificador de
    cualquiera por la URL y respondia con su puerto de proxy.
    """
    cuerpo = _token_de(request)
    return {
        "usuario": cuerpo["sub"],
        "expira": cuerpo["exp"],
        "proxy_port": proxy_manager.get_port(auth_service.espacio_de_datos(cuerpo)),
    }
