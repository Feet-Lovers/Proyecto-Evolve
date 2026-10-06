"""Guardian de la API: autenticacion y, ademas, que el espacio sea el propio.

Antes de esto, el backend no tenia NI UN `Depends`: los ~35 endpoints de `/api`
respondian a cualquiera, y el identificador de sesion viajaba como parametro de la
ruta, asi que bastaba cambiarlo en la URL para operar sobre los datos de otro.

Este modulo cierra las dos cosas a la vez, y conviene no confundirlas:

  - *Autenticacion*: ¿quien eres? Se exige un token firmado valido.
  - *Autorizacion*: ¿esto es tuyo? Muchas rutas siguen nombrando el espacio de datos en
    la ruta (`/api/spider/status/{token}`). Autenticar sin comprobar eso dejaria que un
    usuario legitimo leyera lo de otro simplemente escribiendo su nombre en la URL. Asi
    que si la ruta nombra un espacio, tiene que coincidir con el del token.

Se aplica una vez por router en `main.py` en vez de ruta por ruta: una ruta nueva queda
protegida por omision. Lo contrario —acordarse de poner el guardian en cada ruta— es
como se cuelan los huecos.
"""

from fastapi import HTTPException, Request

from services import auth_service

# Nombres con los que las rutas existentes llaman al espacio de datos. Si manana
# aparece otro, se anade aqui y queda cubierto en todas las rutas de golpe.
PARAMETROS_DE_ESPACIO = ("token", "session_token", "uid")


def _token_del_encabezado(request: Request) -> str:
    cabecera = request.headers.get("Authorization", "")
    return cabecera[7:] if cabecera[:7].lower() == "bearer " else ""


async def usuario_actual(request: Request) -> str:
    """Devuelve el espacio de datos del usuario autenticado, o corta la peticion."""
    cuerpo = auth_service.decodificar_token(_token_del_encabezado(request))
    if cuerpo is None:
        # `WWW-Authenticate` es lo que convierte esto en un 401 bien formado: sin esa
        # cabecera, un cliente no sabe que se le pide autenticacion. Era justo lo que
        # delataba que la API no exigia nada (ver apartado 7 de la memoria).
        raise HTTPException(
            status_code=401,
            detail="Token ausente o invalido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    espacio = auth_service.espacio_de_datos(cuerpo)

    for nombre in PARAMETROS_DE_ESPACIO:
        valor = request.path_params.get(nombre)
        if valor is not None and valor != espacio:
            # 403 y no 404: el usuario esta identificado, lo que falla es el permiso.
            # El mensaje no dice si ese otro espacio existe.
            raise HTTPException(
                status_code=403,
                detail="No puedes operar sobre la sesion de otro usuario",
            )

    return espacio
