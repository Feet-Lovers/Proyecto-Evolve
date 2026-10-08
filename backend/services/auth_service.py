"""Autenticacion por usuario: contrasenas con hash y token firmado (JWT).

Sustituye al login de `routes/auth.py`, que comparaba contrasenas EN CLARO escritas
en el propio codigo y construia el identificador de sesion como
`username + id(objeto_peticion)`.

Por que ese identificador era un fallo y no un detalle:
  - `id()` devuelve la DIRECCION DE MEMORIA del objeto. No es aleatoria: es
    adivinable a partir del comportamiento del proceso.
  - CPython REUTILIZA esas direcciones cuando el objeto anterior se recolecta, asi
    que dos sesiones distintas podian acabar con el mismo identificador.

Modelo que se adopta aqui:
  - El servidor emite el token; el cliente ya no se lo inventa (antes lo generaba el
    navegador con `Math.random()`, que no es criptograficamente seguro).
  - El espacio de datos de cada usuario se indexa por su NOMBRE (`sub`), no por un
    identificador por inicio de sesion. Asi todas las pestanas del mismo usuario ven
    sus propios datos y ninguna ve los de otro, y una reconexion no estrena espacio.
    (La alternativa, un espacio por inicio de sesion, aislaba igual pero partia los
    datos del mismo usuario entre pestanas, que es peor de usar y no mas seguro.)
"""

import os
import uuid
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt

from services.usuarios_store import almacen

ALGORITMO = "HS256"
HORAS_VALIDEZ = int(os.getenv("JWT_HORAS_VALIDEZ", "8"))


def _leer_secreto() -> str:
    """Secreto de firma, obligatorio y sin valor por defecto.

    No se pone un valor de reserva a proposito: un secreto por defecto en el codigo
    es exactamente el fallo que este modulo viene a cerrar — cualquiera que lea el
    repositorio (publico) podria firmar sus propios tokens. Si falta, el backend no
    arranca y el mensaje dice como arreglarlo.
    """
    secreto = os.getenv("JWT_SECRET", "").strip()
    if not secreto:
        raise RuntimeError(
            "Falta la variable de entorno JWT_SECRET y no hay valor por defecto "
            "(seria una puerta abierta: el repositorio es publico). "
            "Generar una con `openssl rand -hex 32` y ponerla en el .env del backend."
        )
    if len(secreto) < 32:
        raise RuntimeError(
            "JWT_SECRET es demasiado corta (minimo 32 caracteres). "
            "Generar una con `openssl rand -hex 32`."
        )
    return secreto


def _leer_usuarios() -> dict:
    """Usuarios desde el entorno, como `nombre:hash_bcrypt` separados por comas.

    Los hashes de bcrypt no contienen comas, asi que el separador es seguro.
    Fuera del codigo: antes estaban escritos en `routes/auth.py`, en claro, y el
    repositorio es publico.
    """
    crudo = os.getenv("HOOKSUITE_USERS", "").strip()
    if not crudo:
        # OPCIONAL desde que existe el registro (RF-12): un despliegue nuevo puede
        # arrancar sin usuarios y que el primero se registre con el codigo de
        # invitacion. Sirve de arranque para tener con quien entrar desde el minuto
        # cero sin depender de que alguien se registre.
        return {}
    usuarios = {}
    for trozo in crudo.split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        if ":" not in trozo:
            raise RuntimeError(
                f"Entrada mal formada en HOOKSUITE_USERS: falta ':' en «{trozo[:16]}…»"
            )
        nombre, _, hash_ = trozo.partition(":")
        nombre = nombre.strip()
        hash_ = hash_.strip()
        if not nombre or not hash_:
            raise RuntimeError("Entrada mal formada en HOOKSUITE_USERS: nombre o hash vacio")
        usuarios[nombre] = hash_
    return usuarios


def _leer_codigo_registro() -> str:
    """Codigo de invitacion del registro. Obligatorio, y sin valor por defecto.

    Es el fallo mas facil de cometer aqui: si esta variable fuera opcional y alguien
    la olvidara en el despliegue, el registro quedaria ABIERTO sin que nadie se diera
    cuenta — y HookSuite lanza ataques contra terceros, asi que eso convierte el
    servicio en una plataforma de ataque publica. Mejor que no arranque.
    """
    codigo = os.getenv("REGISTRO_CODIGO", "").strip()
    if not codigo:
        raise RuntimeError(
            "Falta la variable de entorno REGISTRO_CODIGO y no hay valor por defecto. "
            "Sin ella el registro quedaria abierto a cualquiera, y esta herramienta "
            "lanza trafico contra terceros. Generarla con "
            "`python3 tools/generar-credenciales.py`."
        )
    if len(codigo) < 12:
        raise RuntimeError("REGISTRO_CODIGO es demasiado corto (minimo 12 caracteres).")
    return codigo


# Se leen al importar: si la configuracion es insegura, el backend no arranca en vez
# de arrancar en un estado que parece correcto.
SECRETO = _leer_secreto()
CODIGO_REGISTRO = _leer_codigo_registro()
USUARIOS_ENTORNO = _leer_usuarios()

# Los usuarios del entorno se siembran en el almacen persistente, que es la unica
# fuente de verdad en tiempo de ejecucion. Sembrar nunca sobreescribe: si alguien
# cambio su contrasena registrandose, el valor del entorno no debe revertirla.
almacen.sembrar(USUARIOS_ENTORNO)

# Hash de descarte: bcrypt valido, de una contrasena aleatoria que nadie conoce. Se
# usa para gastar el mismo tiempo cuando el usuario no existe.
_HASH_DESCARTE = bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=12)).decode()

LONGITUD_MINIMA_CONTRASENA = 8


def codigo_registro_valido(codigo: str) -> bool:
    """Compara el codigo en tiempo constante.

    Con `==` el tiempo de respuesta depende de cuantos caracteres coinciden, lo que
    permite adivinarlo carácter a carácter. `compare_digest` no tiene esa fuga.
    """
    return hmac.compare_digest((codigo or "").encode(), CODIGO_REGISTRO.encode())


def registrar(nombre: str, contrasena: str) -> tuple:
    """Da de alta un usuario. Devuelve (ok, motivo_si_falla).

    No valida el codigo: eso lo hace la ruta, antes de llegar aqui, para que el
    codigo no se mezcle con la politica de contrasenas.
    """
    nombre = (nombre or "").strip()
    if not nombre:
        return False, "El nombre de usuario no puede estar vacio"
    if len(nombre) > 32:
        return False, "El nombre de usuario no puede pasar de 32 caracteres"
    if "," in nombre or ":" in nombre:
        return False, "El nombre no puede contener ',' ni ':'"
    if len(contrasena or "") < LONGITUD_MINIMA_CONTRASENA:
        return False, f"La contrasena debe tener al menos {LONGITUD_MINIMA_CONTRASENA} caracteres"

    hash_ = bcrypt.hashpw(contrasena.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    if not almacen.crear(nombre, hash_, origen="registro"):
        return False, "Ese nombre de usuario ya esta en uso"
    return True, ""


def verificar_credenciales(nombre: str, contrasena: str) -> bool:
    """Comprueba la contrasena contra el hash almacenado.

    Si el usuario no existe se verifica igualmente contra un hash de descarte, para
    que el tiempo de respuesta no revele si el nombre esta registrado (un atacante
    podria enumerar usuarios midiendo la diferencia).
    """
    hash_guardado = almacen.obtener_hash(nombre)
    if hash_guardado is None:
        # Hash REAL de una contrasena aleatoria que nadie conoce. Tiene que ser valido
        # y del mismo coste: un hash inventado haria que checkpw fallara al parsearlo
        # y devolviera en microsegundos, delatando que el usuario no existe — justo lo
        # que se intenta evitar.
        hash_guardado = _HASH_DESCARTE
    try:
        return bcrypt.checkpw(contrasena.encode("utf-8"), hash_guardado.encode("utf-8"))
    except (ValueError, TypeError):
        # Hash corrupto o mal formado: se trata como credencial incorrecta, nunca
        # como acceso concedido.
        return False


def crear_token(nombre: str) -> dict:
    """Emite un token firmado para el usuario. `sid` es solo trazabilidad."""
    ahora = datetime.now(timezone.utc)
    caduca = ahora + timedelta(hours=HORAS_VALIDEZ)
    cuerpo = {
        "sub": nombre,
        "sid": str(uuid.uuid4()),
        "iat": int(ahora.timestamp()),
        "exp": int(caduca.timestamp()),
    }
    return {
        "access_token": jwt.encode(cuerpo, SECRETO, algorithm=ALGORITMO),
        "token_type": "bearer",
        "expires_in": HORAS_VALIDEZ * 3600,
        "usuario": nombre,
    }


def decodificar_token(token: str) -> Optional[dict]:
    """Devuelve el contenido del token si es valido, o None.

    Se fija el algoritmo a proposito: aceptar el que venga en la cabecera permite el
    ataque clasico de cambiarlo a «none» y colar un token sin firma.
    """
    if not token:
        return None
    try:
        cuerpo = jwt.decode(token, SECRETO, algorithms=[ALGORITMO])
    except jwt.PyJWTError:
        return None
    if not cuerpo.get("sub"):
        return None
    return cuerpo


def espacio_de_datos(cuerpo: dict) -> str:
    """Clave del espacio de datos del usuario: su nombre.

    Centralizado aqui para que ninguna ruta vuelva a decidirlo por su cuenta, que es
    como se colaron los dos endpoints que escribian en las sesiones de todos.

    `cuerpo` son los CLAIMS decodificados del JWT (lo que devuelve `decodificar_token`),
    NO la respuesta de `crear_token`. Se comprueba y se dice, porque confundir las dos
    cosas ya provoco un 500 en cada inicio de sesion: la respuesta de `crear_token` no
    tiene `sub`, asi que salia un `KeyError` enterrado en la traza en vez de un mensaje
    que explicara el error.
    """
    if not isinstance(cuerpo, dict) or "sub" not in cuerpo:
        raise TypeError(
            "espacio_de_datos() espera los claims decodificados del JWT (con 'sub'). "
            f"Ha recibido: {sorted(cuerpo) if isinstance(cuerpo, dict) else type(cuerpo).__name__}. "
            "Si lo que tienes es la respuesta de crear_token(), usa su campo 'usuario'."
        )
    return cuerpo["sub"]
