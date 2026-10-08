"""Almacen persistente de usuarios (RF-12: *registro* y login).

Por que hace falta algo persistente, cuando el apartado 10 de la memoria justifica
que el estado de SESION sea volatil: son cosas distintas. Perder el historial de una
auditoria al reiniciar es una molestia asumida y documentada; perder la CUENTA de un
usuario en cada despliegue haria el registro inutil, porque el despliegue es
`git reset --hard` + reconstruccion de contenedores.

Formato: un JSON con `{"usuarios": {nombre: {"hash": ..., "creado": ...}}}`, en un
volumen montado. Se eligio un fichero y no una base de datos porque la escala es de
unos pocos usuarios y porque anadir un servicio nuevo a diez dias de la entrega es
mas riesgo que valor. Si alguna vez crece, el punto de cambio es solo este fichero.

Lo que SI se cuida, porque un fichero mal escrito es peor que una base de datos:
  - escritura atomica (temporal + reemplazo) para que un corte no deje medio JSON;
  - cerrojo de fichero en el ciclo leer-modificar-escribir, para que dos registros
    simultaneos no se pisen y se pierda uno;
  - permisos 600: contiene hashes de contrasenas.
"""

import fcntl
import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Optional

RUTA_POR_DEFECTO = os.getenv("USUARIOS_FICHERO", "/data/usuarios.json")


class AlmacenUsuarios:
    def __init__(self, ruta: str = None):
        self.ruta = ruta or RUTA_POR_DEFECTO
        self.ruta_cerrojo = self.ruta + ".lock"
        directorio = os.path.dirname(self.ruta) or "."
        os.makedirs(directorio, exist_ok=True)

    # --- lectura/escritura basicas -------------------------------------------------

    def _leer_sin_cerrojo(self) -> dict:
        try:
            with open(self.ruta, "r", encoding="utf-8") as f:
                datos = json.load(f)
        except FileNotFoundError:
            return {"usuarios": {}}
        except (json.JSONDecodeError, OSError):
            # Fichero corrupto: NO se devuelve un almacen vacio, porque eso dejaria
            # entrar a quien registrase de nuevo un nombre existente. Se avisa alto.
            raise RuntimeError(
                f"El almacen de usuarios {self.ruta} no se puede leer o esta corrupto. "
                "No se continua para no perder cuentas ni permitir suplantaciones. "
                "Revisar el fichero a mano."
            )
        if not isinstance(datos, dict) or not isinstance(datos.get("usuarios"), dict):
            raise RuntimeError(f"El almacen de usuarios {self.ruta} no tiene la forma esperada.")
        return datos

    def _escribir_sin_cerrojo(self, datos: dict) -> None:
        directorio = os.path.dirname(self.ruta) or "."
        tmp_fd, tmp = tempfile.mkstemp(dir=directorio, prefix=".usuarios-", suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(datos, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.ruta)  # atomico en el mismo sistema de ficheros
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    class _Cerrojo:
        """Cerrojo de fichero para el ciclo leer-modificar-escribir."""

        def __init__(self, ruta):
            self.ruta = ruta
            self.f = None

        def __enter__(self):
            self.f = open(self.ruta, "a+")
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
            return self

        def __exit__(self, *exc):
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
            self.f.close()
            return False

    # --- operaciones ---------------------------------------------------------------

    def obtener_hash(self, nombre: str) -> Optional[str]:
        usuario = self._leer_sin_cerrojo()["usuarios"].get(nombre)
        return usuario["hash"] if usuario else None

    def existe(self, nombre: str) -> bool:
        return nombre in self._leer_sin_cerrojo()["usuarios"]

    def nombres(self) -> list:
        return sorted(self._leer_sin_cerrojo()["usuarios"].keys())

    def crear(self, nombre: str, hash_bcrypt: str, origen: str = "registro") -> bool:
        """Crea el usuario. Devuelve False si el nombre ya estaba cogido.

        La comprobacion y la escritura van DENTRO del mismo cerrojo: comprobar fuera
        y escribir despues deja una ventana en la que dos registros del mismo nombre
        pasan los dos y el segundo sobreescribe al primero.
        """
        with self._Cerrojo(self.ruta_cerrojo):
            datos = self._leer_sin_cerrojo()
            if nombre in datos["usuarios"]:
                return False
            datos["usuarios"][nombre] = {
                "hash": hash_bcrypt,
                "creado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "origen": origen,
            }
            self._escribir_sin_cerrojo(datos)
        return True

    def sembrar(self, usuarios: dict) -> int:
        """Mete en el almacen los usuarios del entorno que todavia no esten.

        Sirve para que un despliegue nuevo tenga con quien entrar antes de que nadie
        se registre. Nunca sobreescribe a un usuario existente: si alguien cambio su
        contrasena por el registro, el valor del entorno no debe revertirla.
        """
        if not usuarios:
            return 0
        anadidos = 0
        with self._Cerrojo(self.ruta_cerrojo):
            datos = self._leer_sin_cerrojo()
            for nombre, hash_ in usuarios.items():
                if nombre not in datos["usuarios"]:
                    datos["usuarios"][nombre] = {
                        "hash": hash_,
                        "creado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "origen": "entorno",
                    }
                    anadidos += 1
            if anadidos:
                self._escribir_sin_cerrojo(datos)
        return anadidos


almacen = AlmacenUsuarios()
