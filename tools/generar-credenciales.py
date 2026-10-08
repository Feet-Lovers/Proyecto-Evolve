#!/usr/bin/env python3
"""Genera el secreto de firma y los usuarios del login, y los escribe en el .env.

Por que existe esta herramienta y no unas instrucciones:

  - La bitacora de trabajo registra la salida de TODOS los comandos en texto plano.
    Si la herramienta imprimiera el secreto o las contrasenas para que alguien las
    copiara al .env, quedarian guardadas en claro. Por eso escribe ella misma el
    fichero y solo informa de longitudes y huellas SHA-256 truncadas.
  - Las contrasenas se piden sin eco, asi que tampoco aparecen en la linea de
    comandos ni en el historial del shell.
  - El despliegue de produccion necesita exactamente este mismo paso, hecho a mano
    por quien custodia las credenciales. Tenerlo como herramienta lo hace repetible.

Uso:
    python3 tools/generar-credenciales.py            # escribe en ./.env
    python3 tools/generar-credenciales.py --fichero /ruta/.env

No sobreescribe nada: si el fichero ya tiene las claves, aborta y lo dice.
"""

import argparse
import getpass
import hashlib
import os
import secrets
import sys

try:
    import bcrypt
except ImportError:
    sys.exit("Falta el paquete 'bcrypt'. Instalar con: pip install bcrypt")

CLAVES = ("JWT_SECRET", "REGISTRO_CODIGO", "HOOKSUITE_USERS", "JWT_HORAS_VALIDEZ")


def huella(valor: str) -> str:
    """SHA-256 truncado: permite comprobar que dos valores coinciden sin revelarlos."""
    return hashlib.sha256(valor.encode()).hexdigest()[:12]


def pedir_usuarios() -> list:
    print("Usuarios de ARRANQUE (opcional). Enter directo para no crear ninguno:")
    print("sirven para tener con quien entrar antes de que nadie se registre.")
    print("Los usuarios normales se crean ellos mismos en /registro con el codigo.")
    print("(las contrasenas no se muestran ni se guardan en el historial)\n")
    entradas, nombres = [], set()
    while True:
        nombre = input(f"  usuario #{len(entradas) + 1} (vacio para terminar): ").strip()
        if not nombre:
            break
        if "," in nombre or ":" in nombre:
            print("    el nombre no puede llevar ',' ni ':' — son los separadores")
            continue
        if nombre in nombres:
            print("    ese usuario ya esta")
            continue
        clave = getpass.getpass(f"    contrasena de {nombre}: ")
        if len(clave) < 8:
            print("    demasiado corta (minimo 8)")
            continue
        if clave != getpass.getpass("    repetir: "):
            print("    no coinciden")
            continue
        h = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
        assert "," not in h, "un hash con coma romperia el separador"
        assert bcrypt.checkpw(clave.encode("utf-8"), h.encode("utf-8")), "el hash no verifica"
        entradas.append(f"{nombre}:{h}")
        nombres.add(nombre)
        print(f"    anadido ({nombre}: hash de {len(h)} caracteres)\n")
    return entradas


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fichero", default=".env", help="ruta del .env (por defecto ./.env)")
    ap.add_argument("--horas", type=int, default=8, help="validez del token en horas")
    args = ap.parse_args()

    ruta = os.path.abspath(args.fichero)
    actual = ""
    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8") as f:
            actual = f.read()
        ya = [c for c in CLAVES if f"{c}=" in actual]
        if ya:
            print(f"ABORTADO: {ruta} ya contiene {', '.join(ya)}.")
            print("No se sobreescribe nada. Quitar esas lineas a mano si hay que rehacerlo.")
            return 1

    usuarios = pedir_usuarios()
    if not usuarios:
        print("  (sin usuarios de arranque: el primero tendra que registrarse)")

    secreto = secrets.token_hex(32)   # 256 bits en hexadecimal
    codigo = secrets.token_urlsafe(18)  # ~24 caracteres, comodo de dictar
    with open(ruta, "a", encoding="utf-8") as f:
        f.write("\n# --- Autenticacion por usuario ---\n")
        f.write("# Secreto de firma de los tokens. No tiene valor por defecto en el\n")
        f.write("# codigo a proposito: un secreto por defecto en un repositorio publico\n")
        f.write("# permitiria a cualquiera firmar sus propios tokens.\n")
        f.write(f"JWT_SECRET={secreto}\n")
        f.write("# Codigo de invitacion del registro. El registro NO es abierto porque\n")
        f.write("# esta herramienta lanza trafico contra terceros: con altas anonimas,\n")
        f.write("# cualquiera atacaria a quien quisiera desde nuestra infraestructura.\n")
        f.write(f"REGISTRO_CODIGO={codigo}\n")
        f.write("# Usuarios de arranque, como nombre:hash_bcrypt separados por comas.\n")
        f.write("# Opcional: los usuarios normales se crean ellos mismos en /registro.\n")
        f.write(f"HOOKSUITE_USERS={','.join(usuarios)}\n")
        f.write(f"JWT_HORAS_VALIDEZ={args.horas}\n")

    print(f"\nEscrito en {ruta}. Ningun valor mostrado:")
    print(f"  JWT_SECRET         {len(secreto)} caracteres · sha256:{huella(secreto)}…")
    print(f"  REGISTRO_CODIGO    {len(codigo)} caracteres · sha256:{huella(codigo)}…")
    print(f"  HOOKSUITE_USERS    {len(usuarios)} usuario(s) de arranque"
          + (f": {', '.join(e.split(':', 1)[0] for e in usuarios)}" if usuarios else ""))
    print(f"  JWT_HORAS_VALIDEZ  {args.horas}")
    print()
    print("  El codigo de invitacion NO se ha mostrado a proposito (la bitacora de")
    print("  trabajo registra la salida de los comandos en texto plano). Para leerlo")
    print("  y repartirlo al grupo, abrelo tu directamente:")
    print(f"    grep '^REGISTRO_CODIGO=' {ruta}")
    print("\nSiguiente paso: reconstruir el backend (rebuild, no restart) para que")
    print("recoja las variables y las dependencias nuevas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
