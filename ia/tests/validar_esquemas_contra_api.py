"""
RF-08 — pregunta A LA API si acepta cada esquema, en vez de deducirlo.

POR QUÉ EXISTE. El 10-oct la primera auditoría real se rechazó entera, y hubo que
arreglar-reconstruir-relanzar TRES veces porque cada intento destapaba una restricción
distinta del subconjunto de JSON Schema que admite la salida estructurada:

  1. "For 'object' type, 'additionalProperties: true' is not supported"
  2. "For 'number' type, properties maximum, minimum are not supported"
  3. "For 'object' type, 'additionalProperties' must be explicitly set to false"
     (lo disparaban los campos cuyo tipo era una LISTA que incluía "object")

Las tres eran averiguables en un minuto preguntando. Ninguna prueba local podía cazarlas,
porque el requisito no estaba escrito en ninguna parte nuestra: vive en el servicio del
otro lado. `test_esquemas_api.py` vigila lo que YA sabemos; esto descubre lo que no.

⚠️ GASTA (muy poco): una llamada por esquema, con el tope de salida al mínimo. No va en la
suite automática a propósito — se ejecuta cuando el esquema cambia.

Uso:   set -a; . .env; set +a; python3 ia/tests/validar_esquemas_contra_api.py
(la clave se lee del entorno; nunca se imprime, R7)
"""
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.anthropic.com/v1/messages"
MODELO = os.environ.get("HOOKSUITE_IA_MODELO", "claude-sonnet-4-20250514")


def cargar(ruta):
    spec = importlib.util.spec_from_file_location("esquemas", ruta)
    if spec is None or spec.loader is None:
        raise SystemExit(f"no se puede importar {ruta}")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return {n: v for n, v in sorted(vars(modulo).items())
            if n.startswith("ESQUEMA_") and isinstance(v, dict)}


def probar(nombre, esquema, clave):
    cuerpo = {
        "model": MODELO,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "ok"}],
        "output_config": {"format": {"type": "json_schema", "schema": esquema}},
    }
    pet = urllib.request.Request(
        API, data=json.dumps(cuerpo).encode(), method="POST",
        headers={"x-api-key": clave, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    try:
        with urllib.request.urlopen(pet, timeout=60) as r:
            return True, f"HTTP {r.status} · ACEPTADO"
    except urllib.error.HTTPError as e:
        detalle = ""
        try:
            detalle = json.load(e).get("error", {}).get("message", "")
        except Exception:
            pass
        # 400 = el esquema no vale. Otros códigos son problema de clave/red, no del esquema.
        return (e.code != 400), f"HTTP {e.code} · {detalle[:200]}"
    except Exception as e:
        return False, f"sin respuesta: {type(e).__name__}"


def main():
    clave = os.environ.get("ANTHROPIC_API_KEY", "")
    if not clave:
        print("FALLA  no hay ANTHROPIC_API_KEY en el entorno")
        return 1
    # Nunca el valor: longitud y nada más (R7).
    print(f"clave presente ({len(clave)} caracteres) · modelo {MODELO}\n")

    ruta = sys.argv[1] if len(sys.argv) > 1 else "ia/esquemas.py"
    esquemas = cargar(ruta)
    fallos = 0
    for nombre, esquema in esquemas.items():
        ok, detalle = probar(nombre, esquema, clave)
        print(f"{'ACEPTA ' if ok else 'RECHAZA'} {nombre:22} {detalle}")
        fallos += 0 if ok else 1

    print(f"\n{len(esquemas) - fallos}/{len(esquemas)} esquemas aceptados por la API")
    return 0 if fallos == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
