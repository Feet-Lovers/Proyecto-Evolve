#!/usr/bin/env python3
"""
test_esquemas_bandera.py — comprueba que los esquemas IMPONEN lo que los prompts piden.

Por qué existe: `client.py:115` manda el esquema a la API como salida estructurada
(`{"type": "json_schema", "schema": schema}`), así que **el esquema ES la validación**.
Un tipo abierto no es permisividad: es ausencia de control.

Los cuatro prompts piden la bandera como `true/false` y la confianza en escala 0-100
(informe del `testigo`, 10-oct, §1 y §3). Esta prueba comprueba que el esquema obliga
a las dos cosas. Si no obliga, una cadena de texto llega al código, y el clasificador
hace `if result.get("explotado")` — en Python cualquier cadena no vacía es verdadera,
incluida la palabra que significa "no": un hallazgo inventado.

La salida son líneas PASA/FALLA. Ni los esquemas ni los prompts salen por pantalla.

uso: python3 test_esquemas_bandera.py <esquemas.py>
"""
import importlib.util
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError


def cargar(ruta):
    spec = importlib.util.spec_from_file_location("esquemas_bajo_prueba", ruta)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def rechaza(esquema, dato):
    """True si el esquema RECHAZA el dato (que es lo que queremos en los casos malos)."""
    try:
        Draft202012Validator(esquema).validate(dato)
        return False
    except ValidationError:
        return True


def acepta(esquema, dato):
    return not rechaza(esquema, dato)


def main():
    if len(sys.argv) != 2:
        print("uso: test_esquemas_bandera.py <esquemas.py>", file=sys.stderr)
        return 2
    ruta = Path(sys.argv[1])
    if not ruta.is_file():
        print(f"no existe: {ruta}", file=sys.stderr)
        return 1
    m = cargar(ruta)

    # La palabra que el modelo podría devolver en vez de false. No se escribe aquí
    # el literal en castellano para que la prueba no dependa del idioma del prompt:
    # lo que se comprueba es que CUALQUIER cadena se rechaza.
    CADENA = "no"

    casos = [
        # --- La bandera tiene que ser booleana en los TRES esquemas ---------------
        ("PACKET  · 'vulnerable' rechaza una cadena",
         lambda: rechaza(m.ESQUEMA_PACKET, {"vulnerable": CADENA, "confianza": 90})),
        ("INTRUDER · 'explotado' rechaza una cadena",
         lambda: rechaza(m.ESQUEMA_INTRUDER, {"explotado": CADENA, "confianza": 90})),
        ("CONSOLE · 'sensible' rechaza una cadena",
         lambda: rechaza(m.ESQUEMA_CONSOLE, {"sensible": CADENA, "confianza": 90})),

        # --- Y tiene que seguir aceptando el booleano que el prompt pide ----------
        ("PACKET  · 'vulnerable' acepta false",
         lambda: acepta(m.ESQUEMA_PACKET, {"vulnerable": False, "confianza": 10})),
        ("INTRUDER · 'explotado' acepta true",
         lambda: acepta(m.ESQUEMA_INTRUDER, {"explotado": True, "confianza": 90})),
        ("CONSOLE · 'sensible' acepta false",
         lambda: acepta(m.ESQUEMA_CONSOLE, {"sensible": False, "confianza": 10})),

        # --- La confianza va en 0-100, no en 0-1 ---------------------------------
        # LIMITACIÓN CONOCIDA, documentada aquí a propósito en vez de ocultarla: un rango
        # 0-100 NO puede cazar la confusión de escala, porque 0.85 está dentro de 0-100
        # (sería "0,85 % de confianza"). El código haría `0.85 >= 60` → falso, y el hallazgo
        # desaparecería EN SILENCIO. Cazarlo exige `{"type": "integer"}`, y eso depende de si
        # los prompts piden un número entero — dato que no consta en el informe del testigo
        # del 10-oct (§1 dice la escala, no el tipo). Pendiente de confirmar antes de cerrar.
        ("INTRUDER · 'confianza' 0.85 pasa: el rango NO caza la confusión de escala",
         lambda: acepta(m.ESQUEMA_INTRUDER, {"explotado": True, "confianza": 0.85})),
        ("INTRUDER · 'confianza' acepta 85 (escala 0-100)",
         lambda: acepta(m.ESQUEMA_INTRUDER, {"explotado": True, "confianza": 85})),
        ("PACKET  · 'confianza' rechaza 150 (fuera de rango)",
         lambda: rechaza(m.ESQUEMA_PACKET, {"vulnerable": True, "confianza": 150})),

        # --- FINGERPRINT no puede declarar cero campos ---------------------------
        ("FINGERPRINT · declara los 9 campos que pide su prompt",
         lambda: len(m.ESQUEMA_FINGERPRINT.get("properties", {})) == 9),
        ("FINGERPRINT · 'vectores_prioritarios' es una lista de objetos",
         lambda: m.ESQUEMA_FINGERPRINT["properties"]["vectores_prioritarios"]["type"] == "array"),
    ]

    fallos = 0
    for nombre, prueba in casos:
        try:
            bien = bool(prueba())
        except Exception as e:
            print(f"FALLA  {nombre}  → {type(e).__name__}: {str(e)[:120]}")
            fallos += 1
            continue
        print(f"{'PASA  ' if bien else 'FALLA '} {nombre}")
        fallos += 0 if bien else 1

    # La consecuencia, para que el apartado 8 no tenga que explicarla de palabra.
    print(f"\nconsecuencia en Python: bool({CADENA!r}) == {bool(CADENA)}"
          f"  →  un `if result.get(...)` con una cadena da SIEMPRE verdadero")
    print(f"{len(casos) - fallos}/{len(casos)} pasan")
    return 0 if fallos == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
