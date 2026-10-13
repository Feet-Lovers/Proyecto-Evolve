#!/usr/bin/env python3
"""
test-tres-estados.py — comprueba RNF-06 sin leer el clasificador.

Carga el clasificador con un cliente FALSO y comprueba que distingue los tres
estados que pide el apartado 3 del plan:

    vulnerable  ·  analizado y limpio  ·  no analizado (con motivo)

Es la alternativa a leer el código: una prueba dice lo que el código HACE, que es
más de lo que dice una lectura. Los prompts y el cliente real se sustituyen por
dobles, así que no hace falta ni clave de API ni red: cuesta 0 €.

La salida son líneas PASA/FALLA. Ni el código ni los prompts salen por pantalla;
los errores se resumen a tipo y mensaje recortado, nunca con la línea de origen.

uso: python3 test-tres-estados.py <clasificador.py>
"""
import importlib.util
import sys
import types
from pathlib import Path


class RespuestaFalsa:
    """Mismo contrato que client.RespuestaIA: datos · estado · detalle · ok."""

    def __init__(self, datos, estado, detalle=""):
        self.datos, self.estado, self.detalle = datos, estado, detalle

    @property
    def ok(self):
        return self.estado == "ok"


class ClienteFalso:
    def __init__(self, respuesta=None):
        self.respuesta = respuesta
        self.llamadas = 0

    def analyze(self, **kwargs):
        self.llamadas += 1
        self.ultimo_schema = kwargs.get("schema")
        return self.respuesta


def dobles():
    """Sustituye client, prompts.* y esquemas por módulos de mentira."""
    mod_client = types.ModuleType("client")
    mod_client.HookSuiteAIClient = ClienteFalso
    mod_client.RespuestaIA = RespuestaFalsa
    sys.modules["client"] = mod_client

    paquete = types.ModuleType("prompts")
    paquete.__path__ = []
    sys.modules["prompts"] = paquete
    for nombre in ("network_packet", "intruder", "console", "fingerprint"):
        m = types.ModuleType(f"prompts.{nombre}")
        m.get_system_prompt = lambda: "prompt de mentira"
        m.build_user_message = lambda *a, **k: "mensaje de mentira"
        m.ESQUEMA = {"type": "object"}
        sys.modules[f"prompts.{nombre}"] = m
        setattr(paquete, nombre, m)

    esquemas = types.ModuleType("esquemas")
    for c in ("ESQUEMA_PACKET", "ESQUEMA_INTRUDER", "ESQUEMA_CONSOLE", "ESQUEMA_FINGERPRINT"):
        setattr(esquemas, c, {"type": "object"})
    sys.modules["esquemas"] = esquemas


def cargar(ruta):
    spec = importlib.util.spec_from_file_location("clasificador_en_pruebas", ruta)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def main():
    if len(sys.argv) == 2:
        ruta = Path(sys.argv[1])
    elif len(sys.argv) == 1:
        # Sin argumento: el clasificador que vive al lado (uso dentro del repo).
        ruta = Path(__file__).resolve().parent.parent / "analyzers" / "vulnerability_classifier.py"
    else:
        print("uso: test-tres-estados.py [clasificador.py]", file=sys.stderr)
        return 2
    if not ruta.is_file():
        print(f"no existe: {ruta}", file=sys.stderr)
        return 1

    dobles()
    modulo = cargar(ruta)
    clasificador = modulo.VulnerabilityClassifier()
    umbral = modulo.CONFIDENCE_THRESHOLD

    degradada = RespuestaFalsa(None, "degradado", "clave invalida")
    vulnerable = RespuestaFalsa({"vulnerable": True, "confianza": umbral + 10}, "ok")
    limpia = RespuestaFalsa({"vulnerable": False, "confianza": umbral + 10}, "ok")

    def llamar(respuesta, metodo, *args):
        clasificador.client = ClienteFalso(respuesta)
        return getattr(clasificador, metodo)(*args)

    paquete = {"url": "http://objetivo/prueba"}
    casos = [
        ("A · packet degradado dice «no analizado» y por qué",
         lambda: (lambda r: isinstance(r, dict) and r.get("estado") == "no_analizado"
                  and r.get("motivo") == "clave invalida")(llamar(degradada, "analyze_packet", paquete))),
        ("B · packet vulnerable se marca «analizado»",
         lambda: (lambda r: isinstance(r, dict) and r.get("estado") == "analizado")(
             llamar(vulnerable, "analyze_packet", paquete))),
        ("C · packet analizado y limpio sigue devolviendo None",
         lambda: llamar(limpia, "analyze_packet", paquete) is None),
        ("D · intruder degradado dice «no analizado»",
         lambda: (lambda r: isinstance(r, dict) and r.get("estado") == "no_analizado")(
             llamar(degradada, "analyze_intruder", [], "http://objetivo", "id"))),
        ("E · console degradado dice «no analizado»",
         lambda: (lambda r: isinstance(r, dict) and r.get("estado") == "no_analizado")(
             llamar(degradada, "analyze_console", [], "http://objetivo"))),
        ("F · fingerprint degradado dice «no analizado»",
         lambda: (lambda r: isinstance(r, dict) and r.get("estado") == "no_analizado")(
             llamar(degradada, "fingerprint", {}, "http://objetivo"))),
        ("G · fingerprint correcto devuelve los datos del modelo",
         lambda: llamar(RespuestaFalsa({"servidor": "nginx"}, "ok"), "fingerprint", {}, "http://objetivo")
         == {"servidor": "nginx"}),
        ("H · se le pasa un schema al cliente (lo exige client.analyze)",
         lambda: (lambda: (llamar(degradada, "analyze_packet", paquete),
                           clasificador.client.ultimo_schema is not None)[1])()),
    ]

    fallos = 0
    for nombre, prueba in casos:
        try:
            bien = bool(prueba())
        except Exception as e:  # sin traza: la traza imprimiría el código
            bien = False
            print(f"FALLA  {nombre}  → {type(e).__name__}: {str(e)[:120]}")
            fallos += 1
            continue
        print(f"{'PASA  ' if bien else 'FALLA '} {nombre}")
        fallos += 0 if bien else 1

    print(f"\n{len(casos) - fallos}/{len(casos)} pasan")
    return 0 if fallos == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
