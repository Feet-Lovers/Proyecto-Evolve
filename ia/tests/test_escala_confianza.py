#!/usr/bin/env python3
"""
test_escala_confianza.py — la confusión de escala se VE, no desaparece (RF-08 / RNF-06).

Qué cubre. Los cuatro prompts piden `confianza` en escala 0-100 y ninguno pide que sea
entero, así que el esquema no puede cazar un valor que venga en escala 0-1: un 0.85 está
*dentro* de 0-100. Si llegara así, `0.85 >= 60` sería falso y el hallazgo desaparecería
en silencio — justo lo que RNF-06 existe para evitar.

La guardia del clasificador trata la franja (0, 1] como sospecha de escala y la encamina
al estado degradado. Esta prueba comprueba las dos mitades del contrato:

  · lo sospechoso NO se devuelve como «sin vulnerabilidad», sino como «no analizado»
  · lo legítimo de la escala 0-100 sigue pasando igual que antes (sin falsos positivos)

Usa dobles para el cliente y los prompts: ni clave de API ni red. Cuesta 0 €.
Ni el código ni los prompts salen por pantalla.

uso: python3 test_escala_confianza.py [clasificador.py]
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

    def analyze(self, **kwargs):
        return self.respuesta


def dobles():
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
        ruta = Path(__file__).resolve().parent.parent / "analyzers" / "vulnerability_classifier.py"
    else:
        print("uso: test_escala_confianza.py [clasificador.py]", file=sys.stderr)
        return 2
    if not ruta.is_file():
        print(f"no existe: {ruta}", file=sys.stderr)
        return 1

    dobles()
    m = cargar(ruta)
    umbral = m.CONFIDENCE_THRESHOLD

    # Las tres vías que comparan contra el umbral: (nombre, método, bandera, args)
    VIAS = (
        ("PACKET  ", "analyze_packet", "vulnerable", ({"url": "http://x/a"},)),
        ("INTRUDER", "analyze_intruder", "explotado", ([], "http://x/a", "q")),
        ("CONSOLE ", "analyze_console", "sensible", ([], "http://x/a")),
    )

    def llamar(via, datos):
        _, metodo, _, args = via
        clasificador = m.VulnerabilityClassifier()
        clasificador.client = ClienteFalso(RespuestaFalsa(datos, "ok"))
        return getattr(clasificador, metodo)(*args)

    casos = []

    # --- La guardia, aislada --------------------------------------------------------
    casos += [
        ("guardia · 0.85 es sospechoso", lambda: m.escala_sospechosa(0.85) is True),
        ("guardia · 1 es sospechoso (el caso peor: certeza leída como 1 %)",
         lambda: m.escala_sospechosa(1) is True),
        ("guardia · 0 NO es sospechoso (es confianza nula, no escala mala)",
         lambda: m.escala_sospechosa(0) is False),
        ("guardia · 85 NO es sospechoso", lambda: m.escala_sospechosa(85) is False),
        ("guardia · 87.5 NO es sospechoso (decimal legítimo en 0-100)",
         lambda: m.escala_sospechosa(87.5) is False),
        ("guardia · un valor ausente no la dispara", lambda: m.escala_sospechosa(None) is False),
        ("guardia · un texto no la dispara", lambda: m.escala_sospechosa("alto") is False),
    ]

    # --- En las tres vías: lo sospechoso se ve, lo legítimo pasa --------------------
    for via in VIAS:
        nombre, _, flag, _ = via

        def sospechoso(via=via, flag=flag):
            r = llamar(via, {flag: True, "confianza": 0.85})
            return (r is not None
                    and r.get("estado") == "no_analizado"
                    and bool(r.get("motivo")))
        casos.append((f"{nombre} · 0.85 con hallazgo → no_analizado CON motivo", sospechoso))

        def no_es_none(via=via, flag=flag):
            # Lo que esta prueba defiende: que NO se confunda con «sin vulnerabilidad».
            return llamar(via, {flag: True, "confianza": 0.85}) is not None
        casos.append((f"{nombre} · 0.85 NO se devuelve como «sin vulnerabilidad»", no_es_none))

        def legitimo(via=via, flag=flag, umbral=umbral):
            r = llamar(via, {flag: True, "confianza": umbral + 10})
            return r is not None and r.get("estado") == "analizado"
        casos.append((f"{nombre} · {umbral + 10} sigue pasando como analizado", legitimo))

        def limpio(via=via, flag=flag, umbral=umbral):
            # Sin hallazgo y con escala buena: None, como siempre. Sin falsos positivos.
            return llamar(via, {flag: False, "confianza": umbral + 10}) is None
        casos.append((f"{nombre} · sin hallazgo y escala buena → None", limpio))

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

    print(f"\n{len(casos) - fallos}/{len(casos)} pasan")
    return 0 if fallos == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
