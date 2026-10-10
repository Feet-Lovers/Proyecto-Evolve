"""
RF-08 — los esquemas tienen que ser ACEPTABLES POR LA API, no solo correctos para nosotros.

Por qué existe esta prueba, y por qué no bastaba la que ya había:
`test_esquemas_bandera.py` daba 11/11 el 10-oct y seguía dando 11/11 con el defecto dentro.
Comprobaba lo que nosotros le pedimos al esquema (tipos de las banderas, rango de la
confianza) y nunca lo que la API exige para aceptarlo. La primera auditoría REAL —la primera
vez que un esquema salió de esta casa— se saldó con las nueve llamadas rechazadas:

    400 invalid_request_error — output_config.format.schema: For 'object' type,
    'additionalProperties: true' is not supported. Please set 'additionalProperties' to false

Una prueba que pasa contra el código roto no prueba nada. Esta falla contra él: con los
esquemas del 10-oct por la mañana da 0/5, y con los regenerados, 5/5.

Reproducible:  python3 ia/tests/test_esquemas_api.py ia/esquemas.py
"""
import importlib.util
import sys
from pathlib import Path


def cargar(ruta):
    # Si esto no se comprueba, un fichero ilegible revienta con un AttributeError y su
    # código de salida 1 se confunde con «la prueba ha detectado el defecto». Pasó al
    # estrenarla: el esquema viejo se guardó como .py.antes y no se pudo importar.
    spec = importlib.util.spec_from_file_location("esquemas", ruta)
    if spec is None or spec.loader is None:
        raise SystemExit(f"FALLA  no se puede importar {ruta} (¿termina en .py?)")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return {n: v for n, v in vars(modulo).items()
            if n.startswith("ESQUEMA_") and isinstance(v, dict)}


def objetos_abiertos(nodo, camino="raíz"):
    """Devuelve el camino de cada objeto que la API rechazaría (recursivo: los
    anidados cuentan igual, que es por donde se coló el de `vectores_prioritarios`)."""
    malos = []
    if isinstance(nodo, dict):
        if nodo.get("type") == "object" and nodo.get("additionalProperties") is not False:
            malos.append(camino)
        for clave, valor in nodo.items():
            malos += objetos_abiertos(valor, f"{camino}.{clave}")
    elif isinstance(nodo, list):
        for i, valor in enumerate(nodo):
            malos += objetos_abiertos(valor, f"{camino}[{i}]")
    return malos


def main():
    ruta = Path(sys.argv[1] if len(sys.argv) > 1 else "ia/esquemas.py")
    esquemas = cargar(ruta)
    if not esquemas:
        print(f"FALLA  no se encontró ningún ESQUEMA_* en {ruta}")
        return 1

    fallos = 0
    for nombre, esquema in sorted(esquemas.items()):
        abiertos = objetos_abiertos(esquema, nombre)
        if abiertos:
            print(f"FALLA  {nombre} · objeto(s) abierto(s): {', '.join(abiertos)}")
            fallos += 1
        else:
            print(f"PASA   {nombre} · ningún objeto abierto, ni anidado")

    # Que la prueba sepa contar: si no encuentra objetos, no está mirando nada.
    total_objetos = sum(1 for n in esquemas.values()
                        for _ in objetos_abiertos({**n, "additionalProperties": True}, "x"))
    if total_objetos == 0:
        print("FALLA  el recorrido no encontró ni un objeto → la prueba no está midiendo")
        fallos += 1
    else:
        print(f"PASA   el recorrido ve objetos de verdad ({total_objetos} al abrirlos a propósito)")

    n = len(esquemas) + 1
    print(f"\n{n - fallos}/{n} pasan")
    return 0 if fallos == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
