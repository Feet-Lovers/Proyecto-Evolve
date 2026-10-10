#!/usr/bin/env python3
"""test_bus_reparto.py — cada hallazgo de la IA acaba en la sesion de SU dueño.

Que prueba. El bus interno (services/bus_ia.py) reconecta el modulo de IA con el backend
despues de que el guardian de la Fase 2 cortara el camino HTTP. El riesgo de un bus es el
contrario al del guardian: un mensaje que llega sin dueño podria repartirse «por si
acaso», y eso es EXACTAMENTE la fuga que cerro la Fase 2 —un hallazgo publicado sin token
aparecia en el panel de dos auditores distintos—.

Asi que lo que se comprueba no es solo que el reparto funcione, sino que un mensaje sin
dueño NO se reparte, y que dos espacios no se ven entre ellos.

Usa dobles para redis y para el gestor de sesiones: ni red ni contenedores. Cuesta 0 €.

uso: python3 backend/tests/test_bus_reparto.py
"""
import asyncio
import json
import sys
import types
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent  # backend/
sys.path.insert(0, str(RAIZ))


class RedisFalso:
    """Registra lo publicado. `publish` devuelve el numero de oyentes, como el de verdad."""

    def __init__(self, oyentes=1):
        self.oyentes = oyentes
        self.publicado = []

    async def publish(self, canal, dato):
        self.publicado.append((canal, dato))
        return self.oyentes


class SesionesFalsas:
    def __init__(self):
        self.sesiones = {}
        self.emitido = []

    def get_session(self, espacio):
        return self.sesiones.setdefault(espacio, {})

    async def emit(self, espacio, evento, datos):
        self.emitido.append((espacio, evento, datos))

    async def emit_all(self, evento, datos):
        self.emitido.append(("*", evento, datos))


def dobles():
    """Sustituye redis y el gestor de sesiones por modulos de mentira."""
    mod_redis = types.ModuleType("redis")
    mod_async = types.ModuleType("redis.asyncio")
    mod_async.Redis = lambda **kw: RedisFalso()
    mod_redis.asyncio = mod_async
    mod_redis.Redis = mod_async.Redis
    sys.modules["redis"] = mod_redis
    sys.modules["redis.asyncio"] = mod_async

    sesiones = SesionesFalsas()
    paquete = types.ModuleType("services")
    paquete.__path__ = [str(RAIZ / "services")]
    sys.modules.setdefault("services", paquete)
    mod_ss = types.ModuleType("services.session_service")
    mod_ss.session_manager = sesiones
    sys.modules["services.session_service"] = mod_ss
    return sesiones


def main():
    sesiones = dobles()
    from services import bus_ia, redis_consumer

    ESPACIO_A, ESPACIO_B = "usuario-a", "usuario-b"
    VULN = {"id": "v1", "tipo": "SQLi", "severidad": "alta", "confianza": 90}
    DEGRADADO = {"estado": "no_analizado", "motivo": "clave invalida", "origen": "proxy"}

    def reparte(datos):
        asyncio.run(redis_consumer._repartir_hallazgo(datos))

    casos = []

    # --- El reparto normal -------------------------------------------------------
    def vuln_a_su_dueño():
        sesiones.sesiones.clear(); sesiones.emitido.clear()
        reparte({**VULN, "espacio": ESPACIO_A})
        return (sesiones.sesiones[ESPACIO_A]["vulnerabilities"][0]["id"] == "v1"
                and sesiones.emitido[0][:2] == (ESPACIO_A, "vulnerability_detected"))
    casos.append(("una vulnerabilidad va a la sesion de su dueño", vuln_a_su_dueño))

    # --- RNF-06: el estado degradado tiene su propio camino ----------------------
    def degradado_aparte():
        sesiones.sesiones.clear(); sesiones.emitido.clear()
        reparte({**DEGRADADO, "espacio": ESPACIO_A})
        s = sesiones.sesiones[ESPACIO_A]
        return ("no_analizados" in s and "vulnerabilities" not in s
                and sesiones.emitido[0][:2] == (ESPACIO_A, "ia_no_analizado"))
    casos.append(("«no analizado» NO se cuela entre las vulnerabilidades", degradado_aparte))

    def degradado_lleva_motivo():
        sesiones.sesiones.clear()
        reparte({**DEGRADADO, "espacio": ESPACIO_A})
        return sesiones.sesiones[ESPACIO_A]["no_analizados"][0]["motivo"] == "clave invalida"
    casos.append(("«no analizado» conserva el motivo (sin el, RNF-06 no dice nada)",
                  degradado_lleva_motivo))

    # --- La fuga de la Fase 2, que no se puede reabrir ---------------------------
    def sin_dueño_no_se_reparte():
        sesiones.sesiones.clear(); sesiones.emitido.clear()
        reparte(dict(VULN))  # sin 'espacio'
        return sesiones.sesiones == {} and sesiones.emitido == []
    casos.append(("un hallazgo SIN dueño se descarta: ni se guarda ni se emite",
                  sin_dueño_no_se_reparte))

    def espacio_vacio_tampoco():
        sesiones.sesiones.clear(); sesiones.emitido.clear()
        reparte({**VULN, "espacio": ""})
        return sesiones.sesiones == {} and sesiones.emitido == []
    casos.append(("un dueño vacio tambien se descarta (no es un espacio valido)",
                  espacio_vacio_tampoco))

    def dos_espacios_no_se_ven():
        sesiones.sesiones.clear(); sesiones.emitido.clear()
        reparte({**VULN, "espacio": ESPACIO_A})
        reparte({"id": "v2", "tipo": "XSS", "espacio": ESPACIO_B})
        a = sesiones.sesiones[ESPACIO_A]["vulnerabilities"]
        b = sesiones.sesiones[ESPACIO_B]["vulnerabilities"]
        return len(a) == 1 and len(b) == 1 and a[0]["id"] != b[0]["id"]
    casos.append(("dos auditores no ven los hallazgos del otro", dos_espacios_no_se_ven))

    # --- El lado emisor: la orden sale con su dueño dentro -----------------------
    def instruccion_lleva_dueño():
        falso = RedisFalso(oyentes=1)
        bus_ia._cliente = falso
        oyentes = asyncio.run(bus_ia.publicar_instruccion(
            ESPACIO_A, {"type": "full_audit", "url": "http://dvwa:80"}))
        canal, dato = falso.publicado[0]
        return (canal == bus_ia.CANAL_INSTRUCCIONES
                and json.loads(dato)["espacio"] == ESPACIO_A
                and oyentes == 1)
    casos.append(("la orden se publica en su canal y con el dueño dentro",
                  instruccion_lleva_dueño))

    def sin_oyentes_se_sabe():
        falso = RedisFalso(oyentes=0)
        bus_ia._cliente = falso
        oyentes = asyncio.run(bus_ia.publicar_instruccion(ESPACIO_A, {"type": "full_audit"}))
        return oyentes == 0
    casos.append(("si nadie escucha, publicar lo DICE (0 oyentes) en vez de callar",
                  sin_oyentes_se_sabe))

    def no_muta_la_instruccion():
        falso = RedisFalso(); bus_ia._cliente = falso
        original = {"type": "full_audit", "url": "http://dvwa:80"}
        asyncio.run(bus_ia.publicar_instruccion(ESPACIO_A, original))
        return "espacio" not in original  # se copia, no se ensucia al que llama
    casos.append(("publicar no ensucia el dict de quien llama", no_muta_la_instruccion))

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
