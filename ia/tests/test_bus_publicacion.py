#!/usr/bin/env python3
"""test_bus_publicacion.py — el modulo de IA devuelve TODO y al dueño correcto.

Que prueba. Tras reconectar el canal por el bus interno, el modulo de IA publica lo que
encuentra. Hay tres formas de que eso salga mal y las tres estan aqui:

  1. Publicar solo las vulnerabilidades y callarse lo que no se pudo analizar. El informe
     diria «sin hallazgos» sobre una auditoria a medias: lo que RNF-06 existe para evitar.
  2. Mandarlo a un `ia_session` fijo en vez de al espacio de quien pidio la auditoria
     — el enredo de los cuatro tokens, que es lo que el bus viene a deshacer.
  3. Que la auditoria se caiga y no se publique NADA, dejando el panel esperando para
     siempre. Un fallo silencioso otra vez, un nivel mas arriba.

Usa dobles para redis, dotenv y el orquestador: ni red, ni clave de API, ni contenedores.
Cuesta 0 €. Ni el codigo del orquestador ni los prompts salen por pantalla.

uso: python3 ia/tests/test_bus_publicacion.py
"""
import asyncio
import json
import sys
import types
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent  # ia/
sys.path.insert(0, str(RAIZ))


class RedisFalso:
    def __init__(self):
        self.publicado = []

    async def publish(self, canal, dato):
        self.publicado.append((canal, dato))
        return 1

    async def ping(self):
        return True


class OrquestadorFalso:
    """Mismo contrato que AttackOrchestrator en lo que usa main.py."""

    ultimo_token = None
    reventar = False

    def __init__(self, session_token):
        self.session_token = session_token
        OrquestadorFalso.ultimo_token = session_token
        self.no_analizados = [{"estado": "no_analizado", "motivo": "clave invalida"}]
        self.guardado = False

    async def run_full_audit(self, target_url, field_selector="x"):
        if OrquestadorFalso.reventar:
            raise RuntimeError("playwright no responde")

    def save_results(self, filepath=None):
        self.guardado = True

    def get_vulnerabilities(self):
        return [{"id": "v1", "tipo": "SQLi"}, {"id": "v2", "tipo": "XSS"}]


def dobles():
    mod_redis = types.ModuleType("redis")
    mod_async = types.ModuleType("redis.asyncio")
    mod_async.Redis = lambda **kw: RedisFalso()
    mod_redis.asyncio = mod_async
    sys.modules["redis"] = mod_redis
    sys.modules["redis.asyncio"] = mod_async

    mod_dotenv = types.ModuleType("dotenv")
    mod_dotenv.load_dotenv = lambda *a, **k: None
    sys.modules["dotenv"] = mod_dotenv

    mod_orq = types.ModuleType("orchestrator")
    mod_orq.AttackOrchestrator = OrquestadorFalso
    sys.modules["orchestrator"] = mod_orq


def main():
    dobles()
    import main as modulo

    ESPACIO = "usuario-a"
    casos = []

    def publica(reventar=False, espacio=ESPACIO):
        OrquestadorFalso.reventar = reventar
        OrquestadorFalso.ultimo_token = None
        r = RedisFalso()
        orden = {"type": "full_audit", "url": "http://dvwa:80"}
        if espacio is not None:
            orden["espacio"] = espacio
        asyncio.run(modulo.atender(r, orden))
        return r, [json.loads(d) for _, d in r.publicado]

    # --- 1 · Se publica TODO, no solo lo que se encontro -------------------------
    def publica_las_dos_listas():
        _, msgs = publica()
        vulns = [m for m in msgs if m.get("id")]
        degradados = [m for m in msgs if m.get("estado") == "no_analizado"]
        return len(vulns) == 2 and len(degradados) == 1
    casos.append(("publica las vulnerabilidades Y lo que no se pudo analizar",
                  publica_las_dos_listas))

    def todo_al_canal_correcto():
        r, _ = publica()
        return all(c == modulo.CANAL_HALLAZGOS for c, _ in r.publicado)
    casos.append(("todo sale por el canal de hallazgos", todo_al_canal_correcto))

    # --- 2 · El dueño, no un token fijo -----------------------------------------
    def todo_lleva_el_dueño():
        _, msgs = publica()
        return msgs and all(m.get("espacio") == ESPACIO for m in msgs)
    casos.append(("cada mensaje lleva el espacio de quien pidio la auditoria",
                  todo_lleva_el_dueño))

    def el_orquestador_se_construye_con_el_dueño():
        publica()
        return OrquestadorFalso.ultimo_token == ESPACIO
    casos.append(("el orquestador se construye con el dueño, no con un token fijo",
                  el_orquestador_se_construye_con_el_dueño))

    def sin_dueño_no_se_audita():
        r, msgs = publica(espacio=None)
        return msgs == [] and OrquestadorFalso.ultimo_token is None
    casos.append(("sin dueño no se audita ni se publica nada", sin_dueño_no_se_audita))

    # --- 3 · Si la auditoria se cae, el panel se entera -------------------------
    def auditoria_caida_se_publica():
        _, msgs = publica(reventar=True)
        return (len(msgs) == 1
                and msgs[0]["estado"] == "no_analizado"
                and "playwright no responde" in msgs[0]["motivo"])
    casos.append(("si la auditoria revienta, se publica «no analizado» CON el motivo",
                  auditoria_caida_se_publica))

    def auditoria_caida_no_calla():
        _, msgs = publica(reventar=True)
        return msgs != []
    casos.append(("una auditoria caida NO deja al panel esperando en silencio",
                  auditoria_caida_no_calla))

    def caida_tambien_lleva_dueño():
        _, msgs = publica(reventar=True)
        return msgs[0].get("espacio") == ESPACIO
    casos.append(("el aviso de caida tambien va al dueño, no a todos",
                  caida_tambien_lleva_dueño))

    # --- Valores por omision, que es lo que llega si el panel manda poco ---------
    def url_por_omision():
        OrquestadorFalso.reventar = False
        r = RedisFalso()
        # El panel podria mandar la orden sin url. Auditar el laboratorio interno es un
        # defecto seguro: esta solo en la red interna y es nuestro.
        asyncio.run(modulo.atender(r, {"type": "full_audit", "espacio": ESPACIO}))
        return r.publicado != []
    casos.append(("una orden sin url usa el laboratorio interno y no revienta",
                  url_por_omision))

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
