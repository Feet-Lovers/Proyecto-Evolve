"""Modulo de IA: escucha ordenes de auditoria por el bus interno y devuelve los hallazgos.

POR QUE YA NO PREGUNTA AL BACKEND (cambiado el 10-oct-2026). Antes esto hacia
`GET /api/playwright/instruction/{token}` cada 5 segundos. Desde la Fase 2 ese router
lleva el guardian, asi que la respuesta era 401 — y el fallo era invisible: el codigo
comprobaba `status_code == 200`, un 401 no lanza excepcion, y el bucle volvia a dormir.
Encima `wait_for_backend` ignoraba su propio valor de retorno, asi que tras 30 intentos
fallidos arrancaba igual diciendo «Esperando instrucciones del backend...». El modulo
parecia sano sin poder hacer nada.
Evidencia: docs/evidencias/canal-ia-backend-muerto-10oct.md

Ahora la orden llega por Redis, que vive en la red interna y no esta publicado: la
frontera la pone la red y no una credencial que haya que custodiar. El razonamiento y las
alternativas descartadas estan en backend/services/bus_ia.py.

EL DUEÑO VIAJA CON LA ORDEN. Cada mensaje trae `espacio`, que el backend saca del guardian
al publicar. Con eso se construye el orquestador, de modo que los hallazgos vuelven a la
sesion de QUIEN pidio la auditoria y no a un `ia_session` fijo y compartido. Eso es lo que
deshace el enredo de los cuatro tokens.

Los nombres de los canales estan duplicados aqui y en bus_ia.py a proposito: son dos
contenedores con dependencias distintas y no comparten codigo. Si se cambian, se cambian
en los dos sitios — por eso cada uno nombra al otro.
"""
import asyncio
import json
import os

import redis.asyncio as aioredis
from dotenv import load_dotenv

from orchestrator import AttackOrchestrator

load_dotenv()

# Mismos valores que backend/services/bus_ia.py
CANAL_INSTRUCCIONES = "ia:instrucciones"
CANAL_HALLAZGOS = "ia:hallazgos"

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


async def publicar(r, espacio: str, hallazgo: dict):
    """Manda un hallazgo al backend con su dueño dentro."""
    mensaje = dict(hallazgo)
    mensaje["espacio"] = espacio
    await r.publish(CANAL_HALLAZGOS, json.dumps(mensaje, default=str))


async def publicar_resultados(r, espacio: str, orq) -> tuple:
    """Publica lo que la auditoria encontro Y lo que no pudo analizar (RNF-06).

    Las dos listas se leen del orquestador sin tocarlo: `get_vulnerabilities()` y el
    atributo `no_analizados`. Publicar solo las vulnerabilidades dejaria el informe
    diciendo «sin hallazgos» sobre una auditoria a medias, que es justo lo que RNF-06
    existe para impedir.
    """
    vulns = orq.get_vulnerabilities() or []
    for v in vulns:
        await publicar(r, espacio, v)

    no_analizados = getattr(orq, "no_analizados", None) or []
    for n in no_analizados:
        mensaje = dict(n)
        mensaje.setdefault("estado", "no_analizado")
        await publicar(r, espacio, mensaje)

    return len(vulns), len(no_analizados)


async def atender(r, mensaje: dict):
    """Ejecuta una auditoria pedida por el panel y devuelve lo que salga."""
    espacio = mensaje.get("espacio")
    if not espacio:
        # Sin dueño no se audita: no habria a quien devolverle el resultado, y repartirlo
        # «por si acaso» es la fuga que cerro la Fase 2.
        print("  Orden SIN espacio, descartada")
        return

    url = mensaje.get("url") or "http://dvwa:80"
    selector = mensaje.get("selector") or "input[name='id']"
    print(f"\n  -> Auditoria de {url} para el espacio {espacio[:8]}...")

    orq = AttackOrchestrator(session_token=espacio)
    try:
        await orq.run_full_audit(target_url=url, field_selector=selector)
        orq.save_results()
    except Exception as e:
        # Que la auditoria se caiga no puede terminar en silencio: el panel se quedaria
        # esperando un resultado que no llega. Se devuelve como «no analizado» con motivo,
        # que es la via de RNF-06, en vez de no devolver nada.
        print(f"  Auditoria interrumpida: {type(e).__name__}: {e}")
        await publicar(r, espacio, {
            "estado": "no_analizado",
            "origen": "auditoria",
            "url": url,
            "motivo": f"la auditoria se interrumpio: {type(e).__name__}: {e}",
        })
        return

    hallazgos, degradados = await publicar_resultados(r, espacio, orq)
    print(f"  Auditoria terminada: {hallazgos} hallazgos, {degradados} sin analizar")


async def escuchar():
    r = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT)
    await r.ping()  # si Redis no esta, se entera AQUI y no tras 30 intentos callados
    pubsub = r.pubsub()
    await pubsub.subscribe(CANAL_INSTRUCCIONES)
    print(f"  Escuchando '{CANAL_INSTRUCCIONES}'. Esperando ordenes del panel...")
    async for msg in pubsub.listen():
        if msg["type"] != "message":
            continue
        try:
            datos = json.loads(msg["data"])
        except Exception as e:
            print(f"  Orden ilegible, descartada: {e}")
            continue
        if datos.get("type") != "full_audit":
            continue
        try:
            await atender(r, datos)
        except Exception as e:
            print(f"  Error atendiendo la orden: {type(e).__name__}: {e}")


async def main():
    print(f"\n{60 * '='}")
    print("  HookSuite IA - Modulo de analisis")
    print(f"  Bus: redis://{REDIS_HOST}:{REDIS_PORT}")
    print("  Modo: suscrito al bus interno (ya no pollea el backend)")
    print(f"{60 * '='}\n")
    await escuchar()


if __name__ == "__main__":
    asyncio.run(main())
