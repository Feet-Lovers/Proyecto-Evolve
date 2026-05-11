import asyncio
import json
import os
from typing import Dict
from dotenv import load_dotenv
from core.browser import browser_manager
from core.auth import login_dvwa
from modules.spider import Spider
from modules.forms import FormDiscoverer
from modules.fingerprint import TechFingerprinter
from modules.attacker import WebAttacker
from utils.reporter import EventReporter
load_dotenv()
TARGET_URL = os.getenv("DVWA_URL", "http://localhost:8888")
async def main(target_url, session_token):
    print(f"\n{'='*60}")
    print(f" HookSuite — Auditoría automática")
    print(f" Objetivo: {target_url}")
    print(f"{'='*60}\n")
    reporter = EventReporter(session_token)
    await reporter.check_backend()
    await browser_manager.start()
    context = await browser_manager.new_context()
    page = await browser_manager.new_page(context)
    print("\n📋 FASE 1: Autenticación")
    authenticated = await login_dvwa(page)
    if not authenticated:
        print("✗ No se pudo autenticar. Abortando.")
        await browser_manager.stop()
        return
    print("\n📋 FASE 2: Fingerprinting")
    fingerprinter = TechFingerprinter()
    fingerprint = await fingerprinter.fingerprint(page, target_url)
    await reporter.send_fingerprint(fingerprint)
    attack_priorities = fingerprint.get("attack_priorities", ["sqli", "xss"])
    print(f" Prioridades de ataque: {attack_priorities}")
    print("\n📋 FASE 3: Reconocimiento (Spider)")
    spider = Spider(base_url=target_url, max_pages=15)
    discovered_urls = await spider.run(page)
    spider.save_results()
    print("\n📋 FASE 4: Descubrimiento de formularios")
    form_discoverer = FormDiscoverer()
    all_forms = await form_discoverer.scan_all_pages(page, discovered_urls[:10])
    form_discoverer.save_results(all_forms)
    print(f"\n📋 FASE 5: Ataques automatizados")
    attacker = WebAttacker()
    vulnerabilities_found = []
    for form in all_forms[:5]:
        if not form.get("injectable_fields"):
            continue
        for field in form["injectable_fields"][:2]:
            field_name = field["name"]
            print(f"\n 🎯 Atacando campo '{field_name}' en {form['url']}")
            if "sqli" in attack_priorities:
                sqli_payloads = [
"' OR '1'='1",
"' OR '1'='1'--",
"1 UNION SELECT null--",
]
                for payload in sqli_payloads:
                    result = await attacker.fill_form_with_payload(
page, form, field_name, payload
)
                    if result.get("anomalies"):
                        print(f" ⚠ Anomalías detectadas: {result['anomalies']}")
                        vulnerability = {
"id": f"vuln_{len(vulnerabilities_found)+1}",
"tipo": "SQL Injection",
"severidad": "critical",
"titulo": f"SQL Injection en campo '{field_name}'",
"descripcion": f"El campo '{field_name}' en {form['url']} es vulnerable a SQL Injection.",
"url": form["url"],
"payload": payload,
"anomalies": result["anomalies"],
"recomendacion": "Usar consultas preparadas con parámetros enlazados. Nunca concatenar input de usuario en consultas SQL.",
"screenshot": result.get("screenshot_after"),
}
                        vulnerabilities_found.append(vulnerability)
                        await reporter.send_vulnerability(vulnerability)
                        break
            if "sqli" in attack_priorities:
                blind_result = await attacker.test_sqli_blind_boolean(
page, form, field_name
)
                if blind_result.get("vulnerable"):
                    vulnerability = {
"id": f"vuln_{len(vulnerabilities_found)+1}",
"tipo": "Blind SQL Injection",
"severidad": "critical",
"titulo": f"Blind SQLi en campo '{field_name}'",
"descripcion": f"Posible Blind SQL Injection detectado por diferencia en respuestas booleanas.",
"url": form["url"],
"payload": "Boolean-based blind",
"recomendacion": "Usar consultas preparadas. Nunca usar input del usuario directamente en consultas SQL.",
"evidence": blind_result,
}
                    vulnerabilities_found.append(vulnerability)
                    await reporter.send_vulnerability(vulnerability)
    attacker.save_results()
    reporter.save_local_log()
    print(f"\n{'='*60}")
    print(f" AUDITORÍA COMPLETADA")
    print(f" URLs descubiertas: {len(discovered_urls)}")
    print(f" Formularios analizados: {len(all_forms)}")
    print(f" Vulnerabilidades encontradas: {len(vulnerabilities_found)}")
    print(f"{'='*60}\n")
    await browser_manager.stop()
    return vulnerabilities_found
async def receive_instruction(instruction: Dict) -> Dict:
    url = instruction.get("url")
    field_selector = instruction.get("selector")
    payload = instruction.get("payload")
    session_token = instruction.get("session_token")
    reporter = EventReporter(session_token)
    await reporter.check_backend()
    await browser_manager.start()
    context = await browser_manager.new_context()
    page = await browser_manager.new_page(context)
    try:
        await page.goto(url, wait_until="networkidle", timeout=20000)
        if field_selector:
            await page.fill(field_selector, payload or "")
            await page.keyboard.press("Enter")
            await page.wait_for_load_state("networkidle", timeout=10000)
        response_body = await page.content()
        screenshot = await WebAttacker().take_screenshot(page, "instruction_result")
        result = {
            "url": page.url,
            "response_body_snippet": response_body[:2000],
            "screenshot": screenshot,
            "status": "completed",
        }
        await reporter.send_network_packet(result)
        return result
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        await browser_manager.stop()
if __name__ == "__main__":
    asyncio.run(main(TARGET_URL, session_token="default_session"))