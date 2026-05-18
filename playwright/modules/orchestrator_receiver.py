import asyncio
import httpx
import json
import os
from typing import Dict, Optional
from dotenv import load_dotenv
from core.browser import browser_manager
from core.auth import login_dvwa, login_generic
from modules.attacker import WebAttacker
from modules.spider import Spider
from modules.forms import FormDiscoverer
from modules.fingerprint import TechFingerprinter
from utils.reporter import EventReporter

load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
POLL_INTERVAL = 2

class InstructionReceiver:
    def __init__(self, session_token: str):
        self.session_token = session_token
        self.running = False
        self.attacker = WebAttacker()
        self.reporter = EventReporter(session_token)

    async def execute_instruction(self, instruction: Dict, page) -> Dict:
        instruction_type = instruction.get("type", "attack")
        if instruction_type == "navigate":
            return await self._navigate(page, instruction)
        elif instruction_type == "attack":
            return await self._attack(page, instruction)
        elif instruction_type == "spider":
            return await self._spider(page, instruction)
        elif instruction_type == "fingerprint":
            return await self._fingerprint(page, instruction)
        else:
            return {
                "error": f"Tipo de instrucción desconocido:\n{instruction_type}"
            }

    async def _navigate(self, page, instruction: Dict) -> Dict:
        url = instruction.get("url")
        await page.goto(url, wait_until="networkidle", timeout=20000)
        screenshot = await self.attacker.take_screenshot(page, "navigate")
        return {
            "type": "navigate",
            "url": page.url,
            "screenshot": screenshot,
            "status": "completed",
        }

    async def _attack(self, page, instruction: Dict) -> Dict:
        url = instruction.get("url")
        selector = instruction.get("selector")
        payload = instruction.get("payload", "")
        verify = instruction.get("verify", "")

        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        if selector:
            try:
                await page.fill(selector, payload)
                await page.keyboard.press("Enter")
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception as e:
                return {"status": "error", "error": str(e)}

        response_body = await page.content()
        screenshot = await self.attacker.take_screenshot(page, "attack_result")
        anomalies = self.attacker._detect_anomalies(payload, response_body, 0, url)
        verify_found = verify.lower() in response_body.lower() if verify else False

        result = {
            "type": "attack",
            "url": page.url,
            "payload": payload,
            "response_body_snippet": response_body[:2000],
            "anomalies": anomalies,
            "verify_found": verify_found,
            "screenshot": screenshot,
            "status": "completed",
            "vulnerable": bool(anomalies) or verify_found,
        }

        if result["vulnerable"]:
            vulnerability = {
                "id": f"ia_vuln_{len(self.attacker.results) + 1}",
                "tipo": "IA Detection",
                "severidad": "high",
                "titulo": f"Vulnerabilidad detectada por IA en {url}",
                "descripcion": f"Anomalías encontradas: {anomalies}",
                "url": url,
                "payload": payload,
                "recomendacion": "Revisar y sanitizar el input del usuario.",
            }
            await self.reporter.send_vulnerability(vulnerability)

        return result

    async def _spider(self, page, instruction: Dict) -> Dict:
        url = instruction.get("url")
        max_pages = instruction.get("max_pages", 10)
        spider = Spider(base_url=url, max_pages=max_pages)
        discovered = await spider.run(page)
        spider.save_results()
        return {
            "type": "spider",
            "discovered_urls": discovered,
            "total": len(discovered),
            "status": "completed",
        }

    async def _fingerprint(self, page, instruction: Dict) -> Dict:
        url = instruction.get("url")
        fingerprinter = TechFingerprinter()
        result = await fingerprinter.fingerprint(page, url)
        await self.reporter.send_fingerprint(result)
        return {
            "type": "fingerprint",
            "result": result,
            "status": "completed",
        }

    async def poll_for_instructions(self):
        self.running = True
        print(f"✓ Iniciando polling de instrucciones desde {BACKEND_URL}")
        await browser_manager.start()
        context = await browser_manager.new_context()
        page = await browser_manager.new_page(context)
        await login_dvwa(page)
        await self.reporter.check_backend()

        while self.running:
            try:
                if self.reporter.backend_available:
                    async with httpx.AsyncClient(timeout=5) as client:
                        response = await client.get(
                            f"{BACKEND_URL}/api/playwright/instruction/{self.session_token}"
                        )
                        if response.status_code == 200:
                            data = response.json()
                            instructions = data.get("instructions", [])
                            if instructions:
                                instruction = instructions[0]
                                print(f"Instruccion recibida: {instruction.get('type')}")
                                result = await self.execute_instruction(instruction, page)
                                await client.post(
                                    f"{BACKEND_URL}/api/playwright/result/{self.session_token}",
                                    json=result,
                                )
                                print("Resultado enviado al backend")
            except Exception as e:
                print(f"Error en polling: {e}")

            await asyncio.sleep(POLL_INTERVAL)

        await browser_manager.stop()

    def stop(self):
        self.running = False
