import asyncio
import httpx
import json
import os
import uuid
from typing import Dict, List, Optional
from dotenv import load_dotenv
from datetime import datetime

from ia.analyzers.vulnerability_classifier import VulnerabilityClassifier

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
MOCK_MODE = os.getenv("MOCK_PLAYWRIGHT", "true").lower() == "true"

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1 UNION SELECT null--",
    "1 UNION SELECT null,null--",
    "' AND SLEEP(5)--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
]

FUZZING_PAYLOADS = [
    "../../../../etc/passwd",
    "%00",
    "{{7*7}}",
    "; ls -la",
]


class AttackOrchestrator:
    def __init__(self, session_token: str):
        self.session_token = session_token
        self.classifier = VulnerabilityClassifier()
        self.backend_available = False
        self.confirmed_vulnerabilities = []
        self.vulnerabilities_found = []
        self.analyses_count = 0

    # ─── Conexión con backend ────────────────────────────────────────────────

    async def check_backend(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{BACKEND_URL}/health")
                self.backend_available = response.status_code == 200
                if self.backend_available:
                    print(f"✓ Backend disponible en {BACKEND_URL}")
                return self.backend_available
        except Exception:
            print(f"⚠️  Backend no disponible. Ejecutando en modo mock.")
            self.backend_available = False
            return False

    async def send_instruction_to_playwright(self, instruction: dict) -> Optional[dict]:
        if MOCK_MODE or not self.backend_available:
            return self._mock_playwright_response(instruction)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{BACKEND_URL}/api/playwright/instruction/{self.session_token}",
                    json={**instruction, "session_token": self.session_token},
                )
                if response.status_code == 200:
                    return response.json()
        except Exception as e:
            print(f"  ✗ Error enviando instrucción: {e}")
        return None

    async def send_vulnerability_to_backend(self, vulnerability: dict) -> bool:
        if not self.backend_available:
            print(f"  📁 Vulnerabilidad guardada en local: {vulnerability.get('tipo')}")
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{BACKEND_URL}/api/vulnerabilities",
                    json=vulnerability,
                )
                return response.status_code == 200
        except Exception:
            return False

    # ─── Mock de Playwright ──────────────────────────────────────────────────

    def _mock_playwright_response(self, instruction: dict) -> dict:
        itype = instruction.get("type")

        if itype == "fingerprint":
            return {
                "result": {
                    "url": instruction.get("url"),
                    "technologies": ["PHP", "Apache", "MySQL", "jQuery"],
                    "server": "Apache/2.4.51",
                    "powered_by": "PHP/7.4.3",
                }
            }

        if itype == "spider":
            base = instruction.get("url", "http://localhost:8888")
            return {
                "discovered_urls": [
                    f"{base}/vulnerabilities/sqli/",
                    f"{base}/vulnerabilities/xss_r/",
                    f"{base}/vulnerabilities/fi/",
                ]
            }

        if itype == "attack":
            payload = instruction.get("payload", "")
            vulnerable = any(c in payload for c in ["'", "<", "../", "{{"])
            return {
                "vulnerable": vulnerable,
                "response_body": "mock response — backend no disponible",
                "status": 200,
                "time_ms": 120,
            }

        return {"status": "ok"}

    # ─── Fases de auditoría ──────────────────────────────────────────────────

    async def run_fingerprint_phase(self, target_url: str) -> Optional[dict]:
        print(f"\n📋 FASE 1: Fingerprinting de {target_url}")
        instruction = {"type": "fingerprint", "url": target_url}
        result = await self.send_instruction_to_playwright(instruction)

        if result and result.get("result"):
            fingerprint = result["result"]
            headers = {
                "server": fingerprint.get("server", ""),
                "x-powered-by": fingerprint.get("powered_by", ""),
            }
            analysis = self.classifier.fingerprint(
                headers=headers,
                url=fingerprint.get("url", target_url),
                response_body="",
            )
            if analysis:
                priorities = analysis.get("attack_priorities", [])
                print(f"  ✓ Prioridades: {[p['tipo'] for p in priorities[:3]]}")
            return analysis
        return None

    async def run_spider_phase(self, target_url: str, max_pages: int = 10) -> List[str]:
        print(f"\n🕷️  FASE 2: Spider de {target_url}")
        instruction = {"type": "spider", "url": target_url, "max_pages": max_pages}
        result = await self.send_instruction_to_playwright(instruction)

        if result and result.get("discovered_urls"):
            urls = result["discovered_urls"]
            print(f"  ✓ {len(urls)} URLs descubiertas")
            return urls
        return []

    async def run_attack_phase(
        self,
        target_url: str,
        field_selector: str,
        attack_priorities: List[str],
    ) -> List[dict]:
        print(f"\n⚔️  FASE 3: Ataques en {target_url}")
        found = []

        payload_map = {
            "sqli": SQLI_PAYLOADS,
            "xss": XSS_PAYLOADS,
            "fuzzing": FUZZING_PAYLOADS,
        }

        for attack_type in attack_priorities:
            payloads = payload_map.get(attack_type, [])
            print(f"  → Probando {attack_type.upper()} ({len(payloads)} payloads)")

            for payload in payloads:
                instruction = {
                    "type": "attack",
                    "url": target_url,
                    "selector": field_selector,
                    "payload": payload,
                    "verify": "",
                }
                result = await self.send_instruction_to_playwright(instruction)
                if not result:
                    continue

                fake_packet = {
                    "url": target_url,
                    "method": "GET",
                    "status": result.get("status", 200),
                    "time": result.get("time_ms", 100),
                    "request_body": payload,
                    "response_body": result.get("response_body", ""),
                    "suspicious_reasons": ["INJECTION_CHAR_IN_REQUEST"] if result.get("vulnerable") else [],
                }

                self.analyses_count += 1
                analysis = self.classifier.analyze_packet(fake_packet)

                if analysis and analysis.get("confianza", 0) >= 0.6:
                    confirmed = await self._confirm_vulnerability(
                        target_url, field_selector, payload, analysis
                    )
                    if confirmed:
                        vuln = self._build_vulnerability(fake_packet, analysis, attack_type)
                        found.append(vuln)
                        self.vulnerabilities_found.append(vuln)
                        await self.send_vulnerability_to_backend(vuln)
                        print(f"  ✅ {analysis.get('tipo')} confirmada — confianza {analysis.get('confianza')}")
                        break

                await asyncio.sleep(0.3)

        return found

    async def _confirm_vulnerability(
        self,
        url: str,
        selector: str,
        payload: str,
        initial_finding: dict,
        confirmations_needed: int = 2,
    ) -> bool:
        print(f"  🔄 Confirmando ({confirmations_needed} pases)...")
        confirmed = 0

        for _ in range(confirmations_needed):
            instruction = {"type": "attack", "url": url, "selector": selector, "payload": payload, "verify": ""}
            result = await self.send_instruction_to_playwright(instruction)
            if result and result.get("vulnerable"):
                confirmed += 1

        success = confirmed >= confirmations_needed
        if success:
            self.confirmed_vulnerabilities.append(initial_finding)
            print(f"  ✓ CONFIRMADA ({confirmed}/{confirmations_needed})")
        else:
            print(f"  → No confirmada ({confirmed}/{confirmations_needed})")
        return success

    def _build_vulnerability(self, source: dict, analysis: dict, source_type: str) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "tipo": analysis.get("tipo", "Unknown"),
            "severidad": analysis.get("severidad", "medium"),
            "titulo": f"{analysis.get('tipo', 'Vulnerabilidad')} en {source.get('url', '')[:60]}",
            "descripcion": analysis.get("justificacion", ""),
            "url": source.get("url", ""),
            "payload": source.get("request_body", ""),
            "recomendacion": analysis.get("recomendacion", ""),
            "confianza": analysis.get("confianza", 0),
            "source_type": source_type,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_vulnerabilities(self) -> list:
        return self.vulnerabilities_found.copy()

    def save_results(self, filepath: str = "results/vulnerabilities.json"):
        os.makedirs("results", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(
                {
                    "total_analyses": self.analyses_count,
                    "vulnerabilities_found": len(self.vulnerabilities_found),
                    "vulnerabilities": self.vulnerabilities_found,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )
        print(f"✓ {len(self.vulnerabilities_found)} vulnerabilidades guardadas en {filepath}")

    # ─── Auditoría completa ──────────────────────────────────────────────────

    async def run_full_audit(self, target_url: str, field_selector: str = "input[name='id']"):
        print(f"\n{'='*60}")
        print(f"  HookSuite IA — Auditoría orquestada")
        print(f"  Objetivo: {target_url}")
        print(f"  Modo: {'MOCK' if MOCK_MODE else 'REAL'}")
        print(f"{'='*60}")

        await self.check_backend()

        fingerprint_analysis = await self.run_fingerprint_phase(target_url)
        attack_priorities = ["sqli", "xss", "fuzzing"]
        if fingerprint_analysis:
            priorities_data = fingerprint_analysis.get("attack_priorities", [])
            attack_priorities = [
                p["tipo"].lower().replace(" ", "_")
                for p in sorted(priorities_data, key=lambda x: x.get("prioridad", 99))
            ]

        discovered_urls = await self.run_spider_phase(target_url, max_pages=10)
        target_pages = [target_url] + [u for u in discovered_urls if u != target_url][:4]

        all_vulnerabilities = []
        for page_url in target_pages:
            vulns = await self.run_attack_phase(page_url, field_selector, attack_priorities)
            all_vulnerabilities.extend(vulns)

        self.save_results()

        print(f"\n{'='*60}")
        print(f"  AUDITORÍA COMPLETADA")
        print(f"  Páginas analizadas: {len(target_pages)}")
        print(f"  Vulnerabilidades confirmadas: {len(self.confirmed_vulnerabilities)}")
        print(f"{'='*60}\n")

        return all_vulnerabilities