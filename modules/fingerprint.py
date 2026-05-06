from playwright.async_api import Page, Response
from typing import Dict, List
import re
import json
import os
class TechFingerprinter:
    TECH_SIGNATURES = {
        "PHP": {
            "headers": ["X-Powered-By: PHP"],
            "cookies": ["PHPSESSID"],
            "url_patterns": [r"\.php(\?|$)"],
        },
        "ASP.NET": {
            "headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"],
            "cookies": ["ASP.NET_SessionId", "ASPSESSIONID"],
            "url_patterns": [r"\.aspx?(\?|$)"],
        },
        "Java": {
            "cookies": ["JSESSIONID"],
            "url_patterns": [r"\.jsp(\?|$)", r"\.do(\?|$)"],
        },
        "WordPress": {
            "url_patterns": [r"/wp-content/", r"/wp-admin/", r"/wp-login\.php"],
            "html_patterns": [r"wp-content", r"wordpress"],
        },
        "Nginx": {
            "headers": ["Server: nginx"],
        },
        "Apache": {
            "headers": ["Server: Apache"],
        },
        "MySQL": {
            "error_patterns": [r"You have an error in your SQL syntax",
                r"mysql_fetch"],
        },
        "jQuery": {
            "html_patterns": [r"jquery\.min\.js", r"jquery-\d+\.\d+"],
        },
        "Bootstrap": {
            "html_patterns": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
        },
    }
    def __init__(self):
        self.detected_tech = {}
        self.response_headers = {}
        self.cookies = {}
    async def fingerprint(self, page: Page, url: str) -> Dict:
        detected = {}
        response_headers = {}
        async def handle_response(response: Response):
            if response.url == url or url in response.url:
                try:
                    response_headers.update(dict(response.headers))
                except Exception:
                    pass
        page.on("response", handle_response)
        try:
            await page.goto(url, wait_until="networkidle", timeout=20000)
            html_content = await page.content()
            cookies = await page.context.cookies()
            cookie_names = [c['name'] for c in cookies]
            for tech, signatures in self.TECH_SIGNATURES.items():
                tech_detected = False
                for header_sig in signatures.get("headers", []):
                    header_name, header_value = header_sig.split(": ", 1)
                    if header_name.lower() in response_headers:
                        if header_value.lower() in response_headers[header_name.lower()].lower():
                            tech_detected = True
                            break
                if not tech_detected:
                    for cookie_sig in signatures.get("cookies", []):
                        if cookie_sig in cookie_names:
                            tech_detected = True
                            break
                if not tech_detected:
                    for url_pattern in signatures.get("url_patterns", []):
                        if re.search(url_pattern, url, re.IGNORECASE):
                            tech_detected = True
                            break
                if not tech_detected:
                    for html_pattern in signatures.get("html_patterns", []):
                        if re.search(html_pattern, html_content, re.IGNORECASE):
                            tech_detected = True
                            break
                if tech_detected:
                    detected[tech] = True
        except Exception as e:
            print(f"✗ Error en fingerprinting de {url}: {e}")
        finally:
            page.remove_listener("response", handle_response)
        server = response_headers.get("server", "Unknown")
        powered_by = response_headers.get("x-powered-by", None)
        result = {
            "url": url,
            "technologies": list(detected.keys()),
            "server": server,
            "powered_by": powered_by,
            "response_headers": response_headers,
            "attack_priorities": self._get_attack_priorities(detected),
        }
        print(f"✓ Tecnologías detectadas en {url}: {result['technologies']}")
        self.save_results(result)
        return result
    def _get_attack_priorities(self, detected: Dict) -> List[str]:
        priorities = []
        if "PHP" in detected or "MySQL" in detected:
            priorities.extend(["sqli", "blind_sqli", "file_inclusion"])
        if "ASP.NET" in detected:
            priorities.extend(["sqli", "xss", "viewstate"])
        if "WordPress" in detected:
            priorities.extend(["sqli", "xss", "plugin_vulnerabilities"])
        if not priorities:
            priorities.extend(["xss", "sqli", "fuzzing"])
        return list(dict.fromkeys(priorities))
    def save_results(self, result: Dict, filepath: str =
        "results/fingerprint.json"):
        os.makedirs("results", exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(result, f, indent=2)