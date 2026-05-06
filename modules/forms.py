from playwright.async_api import Page
from typing import List, Dict, Optional
import json
import os
from urllib.parse import urljoin

class FormDiscoverer:
    async def discover_forms(self, page: Page, url: str) -> List[Dict]:
        forms = []
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            form_elements = await page.query_selector_all('form')
            for i, form in enumerate(form_elements):
                action = await form.get_attribute('action') or url
                method = (await form.get_attribute('method') or 'GET').upper()
                if not action.startswith('http'):
                    action = urljoin(url, action)
                fields = []
                inputs = await form.query_selector_all('input, select, textarea')
                for input_el in inputs:
                    field_type = await input_el.get_attribute('type') or 'text'
                    field_name = await input_el.get_attribute('name') or ''
                    field_value = await input_el.get_attribute('value') or ''
                    if field_type.lower() in ['submit', 'button', 'image', 'reset']:
                        continue
                    fields.append({
                        "name": field_name,
                        "type": field_type,
                        "value": field_value,
                    })
                if fields:
                    forms.append({
                        "url": url,
                        "action": action,
                        "method": method,
                        "fields": fields,
                        "injectable_fields": [
                            f for f in fields if f["type"] in
                            ['text', 'search', 'email', 'url', 'hidden', 'password']
                        ],
                    })
            print(f" → {url}: {len(forms)} formularios encontrados")
        except Exception as e:
            print(f" ✗ Error en {url}: {e}")
        return forms

    async def discover_ajax_endpoints(self, page: Page, url: str) -> List[Dict]:
        ajax_requests = []

        async def handle_request(request):
            if request.resource_type in ['xhr', 'fetch']:
                ajax_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                })

        page.on("request", handle_request)
        try:
            await page.goto(url, wait_until="networkidle", timeout=20000)
            clickable = await page.query_selector_all('button, a, [onclick]')
            for element in clickable[:10]:
                try:
                    await element.click(timeout=2000)
                    await page.wait_for_timeout(500)
                except Exception:
                    pass
        except Exception as e:
            print(f" ✗ Error descubriendo AJAX en {url}: {e}")
        finally:
            page.remove_listener("request", handle_request)
        return ajax_requests

    async def scan_all_pages(self, page: Page, urls: List[str]) -> List[Dict]:
        all_forms = []
        for url in urls:
            forms = await self.discover_forms(page, url)
            all_forms.extend(forms)
        print(f"\n✓ Descubrimiento completado: {len(all_forms)} formularios en {len(urls)} páginas")
        return all_forms

    def save_results(self, forms: List[Dict], filepath: str = "results/forms_discovered.json"):
        os.makedirs(os.path.dirname(filepath) or "results", exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({"forms": forms, "total": len(forms)}, f, indent=2, ensure_ascii=False)
        print(f"✓ Formularios guardados en {filepath}")