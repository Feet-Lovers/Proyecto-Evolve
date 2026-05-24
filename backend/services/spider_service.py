import httpx
import uuid
import asyncio
import random
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Set, List
from services.session_service import session_manager
from services.proxy_service import is_suspicious, get_session_client

REALISTIC_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

SKIP_EXTENSIONS = ['.css', '.js', '.png', '.jpg', '.gif', '.svg',
                   '.ico', '.woff', '.woff2', '.ttf', '.pdf', '.zip']
SKIP_PATTERNS = ['logout', 'javascript:', 'mailto:', 'tel:']

SPEED_PRESETS = {
    'rapido': 50,
    'normal': 200,
    'completo': 500
}

class SpiderService:
    def __init__(self, base_url: str, session_token: str, speed: str = 'normal', cookie: str = ''):
        self.base_url = base_url
        self.session_token = session_token
        self.max_pages = SPEED_PRESETS.get(speed, 200)
        self.base_domain = urlparse(base_url).netloc
        self.cookie = cookie
        self.visited: Set[str] = set()
        self.queue: List[str] = [base_url]

    def is_same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ''

    def normalize_url(self, url: str, current_url: str) -> str:
        if url.startswith('http'):
            return url.split('#')[0]
        if url.startswith('/'):
            parsed = urlparse(current_url)
            return f"{parsed.scheme}://{parsed.netloc}{url.split('#')[0]}"
        return urljoin(current_url, url).split('#')[0]

    def should_skip(self, url: str) -> bool:
        url_lower = url.lower()
        for ext in SKIP_EXTENSIONS:
            if url_lower.endswith(ext):
                return True
        for pattern in SKIP_PATTERNS:
            if pattern in url_lower:
                return True
        return False

    def _extract_urls(self, html: str, current_url: str) -> List[str]:
        import re
        urls = []
        matches = re.findall(r'href=["\']([^"\']+)["\']', html)
        for href in matches:
            normalized = self.normalize_url(href, current_url)
            if self.is_same_domain(normalized) and not self.should_skip(normalized):
                urls.append(normalized)
        return urls

    def _extract_forms(self, html: str, current_url: str) -> list:
        import re
        forms = []
        form_matches = re.findall(r'(<form[^>]*>)(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        for form_tag, form_html in form_matches:
            method_match = re.search(r'method=["\'](\w+)["\']', form_tag, re.IGNORECASE)
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_tag, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            action = self.normalize_url(action_match.group(1), current_url) if action_match else current_url

            # Extraer campos con sus valores por defecto
            input_matches = re.findall(r'<input([^>]*)>', form_html, re.IGNORECASE)
            fields = {}
            for input_attrs in input_matches:
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_attrs, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_attrs, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_attrs, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1)
                    value = value_match.group(1) if value_match else name
                    input_type = type_match.group(1).lower() if type_match else 'text'
                    if input_type not in ['button', 'image', 'reset']:
                        fields[name] = value

            forms.append({
                'method': method,
                'action': action,
                'fields': list(fields.keys()),
                'body': '&'.join([f'{k}={v}' for k, v in fields.items()])
            })
        return forms

    async def crawl_page(self, url: str):
        if url in self.visited or len(self.visited) >= self.max_pages:
            return
        self.visited.add(url)
        print(f'Spider visitando: {url}', flush=True)
        await asyncio.sleep(random.uniform(0.3, 0.8))
        try:
            client = get_session_client(self.session_token)
            chosen_headers = {
                'User-Agent': random.choice(REALISTIC_USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
            }
            if self.cookie:
                chosen_headers['Cookie'] = self.cookie
            start = time.time()
            response = await client.get(url, headers=chosen_headers)
            elapsed_ms = int((time.time() - start) * 1000)
            try:
                response_body = response.text
            except Exception:
                response_body = '[binary content]'

            forms = self._extract_forms(response_body, str(response.url))
            new_urls = self._extract_urls(response_body, url)
            chosen_ua = random.choice(REALISTIC_USER_AGENTS)

            result = {
                'id': str(uuid.uuid4()),
                'method': 'GET',
                'url': str(response.url),
                'status': response.status_code,
                'size': len(response.content),
                'time': elapsed_ms,
                'timestamp': datetime.utcnow().isoformat(),
                'request_headers': {
                    'User-Agent': chosen_ua,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
                    'Host': str(response.url).split('/')[2],
                },
                'request_body': None,
                'response_headers': {**dict(response.headers), **({'set-cookie': '; '.join([f'{k}={v}' for k,v in client.cookies.items()])} if client.cookies else {})},
                'response_body': response_body[:50000],
                'suspicious': is_suspicious(url, response_body, response.status_code),
                'vulnerable': False,
                'forms': forms,
                'source': 'spider'
            }

            session = session_manager.get_session(self.session_token)
            session['requests'].append(result)
            await session_manager.emit(self.session_token, 'request_intercepted', result)

            # Emitir peticiones de formularios como peticiones independientes
            for form in forms:
                if form['body']:
                    form_result = {
                        'id': str(uuid.uuid4()),
                        'method': form['method'],
                        'url': form['action'] + ('?' + form['body'] if form['method'] == 'GET' and form['body'] else ''),
                        'status': 'FORM',
                        'size': 0,
                        'time': 0,
                        'timestamp': datetime.utcnow().isoformat(),
                        'request_headers': {
                            'User-Agent': chosen_ua,
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Host': str(response.url).split('/')[2],
                        },
                        'request_body': form['body'] if form['method'] == 'POST' else None,
                        'response_headers': {},
                        'response_body': '',
                        'suspicious': False,
                        'vulnerable': False,
                        'forms': [],
                        'source': 'spider-form'
                    }
                    session['requests'].append(form_result)
                    await session_manager.emit(self.session_token, 'request_intercepted', form_result)

            for new_url in new_urls:
                if new_url not in self.visited and new_url not in self.queue:
                    self.queue.append(new_url)

        except Exception as e:
            await session_manager.emit(self.session_token, 'spider_error', {
                'url': url,
                'error': str(e)
            })

    async def run(self):
        await session_manager.emit(self.session_token, 'spider_started', {
            'base_url': self.base_url,
            'max_pages': self.max_pages
        })
        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.pop(0)
            await self.crawl_page(current_url)
        limite_alcanzado = len(self.visited) >= self.max_pages and len(self.queue) > 0
        await session_manager.emit(self.session_token, 'spider_completed', {
            'base_url': self.base_url,
            'total': len(self.visited),
            'max_pages': self.max_pages,
            'completo': not limite_alcanzado,
            'mensaje': (
                f"Spider detenido — limite de {self.max_pages} paginas alcanzado. Pueden existir paginas sin analizar."
                if limite_alcanzado else
                f"Spider completado — {len(self.visited)} paginas encontradas y analizadas. Auditoria completa."
            )
        })
