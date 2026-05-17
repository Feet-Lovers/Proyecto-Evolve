import httpx
import asyncio
import uuid
from datetime import datetime
from mitmproxy import http

BACKEND_URL = "http://127.0.0.1:8000"

IGNORED_EXTENSIONS = ['.css', '.woff', '.woff2', '.ttf', '.ico', '.png', '.jpg', '.gif', '.svg']

IGNORED_HOSTS = [
    '91.98.143.219:80',
    '91.98.143.219:8000',
    '91.98.143.219:3000',
]

SUSPICIOUS_PARAMS = ["'", '"', '<', '>', 'UNION', 'SELECT', '--', ';']
ERROR_KEYWORDS = ['sql syntax', 'mysql_fetch', 'ora-', 'pg_query', 'sqlite_']

def should_filter(url: str, host: str = '') -> bool:
    if any(ignored == host for ignored in IGNORED_HOSTS):
        return True
    url_lower = url.lower().split('?')[0]
    if any(url_lower.endswith(ext) for ext in IGNORED_EXTENSIONS):
        return True
    return False

def is_suspicious(url: str, response_body: str, status: int) -> bool:
    if status >= 500:
        return True
    for param in SUSPICIOUS_PARAMS:
        if param in url:
            return True
    body_lower = (response_body or '').lower()
    return any(kw in body_lower for kw in ERROR_KEYWORDS)

class HookSuiteAddon:
    def __init__(self):
        self.request_data = {}
        self.request_times = {}

    def request(self, flow: http.HTTPFlow):
        host = flow.request.host_header or ''
        if should_filter(flow.request.pretty_url, host):
            return
        request_id = str(uuid.uuid4())
        flow.request.headers["X-HookSuite-ID"] = request_id
        self.request_times[request_id] = asyncio.get_event_loop().time()
        self.request_data[request_id] = {
            "id": request_id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text(strict=False),
            "timestamp": datetime.utcnow().isoformat(),
        }
        phpsessid = flow.request.cookies.get("PHPSESSID", "")
        if phpsessid:
            asyncio.ensure_future(self._store_session_cookie(host, phpsessid))

    def response(self, flow: http.HTTPFlow):
        request_id = flow.request.headers.get("X-HookSuite-ID", "")
        if request_id not in self.request_data:
            return
        req_data = self.request_data.pop(request_id)
        start_time = self.request_times.pop(request_id, 0)
        elapsed_ms = int((asyncio.get_event_loop().time() - start_time) * 1000) if start_time else 0
        response_body = flow.response.get_text(strict=False)[:50000]
        packet = {
            **req_data,
            "status": flow.response.status_code,
            "size": len(flow.response.content),
            "time": elapsed_ms,
            "response_headers": dict(flow.response.headers),
            "response_body": response_body,
            "suspicious": is_suspicious(req_data["url"], response_body, flow.response.status_code),
            "vulnerable": False,
        }
        asyncio.ensure_future(self._send_packet(packet))

    async def _store_session_cookie(self, host: str, phpsessid: str):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(f"{BACKEND_URL}/api/network/session_cookie", json={
                    "host": host,
                    "phpsessid": phpsessid,
                })
        except Exception:
            pass

    async def _send_packet(self, packet: dict):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(f"{BACKEND_URL}/api/network/packet", json=packet)
        except Exception as e:
            print(f"Error enviando paquete: {e}")

addons = [HookSuiteAddon()]
