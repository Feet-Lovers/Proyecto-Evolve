import httpx
from urllib.parse import urlparse
import uuid
import time
from datetime import datetime
from typing import Optional, Dict

IGNORED_DOMAINS = [
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'facebook.com', 'twitter.com', 'cdn.cloudflare.com',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
]
IGNORED_EXTENSIONS = ['.css', '.woff', '.woff2', '.ttf', '.ico', '.png', '.jpg', '.gif', '.svg']

def should_filter(url: str) -> bool:
    url_lower = url.lower()
    for domain in IGNORED_DOMAINS:
        if domain in url_lower:
            return True
    for ext in IGNORED_EXTENSIONS:
        if url_lower.split('?')[0].endswith(ext):
            return True
    return False

def is_suspicious(url: str, response_body: str, status: int) -> bool:
    if status >= 500:
        return True
    suspicious_params = ["'", '"', '<', '>', 'UNION', 'SELECT', '--', ';']
    for param in suspicious_params:
        if param in url:
            return True
    error_keywords = ['sql syntax', 'mysql_fetch', 'ORA-', 'pg_query', 'sqlite_']
    body_lower = response_body.lower() if response_body else ''
    for keyword in error_keywords:
        if keyword.lower() in body_lower:
            return True
    return False

# Clientes persistentes por sesion
_session_clients: Dict[str, httpx.AsyncClient] = {}

def get_session_client(session_token: str) -> httpx.AsyncClient:
    if session_token not in _session_clients:
        _session_clients[session_token] = httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=30,
        )
    return _session_clients[session_token]

def _mensaje_de_error(exc: Exception, url: str) -> str:
    """Traduce el fallo de red a algo que el operador pueda leer.

    El mensaje crudo de la libreria no dice ni que host fallo: un
    "[Errno -2] Name or service not known" deja al usuario sin pista.
    """
    host = urlparse(url).hostname or url
    detalle = str(exc).strip() or exc.__class__.__name__
    texto = detalle.lower()
    if "name or service not known" in texto or "nodename nor servname" in texto or "temporary failure in name resolution" in texto:
        return f"Error: no se pudo resolver el host '{host}'. Comprueba el dominio (o si hay DNS disponible). Detalle: {detalle}"
    if "connection refused" in texto:
        return f"Error: '{host}' rechazo la conexion (puerto cerrado o servicio caido). Detalle: {detalle}"
    if "certificate" in texto or "ssl" in texto:
        return f"Error: fallo de TLS al conectar con '{host}'. Detalle: {detalle}"
    if "network is unreachable" in texto or "no route to host" in texto:
        return f"Error: no hay ruta hasta '{host}'. Detalle: {detalle}"
    return f"Error al conectar con '{host}': {detalle}"


async def forward_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: int = 30,
    session_token: str = None,
) -> dict:
    start = time.time()
    request_id = str(uuid.uuid4())
    protected_headers = ['host', 'content-length', 'transfer-encoding', 'connection']
    clean_headers = {k: v for k, v in headers.items() if k.lower() not in protected_headers}

    try:
        if session_token:
            client = get_session_client(session_token)
            response = await client.request(
                method=method,
                url=url,
                headers=clean_headers,
                content=body.encode() if body else None,
            )
        else:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=clean_headers,
                    content=body.encode() if body else None,
                )

        elapsed_ms = int((time.time() - start) * 1000)
        try:
            response_body = response.text
        except Exception:
            response_body = '[binary content]'

        suspicious = is_suspicious(url, response_body, response.status_code)

        # Detectar cookies de sesion y notificar al frontend
        if session_token:
            cookies = dict(client.cookies)
            if cookies:
                from services.session_service import session_manager
                import asyncio
                asyncio.create_task(session_manager.emit(session_token, 'session_cookies', {
                    'cookies': cookies,
                    'url': url
                }))

        return {
            "id": request_id,
            "method": method,
            "url": url,
            "status": response.status_code,
            "size": len(response.content),
            "time": elapsed_ms,
            "timestamp": datetime.utcnow().isoformat(),
            "request_headers": dict(headers),
            "request_body": body,
            "response_headers": dict(response.headers),
            "response_body": response_body[:50000],
            "suspicious": suspicious,
            "vulnerable": False,
        }
    except httpx.TimeoutException:
        return {
            "id": request_id,
            "method": method,
            "url": url,
            "status": 0,
            "size": 0,
            "time": int((time.time() - start) * 1000),
            "timestamp": datetime.utcnow().isoformat(),
            "request_headers": dict(headers),
            "request_body": body,
            "response_headers": {},
            "response_body": "Error: Timeout",
            "suspicious": False,
            "vulnerable": False,
        }
    except Exception as e:
        return {
            "id": request_id,
            "method": method,
            "url": url,
            "status": 0,
            "size": 0,
            "time": int((time.time() - start) * 1000),
            "timestamp": datetime.utcnow().isoformat(),
            "request_headers": dict(headers),
            "request_body": body,
            "response_headers": {},
            "response_body": _mensaje_de_error(e, url),
            "suspicious": False,
            "vulnerable": False,
        }
