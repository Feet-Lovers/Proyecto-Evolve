import httpx
import uuid
import time
from datetime import datetime
from typing import Optional, Dict

IGNORED_DOMAINS = [
	'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
	'facebook.com', 'twitter.com', 'cdn.cloudflare.com',
	'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
]

IGNORED_EXTENSIONS = ['.css', '.woff', '.woff2', '.ttf', '.ico', '.png', '.jpg', 
'.gif', '.svg']

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

async def forward_request(
	method: str,
	url: str,
	headers: Dict[str, str],
	body: Optional[str],
	timeout: int = 30
) -> dict:
	start = time.time()
	request_id = str(uuid.uuid4())

	protected_headers = ['host', 'content-length', 'transfer-encoding', 'connection']
	clean_headers = {k: v for k, v in headers.items() if k.lower() not in protected_headers}

	try:
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
				"response_body": f"Error: {str(e)}",
				"suspicious": False,
				"vulnerable": False,
			}