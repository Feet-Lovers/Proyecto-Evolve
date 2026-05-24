from fastapi import APIRouter
from models.schemas import RepeaterRequest, ParseRequest
from services.proxy_service import forward_request
from services.session_service import session_manager
import re

router = APIRouter()

@router.post("/send")
async def send_request(request: RepeaterRequest):
	result = await forward_request(
		method=request.method,
		url=request.url,
		headers=request.headers,
		body=request.body,
		session_token=request.session_token,
	)
	return result

@router.post("/parse")
async def parse_request(parse_request: ParseRequest):
	text = parse_request.text.strip()

	if text.startswith("curl"):
		return parse_curl(text)
	else:
		return parse_raw_http(text)

def parse_raw_http(text: str) -> dict:
	lines = text.split('\n')
	first_line = lines[0].strip().split(' ')
	method = first_line[0] if len(first_line) > 0 else 'GET'
	path = first_line[1] if len(first_line) > 1 else '/'
	
	headers = {}
	host = ''
	body_start = 0

	for i, line in enumerate(lines[1:], 1):
		if line.strip() == '':
			body_start = i + 1
			break
		if ':' in line:
			key, value = line.split(':', 1)
			headers[key.strip()] = value.strip()
			if key.strip().lower() == 'host':
				host = value.strip()

	body = '\n'.join(lines[body_start:]).strip() if body_start > 0 else None

	protocol = 'https' if ':443' in host else 'http'
	url = f"{protocol}://{host}{path}" if host else path

	return {
		"method": method,
		"url": url,
		"headers": headers,
		"body": body or None,
	}

def parse_curl(text: str) -> dict:
	method = 'GET'
	url = ''
	headers = {}
	body = None

	method_match = re.search(r'-X\s+(\w+)', text)
	if method_match:
		method = method_match.group(1)

	url_match = re.search(r"curl\s+(?:-[^\s]+\s+)*'?\"?([^'\"\\s]+)'?\"?", text)
	if url_match:
		url = url_match.group(1)

	header_matches = re.findall(r"-H\s+'([^']+)'|-H\s+\"([^\"]+)\"", text)
	for match in header_matches:
		header_str = match[0] or match[1]
		if ':' in header_str:
			key, value = header_str.split(':', 1)
			headers[key.strip()] = value.strip()

	body_match = re.search(r"(?:-d|--data)\s+'([^']+)'|(?:-d|--data)\s+\"([^\"]+)\"", text)
	if body_match:
		body = body_match.group(1) or body_match.group(2)
		if not method_match:
			method = 'POST'

	return {
		"method": method,
		"url": url,
		"headers": headers,
		"body": body,
	}

@router.get("/history/{token}")
async def get_history(token: str):
	session = session_manager.get_session(token)
	return session.get("requests", [])[-100:]