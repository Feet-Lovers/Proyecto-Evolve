from fastapi import APIRouter
from models.schemas import HashRequest, EncodeRequest, RegexRequest
import hashlib
import base64
import urllib.parse
import html
import re

router = APIRouter()

@router.post("/hash")
async def generate_hashes(request: HashRequest):
	text_bytes = request.text.encode('utf-8')
	return {
		"md5": hashlib.md5(text_bytes).hexdigest(),
		"sha1": hashlib.sha1(text_bytes).hexdigest(),
		"sha256": hashlib.sha256(text_bytes).hexdigest(),
		"sha512": hashlib.sha512(text_bytes).hexdigest(),
	}

@router.post("/encode")
async def encode_decode(request: EncodeRequest):
	text = request.text
	encode_type = request.type

	try:
		if encode_type == "base64_encode":
			result = base64.b64encode(text.encode()).decode()
		elif encode_type == "base64_decode":
			result = base64.b64decode(text.encode()).decode()
		elif encode_type == "url_encode":
			result = urllib.parse.quote(text)
		elif encode_type == "url_decode":
			result = urllib.parse.unquote(text)
		elif encode_type == "html_encode":
			result = html.escape(text)
		elif encode_type == "html_decode":
			result = html.unescape(text)
		else:
			result = f"Tipo no soportado: {encode_type}"

		return {"result": result, "type": encode_type}
	
	except Exception as e:
		return {"error": str(e), "type": encode_type}

@router.post("/regex")
async def test_regex(request: RegexRequest):
	try:
		python_flags = 0
		if 'i' in request.flags:
			python_flags |= re.IGNORECASE
		if 'm' in request.flags:
			python_flags |= re.MULTILINE
		if 's' in request.flags:
			python_flags |= re.DOTALL
		pattern = re.compile(request.pattern, python_flags)
		matches = []

		for match in pattern.finditer(request.text):
			matches.append({
				"match": match.group(),
				"start": match.start(),
				"end": match.end(),
				"groups": list(match.groups()),
			})

		return {
			"matches": matches,
			"count": len(matches),
			"error": None,
		}

	except re.error as e:
		return {
			"matches": [],
			"count": 0,
			"error": str(e),
		}