from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class ProxyRequest(BaseModel):
	method: str
	url: str
	headers: Dict[str, str] = {}
	body: Optional[str] = None
	session_token: str

class ProxyResponse(BaseModel):
	id: str
	method: str
	url: str
	status: int
	size: int
	time: int
	timestamp: str
	request_headers: Dict[str, str] = {}
	request_body: Optional[str] = None
	response_headers: Dict[str, str] = {}
	response_body: Optional[str] = None
	suspicious: bool = False
	vulnerable: bool = False

class RepeaterRequest(BaseModel):
	method: str
	url: str
	headers: Dict[str, str] = {}
	body: Optional[str] = None

class ParseRequest(BaseModel):
	text: str

class IntruderConfig(BaseModel):
	url: str
	injection_point: str
	attack_type: str
	session_token: str
	concurrency: int = 5
	delay_ms: int = 0

class NetworkPacket(BaseModel):
	id: str
	method: str
	url: str
	status: int
	size: int
	time: int
	timestamp: str
	request_headers: Dict[str, str] = {}
	request_body: Optional[str] = None
	response_headers: Dict[str, str] = {}
	response_body: Optional[str] = None
	suspicious: bool = False
	vulnerable: bool = False

class HashRequest(BaseModel):
	text: str

class EncodeRequest(BaseModel):
	text: str
	type: str

class RegexRequest(BaseModel):
	pattern: str
	text: str
	flags: str = "g"