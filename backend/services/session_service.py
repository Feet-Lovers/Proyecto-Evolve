import uuid
from typing import Dict, Any
from fastapi import WebSocket

class SessionManager:
	def __init__(self):
		self.sessions: Dict[str, dict] = {}
		self.websockets: Dict[str, WebSocket] = {}

	def create_session(self) -> str:
		token = str(uuid.uuid4())
		self.sessions[token] = {
			"token": token,
			"requests": [],
			"intruder_status": "idle",
			"intruder_results": [],
			"network_packets": [],
		}
		return token

	def get_session(self, token: str) -> dict:
		if token not in self.sessions:
			self.sessions[token] = {
				"token": token,
				"requests": [],
				"intruder_status": "idle",
				"intruder_results": [],
				"network_packets": [],
			}
		return self.sessions[token]

	def register_websocket(self, token: str, ws: WebSocket):
		self.websockets[token] = ws

	def unregister_websocket(self, token: str):
		if token in self.websockets:
			del self.websockets[token]

	async def emit(self, token: str, event_type: str, payload: Any):
		if token in self.websockets:
			try:
				await self.websockets[token].send_json({
					"type": event_type,
					"payload": payload
				})
			except Exception:
				self.unregister_websocket(token)

	def cleanup_old_sessions(self, max_sessions: int = 100):
		if len(self.sessions) > max_sessions:
			oldest = list(self.sessions.keys())[0]
			del self.sessions[oldest]

session_manager = SessionManager()