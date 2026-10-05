import uuid
from typing import Dict, Any, List
from fastapi import WebSocket

class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
        self.websockets: Dict[str, List[WebSocket]] = {}

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
        # Lista de sockets por token: varios consumidores del frontend (y varias
        # pestanas) comparten token sin pisarse. Antes era 1 socket/token y el
        # segundo register sobrescribia al primero (last-wins).
        self.websockets.setdefault(token, [])
        if ws not in self.websockets[token]:
            self.websockets[token].append(ws)

    def unregister_websocket(self, token: str, ws: WebSocket = None):
        if token not in self.websockets:
            return
        if ws is None:
            del self.websockets[token]  # compat: quita todos los del token
            return
        self.websockets[token] = [w for w in self.websockets[token] if w is not ws]
        if not self.websockets[token]:
            del self.websockets[token]

    async def emit(self, token: str, event_type: str, payload: Any):
        dead = []
        for ws in list(self.websockets.get(token, [])):
            try:
                await ws.send_json({"type": event_type, "payload": payload})
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.unregister_websocket(token, ws)

    async def emit_all(self, event_type: str, payload: Any):
        for token in list(self.websockets.keys()):
            await self.emit(token, event_type, payload)

    def cleanup_old_sessions(self, max_sessions: int = 100):
        if len(self.sessions) > max_sessions:
            oldest = list(self.sessions.keys())[0]
            del self.sessions[oldest]

session_manager = SessionManager()
