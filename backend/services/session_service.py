import os
import uuid
from typing import Dict, Any, List
from fastapi import WebSocket

# Topes de memoria (configurables por entorno). El estado de sesion vive en memoria:
# sin topes, cualquiera que llame a la API con un token nuevo crea una sesion mas, y
# cada peticion guardada arrastra hasta 50 KB de cuerpo -> crecimiento ilimitado.
MAX_SESSIONS = int(os.getenv("MAX_SESSIONS", "50"))
MAX_REQUESTS_PER_SESSION = int(os.getenv("MAX_REQUESTS_PER_SESSION", "1000"))


class BoundedList(list):
    """Lista con tope: al pasarse, descarta por el principio (lo mas antiguo).

    Se usa en vez de tocar las decenas de sitios que hacen
    session["requests"].append(...): el tope se aplica solo.
    """

    def __init__(self, maxlen: int, iterable=()):
        super().__init__(iterable)
        self.maxlen = maxlen
        self._trim()

    def _trim(self):
        exceso = len(self) - self.maxlen
        if exceso > 0:
            del self[0:exceso]

    def append(self, item):
        super().append(item)
        self._trim()

    def extend(self, items):
        super().extend(items)
        self._trim()


class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
        self.websockets: Dict[str, List[WebSocket]] = {}

    def _nueva_sesion(self, token: str) -> dict:
        return {
            "token": token,
            "requests": BoundedList(MAX_REQUESTS_PER_SESSION),
            "intruder_status": "idle",
            "intruder_results": [],
            "network_packets": BoundedList(MAX_REQUESTS_PER_SESSION),
            "vulnerabilities": BoundedList(MAX_REQUESTS_PER_SESSION),
        }

    def create_session(self) -> str:
        token = str(uuid.uuid4())
        self.sessions[token] = self._nueva_sesion(token)
        self.cleanup_old_sessions()
        return token

    def get_session(self, token: str) -> dict:
        if token not in self.sessions:
            self.sessions[token] = self._nueva_sesion(token)
            # Este es el camino por el que un token inventado crea sesion: se recolecta
            # aqui tambien, para que no crezca sin limite mientras /api no tenga auth.
            self.cleanup_old_sessions()
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

    def cleanup_old_sessions(self, max_sessions: int = None):
        """Recolecta sesiones viejas hasta volver al tope.

        Antes: definida pero NUNCA llamada, y ademas quitaba solo UNA por invocacion.
        Ahora se llama al crear sesion y descarta en bucle, prefiriendo las que no
        tienen WebSocket vivo para no tumbar a quien este trabajando.
        """
        tope = MAX_SESSIONS if max_sessions is None else max_sessions
        if len(self.sessions) <= tope:
            return
        # Primero, las que no tienen socket vivo (por orden de antiguedad de insercion).
        candidatas = [t for t in self.sessions if t not in self.websockets]
        for token in candidatas:
            if len(self.sessions) <= tope:
                return
            del self.sessions[token]
        # Si aun sobran, se descartan las mas antiguas aunque tengan socket.
        for token in list(self.sessions.keys()):
            if len(self.sessions) <= tope:
                return
            del self.sessions[token]
            self.websockets.pop(token, None)

session_manager = SessionManager()
