import asyncio
import json
import websockets
import httpx
from typing import Callable, Dict
from dotenv import load_dotenv
import os

load_dotenv()

DEBUG_PORT = int(os.getenv("CHROME_DEBUG_PORT", 9222))

class CDPClient:
    def __init__(self):
        self.ws = None
        self.message_id = 0
        self.pending_commands = {}
        self.event_handlers: Dict[str, list] = {}
        self.connected = False

    async def connect(self, tab_url: str = None) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"http://localhost:{DEBUG_PORT}/json")
                tabs = response.json()
                if not tabs:
                    print("✗ No hay pestañas disponibles en Chrome")
                    return False
                target_tab = None
                if tab_url:
                    for tab in tabs:
                        if tab_url in tab.get("url", ""):
                            target_tab = tab
                            break
                if not target_tab:
                    target_tab = tabs[0]
                ws_url = target_tab.get("webSocketDebuggerUrl")
                if not ws_url:
                    print("✗ La pestaña no tiene WebSocket debugger URL")
                    return False
                self.ws = await websockets.connect(ws_url, max_size=100 * 1024 * 1024)
                self.connected = True
                print(f"✓ Conectado al CDP: {target_tab.get('title', 'Sin título')}")
                asyncio.create_task(self._listen())
                return True
        except Exception as e:
            print(f"✗ Error conectando al CDP: {e}")
            return False

    async def _listen(self):
        try:
            async for message in self.ws:
                data = json.loads(message)
                if "id" in data and data["id"] in self.pending_commands:
                    future = self.pending_commands.pop(data["id"])
                    if not future.done():
                        future.set_result(data.get("result", {}))
                if "method" in data:
                    method = data["method"]
                    for handler in self.event_handlers.get(method, []):
                        asyncio.create_task(handler(data.get("params", {})))
        except websockets.exceptions.ConnectionClosed:
            self.connected = False
        except Exception as e:
            print(f"✗ Error en listener CDP: {e}")

    async def send(self, method: str, params: dict = None) -> dict:
        if not self.connected:
            return {}
        self.message_id += 1
        msg_id = self.message_id
        message = {"id": msg_id, "method": method, "params": params or {}}
        future = asyncio.get_running_loop().create_future()
        self.pending_commands[msg_id] = future
        await self.ws.send(json.dumps(message))
        try:
            return await asyncio.wait_for(future, timeout=10.0)
        except asyncio.TimeoutError:
            self.pending_commands.pop(msg_id, None)
            return {}

    def on(self, event: str, handler: Callable):
        if event not in self.event_handlers:
            self.event_handlers[event] = []
        self.event_handlers[event].append(handler)

    async def enable_network(self):
        await self.send("Network.enable")
        print("✓ Network domain activado")

    async def enable_console(self):
        await self.send("Console.enable")
        print("✓ Console domain activado")

    async def enable_page(self):
        await self.send("Page.enable")
        print("✓ Page domain activado")

    async def navigate(self, url: str):
        await self.send("Page.navigate", {"url": url})
        await asyncio.sleep(2)

    async def get_response_body(self, request_id: str) -> str:
        result = await self.send("Network.getResponseBody", {"requestId": request_id})
        body = result.get("body", "")
        if result.get("base64Encoded"):
            import base64
            try:
                body = base64.b64decode(body).decode("utf-8", errors="replace")
            except Exception:
                body = "[binary content]"
        return body

    async def close(self):
        if self.ws:
            await self.ws.close()
        self.connected = False
        print("✓ Conexión CDP cerrada")
