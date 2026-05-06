import httpx
import asyncio
import json
import os
from typing import Dict, Any
from dotenv import load_dotenv
load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
class EventReporter:
    def __init__(self, session_token: str = None):
        self.session_token = session_token or "playwright_default"
        self.backend_available = False
        self.local_log = []

    async def check_backend(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{BACKEND_URL}/health")
                self.backend_available = response.status_code == 200
                if self.backend_available:
                    print(f"✓ Backend disponible en {BACKEND_URL}")
                    return self.backend_available
        except Exception:
            print(f"⚠ Backend no disponible en {BACKEND_URL}. Guardando resultados en local.")
            self.backend_available = False
            return False

    async def send_network_packet(self, packet: Dict) -> bool:
        self.local_log.append({"type": "network_packet", "data": packet})
        if not self.backend_available:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{BACKEND_URL}/api/network/packet/{self.session_token}",
                    json=packet
                )
                return response.status_code == 200
        except Exception as e:
            print(f"✗ Error enviando paquete al backend: {e}")
            return False

    async def send_vulnerability(self, vulnerability: Dict) -> bool:
        self.local_log.append({"type": "vulnerability", "data": vulnerability})
        if not self.backend_available:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{BACKEND_URL}/api/vulnerabilities",
                    json=vulnerability
                )
                return response.status_code == 200
        except Exception as e:
            print(f"✗ Error enviando vulnerabilidad al backend: {e}")
            return False

    async def send_fingerprint(self, fingerprint: Dict) -> bool:
        self.local_log.append({"type": "fingerprint", "data": fingerprint})
        if not self.backend_available:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{BACKEND_URL}/api/ia/fingerprint",
                    json=fingerprint
                )
                return response.status_code == 200
        except Exception as e:
            print(f"✗ Error enviando fingerprint al backend: {e}")
            return False

    def save_local_log(self, filepath: str = "results/events_log.json"):
        os.makedirs("results", exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(self.local_log, f, indent=2)
        print(f"✓ Log local guardado en {filepath} ({len(self.local_log)} eventos)")