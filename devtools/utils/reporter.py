import httpx
import json
import os
from typing import Dict
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
SESSION_TOKEN = os.getenv("SESSION_TOKEN", "devtools_session")

class PacketReporter:
    def __init__(self, session_token: str = None):
        self.session_token = session_token or SESSION_TOKEN
        self.backend_available = False
        self.sent_count = 0
        self.failed_count = 0
        self.local_buffer = []
        self.local_log_path = "results/captured_packets.json"
        os.makedirs("results", exist_ok=True)

    async def check_backend(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{BACKEND_URL}/health")
                self.backend_available = response.status_code == 200
                if self.backend_available:
                    print(f"✓ Backend disponible en {BACKEND_URL}")
                return self.backend_available
        except Exception:
            print(f"⚠️  Backend no disponible. Guardando en local.")
            self.backend_available = False
            return False

    async def send_packet(self, packet: Dict) -> bool:
        self.local_buffer.append(packet)
        if len(self.local_buffer) % 10 == 0:
            self._flush_local()
        if not self.backend_available:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{BACKEND_URL}/api/network/packet/{self.session_token}",
                    json=packet,
                )
                if response.status_code == 200:
                    self.sent_count += 1
                    return True
                self.failed_count += 1
                return False
        except Exception:
            self.failed_count += 1
            return False

    async def send_console_finding(self, finding: Dict) -> bool:
        if not self.backend_available:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{BACKEND_URL}/api/network/console_finding/{self.session_token}",
                    json=finding,
                )
                return response.status_code == 200
        except Exception:
            return False

    def _flush_local(self):
        try:
            with open(self.local_log_path, 'w') as f:
                json.dump({
                    "session_token": self.session_token,
                    "timestamp": datetime.utcnow().isoformat(),
                    "total": len(self.local_buffer),
                    "packets": self.local_buffer,
                }, f, indent=2)
        except Exception as e:
            print(f"✗ Error guardando log local: {e}")

    def flush(self):
        self._flush_local()
        print(f"✓ {len(self.local_buffer)} paquetes en {self.local_log_path}")
        print(f"  → Enviados al backend: {self.sent_count} | Fallidos: {self.failed_count}")
