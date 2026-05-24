import subprocess
import socket
import asyncio
import time
import json
from typing import Dict, Optional

SESSION_TIMEOUT = 4 * 60 * 60
SOCKET_PATH = "/tmp/firewall.sock"

class ProxySession:
    def __init__(self, uid: str, port: int, pid: int, client_ip: str):
        self.uid = uid
        self.port = port
        self.pid = pid
        self.client_ip = client_ip
        self.last_activity = time.time()

    def touch(self):
        self.last_activity = time.time()

    def is_expired(self):
        return time.time() - self.last_activity > SESSION_TIMEOUT

class ProxyManager:
    def __init__(self):
        self.sessions = {}

    def get_free_port(self, start=10000, end=60000):
        for port in range(start, end):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("localhost", port)) != 0:
                    return port
        raise RuntimeError("No hay puertos disponibles")

    def firewall_command(self, action: str, port: int, ip: str):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(SOCKET_PATH)
                cmd = json.dumps({"action": action, "port": port, "ip": ip})
                s.send(cmd.encode())
                response = s.recv(1024)
                print(f"Firewall {action} puerto {port} para {ip}: {response.decode()}")
        except Exception as e:
            print(f"Error firewall: {e}")

    def start_proxy(self, uid: str, client_ip: str) -> int:
        if uid in self.sessions:
            self.sessions[uid].touch()
            return self.sessions[uid].port
        port = self.get_free_port()
        proc = subprocess.Popen([
            "mitmdump",
            "--listen-host", "0.0.0.0",
            "--listen-port", str(port),
            "--set", "block_global=false",
            "--proxyauth", "hooksuite:audit2026",
            "-s", "/app/services/mitm_addon.py",
            "--quiet"
        ])
        self.firewall_command("open", port, client_ip)
        self.sessions[uid] = ProxySession(uid=uid, port=port, pid=proc.pid, client_ip=client_ip)
        print(f"Proxy arrancado para {uid} en puerto {port}")
        return port

    def stop_proxy(self, uid: str):
        if uid not in self.sessions:
            return
        session = self.sessions.pop(uid)
        try:
            subprocess.run(["kill", str(session.pid)], check=False)
            self.firewall_command("close", session.port, session.client_ip)
            print(f"Proxy parado para {uid} puerto {session.port}")
        except Exception as e:
            print(f"Error: {e}")

    def get_port(self, uid: str) -> Optional[int]:
        if uid in self.sessions:
            self.sessions[uid].touch()
            return self.sessions[uid].port
        return None

    async def cleanup_expired(self):
        while True:
            await asyncio.sleep(60)
            expired = [uid for uid, s in self.sessions.items() if s.is_expired()]
            for uid in expired:
                print(f"Sesion expirada: {uid}")
                self.stop_proxy(uid)

proxy_manager = ProxyManager()
