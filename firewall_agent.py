import socket
import os
import json
import subprocess

SOCKET_PATH = "/tmp/firewall.sock"

if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCKET_PATH)
os.chmod(SOCKET_PATH, 0o777)
server.listen(5)
print(f"Firewall agent escuchando en {SOCKET_PATH}")

while True:
    conn, _ = server.accept()
    try:
        data = conn.recv(1024).decode()
        cmd = json.loads(data)
        action = cmd.get("action")
        port = cmd.get("port")
        ip = cmd.get("ip")
        if action == "open":
            subprocess.run([
                "iptables", "-I", "INPUT", "-p", "tcp",
                "--dport", str(port), "-s", ip, "-j", "ACCEPT"
            ], check=False)
            print(f"Abierto puerto {port} para {ip}")
            conn.send(b"OK")
        elif action == "close":
            subprocess.run([
                "iptables", "-D", "INPUT", "-p", "tcp",
                "--dport", str(port), "-s", ip, "-j", "ACCEPT"
            ], check=False)
            print(f"Cerrado puerto {port} para {ip}")
            conn.send(b"OK")
        else:
            conn.send(b"ERROR")
    except Exception as e:
        print(f"Error: {e}")
        conn.send(b"ERROR")
    finally:
        conn.close()
