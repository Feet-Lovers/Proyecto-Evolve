import socket
import os
import json
import subprocess
import ipaddress

SOCKET_PATH = "/tmp/firewall.sock"


def _valid_port(port):
    """Devuelve el puerto como int si es válido (1-65535), si no None."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def _valid_ip(ip):
    """Devuelve la IP normalizada si es una dirección única válida, si no None.
    Se exige una IP de host (no rangos/CIDR): el firewall dinámico abre un puerto
    para la IP de UNA sesión, nunca para una red."""
    try:
        return str(ipaddress.ip_address(ip))
    except (TypeError, ValueError):
        return None


if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCKET_PATH)
# 0o660 (antes 0o777): quita el permiso de escritura a "otros". Un socket world-writable
# permitía a cualquier proceso del host/contenedor manipular el firewall (escalada).
os.chmod(SOCKET_PATH, 0o660)
server.listen(5)
print(f"Firewall agent escuchando en {SOCKET_PATH}")

while True:
    conn, _ = server.accept()
    try:
        data = conn.recv(1024).decode()
        cmd = json.loads(data)
        action = cmd.get("action")
        port = _valid_port(cmd.get("port"))
        ip = _valid_ip(cmd.get("ip"))
        if action in ("open", "close") and port is not None and ip is not None:
            flag = "-I" if action == "open" else "-D"
            subprocess.run(
                ["iptables", flag, "INPUT", "-p", "tcp",
                 "--dport", str(port), "-s", ip, "-j", "ACCEPT"],
                check=False,
            )
            print(f"{'Abierto' if action == 'open' else 'Cerrado'} puerto {port} para {ip}")
            conn.send(b"OK")
        else:
            conn.send(b"ERROR")
    except Exception as e:
        print(f"Error: {e}")
        try:
            conn.send(b"ERROR")
        except Exception:
            pass
    finally:
        conn.close()
