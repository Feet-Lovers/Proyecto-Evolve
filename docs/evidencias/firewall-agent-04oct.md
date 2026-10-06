# Evidencia · firewall_agent.py: socket world-writable + iptables sin validar — 2026-10-04

## ANTES (código, backend/../firewall_agent.py)
- Línea 13: `os.chmod(SOCKET_PATH, 0o777)` → socket `/tmp/firewall.sock` escribible por CUALQUIER proceso
  (el socket se monta en el contenedor backend) → un proceso comprometido manipula el firewall del host (escalada).
- `ip` y `port` del JSON recibido se pasaban a `iptables` SIN validar (`-s ip`, `--dport port`).

## FIX
- Socket a `0o660` (quita escritura a "otros").
- `_valid_port`: int en 1-65535 o rechazo. `_valid_ip`: IP de host única (ipaddress), NO rangos/CIDR.
- Comando malformado → responde ERROR, no toca iptables.

## DESPUÉS (validación probada, aislada)
- port 8080 -> 8080 · port '80; rm' -> None · port 99999 -> None
- ip '1.2.3.4' -> '1.2.3.4' · ip '0.0.0.0/0' -> None · ip '-j DROP' -> None
