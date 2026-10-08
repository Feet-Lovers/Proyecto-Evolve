# Evidencia · Despliegue de la Fase 0+1 en la caja Hetzner

> 2026-10-05. Los comandos de mutación los ejecutó **josemax** (bloques de la bandeja); Claude preparó,
> verificó y dejó el punto de retorno. Terminal (R6), sin secretos (R7).
> Punto de retorno vigente: imágenes `:pre-p3`, `/root/foto-arbol-pre-p3-20261005.tgz`, rama local
> `develop@7dfa6acf` y el respaldo del 3-oct.

## Antes (estado heredado de mayo)
```
/root/hooksuite: rama develop @ 7dfa6acf + 32 ficheros SIN COMMITEAR  (historial viejo, solo existía ahí)
puertos publicados:  nginx 0.0.0.0:80 · backend 0.0.0.0:8000 · frontend 0.0.0.0:3000
socket del agente:   srwxrwxrwx (0o777)   <- world-writable
ufw: inactive · fail2ban: inactive
```

## Después
```
/root/hooksuite: main @ 20728329 (merge del PR #4, 26 commits) · 0 ficheros sin commitear

DESDE FUERA («IP-de-la-caja»):
  :8000/health          -> conexión rechazada      <- CERRADO
  :3000/                -> conexión rechazada      <- CERRADO
  :80/                  -> 401 (Basic Auth)
  :80/api/session/new   -> 200
  :80/ws/<token>        -> 101  (WebSocket a mismo origen, por el proxy)
  :80/api/proxy/check/alive     -> 200   (antes 500)
  :80/api/intruder/cancel/<tok> -> 200   (antes 500)
  :80/api/spider/stop/<tok>     -> 200

DENTRO:
  puertos:  nginx 0.0.0.0:80->80 · backend 8000/tcp (interno) · frontend 80/tcp (interno)
  bundle del frontend desplegado: 0 ocurrencias de ':8000', ninguna de la IP -> mismo origen
  socket del agente: srw-rw---- (0o660), host y contenedor ven el MISMO socket
  backend dentro del contenedor corre como root (uid=0) -> 0o660 no le cierra la puerta
```

## Alcance del rebuild
Solo **backend** y **frontend** (lo único que cambió). `ia` (698 MB), `playwright` (2,39 GB), `redis` y el
laboratorio quedaron intactos, con sus 4 meses de uptime: no habían cambiado y rebuildearlos arrastraría
dependencias nuevas sin motivo.

## Dos cosas que el despliegue NO aplicó, y hubo que hacer aparte
Mi primera verificación fue **insuficiente** y conviene dejarlo escrito:

1. **Nginx no recargó su configuración.** Compose no recreó el contenedor porque su definición de servicio no
   cambió (la config entra por *bind-mount*), así que seguía sirviendo la configuración **vieja en memoria**.
   ⚠️ El `401` de `/dvwa/` que comprobé primero **no lo distinguía**: la configuración vieja también pedía
   Basic Auth en esa ruta. Resuelto con `nginx -t` + `nginx -s reload`.
   **Prueba de que recargó:** el master (PID 1) sigue siendo del **21-mayo**, pero el worker arrancó
   **hoy a las 08:43:31** (mtime de `/proc/<pid>`) → el master releyó la configuración y generó workers nuevos.
   Encadenado con que el fichero en disco ya no tiene la ruta del laboratorio, la configuración cargada
   tampoco la tiene.

2. **El `firewall_agent` no se reinició**: corre en el **host** (systemd `firewall-agent.service`), no en
   contenedor, así que el despliegue de contenedores no lo toca.
   ⚠️ **El orden importaba:** el agente hace `os.remove()` del socket antes del `bind`, así que al arrancar
   crea un **inodo nuevo**; y el socket entra al backend como **bind-mount de un fichero**, de modo que el
   montaje del contenedor habría quedado apuntando al inodo muerto. Por eso **reiniciar el agente y recrear
   el backend se hicieron juntos y en ese orden**. Verificado después: host y contenedor ven el mismo socket
   `0o660` con la misma marca de tiempo.

## Hallazgo nuevo (pendiente)
🔴 **`firewall_agent` huérfano desde el 21-mayo** (PID 21885, lanzado **a mano** —`python3` sin ruta
absoluta—, fuera de systemd), con un socket de inodo ya inalcanzable por ruta. Es un proceso **root con
capacidad de manipular iptables, abandonado desde la P1**. A terminar (acción destructiva → la ejecuta josemax).

## Requisitos
RNF-07 (exposición y operación controlada) · apartado 7 de la memoria (endurecimiento: antes/después).
