# Evidencia · Endurecimiento del host de la caja Hetzner

> 2026-10-05. Las acciones las ejecutó **josemax** (son críticas); Claude preparó, verificó y diseñó las
> redes de seguridad. Terminal (R6), sin secretos (R7).

## Estado previo (verificado en vivo, no de memoria)
```
ufw: inactive · fail2ban: inactive
escuchando en el host: 22 (sshd) y 80 (docker-proxy); 53 solo en loopback
sshd efectivo: permitrootlogin without-password · passwordauthentication yes · pubkeyauthentication yes
7 reglas huerfanas en INPUT (puertos 10000-10005), ninguna con servicio detras
6 claves en authorized_keys de root (4 del equipo + josemax + la de recon de Claude)
```

## 1 · fail2ban — instalado y trabajando desde el primer minuto
`backend = systemd` es imprescindible: Ubuntu 24.04 no instala `rsyslog`, así que puede no existir
`/var/log/auth.log`; sin ese ajuste fail2ban arranca pero **no lee nada** (falso «está protegido»).
```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 4
|  |- Total failed:     148
|  `- Journal matches:  _SYSTEMD_UNIT=sshd.service + _COMM=sshd
`- Actions
   |- Currently banned: 2
   |- Total banned:     2
   `- Banned IP list:   «IP-atacante-1» «IP-atacante-2»
```

## 2 · ufw — activo, sin romper Docker
Orden obligatorio: **permitir el 22 ANTES de activar**. Además se armó una red de seguridad que lo
desactivaba solo a los 5 minutos (cancelada tras verificar).
```
Status: active
Default: deny (incoming), allow (outgoing), deny (routed)
  8080      DENY IN    Anywhere        <- regla PREEXISTENTE de la P1, nunca aplicada (ufw estaba apagado)
  22/tcp    ALLOW IN   Anywhere
  80/tcp    ALLOW IN   Anywhere
puerto 80 -> HTTP 401   (Docker no se descolocó al reordenar iptables)
```
📌 Hallazgo: alguien configuró reglas de ufw en la P1 pero **nunca lo activó**, así que llevaban meses
siendo decorativas.

## 3 · SSH — solo clave
```
/etc/ssh/sshd_config.d/99-hardening.conf:
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  PermitRootLogin prohibit-password
  PubkeyAuthentication yes

sshd -t  -> config valida
sshd -T  -> permitrootlogin without-password / pubkeyauthentication yes / passwordauthentication no
```
**La prueba más limpia está en el mensaje de error del propio servidor:**
```
ANTES:  root@«IP-de-la-caja»: Permission denied (publickey,password)
AHORA:  root@«IP-de-la-caja»: Permission denied (publickey)
```
Verificado también que el acceso por clave sigue funcionando y que la web responde (`/api/session/new` 200).

## ⚠️ Corrección de un riesgo que teníamos sobrevalorado (R9)
La memoria decía «**SSH acepta contraseña**» como riesgo rojo. Es más matizado: el valor efectivo ya era
`permitrootlogin without-password`, es decir, **el login de root por contraseña estaba bloqueado por defecto
desde siempre**. Los ~127.000 intentos registrados **nunca tuvieron ninguna opción**. Lo que seguía abierto
era `passwordauthentication yes` a nivel general, que afecta a *otros* usuarios.
**Por qué se hizo igual:** deja de depender de un valor por defecto que una actualización podría cambiar sin
avisar, cierra la puerta a cualquier usuario futuro creado con contraseña, y es una medida demostrable.

## ⚠️ Lo que ufw NO hace aquí (para no venderlo de más)
No bloquea los puertos publicados por Docker: sus reglas se recorren antes. El `:80` sigue abierto haga lo
que haga ufw — y es correcto, porque es la entrada legítima. **Quien cerró de verdad `:8000` y `:3000` fue el
despliegue**, al dejar de publicarlos. Y el firewall dinámico (RNF-08) inserta con `-I INPUT`, por encima de
ufw, así que sigue funcionando: **ufw no puede contenerlo**.

## Hallazgos nuevos (pendientes)
- 🔴 **Kernel sin estrenar**: corriendo **6.8.0-117**, instalado **6.8.0-142**. Más **49 paquetes** sin
  actualizar y `docker.service` pendiente de reiniciar por binario viejo. Estrenarlo exige reiniciar la caja.
- 🧹 **`firewall_agent` huérfano del 21-mayo** (PID 21885, fuera de systemd) — reconfirmado por `needrestart`
  («root @ session #77: python3[21885]»).
- 🧹 **7 reglas huérfanas** en INPUT. Ninguna abre nada real (no hay servicio en esos puertos), pero una
  contiene una **IP pública real** de alguien del grupo → **censurar si llega a la memoria técnica (R7)**.

## Requisitos
RNF-07 · apartado 7 de la memoria (endurecimiento, con antes/después).

---

## 4 · Limpieza final (mismo día, tras verificar lo anterior)

### Las 7 reglas huérfanas, fuera
Copia previa en `/root/iptables-antes-limpieza-20261005.rules` (167 líneas); restauración con
`iptables-restore < …`. Se borraron por especificación, no por número de línea (los números cambian al borrar).
```
reglas que quedan con esos puertos: 0

-P INPUT DROP
-A INPUT -j ufw-before-logging-input
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A INPUT -j ufw-after-logging-input
-A INPUT -j ufw-reject-input
-A INPUT -j ufw-track-input
```
El `INPUT` queda con **política DROP** y únicamente las cadenas de ufw. Eran reglas **ACCEPT** hacia puertos
sin servicio detrás, así que borrarlas no podía dejar a nadie fuera.
📌 Con esto desaparece también la regla con la **IP pública de un miembro del grupo** y el placeholder
`1.2.3.4` — ya no hay dato personal que censurar en las reglas vivas.

### El agente huérfano del 21-mayo, terminado
```
pgrep -af firewall_agent  ->  2975777 /usr/bin/python3 /root/hooksuite/firewall_agent.py   (solo uno)
systemctl is-active firewall-agent  ->  active
ls -l /tmp/firewall.sock            ->  srw-rw---- root root
```

### Verificación posterior desde fuera
```
web :80/api/session/new -> 200
SSH por clave           -> OK
socket visto por el backend -> srw-rw----   (firewall dinamico operativo)
procesos del agente         -> 1
```

---

## 5 · Reinicio de la caja para estrenar el kernel (5-oct, tarde)

La caja llevaba **sin reiniciarse desde mayo**: ningún comportamiento de arranque estaba probado.

### Riesgo detectado ANTES de reiniciar, y corregido
El agente del firewall solo declaraba `After=network.target`: **ninguna orden respecto a Docker**. Si Docker
levantaba el backend antes de que el agente creara `/tmp/firewall.sock`, **Docker habría creado un DIRECTORIO**
en esa ruta (es lo que hace un bind-mount cuando el origen no existe); el agente fallaría entonces al arrancar
(su limpieza previa borra ficheros, no directorios) y entraría en bucle por su `Restart=always`.
Corregido con un drop-in de systemd `10-orden.conf`: **`Before=docker.service`** más una limpieza previa
tolerante a fallos que elimina lo que encuentre en esa ruta (autocuración). Tras reiniciar el agente hubo que
**recrear el backend**, porque el socket nace con inodo nuevo — la trampa del bind-mount de fichero ya conocida.

### Verificación previa (qué debía volver solo)
`docker`, `firewall-agent`, `fail2ban` y `ufw` **enabled**; los 7 contenedores con `unless-stopped`.
⚠️ `ssh.service` figura como **`disabled`**, lo que asusta, pero en Ubuntu 24.04 quien arranca el acceso es
**`ssh.socket`, que SÍ está enabled**. Comprobarlo era imprescindible: sin esa verificación, el reinicio podía
haber dejado la caja sin acceso remoto.

### Después del reinicio
```
kernel:  6.8.0-142-generic      (antes 6.8.0-117)      uptime: up 1 minute
socket:  srw-rw---- root root   <- SOCKET, no directorio
agente:  active · NRestarts = 0 <- la carrera NO llego a producirse
backend ve: srw-rw----          (el mismo socket, con sus permisos)
ufw: active · fail2ban: active · passwordauthentication no    <- todo persistio
contenedores: 7/7 arriba

desde fuera:  :80 -> 401 · /api/session/new -> 200 · /ws/<token> -> 101 · :8000 -> rechazado
```
Los **0 reinicios del agente** son la prueba limpia de que el drop-in hizo su trabajo.

### Pendiente aparte (no entraba en este reinicio)
Los **49 paquetes** del sistema siguen sin actualizar: necesitan `apt upgrade` y van como cambio propio, con
su propia verificación.
