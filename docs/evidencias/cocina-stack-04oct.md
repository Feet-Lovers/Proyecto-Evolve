# Evidencia · la cocina levantada y funcionando en local (R1)

- **Tomada:** 2026-10-04 por Claude. Stack clonado de GitHub (`main`, 49414ec) en `/home/josemax/cocina/Proyecto-Evolve`.
- **Para:** cerrar el paso 3 (montar la cocina y verificar que funciona ANTES de tocar nada).

## Contenedores (núcleo; playwright e ia diferidos hasta trabajar RF-08)
```
SERVICE    STATUS         PORTS
redis      Up             6379/tcp
backend    Up             8080/tcp, 0.0.0.0:8800->8000/tcp
dvwa       Up             80/tcp              (solo red interna, NO publicado)
frontend   Up             0.0.0.0:8830->80/tcp
nginx      Up             0.0.0.0:8880->80/tcp
```
Puertos host remapeados (override local `!override`) para no chocar con panel-caddy(:80)/comprapp(:3000)/
comprapp-backend(:8000) del mediaserver: **nginx 8880 · frontend 8830 · backend 8800**.

## Verificación funcional (curl a 127.0.0.1) — reproduce el comportamiento de producción
```
backend  :8800/health            HTTP 200  {"status":"ok","service":"HookSuite Backend"}
frontend :8830/ (directo)        HTTP 200
nginx    :8880/ sin credencial   HTTP 401   (pide Basic Auth)
nginx    :8880/ credencial mala  HTTP 401
nginx    :8880/openapi.json      HTTP 401   (nginx SÍ protege la API; el :8000 directo NO)
```
→ Igual que la caja: API y frontend directos abiertos sin auth; nginx con Basic Auth delante.

## Hallazgo del arranque (va al backlog de arreglos)
🔴 **nginx no arranca sin DVWA.** `infra/nginx.conf:44` tiene `proxy_pass http://dvwa/` con `upstream dvwa`,
y nginx hace `[emerg] host not found in upstream "dvwa"` si el servicio dvwa no está → **crash loop**.
El lab de pruebas es, por diseño, **requisito de arranque del proxy de producción**: acoplamiento a corregir
(pendiente ya existente «desacoplar de DVWA»). Evidencia: primer intento sin dvwa → nginx en bucle; al
levantar dvwa, nginx pasó a 401 correcto.

## Notas de higiene
- `.env` de cocina con **placeholder** de clave (sin valor real, R7); la de IA está pendiente de emitir.
- `/tmp/firewall.sock` creado como fichero vacío en el host para que el bind-mount del backend no cree un
  directorio (el firewall_agent real no corre en la cocina; RNF-08 no se prueba aún).
- `docker-compose.override.yml` y `.env` excluidos del control de versiones (`.git/info/exclude`), sin tocar
  el `.gitignore` versionado.
