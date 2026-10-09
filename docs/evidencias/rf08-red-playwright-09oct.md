# Evidencia — Playwright entra en la red interna (2026-10-09 12:29)

**Qué se arregló.** El servicio `playwright` era **el único del compose sin bloque `networks:`** (backend,
redis, dvwa, ia, frontend y nginx lo tenían). Sin red declarada, Compose lo habría puesto en la red
`default` del proyecto, aislado de `hooksuite-net` — y por tanto incapaz de resolver `backend` y `dvwa`,
**pese a tener configurados** `BACKEND_URL=http://backend:8000` y `DVWA_URL=http://dvwa:80`. Es la causa
raíz de RF-10/RF-08 sin operar.

**Dato que el backlog no recogía y se comprobó en vivo:** `playwright` e `ia` **no están levantados**. Solo
corren frontend, backend, nginx, dvwa y redis, todos en `proyecto-evolve_hooksuite-net`, y **no existe
ninguna red `default`** — coherente con que playwright nunca haya arrancado en este stack.

## Antes

```
$ docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Networks}}'
proyecto-evolve-frontend-1	Up 26 hours	proyecto-evolve_hooksuite-net
proyecto-evolve-backend-1	Up 2 days	proyecto-evolve_hooksuite-net
proyecto-evolve-nginx-1	Up 2 days	proyecto-evolve_hooksuite-net
proyecto-evolve-dvwa-1	Up 5 days	proyecto-evolve_hooksuite-net
hooksuite-redis-1	Up 5 days	proyecto-evolve_hooksuite-net
            (ni playwright ni ia)

$ docker network ls | grep -iE 'hooksuite|evolve'
082e4aeb8c9f   proyecto-evolve_hooksuite-net   bridge    local
            (no hay red "default")
```

## El cambio — una línea (dos, con la clave)

```yaml
  playwright:
    build: ./playwright
    environment:
      - BACKEND_URL=http://backend:8000
      - SESSION_TOKEN=hooksuite_session
      - PYTHONUNBUFFERED=1
      - DVWA_URL=http://dvwa:80
    depends_on:
      - backend
    restart: unless-stopped
+   networks:
+     - hooksuite-net
```

## Después — verificado por Docker, no leyendo el fichero

Se comprueba con `docker compose config`, que es **lo que Docker entiende**, no lo que el YAML parece decir
(R9: contrastar la fuente). Punto de retorno previo: `docker-compose.yml.bak-20261009-122912`.

```
$ docker compose config --format json | jq -r '.services | to_entries[] | "  \(.key): \(.value.networks // {} | keys | join(", "))"'
  backend: hooksuite-net
  dvwa: hooksuite-net
  frontend: hooksuite-net
  ia: hooksuite-net
  nginx: hooksuite-net
  playwright: hooksuite-net
  redis: hooksuite-net

$ docker compose config -q      # YAML valido
```

## Lo que esto NO demuestra todavía

Que los siete servicios estén **declarados** en la misma red no prueba que `playwright` **hable** con el
backend: eso solo se ve levantándolo (`up -d --force-recreate playwright`, que implica un `build`) y
resolviendo el nombre desde dentro. **No se ha levantado en esta pasada** — queda como paso siguiente, con
su coste de construcción de imagen. Es la misma lección del nginx del 7-oct: **nombrar un servicio no prueba
que el comando lo toque**, y un «en verde» declarativo no es un «en verde» funcional.

## Efecto en la memoria técnica

El apartado 5 del `.typ` afirmaba que los contenedores estaban «todos en una red interna `hooksuite-net`»
mientras el mismo documento, en «Puntos a corregir», decía que `playwright` **no** la declaraba: **el
documento se contradecía a sí mismo**. Corregido en la misma pasada (R4) y **declarado en el propio
documento** en vez de reescrito en silencio (R9). Añadido al `.memoria-sunset.txt` el patrón
`no +declara +.networks`, para que el cerco **R4b** salte si la frase vuelve a aparecer en presente.
