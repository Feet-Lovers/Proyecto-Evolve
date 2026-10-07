# Comprobación previa al despliegue de la Fase 2 — el Nginx no se va a recrear solo

**Fecha:** 2026-10-07 (tarde) · **Entorno:** caja de producción `91.98.143.219` (solo lectura, R1) +
cocina del mediaserver · **Requisito:** RF-12, RNF-03 · **Quién:** Claude

Esta comprobación existe porque el plan de despliegue escrito el 5-oct dice «rebuild **solo de `backend`,
`frontend` y `nginx`**», y esa frase **no hace lo que parece** con el Nginx.

---

## 1. El servicio `nginx` no se construye y su definición no ha cambiado

```
$ grep -nE '^  [a-z]+:|^    (build|image):' docker-compose.yml
  backend:     build: ./backend
  playwright:  build: ./playwright
  redis:       image: redis:7-alpine
  dvwa:        image: vulnerables/web-dvwa
  ia:          build: ./ia
  frontend:    build: ./frontend
  nginx:       image: nginx:alpine        <-- imagen descargada, NO se construye

$ sed -n '/^  nginx:/,/^  [a-z]/p' docker-compose.yml
  nginx:
    image: nginx:alpine
    ports: ["80:80"]
    volumes:
      - ./infra/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./infra/htpasswd:/etc/nginx/htpasswd:ro
    depends_on: [backend, frontend]
```

`git diff origin/main..develop -- docker-compose.yml` toca **solo** el `volumes:` de primer nivel (el
volumen `usuarios`) y el servicio `backend` (las variables nuevas). **El bloque `nginx` no cambia ni un
byte.**

**Consecuencia:** el `up -d --build backend frontend nginx` del plan
- no construye nada para `nginx` (no tiene contexto de build), y
- **no lo recrea**, porque Compose lo ve idéntico a lo que ya corre.

Y Nginx lee su configuración **una sola vez, al arrancar**. Los contenedores de producción llevan vivos
desde el 5-oct a las 15:35:

```
$ docker inspect -f '{{.State.StartedAt}}' <cada contenedor>
hooksuite-backend-1     2026-10-05T15:35
hooksuite-frontend-1    2026-10-05T15:35
hooksuite-nginx-1       2026-10-05T15:35      <-- la config que tiene cargada es la del 5-oct
hooksuite-ia-1          2026-10-05T15:35
hooksuite-playwright-1  2026-10-05T15:35
hooksuite-redis-1       2026-10-05T15:35
hooksuite-dvwa-1        2026-10-05T15:35
```

**Lo que se perdería sin forzar la recreación:** la Fase 2 retira la autenticación básica compartida y las
rutas `/proxy.pac` y `/check/` **en el `nginx.conf`**. Con el Nginx viejo en memoria, el despliegue
terminaría «en verde» y esos dos cambios **no estarían aplicados**: el panel de entrada nuevo seguiría
detrás de la contraseña compartida y las dos rutas retiradas seguirían publicadas. Es **el mismo fallo del
5-oct** (Nginx no recreado sirviendo la configuración vieja), que entonces costó una verificación
insuficiente.

**Arreglo adoptado:** `--force-recreate nginx` explícito en el bloque de despliegue. Cuesta segundos y no
construye nada.

---

## 2. Hipótesis descartada: la «trampa del inodo» NO aplica aquí

Esta línea tiene documentado dos veces el patrón «bind-mount de FICHERO + sustitución en el host = el
contenedor se queda mirando el inodo muerto» (el socket del `firewall_agent` y el fichero de credenciales de
Nginx). La sospecha era que `git reset --hard` haría lo mismo con `infra/nginx.conf`, y que entonces **ni un
`nginx -s reload` valdría**, porque releería el inodo viejo.

**Probado, y es falso: `git reset --hard` reescribe el fichero EN EL SITIO, conservando el inodo.**

```
$ git init && echo viejo > f.conf && git add f.conf && git commit -m v1
inodo v1:                   29508214
$ echo nuevo > f.conf && git commit -am v2
inodo v2:                   29508214
$ git reset --hard HEAD~1
inodo tras reset --hard:    29508214   ·  contenido: viejo
```

Mismo inodo en los tres estados → el montaje sigue apuntando al fichero correcto.

**Y contrastado contra producción** (`sha256` truncado a 16 caracteres):

```
nginx.conf en el HOST            : inodo 388756 · sha256 110d2d8b8ef7b9b1
nginx.conf DENTRO del contenedor : sha256 110d2d8b8ef7b9b1    <-- IDÉNTICO
  auth_basic (líneas)  = 2       (coherente con main: la autenticación básica aún está)
  location /dvwa       = 0       (coherente con main: DVWA ya retirado de Nginx)
```

El contenedor ve **la configuración actual de `main`**, no una fantasma. Es decir: **la conclusión del 5-oct
(«Nginx recargado») se sostiene**, y hoy no hay configuración vieja sirviendo en producción.

> Matiz honesto: los 7 contenedores arrancaron el 5-oct a las 15:35, **después** del `reload` de las 08:43,
> así que la coincidencia de hoy no prueba por sí sola que aquel reload funcionara. Lo que sí queda probado
> es que **no existe mecanismo** por el que pudiera haber quedado una config fantasma: el inodo se conserva.

**Por qué se usa `--force-recreate` igualmente:** no depende de este detalle. El `reload` sí.

---

## 3. Los dos secretos nuevos NO están en el `.env` de la caja

```
$ grep -o '^[A-Z_]*' /root/hooksuite/.env        # SOLO los nombres (R7)
ANTHROPIC_API_KEY HOST PORT PROXY_PORT BACKEND_URL MOCK_PLAYWRIGHT
```

Faltan `JWT_SECRET` y `REGISTRO_CODIGO`, que la Fase 2 declara **sin valor por defecto** a propósito.

Y el backend **falla al arrancar**, no a medias — los validadores corren a nivel de módulo, en el import:

```
backend/services/auth_service.py:116:  SECRETO = _leer_secreto()
backend/services/auth_service.py:117:  CODIGO_REGISTRO = _leer_codigo_registro()
```

`_leer_secreto()` hace `os.getenv("JWT_SECRET", "").strip()` y lanza `RuntimeError` si está vacía (y otra si
mide menos de 32 caracteres). O sea que **una variable vacía cuenta como ausente**, que es lo correcto:
Compose, si no encuentra la variable, la pasa vacía en vez de no pasarla.

**Consecuencia para el orden del despliegue:** los secretos entran en el `.env` **ANTES** del arranque de los
contenedores. Si se hace al revés, el backend queda en bucle de reinicio (`restart: unless-stopped`) con el
panel de entrada visible y **toda** la API devolviendo 502. Fallo seguro y visible, pero fallo.

---

## Estado de la caja al hacer esta comprobación

```
HEAD_desplegado = 485a22ec663cb332a6bdb02e269246c1fe65382d   (= origin/main)
sin_commitear   = 0
```

Peticiones de solo lectura al dominio público (ninguna escritura, ningún ataque):

```
/dvwa/        -> 401     (cae en `location /`, que aún pide la contraseña compartida)
/proxy.pac    -> 200     (ruta del modelo abandonado, aún publicada: la Fase 2 la retira)
/check/alive  -> 200     (idem)
/             -> 401     (autenticación básica vieja, la que la Fase 2 sustituye por el login)
```
