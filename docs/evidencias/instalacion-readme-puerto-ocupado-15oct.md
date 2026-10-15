# Evidencia · El README instala, y el tramo del puerto ocupado (15-oct-2026)

Prueba hecha en la **cocina** del mediaserver (R1), sobre un árbol independiente clonado de `develop`
(`6a7ccb6f`) en un directorio temporal, con su propio proyecto de Compose —ni red, ni volumen, ni
contenedores compartidos con el despliegue de la cocina— y **sin** el `docker-compose.override.yml` local,
que remapea a 8880 y no está versionado. Pasos 1 a 3 del README reproducidos tal cual: 14 variables en el
`.env` y credenciales de 64 y 24 caracteres (valores no mostrados, R7).

## 1 · Paso 5 con el puerto 80 ocupado

El anfitrión tiene el 80 tomado por un proceso que no es Docker. Salida del paso 5:

```
Container <proyecto>-redis-1       Started
Container <proyecto>-backend-1     Started
Container <proyecto>-playwright-1  Started
Container <proyecto>-ia-1          Started
Container <proyecto>-frontend-1    Started
Container <proyecto>-nginx-1       Starting
Error response from daemon: failed to set up container networking: driver failed programming external
connectivity on endpoint <proyecto>-nginx-1: failed to bind host port 0.0.0.0:80/tcp: address already in use
```

**Dos hechos que importan:**

1. El texto del error contiene `address already in use`, que es exactamente lo que cita el aviso del
   README, así que el lector lo encuentra buscando el mensaje.
2. **El fallo lo da solo `nginx`**, el único servicio que publica puerto: los otros cinco arrancan igual.
   Quien no lea la salida del paso 5 y vaya directo al paso 6 ve cinco servicios en marcha y puede creer
   que ha instalado. De aquí sale la frase nueva del README que avisa de que el paso 6 debe mostrar **seis**.

## 2 · El ejemplo del README tampoco estaba libre

El aviso daba un único valor concreto (`HOOKSUITE_PUERTO=8080`) y fijaba la URL en `http://localhost:8080`.
En esta máquina el 8080 lo tiene Caddy escuchando en `127.0.0.1:8080`, así que seguir el texto al pie de la
letra producía **el mismo error por segunda vez**, y el documento ya no acompañaba: no decía que el ejemplo
pudiera estar cogido, ni cómo averiguar un puerto libre. Es el defecto que corrige esta pasada.

## 3 · Comprobación del puerto y relanzamiento

Con la orden que el README incorpora ahora:

```
$ ss -ltnH 'sport = :8088'
(sin salida)            → el puerto está libre
```

`HOOKSUITE_PUERTO=8088` en el `.env` (la variable ya venía en el fichero) y `docker compose up -d --build`:
recreó **solo `nginx`** y dejó los otros cinco en marcha. Paso 6:

```
backend     running  8000/tcp, 8080/tcp
frontend    running  80/tcp
ia          running
nginx       running  0.0.0.0:8088->80/tcp, [::]:8088->80/tcp
playwright  running
redis       running  6379/tcp
```

## 4 · La pantalla de acceso

```
$ curl -sS -o panel.html -w '%{http_code} %{size_download}B' http://localhost:8088/
200 459B
$ grep -o '<title>[^<]*</title>' panel.html
<title>HookSuite</title>
```

Eso prueba que el panel **se sirve**, no que se pinte: es una aplicación React y el HTML de arranque llega
igual aunque el panel fallara. **La otra mitad la verificó josemax con su navegador**: entró por el 8088 y
la pantalla de acceso estaba ahí, y después se registró con el código de invitación del `.env` y entró sin
problemas. Con eso queda verificada la cadena completa `nginx` → `frontend` → `/api` en el puerto remapeado.

## 5 · Qué NO prueba esta evidencia

- **No tacha la casilla del enunciado** «una persona ajena al grupo lo ha instalado siguiendo el README»:
  la prueba la ha conducido quien escribió el README. Comprueba que las instrucciones se sostienen, que es
  otra cosa.
- El clon se hizo de **`develop`** a propósito, porque el arreglo del `container_name` de `redis` y el
  README nuevo no están en `main`. Quien clone la rama por defecto hoy se trae la versión anterior: la
  prueba fiel al 100 % exige haber fusionado `develop` en `main` antes.
