# Evidencia · exposición de la caja HookSuite a internet (pre-arreglo)

- **Tomada:** 2026-10-04 09:14 CEST por Claude, desde el mediaserver contra `«IP-de-la-caja»`.
- **Para:** apartado 8 de la memoria (lo que falla) + requisitos RF/RNF de seguridad. Es la evidencia que
  **nuestros propios arreglos de la Fase 1 van a destruir** (cerrar `:8000`/`:3000`, Basic Auth, DVWA interno).
- **Naturaleza:** solo peticiones **de lectura o de validación** (GET, y HEAD de cabeceras). **No se lanzó
  el Spider ni el Intruder contra nadie** (R1 + ética RNF-07); el POST a `spider/start`/`intruder/start` lo
  bloqueó además el clasificador de permisos y **no se rodeó**. La prueba de «API sin auth» se apoya en la
  propia `openapi.json` + `/health`, que no exigen credenciales — sin necesidad de disparar un ataque.

## 1 · Mapa de puertos abiertos a internet
```
:80    HTTP 401   → nginx con Basic Auth (frontend "oficial")
:8000  HTTP 404 / → uvicorn (API backend) ABIERTO, responde sin credenciales (ver §2)
:3000  HTTP 200   → frontend servido DIRECTO, SIN el Basic Auth del :80 (ver §3)
:8080  HTTP 000   → sin respuesta (cerrado/filtrado)
```

## 2 · La API `:8000` no tiene autenticación — confirmado por su propia especificación
`GET http://«IP-de-la-caja»:8000/health` **sin credenciales** →
```
HTTP/1.1 200 OK
server: uvicorn
{"status":"ok","service":"HookSuite Backend"}
```
No hay cabecera `WWW-Authenticate`: no es que falle el login, es que **no hay login**.

`GET http://«IP-de-la-caja»:8000/openapi.json` **sin credenciales** → HTTP 200, 24.481 bytes. La propia API declara:
```
components.securitySchemes : NINGUNO
security (global)          : NINGUNO
40 operaciones, TODAS con security = -   (ni una exige credenciales)
```
Incluye los endpoints que **atacan a terceros desde la IP del grupo**, todos sin auth:
`POST /api/spider/start`, `POST /api/intruder/start`, `POST /api/repeater/send`, `POST /api/network/packet`.
→ Evidencia directa de **RNF «autenticación en /api»** incumplido y del riesgo legal del recon (cualquiera
puede usar la caja como plataforma de ataque).

## 3 · El Basic Auth del `:80` es un cartón: el frontend se sirve igual por `:3000`
- `GET :80/` → HTTP 401 (pide Basic Auth), y **la credencial documentada en el informe P1
  (`hooksuite:audit2026`) NO abre** → también HTTP 401. (Ya conocido; reconfirmado.)
- `GET :3000/` **sin credenciales** → HTTP 200 + el HTML de la SPA (`<title>frontend</title>`,
  `/assets/index-Via5rL7O.js`). **La protección del :80 se evita entrando por el :3000.**

## 4 · Corrección de un supuesto del plan: DVWA **NO** está expuesto a internet
El plan asumía «DVWA servido por Nginx» como evidencia a capturar. **Verificado y es FALSO visto desde fuera:**
- `:80/dvwa/` y `:80/login.php` → 401 (tapados por el Basic Auth).
- `:3000/dvwa/` → 200 **pero es el fallback de la SPA**, no DVWA: una ruta inventada
  (`:3000/ruta-que-no-existe-xyz123`) devuelve **el mismo** `<title>frontend</title>`.
- `:8888/` (el DVWA "suelto" del recon) → sin respuesta (ya constaba `Exited (255)`).
→ DVWA solo escucha **interno** (`hooksuite-dvwa-1` en la red del compose). El pendiente «dejar DVWA solo
interno en Nginx» **ya se cumple de hecho**; conviene documentarlo así en vez de como arreglo pendiente.
La captura de «DVWA sirviéndose desde la IP del grupo» que pedía el plan para josemax **no procede** — no ocurre.

## Trazabilidad de requisitos
| Evidencia | Toca |
|---|---|
| §2 API sin auth + endpoints de ataque abiertos | RNF auth en /api · riesgo legal del recon · criterio Seguridad 15 % |
| §3 frontend por :3000 salta el Basic Auth | «cerrar :3000 y rebuild a mismo origen», no solo compose |
| §4 DVWA no expuesto | «dejar DVWA solo interno» = ya cumplido (documentar, no arreglar) |

---
## Capturas de pantalla recibidas y verificadas (4-oct, subidas por josemax vía FileZilla)
Guardadas en `evidencias/capturas/`. Verificadas una a una abriendo la imagen (contenido visual), no solo `file`.

| Fichero | Válido | Qué muestra | Veredicto |
|---|---|---|---|
| `RNF-auth-api-health-sin-login.png` | PNG 750×312 | `:8000/health` → `{"status":"ok",...}` sin diálogo de login | ✅ correcta |
| `RNF-auth-api-swagger-abierto.png` | PNG 1920×1020 | `:8000/docs` → Swagger de HookSuite API abierto, endpoints a la vista | ✅ correcta (mejor de lo pedido) |
| `seg-frontend-3000-sin-basic-auth.png` | PNG 1920×496 | `:3000/proxy` → la app cargada y «conectado», con «Iniciar spider», SIN Basic Auth | ✅ correcta (muestra la app funcional) |
| `seg-nginx-80-pide-basic-auth.png` | PNG 1441×588 | `:80` → diálogo «Autorización requerida por http://«IP-de-la-caja»», campos vacíos | ✅ correcta |
| `seg-credencial-informe-p1-no-abre.png` | PNG 1470×377 | `:80` → página **«401 Authorization Required»** de `nginx/1.31.0` tras enviar `hooksuite:audit2026` | ✅ **REHECHA 10:19 — correcta** (prueba el rechazo + revela versión de nginx) |

✅ **RESUELTO (10:19): captura 5 rehecha y correcta.** Muestra la página «401 Authorization Required» de `nginx/1.31.0` servida por el `:80` tras enviar `hooksuite:audit2026` → prueba inequívoca de que la credencial del informe P1 **no abre**. Concuerda con la prueba técnica en texto (curl `-u hooksuite:audit2026` → HTTP 401, §3). Bonus: la página de error revela la **versión de nginx (1.31.0)** — dato de fingerprinting para la memoria. **Las 5 capturas de la exposición quedan completas y verificadas.**

**R7:** en la captura 5 el valor de la contraseña va **oculto con puntos** (no se lee); el usuario `hooksuite`
y la credencial `hooksuite:audit2026` son **públicos** (constan en el informe P1 del grupo), así que no hay
secreto nuevo expuesto. Aun así, al llevarla a la memoria/artefacto se sustituye por los usuarios de prueba
del login nuevo (pendiente ya anotado).
