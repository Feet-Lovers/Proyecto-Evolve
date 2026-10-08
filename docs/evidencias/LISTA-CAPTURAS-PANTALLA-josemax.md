# Capturas de PANTALLA que tiene que sacar josemax (navegador) — sesión de evidencia P3

> Las de terminal ya están sacadas por Claude como texto (`exposicion-caja-04oct.md`, `claves-estado-04oct.md`).
> Estas necesitan tus ojos. **Son evidencia de "lo que falla/está expuesto" → ANTES de que arreglemos nada**
> (R6): el login nuevo y el cierre de puertos de la Fase 1 las destruyen. Todo desde tu navegador, contra la
> caja de producción `«IP-de-la-caja»` (esto es recon visual, no probar en prod: solo miras, no cambias nada).

**Cómo guardarlas:** PNG a pantalla completa, nombre tal cual la columna "fichero", en `docs/capturas/` cuando
montemos la cocina (de momento guárdalas donde quieras y las movemos). **Que se vea la barra de direcciones
con la IP/puerto** — es parte de la prueba.

| # | Qué abrir en el navegador | Qué tiene que verse | Fichero | Requisito |
|---|---|---|---|---|
| 1 | `http://«IP-de-la-caja»:8000/health` | El JSON `{"status":"ok"...}` **sin que pida usuario/contraseña** | `RNF-auth-api-health-sin-login.png` | API sin auth |
| 2 | `http://«IP-de-la-caja»:8000/docs` | La interfaz Swagger de la API **abierta a cualquiera** (si responde; si da 404, anótalo y pasa) | `RNF-auth-api-swagger-abierto.png` | API sin auth |
| 3 | `http://«IP-de-la-caja»:3000/` | El frontend de HookSuite cargando **sin pedir el Basic Auth** (la barra muestra `:3000`) | `seg-frontend-3000-sin-basic-auth.png` | cerrar :3000 / rebuild |
| 4 | `http://«IP-de-la-caja»/` (puerto 80) | El cuadro de **Basic Auth pidiendo usuario/contraseña** (el contraste con la nº 3) | `seg-nginx-80-pide-basic-auth.png` | contraste :80 vs :3000 |
| 5 | `http://«IP-de-la-caja»/` + meter `hooksuite:audit2026` | Que **rechaza** la credencial documentada en el informe P1 (vuelve a pedirla / 401) | `seg-credencial-informe-p1-no-abre.png` | credencial muerta → portada memoria |

**Lo que NO hay que capturar (y por qué), para que no pierdas tiempo:**
- ❌ *DVWA sirviéndose desde la IP del grupo* — **no ocurre**: verificado que DVWA solo escucha interno
  (ver `exposicion-caja-04oct.md` §4). El plan lo asumía y era un supuesto falso.
- ❌ *Pantallas de bugs del producto (500 del Repeater, trampa del Spider)* — esas se capturan **en la cocina**,
  no en producción (R1), y son reproducibles: no corre prisa y no las destruimos nosotros.

**Opcional pero valioso si te apetece:** una captura de tu consola de Anthropic mostrando que **solo aparece
una clave** (la que comentaste) — ilustra en la memoria que las claves filtradas no eran ni de tu cuenta
principal. Tápale el sufijo/ID antes de guardarla (R7).

---
## ¿Dónde las guardo? (resuelto 4-oct)
- **Casa definitiva:** `docs/capturas/` dentro del repo (R6), que nace al montar la cocina (paso 3).
- **Ahora mismo:** dispáralas ya (la caja está expuesta HOY; es irreversible) y **guárdalas en tu PC** en una
  carpeta cualquiera —p.ej. `Descargas/capturas-p3/`— **con los nombres EXACTOS de la tabla de arriba**. El
  nombre es lo que importa: rellena solo la matriz de trazabilidad.
- **No las subas al servidor todavía:** la pestaña «Subir» de MediaHub deja los ficheros en `/DATA/Media`
  (tu biblioteca), que no es su sitio. Cuando Claude monte la cocina creará `docs/capturas/` y las subes ahí
  **de una vez**, ya con el nombre correcto y a su destino final.
