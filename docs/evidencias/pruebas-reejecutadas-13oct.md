# Reejecución de pruebas · 13-oct-2026

Contra **producción** (`www.hooksuite.de`), sobre el código congelado `01c81ab3` ya desplegado.
**Solo lectura:** ningún comando de aquí modifica la caja (R1). Se compara con la foto del **29-sep**,
que se tomó sobre el prototipo *antes* de las Fases 1 y 2.

## ⚠️ Cómo hay que leer un `200` en este host
El frontend es una SPA y Nginx le devuelve `index.html` a **cualquier ruta desconocida**: una dirección
inventada (`/esto-no-existe-12345`) responde **200 · text/html · 459 bytes**, igual que `/openapi.json`.
Por eso aquí **un 200 no prueba nada por sí solo**; hay que mirar el tipo de contenido y el cuerpo. Esta
nota existe porque sin ella la fila de PR-13 se habría leído como «el esquema sigue publicado», que es
justo lo contrario de lo que pasa.

| Prueba | Req. | Qué se midió | 29-sep (prototipo) | Hoy (congelado) |
|---|---|---|---|---|
| PR-01 | RF-01 | `GET /` sin credencial | **401** Basic Auth → FALLA | **200** · sirve el panel |
| PR-13 | RNF-03 | `GET /health` | 200 | **200** |
| PR-13 | RNF-03 | ¿se publica el esquema de la API? | **sí, abierto** | `/openapi.json` devuelve la SPA (`text/html`) y `/api/openapi.json` → **404**: **ya no se publica** |
| PR-19 | RF-02 | `GET /api/proxy/check/alive` | **500** → FALLA | **401**: el extremo responde y **exige credencial** |
| PR-16 | RNF-07 | una ruta de API real sin credencial | **toda la API abierta** → FALLA | **401** |
| PR-16 | RNF-07 | puerto 8000 desde fuera | abierto | **conexión rechazada** |
| PR-16 | RNF-07 | puerto 3000 desde fuera | abierto | **conexión rechazada** |
| PR-18 | RNF-09 | `https://` | timeout, no hay TLS | **conexión rechazada** → sigue sin TLS |
| PR-14 | RNF-07 | claves en ficheros seguidos por git | — | **0** ficheros |

**El cero de PR-14 vale porque el medidor demostró que sabe contar:** el mismo barrido buscando
`HookSuite` devuelve **40** ficheros.

Ejecutado: 2026-10-13T12:03:23+02:00 · desde el mediaserver, sin tocar la caja.
