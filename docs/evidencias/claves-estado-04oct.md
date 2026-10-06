# Evidencia · estado real de las 4 claves del incidente de secretos

- **Tomada:** 2026-10-04 08:59 CEST por Claude, a petición y con autorización expresa de josemax.
- **Para:** apartado 8 de la memoria (pruebas que han fallado) + cierre del pendiente «revocar las claves».
- **R7:** ningún valor de clave aparece aquí ni pasó por pantalla. Solo SHA-256 truncado y longitud.
  El valor se leyó **solo en variable de shell** desde el respaldo del 3-oct.
- **Destino:** trasladar al diario (`docs/informe/diario.md`) en cuanto la cocina exista (R3).

## Método
Una petición `GET https://api.anthropic.com/v1/models` por clave, cabeceras `x-api-key` +
`anthropic-version: 2023-06-01`. Lectura pura: no modifica nada, no consume tokens.
Origen de cada valor: el `clone --mirror` y el `caja-root-hooksuite.tar.gz` del punto de retorno
`«ruta-del-respaldo»/` — **no se tocó ni la caja ni GitHub**.

## Resultado — LAS CUATRO ESTÁN MUERTAS

| SHA-256 (8) | long | Origen | HTTP | Veredicto |
|---|---|---|---|---|
| `d7532af3` | 108 | `39cff11f:ia/.env.example` (2-may) | 401 | inservible |
| `8a9050cd` | 108 | `aba2fde2:ia/.env` (10-may) | 401 | inservible |
| `a7294836` | 108 | `02e4bd6e:ia/.env` (11-may, Macarena) · **viva hoy en la caja** | 401 | inservible |
| `ff15b863` | 108 | `.env` raíz de `/root/hooksuite`, nunca versionada | 401 | inservible |

Respuesta idéntica en las cuatro (verbatim):
```json
{"type":"error","error":{"type":"authentication_error","message":"API key is invalid."},"request_id":null}
```

## Por qué el 401 es concluyente
El cuerpo es un JSON de error **de la propia API de Anthropic** (`authentication_error`), no una respuesta
genérica de proxy o de red: la petición llegó al servicio y fue **él** quien rechazó la credencial. Una clave
activa no devuelve `API key is invalid.`

## Salvedad honesta (R9)
Un 401 `API key is invalid.` **no distingue** entre (a) revocada, (b) borrada, (c) de una organización
eliminada, o (d) expirada. Para el efecto que importa — ¿hay que revocarla? ¿sirve a quien la encuentre en
el historial público? — los cuatro casos son el mismo: **no es utilizable por nadie**.

## Consecuencias
1. **No hay nada que revocar.** El pendiente «revocar las ≥3 claves» se cierra con esta evidencia.
2. **No hay que pedirle a Macarena que revoque** la suya (`a7294836`): ya no sirve.
3. **Limpiar el historial sigue siendo obligatorio** — el enunciado (sección 7) exige que no haya secretos
   reales «ni en su historial», y no condiciona eso a que estén vivos. La Fase 0 no cambia.
4. 🆕 **El módulo IA de producción corre con una clave inválida** (`a7294836` en `ia/.env`): RF-08 no
   funcionaría ni aunque tuviera disparador en la interfaz. Hace falta **emitir una clave nueva** para la
   Fase 3 — deja de ser «reponer lo revocado» y pasa a ser requisito previo del módulo de IA.
5. La clave que josemax ve en su consola **no es ninguna de estas cuatro** (ninguna responde): es otra.
