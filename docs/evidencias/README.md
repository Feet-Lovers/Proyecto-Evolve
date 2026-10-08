# Evidencias de la Práctica 3

Salidas de terminal y capturas que respaldan la memoria técnica (`docs/informe/`) y el diario
(`docs/informe/diario.md`). Cada entrada del diario cita el fichero de esta carpeta que la respalda.

Las de **terminal se guardan como texto, no como foto**: son buscables, comparables, y así ninguna imagen
publica por error un secreto. Las de **pantalla** las saca José María, porque necesitan sus ojos.

## Estas copias están REDACTADAS a propósito

Este repositorio es **público**, así que estos ficheros llevan la misma censura que la memoria. Se han
sustituido por marcadores, sin tocar nada que tenga valor probatorio:

| Marcador que verás | Qué sustituye | Por qué |
|---|---|---|
| `«IP-de-la-caja»` | La dirección pública del servidor de producción | La memoria técnica la mantiene fuera a propósito; publicarla junto a un documento que describe cómo estaba expuesto el servidor es señalar el objetivo |
| `«ruta-del-respaldo»` | La ruta del punto de retorno previo a la Fase 0 | La norma de la línea prohíbe las rutas del respaldo en material compartible |
| `«IP-atacante-1»` / `«-2»` | Dos direcciones de la lista de baneos del bloqueo de fuerza bruta | Datos de terceros, sin valor probatorio: lo que prueba la evidencia es que el bloqueo funciona, no quién llamó |

**Dos capturas no están aquí**, y es deliberado: los originales de
`RF-03-spider-52-forms-duplicados` y `RF-03-spider-sin-boton-stop` mostraban un identificador de sesión de
la web de pruebas a la vista. Se publican solo sus versiones `-censurada`, que muestran exactamente lo mismo
con esa franja tapada. El par antes/después de la memoria usa las censuradas.

## Lo que sí aparece, y no es un descuido

- La cadena `sk-ant-` aparece en los ficheros del incidente de claves, pero **solo como prefijo de 7
  caracteres**: es el patrón de redacción que se usó para limpiar el historial, nunca un valor.
- El fichero `openapi-caja-04oct.json` contiene la palabra `password`, pero como **nombre de campo** del
  esquema de la API (`"password": {"type": "string"}`), no como valor.
- La dirección `169.254.169.254` aparece a propósito: es el endpoint de metadatos del proveedor de nube y es
  **el objetivo de la trampa de petición del lado servidor** que detectó el Spider. Es conocimiento público y
  tiene valor probatorio.
- `1.2.3.4` es un valor de ejemplo.

El archivo interno sin redactar se conserva fuera de este repositorio.
