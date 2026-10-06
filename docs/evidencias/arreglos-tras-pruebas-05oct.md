# Evidencia · Tres arreglos salidos de las pruebas de josemax en producción

> 2026-10-05, cocina (R1). Origen: josemax probó la web desplegada y reportó lo que veía.
> Capturas de PANTALLA suyas; las de terminal, de Claude (R6). Sin secretos (R7).

## Capturas (almacén de la línea)
| Fichero | Qué muestra |
|---|---|
| `capturas/RF-03-spider-52-forms-duplicados.png` | **ORIGINAL — NO PUBLICABLE.** Lleva un `XSRF-TOKEN` de la web de pruebas a la vista |
| `capturas/RF-03-spider-52-forms-duplicados-censurada.png` | **La publicable.** Mismo contenido con la franja del token tapada (R7) |
| `capturas/RF-03-spider-sin-boton-stop.png` | **ORIGINAL — NO PUBLICABLE.** Spider EN MARCHA; lleva `XSRF-TOKEN` a la vista |
| `capturas/RF-03-spider-sin-boton-stop-censurada.png` | **La publicable.** Misma captura con la franja del token tapada (R7) |

### Lo que prueba la captura de los formularios
`https://web.academyx.es/tienda` · «Spider completado» · una petición
`…/tienda?page=1&sort=newest` (200, 38.4 KB, 52 ms) con el contador **`[52 FORM ▲]`**, desplegada en una lista
de entradas `↳ https://web.academyx.es/tienda?search=` **todas idénticas**.
📌 **Corrección de dato:** josemax habló primero de «104»; la captura documenta **52 bajo una sola petición**
(los 104 eran la suma de dos). El defecto es el mismo.

### Lo que prueba la captura del botón ausente
**Sustituida por josemax a petición de Claude**: la primera mostraba el panel en reposo, donde el arreglo no
se nota (el botón «Detener» solo aparece durante la ejecución), así que no servía como par antes/después.
La definitiva capta **el momento exacto**: mensaje «Spider en ejecucion ...», el único botón del panel
**deshabilitado mostrando «Ejecutando...»**, **ninguna forma de detener el rastreo**, y 5 peticiones ya
capturadas (`/tienda/category/2`, `/category/1`, `/register`, `/login`, `/tienda`, todas 200).
El **«después»** será la misma pantalla con el botón «Detener» al lado, tras el despliegue.

> 🔴 **Las DOS capturas llevaban el mismo `XSRF-TOKEN` a la vista** — la herramienta muestra por diseño las
> cookies que captura, así que sus pantallas son justo donde aparecen los secretos. Ambas censuradas con
> Pillow y verificadas abriéndolas. **A la memoria y al artefacto van solo las versiones censuradas.**

## Arreglo 1 · Botón Detener del Spider — `dd9dc3e4` (Ivan)
El endpoint de parada ya funcionaba en el backend (commit `fa7aab61`), pero **la interfaz no tenía forma de
llamarlo**: el único botón era «Iniciar spider», que se quedaba deshabilitado como «Ejecutando...». Sin esto,
«parar el Spider» no era demostrable ni en el vídeo ni en la memoria.
Añadido: botón «Detener» visible **solo durante la ejecución**, y corte del sondeo de estado al desmontar la
pantalla (seguía pidiendo `/spider/status` cada 2 s sin nadie mirando).

## Arreglo 2 · Formularios duplicados — `d4429e5b` (Nacho)
Se emitía una entrada por formulario encontrado **en cada página**, sin colapsar los repetidos. Ahora se
guarda una huella `(método, acción, campos)` y los repetidos se descartan.
```
Prueba unitaria (HTML con 20 formularios idénticos, recorrido 2 veces):
  formularios encontrados en el HTML: 20 (todos identicos)
  entradas FORM emitidas tras 2 paginas: 1   (antes serian 40)
  RESULTADO: OK
```

## Arreglo 3 · Mensajes de error legibles — `61020468` (Macarena)
Un fallo de red devolvía el texto crudo de la librería, que no dice ni qué host falló.
```
Antes:   Error: [Errno -2] Name or service not known
Ahora:   Error: no se pudo resolver el host 'noexiste.invalid'. Comprueba el dominio
         (o si hay DNS disponible). Detalle: [Errno -2] Name or service not known
         Error: 'lab.local' rechazo la conexion (puerto cerrado o servicio caido). …
         Error: fallo de TLS al conectar con 'lab.local'. Detalle: certificate verify failed
```

## Lo que NO era un fallo
- **El error del Repeater no se reprodujo** y el envío funciona en producción (`repeater/send` →
  **200, 39 KB** contra la web de pruebas; el parser de `curl` devuelve la URL correcta). Fue un fallo puntual
  de resolución de nombres, no un defecto del producto. De ahí que la acción fuera **mejorar el mensaje**.
- **El flashbang salta una vez por carga de página**: comportamiento desde la P1, easter egg intencional.

## Requisitos
RF-03 (Spider) · RF-05 (Repeater) · RNF-07.

---

## Despliegue de estos tres arreglos (5-oct, tarde)

PR #5 mergeado → `main` = `485a22ec`. Punto de retorno previo: imágenes etiquetadas **`:pre-fase1b`** (2),
que devuelven al estado *bueno* de hoy, no al de mayo. Rebuild de `backend` y `frontend`; Nginx no hizo falta
tocarlo (su configuración no cambia en este lote).

### Verificación en producción
```
codigo desplegado: main @ 485a22ec · 0 ficheros sin commitear
bundle del frontend: la cadena "Detener" esta presente  -> el boton llego al desplegado
:80/            -> 401      (Basic Auth)
/api/session/new -> 200

# Mensajes de error legibles, probados en vivo:
host que no resuelve ->
  Error: no se pudo resolver el host 'este-host-no-existe.invalid'. Comprueba el dominio
  (o si hay DNS disponible). Detalle: [Errno -2] Name or service not known
puerto cerrado ->
  Error al conectar con '127.0.0.1': All connection attempts failed
```
Compárese con el mensaje que recibió josemax por la mañana: `Error: [Errno -2] Name or service not known`,
sin indicar siquiera qué host había fallado.

### Captura del «después» (pendiente de josemax)
Un solo rastreo del Spider en producción da **las dos pruebas a la vez**: el **botón «Detener» visible**
mientras corre (par de `RF-03-spider-sin-boton-stop-censurada.png`) y la **ausencia de formularios repetidos**
(par de `RF-03-spider-52-forms-duplicados-censurada.png`).
⚠️ Recordar **censurar el token de sesión** antes de publicarla: aparece en la misma franja superior.

### ✅ Capturas del «después» (recibidas y verificadas abriéndolas)
| Fichero | Qué prueba |
|---|---|
| `capturas/RF-03-spider-CON-boton-detener.png` | Spider **en marcha**: junto a «Ejecutando...» aparece el botón rojo **«Detener»**. Par exacto de `RF-03-spider-sin-boton-stop-censurada.png`, donde no había ninguno |
| `capturas/RF-03-spider-forms-deduplicados.png` | **Misma URL que la captura del defecto** (`…/tienda?page=1&sort=newest`, 200, 38.4 KB): de **`[52 FORM ▲]`** a **`[1 FORM ▲]`** |

📌 **Ninguna de las dos necesita censura**: la sesión estaba «sin autenticar», así que no hay token en la
franja superior (a diferencia de las dos del defecto, que sí lo llevaban). Van tal cual a la memoria.

📌 El par de formularios es especialmente limpio porque es **la misma petición de la misma página**: cambia
solo el contador. No hace falta explicar nada más.
