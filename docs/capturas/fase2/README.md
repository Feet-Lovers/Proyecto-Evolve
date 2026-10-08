# Capturas de la Fase 2 — sistema de acceso por usuario (RF-12)

Capturadas el **6-oct-2026** contra la cocina (entorno de pruebas), a través de Nginx y como un cliente real.
Cada pie dice qué muestra y a qué requisito toca, como exige el enunciado. Estos mismos pies son los que
usa la memoria técnica al incrustar las imágenes.

| Fichero | Pie |
|---|---|
| `RF-12-panel-login.png` | **RF-12** — la entrada del producto tras retirar el Basic Auth de Nginx: un panel de acceso propio, con pestañas «Entrar» y «Crear cuenta». Antes, la raíz devolvía `401` con una credencial que nadie del grupo conocía. |
| `RF-12-panel-registro.png` | **RF-12** — el alta exige **código de invitación**. El registro no es abierto a propósito: HookSuite lanza tráfico contra terceros, así que con altas anónimas cualquiera podría atacar desde la infraestructura del grupo. La contraseña la elige el usuario y solo la conoce él. |
| `RF-12-registro-cuenta-creada.png` | **RF-12** — alta completada para `UsuarioA`: la interfaz confirma la creación y devuelve al formulario de entrada. Cubre la mitad «Registro» del requisito, que el enunciado pide junto al login. |
| `RF-12-aislamiento-usuarioA-con-datos.png` | **RF-12 (aislamiento, caso con datos)** — `UsuarioA`, autenticado, ve las 13 peticiones que su Spider capturó del objetivo autorizado `web.academyx.es`. Compárese con la captura siguiente, tomada al mismo tiempo. |
| `RF-12-aislamiento-usuarioB-sin-datos.png` | **RF-12 (aislamiento, caso sin datos)** — `UsuarioB`, autenticado en otro navegador y al mismo tiempo, ve su proxy **vacío**: «no hay peticiones interceptadas». Antes de la Fase 2 ambos compartían el mismo espacio. Este par es la prueba del aislamiento por usuario. |

## Redacciones aplicadas (R7)

Dos de las cinco llevan una banda de redacción. **Los originales sin censurar NO entran en este repo**:
se quedan fuera, igual que se hizo con las evidencias del 6-oct.

- `RF-12-aislamiento-usuarioA-con-datos.png`: se tapó el valor de la cabecera **`XSRF-TOKEN`**, que aparecía
  entero. Es el token de sesión capturado **de la web auditada** — precisamente el dato que RF-12 existe para
  no compartir. Publicarlo habría publicado la fuga que este requisito cierra. La etiqueta se conserva para
  que se vea qué se redactó.
- `RF-12-aislamiento-usuarioB-sin-datos.png`: se tapó la barra de marcadores del navegador, que mostraba
  marcadores personales ajenos al proyecto.

Ninguna otra redacción: los nombres `UsuarioA`/`UsuarioB` son cuentas de prueba, el dominio auditado es un
objetivo autorizado y la dirección `192.168.1.48:8880` es la del entorno de pruebas en red local, no la de
producción.
