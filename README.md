# HookSuite

**Herramienta de auditoría de seguridad web con inteligencia artificial.**

HookSuite se usa **desde el navegador, sin instalar nada en el equipo del auditor**: se abre una
dirección, se entra con un usuario propio y se trabaja con datos aislados de los del resto. Reúne en un
panel el rastreo de un sitio, el reenvío manual de peticiones, el *fuzzing* de parámetros, un juego de
utilidades de codificación y un módulo de IA que prioriza los hallazgos.

---


## Probarlo sin instalar nada

HookSuite está **desplegado y en marcha** en **http://www.hooksuite.de**. No hace falta instalar nada: se
abre la dirección, se crea una cuenta con el código de invitación y se trabaja. Es el modo de uso para el
que está pensada la herramienta.

El *código de invitación de esa instalación no se publica en este repositorio*: el registro no es abierto porque esta
herramienta lanza tráfico contra terceros, y un código en un repositorio público sería una invitación a
usarla contra cualquiera. Se facilita al equipo docente en el comentario de la entrega.

> ⚠️ Esa instalación se sirve por **HTTP, sin TLS todavía** (limitación declarada en la memoria). No metas
> ahí credenciales que uses en ningún otro sitio.

Si prefieres levantar tu propia copia —que es lo que describe el resto de este documento—, sigue leyendo.

---

## Requisitos previos

| | |
|---|---|
| **Docker** y **Docker Compose v2** | Es lo único imprescindible. Todo el producto se levanta en contenedores. |
| **`openssl`** | Para generar las dos credenciales del paso 3. Viene de serie en Linux y macOS. |
| **Python 3** | Solo si quieres ejecutar las pruebas automatizadas. No hace falta para instalar. |
| **Clave de API de Anthropic** | Solo si se quiere usar el módulo de IA. El resto del producto funciona sin ella. |
| **Un puerto libre** | Por defecto el **80**, que es el único que se publica. Si lo tienes ocupado, sirve cualquier otro por encima de 1024: lo cambias con una variable, y en «¿Y si el puerto está ocupado?» tienes cómo comprobar cuál tienes libre. |

---

## Instalación y ejecución, paso a paso

```bash
# 1 · Clonar
git clone https://github.com/Feet-Lovers/Proyecto-Evolve.git
cd Proyecto-Evolve

# 2 · Partir del fichero de ejemplo
cp .env.example .env

# 3 · Rellenar las dos credenciales obligatorias. Sin ellas el backend NO arranca:
#     es deliberado, nunca levanta sin autenticación. JWT_SECRET necesita al menos
#     32 caracteres y REGISTRO_CODIGO al menos 12.
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n=')|" .env
sed -i "s|^REGISTRO_CODIGO=.*|REGISTRO_CODIGO=$(openssl rand -base64 18 | tr -d '\n=')|" .env

# Apunta tu código de invitación: lo necesitas para crear la primera cuenta.
grep '^REGISTRO_CODIGO=' .env

# 4 · (Opcional) Añadir la clave de la API de Anthropic al .env, para el módulo de IA:
#     ANTHROPIC_API_KEY=sk-ant-...

# 5 · Construir y levantar
docker compose up -d --build

# 6 · Comprobar que los seis servicios están arriba
docker compose ps
```

Abre **http://localhost** en el navegador. Si todo ha ido bien, aparece la pantalla de acceso.

> *¿`address already in use` en el paso 5?* El **80** lo tiene otro servicio de tu máquina. Sirve
> **cualquier puerto libre por encima de 1024**: cambia `HOOKSUITE_PUERTO` en tu `.env` —la variable ya
> viene en el fichero, se cambia, no se añade—, vuelve a lanzar `docker compose up -d --build` y abre
> `http://localhost:<TU_PUERTO>`. Dentro del contenedor nginx sigue escuchando en el 80; esto solo cambia
> por qué puerto de tu máquina se llega. **Cómo saber cuál tienes libre: «¿Y si el puerto está ocupado?»,
> justo debajo.**

> **Nota sobre `tools/generar-credenciales.py`.** El repositorio incluye un script que genera esas dos
> credenciales **sin mostrarlas por pantalla**. Lo usamos nosotros porque nuestro entorno de trabajo
> registra la salida de los comandos en texto plano, y un secreto impreso quedaría escrito en disco. Para
> instalar no hace falta: el paso 3 de arriba es suficiente.

> **Si el backend no arranca, es a propósito.** Sin `JWT_SECRET` o sin `REGISTRO_CODIGO` se niega a
> levantar en vez de arrancar sin autenticación pareciendo correcto. Revisa que el paso 3 los dejó
> escritos en el `.env`.

### ¿Y si el puerto está ocupado?

El valor por defecto es el **80**, y es el único puerto que el producto publica. Si lo tienes ocupado sirve
cualquier otro **por encima de 1024**; no hay ninguno «correcto».

> ⚠️ **No elijas por costumbre: `8080` es el puerto alternativo más usado que existe** —paneles de
> administración, proxys y servidores de desarrollo lo ocupan—, así que es fácil que también lo tengas
> cogido y te lleves el mismo error dos veces.

Para saber si un puerto está libre, pregúntale al sistema por **ese** puerto (aquí `8088`). En Linux:

```bash
ss -ltnH 'sport = :8088'
```

**Si no imprime nada, está libre.** Si imprime una línea, está ocupado: prueba con otro.

**Qué verás si el puerto está ocupado:** el error lo da **solo `nginx`**, que es el único servicio que
publica puerto; los otros cinco arrancan igual. No te fíes de que «parece que va»: el paso 6
(`docker compose ps`) tiene que mostrar los **seis** servicios. Si ves cinco, el panel no se está sirviendo.

### Qué se levanta

| Servicio | Qué hace | ¿Publicado? |
|---|---|---|
| `nginx` | Única puerta de entrada; sirve el panel y proxea `/api` y `/ws` | **Sí**, puerto `HOOKSUITE_PUERTO` (80 por defecto) |
| `frontend` | Panel React | No — solo por nginx |
| `backend` | API FastAPI, WebSocket y motor de auditoría | No — solo por nginx |
| `ia` | Análisis de hallazgos con la API de Anthropic | No |
| `redis` | Bus interno entre el backend y el módulo de IA | No |
| `playwright` | Navegador real para automatización | No |

**Solo ese puerto sale a la red.** Los demás servicios se hablan por la red interna `hooksuite-net`.

---

## Datos de acceso de prueba

**No hay usuario y contraseña publicados en este repositorio, y es deliberado:** la instalación pública
lanza tráfico contra terceros, así que unas credenciales en un repositorio público serían una invitación
a usarla contra quien sea.

En su lugar, **cada despliegue crea las suyas**:

1. El paso 3 de la instalación genera un **código de invitación** (`REGISTRO_CODIGO`) y lo escribe en tu
   `.env`. Ábrelo y cópialo.
2. En la pantalla de acceso, pulsa **Registro**.
3. Rellena usuario y contraseña **tuyos** y pega ese código.
4. Entra con esa cuenta.

El registro *no es abierto*: sin el código no se crea ninguna cuenta. Cada cuenta trabaja con sus propios
datos y no ve los de las demás; si quieres comprobarlo, basta registrar un segundo usuario.

> Para la *instalación pública* (ver arriba) el código de invitación no está en este repositorio ni en la
> memoria —el PDF de la memoria también se versiona aquí—: se facilita en el comentario de la entrega.

---

## Uso básico

1. **Spider** — escribe la dirección del sitio a auditar y lanza el rastreo. Las páginas y los
   formularios van apareciendo en vivo.
2. **Repeater** — reenvía una petición a mano y toca lo que quieras: cabeceras, cuerpo, método. Trae
   formularios directamente desde el Spider.
3. **Intruder** — marca un parámetro con `*`, elige un diccionario y lanza el ataque. La tabla muestra
   código, tamaño, tiempo y veredicto de cada envío.
4. **Utilidades** — hash, codificador (base64, URL, HTML y **lectura de JWT**), probador de expresiones
   regulares y generador de *payloads*.
5. **Vulnerabilidades** — los hallazgos que el módulo de IA prioriza, con su nivel de confianza.
6. **Manual** — la guía de uso, dentro del propio panel.

> ⚠️ **Audita solo sistemas sobre los que tengas autorización.**

---

## Pruebas

Son **scripts independientes**: no hacen falta `pytest` ni dependencias extra más allá de las del módulo.

```bash
# Las cinco del módulo de IA (esquemas, escala de confianza, tres estados, bus)
for t in ia/tests/test_*.py; do echo "== $t"; python3 "$t"; done

# La del backend: cada hallazgo acaba en la sesión de su dueño
python3 backend/tests/test_bus_reparto.py

# Validador de los esquemas contra la API real (necesita clave de Anthropic)
python3 ia/tests/validar_esquemas_contra_api.py
```

---

## Estructura del repositorio

```
Proyecto-Evolve/
├── frontend/            React + Vite + Tailwind — el panel
├── backend/             FastAPI — API, WebSocket y motor de auditoría
│   └── tests/           pruebas del backend
├── ia/                  módulo de IA (API de Anthropic)
│   ├── prompts/         instrucciones del clasificador
│   └── tests/           pruebas del módulo
├── playwright/          navegador real para automatización
├── devtools/            captura con Chrome DevTools Protocol (ver nota)
├── infra/               configuración de nginx
├── tools/               generación de credenciales y utilidades de la memoria
├── docs/                memoria técnica, capturas y evidencias
├── firewall_agent.py    agente del cortafuegos por sesión
├── docker-compose.yml
├── .env.example
└── LICENSE
```

**Nota sobre `devtools/`:** el panel «Red» basado en Chrome DevTools Protocol **se descartó** durante esta
práctica y en su lugar se incorporó la pestaña **Manual**. El código del módulo sigue en el repositorio
porque forma parte del trabajo de la Práctica 1; no está en uso.

---

## Estado y limitaciones conocidas

- **No hay HTTPS todavía**: el servicio se publica por HTTP. Es la limitación declarada en la memoria.
- La pestaña **Vulnerabilidades** está funcional pero **sin terminar de pulir**.
- **Playwright** está construido y en la red interna, pero su integración es **parcial**.
- El estado de **sesión es volátil** a propósito; lo único que persiste son las cuentas de usuario.

---

## Documentación

- **Memoria técnica (Práctica 3):** `docs/informe/P3_GrupoFeetLovers_Memoria.pdf`
- **Reglas de contribución:** [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## Licencia

MIT. Ver [`LICENSE`](LICENSE).
