# RF-08 · Paso 1 (+3b): `ia/client.py` reescrito y el techo probado a 0 € — 9-oct-2026

> Evidencia de terminal capturada como **texto** (R3), en la **cocina** (R1), el 9-oct ~09:45.
> Sin ningún valor de clave (R7): las pruebas usan una cadena de usar y tirar que **nunca viaja**,
> porque se ejecutan con `--network none`.

## 1 · La puerta del plan, superada antes de escribir código

El plan exigía literalmente: *«`output_config` puede no existir en la versión del SDK instalada …
**Comprobarlo antes de dar el cambio por bueno**. No se deja asumido: se mira.»* Comprobado **dentro de la
imagen**, sin llamar a la API:

| Comprobación | Resultado |
|---|---|
| `anthropic.__version__` en la imagen | **1.12.1** (el `requirements.txt` solo pedía `>=0.97.0`) |
| `output_config` en `message_create_params` | ✅ existe |
| `OutputConfigParam.effort` | ✅ `Literal["low","medium","high","xhigh","max"]` — los 5 niveles |
| `OutputConfigParam.format` → `JSONOutputFormatParam` | ✅ `schema` (requerido) + `type: "json_schema"` |
| `Message.stop_details` | ✅ está entre los campos del modelo |
| `NotFoundError`/`AuthenticationError`/`BadRequestError`/`RateLimitError`/`APIConnectionError`/`APIStatusError` | ✅ las 6 existen |

**Consecuencia:** se aplica la vía principal del plan. **No** hace falta su plan B (subir el pin del SDK o
mantener el parseo manual de JSON).

## 2 · Dos correcciones al código del plan, salidas de contrastar la referencia de la API

El plan se escribió el 8-oct y nunca se había ejecutado. Al contrastarlo con la referencia oficial
aparecieron dos cosas:

1. 🔴 **`max_tokens=4000` era arriesgado y ahora es configurable (8000 por defecto).** En Claude 5 el
   pensamiento está **activado por defecto** y `max_tokens` cubre **pensamiento + respuesta**: un tope
   corto trunca el JSON a media llave. Queda en `HOOKSUITE_IA_MAX_TOKENS`.
2. 🔴 **Faltaba tratar `stop_reason == "max_tokens"`.** Sin eso, una respuesta truncada caía en la rama
   «no era JSON pese al esquema» y el motivo que vería el panel sería **engañoso**. Ahora se dice con su
   nombre: *«respuesta truncada: agotado el tope de N tokens (pensamiento + respuesta)»*.

Se mantiene lo demás del plan tal cual, incluida la comprobación de `stop_reason == "refusal"` **antes** de
leer `content` (si no, es un `IndexError`) y el leer `stop_reason` y nunca `stop_details`, que puede venir a
`None`.

## 3 · Prueba del techo con el techo a 0 — **0 €, y sin red**

`docker run --network none -e HOOKSUITE_IA_MAX_LLAMADAS=0`:

```
=== 1) TECHO A 0: ninguna llamada debe salir ===
   MODEL=claude-sonnet-5  EFFORT=low  MAX_LLAMADAS=0  MAX_TOKENS=8000
   tipo devuelto     : RespuestaIA
   r.ok              : False
   r.estado          : degradado
   r.datos           : None
   r.detalle         : techo de 0 llamadas por auditoria alcanzado
   techo_alcanzado   : True
   llamadas gastadas : 0   <-- 0 = no salio ninguna peticion
   OK: degradado por techo, sin tocar la API

=== 2) reiniciar_presupuesto() limpia el estado ===
   llamadas=0  techo_alcanzado=False
   OK

=== 3) Los tres estados de RNF-06 son DISTINGUIBLES ===
   vulnerable         ok=True  datos={'vulnerable': True, 'confianza':    detalle=''
   analizado-limpio   ok=True  datos={'vulnerable': False}                detalle=''
   NO analizado       ok=False datos=None                                 detalle='clave de API invalida o ausente'
   OK: 'limpio' y 'no analizado' ya NO son lo mismo (era el fallo silencioso)
```

**Lo que demuestra el punto 3:** el fallo que RNF-06 necesitaba arreglar —que «la IA falló» y «analizado y
limpio» fueran **indistinguibles**— ya no existe **en el cliente**. Falta que el clasificador y el
orquestador lo propaguen (apartados 2 y 3 del plan).

## 4 · Prueba del techo a 1 — el contador y el reintento

`docker run --network none -e HOOKSUITE_IA_MAX_LLAMADAS=1`:

```
MAX_LLAMADAS=1

1a llamada  -> estado=degradado  detalle='agotados 3 intentos (APIConnectionError)'
            llamadas=1  techo_alcanzado=False  (6.9s: reintentos con espera)

2a llamada  -> estado=degradado  detalle='techo de 1 llamadas por auditoria alcanzado'
            llamadas=1  techo_alcanzado=True

OK: 1 intento consumido, las siguientes cortadas por el techo y MARCADAS
```

Tres cosas quedan probadas de una vez: **(a)** el contador suma el intento real; **(b)** el techo **no**
gasta contador cuando corta; **(c)** el reintento exponencial funciona —los **6,9 s** son el `1 s + 2 s` de
espera más los tiempos de conexión— y al agotarse degrada en vez de lanzar la excepción hacia arriba, que
es lo que antes **tumbaba la fase de ataque entera**.

## 5 · Qué queda roto A PROPÓSITO, por estar a mitad de la secuencia

El plan impone el orden **1 → 2 → 3b → 3** y dice que el techo (3b) entra **en la misma pasada** que el
cliente: eso es lo hecho. Pero `analyze()` ahora **exige `schema`** y devuelve `RespuestaIA` en vez de un
`dict`, así que **los cuatro llamadores quedan pendientes** (verificado con `grep`, y coinciden exactamente
con lo que predecía el plan):

```
ia/analyzers/vulnerability_classifier.py:21   analyze(  <- analyze_packet
ia/analyzers/vulnerability_classifier.py:44   analyze(  <- analyze_intruder
ia/analyzers/vulnerability_classifier.py:68   analyze(  <- analyze_console
ia/analyzers/vulnerability_classifier.py:91   analyze(  <- fingerprint
```

⚠️ **Mientras los pasos 2–4 no se apliquen, el módulo de IA NO funciona** — y no puede funcionar de todas
formas, porque la clave de la caja está inválida. No hay contenedor `ia` levantado y nada lo invoca, así
que **nada en marcha se rompe**. Vuelta atrás: `git show HEAD~1:ia/client.py` (el fichero estaba
commiteado y el árbol limpio antes de tocarlo, R8).

**Pendiente de la misma tanda:** el `ESQUEMA` de los cuatro prompts (paso 4), la delegación de
`reiniciar_presupuesto()` en el clasificador, el `self.classifier.reiniciar_presupuesto()` al empezar
`run_full_audit`, y los campos `ia_llamadas` / `ia_truncada_por_techo` en `save_results` — que son los que
hacen que el recorte **se vea en el informe**.
