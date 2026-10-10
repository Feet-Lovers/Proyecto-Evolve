# Evidencia · Los esquemas de RF-08 no imponen lo que los prompts piden (10-oct-2026)

Capturada **ANTES del arreglo** (R6: nuestros propios arreglos destruyen esta evidencia).

El esquema viaja a la API como salida estructurada (`ia/client.py:115`), así que **el esquema ES la
validación**. Un tipo abierto no es permisividad: es ausencia de control.

## Salida de `python3 ia/tests/test_esquemas_bandera.py ia/esquemas.py`

```
PASA   PACKET  · 'vulnerable' rechaza una cadena
FALLA  INTRUDER · 'explotado' rechaza una cadena
FALLA  CONSOLE · 'sensible' rechaza una cadena
PASA   PACKET  · 'vulnerable' acepta false
PASA   INTRUDER · 'explotado' acepta true
PASA   CONSOLE · 'sensible' acepta false
FALLA  INTRUDER · 'confianza' rechaza 0.85 (escala 0-1)
PASA   INTRUDER · 'confianza' acepta 85 (escala 0-100)
FALLA  PACKET  · 'confianza' rechaza 150 (fuera de rango)
FALLA  FINGERPRINT · declara los 9 campos que pide su prompt
FALLA  FINGERPRINT · 'vectores_prioritarios' es una lista de objetos  → KeyError: 'vectores_prioritarios'

consecuencia en Python: bool('no') == True  →  un `if result.get(...)` con una cadena da SIEMPRE verdadero
5/11 pasan
```

## Lectura

- `vulnerable` (PACKET) es el **único** campo bandera blindado: `{'type': 'boolean'}` en `ia/esquemas.py:14`.
- `explotado` (`:28`) y `sensible` (`:42`) llevan tipo **abierto** y aceptan una cadena, aunque
  `ia/analyzers/vulnerability_classifier.py:75` y `:112` las interpretan en un `if`, igual que la línea 39
  interpreta `vulnerable`. Consecuencia medida arriba: `bool('no') == True`.
- `confianza` se declara `type: number` **sin rango**, así que un 0.85 pasa la validación y luego
  `0.85 >= CONFIDENCE_THRESHOLD` (60) lo descarta **en silencio**.
- `ESQUEMA_FINGERPRINT` declara **0** campos y su prompt pide **9** (informe del testigo §2 y §4).

## Causa raíz — una sola, y fuera del repo del producto

`lineas/practica3-hooksuite/herramientas/generar-esquemas.py:25` fija a mano
`TIPOS_CONOCIDOS = {"vulnerable": boolean, "confianza": number}`. Se escribió mirando solo PACKET; el
comentario de la línea 24 lo delata hablando de «"vulnerable" en un if», en singular. INTRUDER y CONSOLE
usan **otro nombre para el mismo papel**. Y el esquema vacío de fingerprint es consecuencia mecánica: el
generador deriva las claves de los `result.get(...)` del clasificador, y `fingerprint()` no hace ninguno
(`vulnerability_classifier.py:140` hace `return respuesta.datos`).

**No son tres defectos: es un generador con la lista incompleta.**

---

## Después del arreglo (mismo día, 10-oct)

El arreglo NO se hizo en `ia/esquemas.py` —su cabecera lo prohíbe y el siguiente generador se lo
llevaría— sino en `herramientas/generar-esquemas.py`, y luego se regeneró:

```
$ python3 ~/claude-workspace/lineas/practica3-hooksuite/herramientas/generar-esquemas.py \
      ia/analyzers/vulnerability_classifier.py ia/esquemas.py
ESQUEMA_PACKET: 7 claves (deducidas del clasificador)
ESQUEMA_INTRUDER: 7 claves (deducidas del clasificador)
ESQUEMA_CONSOLE: 7 claves (deducidas del clasificador)
ESQUEMA_FINGERPRINT: 9 claves (declaradas)
escrito: ia/esquemas.py
```

Nótese el `(declaradas)` de FINGERPRINT: el generador ahora dice de dónde salen las claves de cada
esquema, para que una sesión futura no tenga que averiguarlo.

```
PASA   PACKET  · 'vulnerable' rechaza una cadena
PASA   INTRUDER · 'explotado' rechaza una cadena
PASA   CONSOLE · 'sensible' rechaza una cadena
PASA   PACKET  · 'vulnerable' acepta false
PASA   INTRUDER · 'explotado' acepta true
PASA   CONSOLE · 'sensible' acepta false
PASA   INTRUDER · 'confianza' 0.85 pasa: el rango NO caza la confusión de escala
PASA   INTRUDER · 'confianza' acepta 85 (escala 0-100)
PASA   PACKET  · 'confianza' rechaza 150 (fuera de rango)
PASA   FINGERPRINT · declara los 9 campos que pide su prompt
PASA   FINGERPRINT · 'vectores_prioritarios' es una lista de objetos

consecuencia en Python: bool('no') == True  →  un `if result.get(...)` con una cadena da SIEMPRE verdadero
11/11 pasan
```

Y sin regresión en RNF-06:

```
$ python3 ia/tests/test_tres_estados.py ia/analyzers/vulnerability_classifier.py

8/8 pasan
```

## Lo que queda abierto, y por qué no se cierra a ojo

El caso de `0.85` **pasa a propósito** y el test lo dice con ese nombre. Un rango 0-100 no puede cazar la
confusión de escala, porque 0.85 está *dentro* de 0-100 (sería «0,85 % de confianza»): el código haría
`0.85 >= 60` → falso y el hallazgo desaparecería en silencio. Cazarlo exige `{"type": "integer"}`, y eso
depende de si los prompts piden un **número entero** — dato que el informe del testigo **no recoge** (§1
da la escala, no el tipo). Se deja documentado en el propio test en vez de adivinarlo.
