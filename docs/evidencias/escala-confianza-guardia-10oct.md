# Evidencia · La confusión de escala de `confianza` ya se ve en vez de desaparecer (10-oct-2026)

## Por qué el arreglo NO fue en el esquema

Los cuatro prompts piden `confianza` en escala **0-100** y **ninguno pide que sea entero** (comprobado
leyendo los cuatro, sin citarlos: `evidencias/testigo-confianza-entero-10oct.md`). Poner
`{"type": "integer"}` en el esquema habría **impuesto algo que el prompt no pide** y habría rechazado un
87.5 legítimo. Prompt y esquema deben acercarse, no separarse — el error de la mañana, del revés.

El riesgo real: si el modelo devolviera la escala 0-1 (un 0.85 queriendo decir «85 %»), la comparación
`0.85 >= 60` es falsa y **el hallazgo desaparece en silencio**. El caso peor es el `1`: en escala 0-1
significa certeza total, y leído como «1 %» descartaría un hallazgo seguro.

Arreglo: la franja `(0, 1]` se trata como sospecha de escala en el clasificador y se encamina al estado
degradado de **RNF-06**, que ya estaba montado. El problema **se ve**; no se corrige a la fuerza.

## La prueba distingue las dos versiones (lección del 5-oct: un cerco nuevo no vale sin verlo fallar)

### Contra el código ANTERIOR → 6/19

```
FALLA  guardia · 0.85 es sospechoso  → AttributeError: module 'clasificador_en_pruebas' has no attribute 'escala_sospechosa'
FALLA  guardia · 1 es sospechoso (el caso peor: certeza leída como 1 %)  → AttributeError: module 'clasificador_en_pruebas' has no attribute 'escala_sospechosa'
FALLA  guardia · 0 NO es sospechoso (es confianza nula, no escala mala)  → AttributeError: module 'clasificador_en_pruebas' has no attribute 'escala_sospechosa'
FALLA  guardia · 85 NO es sospechoso  → AttributeError: module 'clasificador_en_pruebas' has no attribute 'escala_sospechosa'
FALLA  guardia · 87.5 NO es sospechoso (decimal legítimo en 0-100)  → AttributeError: module 'clasificador_en_pruebas' has no attribute 'escala_sospechosa'
FALLA  guardia · un valor ausente no la dispara  → AttributeError: module 'clasificador_en_pruebas' has no attribute 'escala_sospechosa'
FALLA  guardia · un texto no la dispara  → AttributeError: module 'clasificador_en_pruebas' has no attribute 'escala_sospechosa'
FALLA  PACKET   · 0.85 con hallazgo → no_analizado CON motivo
FALLA  PACKET   · 0.85 NO se devuelve como «sin vulnerabilidad»
PASA   PACKET   · 70 sigue pasando como analizado
PASA   PACKET   · sin hallazgo y escala buena → None
FALLA  INTRUDER · 0.85 con hallazgo → no_analizado CON motivo
FALLA  INTRUDER · 0.85 NO se devuelve como «sin vulnerabilidad»
PASA   INTRUDER · 70 sigue pasando como analizado
PASA   INTRUDER · sin hallazgo y escala buena → None
FALLA  CONSOLE  · 0.85 con hallazgo → no_analizado CON motivo
FALLA  CONSOLE  · 0.85 NO se devuelve como «sin vulnerabilidad»
PASA   CONSOLE  · 70 sigue pasando como analizado
PASA   CONSOLE  · sin hallazgo y escala buena → None

6/19 pasan
```

Los **6 que pasan son los que deben pasar**: los casos legítimos. Eso prueba que la guardia no introduce
falsos positivos. Y el caso que lo demuestra todo es
`0.85 NO se devuelve como «sin vulnerabilidad»`: **falla**, es decir, el código anterior devolvía `None`
ante un hallazgo con confianza 0.85. El descarte silencioso queda **demostrado**, no argumentado.

### Contra el código CORREGIDO → 19/19

```
PASA   guardia · 0.85 es sospechoso
PASA   guardia · 1 es sospechoso (el caso peor: certeza leída como 1 %)
PASA   guardia · 0 NO es sospechoso (es confianza nula, no escala mala)
PASA   guardia · 85 NO es sospechoso
PASA   guardia · 87.5 NO es sospechoso (decimal legítimo en 0-100)
PASA   guardia · un valor ausente no la dispara
PASA   guardia · un texto no la dispara
PASA   PACKET   · 0.85 con hallazgo → no_analizado CON motivo
PASA   PACKET   · 0.85 NO se devuelve como «sin vulnerabilidad»
PASA   PACKET   · 70 sigue pasando como analizado
PASA   PACKET   · sin hallazgo y escala buena → None
PASA   INTRUDER · 0.85 con hallazgo → no_analizado CON motivo
PASA   INTRUDER · 0.85 NO se devuelve como «sin vulnerabilidad»
PASA   INTRUDER · 70 sigue pasando como analizado
PASA   INTRUDER · sin hallazgo y escala buena → None
PASA   CONSOLE  · 0.85 con hallazgo → no_analizado CON motivo
PASA   CONSOLE  · 0.85 NO se devuelve como «sin vulnerabilidad»
PASA   CONSOLE  · 70 sigue pasando como analizado
PASA   CONSOLE  · sin hallazgo y escala buena → None

19/19 pasan
```

## Sin regresión

```
test_tres_estados      8/8 pasan
test_esquemas_bandera  11/11 pasan
test_escala_confianza  19/19 pasan
```

## Lo que la guardia NO hace, a propósito

- **No se aplica a la vía de identificación de servidor**: esa no compara contra el umbral (devuelve los
  datos del modelo sin filtrar), así que ahí no hay descarte silencioso que cerrar.
- **Un `1` legítimo (1 % de confianza) también cae en la franja** y se marca como sospechoso. Es
  aceptable: con umbral 60 tampoco se habría reportado, y así queda **visible e inspeccionable** en vez de
  desaparecer. Preferir el falso positivo visible al falso negativo silencioso es la misma elección que
  RNF-06 ya tomó.
- **No se tocaron los prompts.** Cambiarlos para pedir «entero» era la alternativa más limpia
  conceptualmente, y se descartó: son cuatro ficheros protegidos, en prosa, editados a ciegas, a tres días
  de la congelación.
