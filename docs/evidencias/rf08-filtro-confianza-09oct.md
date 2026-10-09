# Evidencia — el orquestador anulaba el umbral de RNF-06, y habría tapado el estado degradado (2026-10-09 13:10)

## El defecto

`ia/orchestrator.py:223`, dentro de `run_attack_phase`:

```python
if analysis and analysis.get("confianza", 0) >= 0.6:
```

El clasificador declara su umbral como **`CONFIDENCE_THRESHOLD = 60`**, en escala **0-100** (verificado con
`grep -c`, sin volcar el fichero). El orquestador comparaba contra **0.6**. Dos consecuencias, y la segunda
es la que bloqueaba RNF-06:

1. **El filtro no filtraba.** Cualquier hallazgo con confianza ≥ 1 pasaba — es decir, prácticamente todos.
   El umbral de RNF-06 existía en el clasificador y el orquestador lo estaba anulando.
2. 🔴 **Habría descartado el estado degradado en silencio.** El dict `no_analizado` del apartado 3 no lleva
   campo `confianza`, así que `.get("confianza", 0)` devuelve 0, `0 >= 0.6` es falso, y el «no analizado» se
   perdía antes de llegar al informe. **RNF-06 habría seguido invisible aunque se arreglara el
   clasificador** — de ahí que el orden del plan sea obligado: orquestador antes que clasificador.

## El arreglo

- **Una sola fuente para el umbral.** Se importa `CONFIDENCE_THRESHOLD` del clasificador en vez de repetir
  el número. Tener el umbral escrito en dos sitios con dos escalas distintas *es* la causa del bug; cambiar
  el `0.6` por un `60` habría arreglado el síntoma y dejado la causa.
- **Tres ramas en vez de una.** «No analizado» no es una vulnerabilidad candidata: no hay nada que
  confirmar, así que se registra con su motivo y la fase sigue, sin pasar por `_confirm_vulnerability`
  (que además gastaría llamadas a la API para confirmar algo que no se analizó).
- **Que SE VEA en el resultado.** `save_results` publica ahora `no_analizados` (cuántos) y
  `no_analizados_detalle` (con el motivo de cada uno), junto a `total_analyses` y `vulnerabilities`. Un
  recorte silencioso dejaría el informe diciendo «sin hallazgos» sobre una auditoría a medias.

## Comprobación

- `python3 -m py_compile orchestrator.py` → compila. Diff de **15 inserciones / 2 borrados**, del tamaño del
  cambio. Vuelta atrás: `git show HEAD:ia/orchestrator.py`.
- El único `0.6` que queda en el fichero es el comentario que explica el bug, para que nadie lo reintroduzca.

## Lo que NO demuestra

Que el estado degradado llegue al informe **de punta a punta**: el clasificador todavía no produce el dict
`no_analizado` (apartado 3, pendiente del visto bueno de josemax para leer ese fichero). Lo demostrado aquí
es que **el camino ya no lo descarta** y que el umbral vuelve a tener un solo valor y una sola escala.
