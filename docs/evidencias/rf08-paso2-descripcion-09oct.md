# Evidencia — el campo «descripcion» de las vulnerabilidades salía siempre vacío (2026-10-09 12:50)

**El defecto.** `ia/orchestrator.py:270`, dentro de `_build_vulnerability()`:

```python
# Antes
"descripcion": analysis.get("justificacion", ""),
# Despues
"descripcion": analysis.get("descripcion", ""),
```

La clave `justificacion` **no la produce ningún prompt**. El `.get(..., "")` con defecto vacío es lo que ha
mantenido el fallo invisible durante meses: no lanza excepción, no deja rastro en los logs — simplemente
entrega **cada vulnerabilidad sin descripción**. Un fallo silencioso más, de la misma familia que el de
RNF-06 (apartado 3 del plan), donde un error de la IA era indistinguible de «sin hallazgos».

**Alcance comprobado, no supuesto.** Era el único sitio del repositorio que leía esa clave:

```
$ grep -rn 'justificacion' <cocina> --include='*.py'
ia/orchestrator.py:270:            "descripcion": analysis.get("justificacion", ""),
      (una sola ocurrencia; tras el arreglo, cero en todo el repo)
```

**Por qué `descripcion` es la clave correcta.** Se verificó cuál producen los prompts de verdad, en vez de
darlo por hecho:

| Prompt | ¿produce `descripcion`? |
|---|---|
| `network_packet.py` | sí |
| `intruder.py` | sí |
| `console.py` | sí |
| `fingerprint.py` | **no** |

`fingerprint` devuelve un informe de stack (`servidor`, `lenguaje`, `framework`, `vectores_prioritarios`), no
una vulnerabilidad. No afecta a este arreglo porque `_build_vulnerability()` construye vulnerabilidades, y
las tres vías que alimentan esa función son las tres primeras. Corrige además una frase inexacta del plan,
que decía «ningún prompt» a secas (declarado en su día por R9).

**Vuelta atrás (R8):** `git show HEAD:ia/orchestrator.py`. El diff es de **una línea**, del tamaño del
cambio.

**Lo que NO demuestra esta evidencia.** Que el campo llegue relleno al panel: eso exige una auditoría real,
que sigue bloqueada por la clave de API inválida. Lo demostrado aquí es que **se lee la clave que los
prompts escriben**, que era el defecto.
