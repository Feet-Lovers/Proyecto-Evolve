# Evidencia · La interfaz en móvil: el layout no se adapta

**Fecha:** 2026-10-08, 10:05 CEST · **Entorno:** `www.hooksuite.de` en producción, navegador de móvil
(datos móviles, 5G) · **Requisito:** RF-01, RNF-09 · **Quién:** josemax

**Qué muestra:** la pestaña *Repeater* del panel, ya en producción con la Fase 2, abierta desde un teléfono.
El diseño es el de escritorio sin adaptar.

**Por qué se captura ANTES de tocar nada (R6):** si se arregla el responsive, esta imagen deja de poder
tomarse. El apartado 8 pide las pruebas que fallaron con su explicación, y el 10 las limitaciones
conocidas: en cualquiera de los dos casos, la evidencia tenía que existir antes del arreglo. Se capturó
nada más detectarlo, sin esperar a decidir si se corrige.

**Captura:** `capturas/fase2/RF-01-movil-layout-desbordado.jpeg`

---

## Defectos visibles, uno a uno

| # | Qué pasa | Gravedad |
|---|---|---|
| 1 | La barra de secciones se corta tras `INTRUDER`: **UTILIDADES, VULNERABILIDADES y RED quedan fuera de pantalla** | ⚠️ por determinar — ver abajo |
| 2 | El campo de URL aparece seccionado a media palabra (`https://ob…`) | impide leer y revisar lo que se envía |
| 3 | El botón `+ añadir` de cabeceras queda cortado por el borde derecho | puede ser impulsable |
| 4 | El layout de **dos columnas se mantiene en vertical**: la derecha gasta media pantalla con «envía una petición para ver la respuesta aquí» mientras la izquierda va estrujada | debería apilarse en vertical |
| 5 | Aviso **«No seguro»** junto al dominio | es RNF-09 (sin TLS), ya conocido y pendiente |

## ⚠️ Lo que esta evidencia NO resuelve todavía

**No se sabe si la barra de secciones se puede desplazar con el dedo.** De eso depende cómo se clasifica
el hallazgo, y la diferencia no es menor:

- **Si se desplaza** → es incomodidad de uso. RF-01 sigue cumplido y el arreglo es una mejora.
- **Si no se desplaza** → **tres de las siete secciones del producto son inalcanzables desde un móvil**, y
  RF-01 («dashboard web de control accesible desde cualquier navegador, sin instalar nada en el cliente»)
  deja de estar limpiamente cumplido: se accede al panel, pero no a un tercio de sus funciones.

⚠️ **FALTA: confirmar si la barra de secciones se desplaza en el móvil [pantalla, josemax]**

Se deja escrito sin resolver en lugar de suponer la respuesta cómoda. Es el mismo criterio que con el 404
de IPv6: una hipótesis razonable no es una comprobación.

## Contexto de la decisión (8-oct)

Los nueve RNF del proyecto **no incluyen ninguno de responsive, móvil ni usabilidad**, así que el retoque
no nace de un requisito explícito. La congelación de código es el **13-oct**. Con eso sobre la mesa, el
plan acordado es: capturar ahora (hecho), valorar un *responsive mínimo* —usable, no bonito— solo si
sobra tiempo tras lo que sí puntúa, y llevar el rediseño al apartado 10 como trabajo futuro, con el
razonamiento de por qué no se abordó antes de entregar.
