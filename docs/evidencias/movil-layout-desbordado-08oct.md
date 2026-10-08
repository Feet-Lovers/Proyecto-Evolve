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

## Resuelto: comprobado por josemax el mismo día

Se preguntó si la barra de secciones se podía desplazar con el dedo, porque de eso dependía la
clasificación. Respuesta, con tres comprobaciones:

| Cómo se mira | Qué pasa |
|---|---|
| Vertical, deslizando la barra | **No hace nada.** No hay scroll horizontal |
| Girando el móvil a horizontal | Se ven **más** secciones, no necesariamente todas |
| Activando «modo escritorio» del navegador | Se ve **la herramienta completa** |

**Clasificación: RF-01 cumplido, con limitación documentada.** No se baja a «Parcial» porque se puede
llegar a todas las funciones **sin instalar nada** —girando el aparato o pidiendo el modo escritorio—, que
es literalmente lo que el requisito exige. Pero en el uso normal (vertical, navegador tal cual) **tres de
las seis secciones no son alcanzables y nada indica que existan**: no hay flecha, ni scroll, ni menú. La
salvedad se declara en la matriz de trazabilidad y en el apartado 10 en vez de dejar un «Cumplido» liso.

## Causa, localizada en el código

`frontend/src/components/layout/Layout.jsx`:

- `.hs-tabs` es un contenedor `flex` **sin `overflow-x`**, y el contenedor raíz tiene `overflow: hidden`:
  lo que no cabe se recorta, sin posibilidad de desplazarlo.
- `.hs-tab` lleva `white-space: nowrap` pero **no `flex-shrink: 0`**, así que las pestañas se comprimen
  hasta su mínimo antes de desaparecer.
- **El fichero no tiene ninguna `@media`.** No es un responsive mal ajustado: es que no existe.

## Contexto de la decisión (8-oct)

Los nueve RNF del proyecto **no incluyen ninguno de responsive, móvil ni usabilidad**, así que el retoque
no nace de un requisito explícito. La congelación de código es el **13-oct**. Con eso sobre la mesa, el
plan acordado es: capturar ahora (hecho), valorar un *responsive mínimo* —usable, no bonito— solo si
sobra tiempo tras lo que sí puntúa, y llevar el rediseño al apartado 10 como trabajo futuro, con el
razonamiento de por qué no se abordó antes de entregar.
