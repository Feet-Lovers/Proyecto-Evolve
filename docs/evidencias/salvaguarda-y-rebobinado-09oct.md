# La salvaguarda, el rebobinado y las cuatro opciones — qué hacer la próxima vez (9-oct-2026)

> Transcrito **de cinco capturas que sacó josemax en el momento** (`001.png`–`005.png`), borradas después
> de volcarlas aquí porque el texto es buscable y comparable y la imagen no (R3). Sin secretos a la vista:
> no aparece ningún valor de clave ni token (R7). El `Request ID` **no es un secreto**: es la referencia
> para `/feedback` o soporte.

## 1 · Qué pasó exactamente (captura 001)

La sesión **no se pausó dando a elegir modelo**: devolvió un **error de API** que impidió la respuesta.
Texto literal:

```
API Error: Opus 5's safeguards flagged this message (https://www.anthropic.com/legal/aup).
Our intentionally broad safeguards allow us to deliver more capabilities faster, but can
sometimes flag legitimate coding, cybersecurity, and biology tasks.
Claude Code can't respond to this message with Opus 5.

Double press esc to edit your last message, or try a different model with /model.
Send feedback with /feedback or learn more: https://support.claude.com/en/articles/16049681
Request ID: req_011CfrDXntKLez5jssh7kN1s
✳ Worked for 5m 23s
```

**Lo que esto confirma:** la variable `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` que josemax aplicó el 8-oct
**funciona**: la sesión **no se cambió sola a Opus 4.8**, se detuvo. Y el propio mensaje de Anthropic admite
que el filtro «a veces marca tareas legítimas de programación, **ciberseguridad** y biología» — que es
exactamente lo que es esta línea.

**Qué se estaba haciendo al marcarse:** leer los cuatro *prompts* del módulo de IA (clasificador de
vulnerabilidades) de la Práctica 3. El turno había trabajado **5 min 23 s** antes de ser bloqueado.

## 2 · El rebobinado NO es parte de la salvaguarda

El error no ofrece ningún menú. El **Rewind** es otra función de Claude Code (doble `Esc`) que josemax abrió
para desatascarse. Su lista mostraba dos puntos de retorno:

| Mensaje | Lo que el Rewind sabía de él |
|---|---|
| `Hola. Muy buenos días. ¿Que tal todo?` | `4 files changed +19 -4` |
| `No. Vamos a seguir con la practica 3 a ver si hoy pudieramos dejarla terminada` | `No code changes` |

🔴 **Dato crítico:** el turno que **construyó la imagen Docker** figura como **«No code changes»**. El Rewind
**contabiliza ficheros, no efectos en el servidor**. Por eso su promesa «*The code will be unchanged*» da una
tranquilidad engañosa: no deshace —ni sabe de— imágenes construidas, contenedores levantados, servicios
reiniciados o llamadas a la API ya gastadas.

## 3 · Las cuatro opciones, literales (capturas 002–005)

Todas sobre: *«restore to the point before you sent this message: No. Vamos a seguir con la practica 3…»*

| # | Opción | Qué dice que hace | Efecto real |
|---|---|---|---|
| 1 | `Restore conversation` | «The conversation will be **forked**. The code will be unchanged.» | 🔴 **Tira todo lo posterior.** Es la que se eligió y la que costó los 8 minutos |
| 2 | `Summarize from here` | «Messages after this point **will be summarized**.» (+ campo «add context» opcional) | 🟡 Vuelve atrás **pero conserva el resumen** de lo trabajado |
| 3 | `Summarize up to here` | «**Preceding** messages will be summarized. This and subsequent messages will remain unchanged — **you will stay at the end of the conversation**.» (+ «add context») | 🟢 **No retrocede**: comprime lo anterior y te deja donde estabas |
| 4 | `Never mind` | «The conversation will be unchanged. The code will be unchanged.» | ⚪ Sale sin tocar nada |

## 4 · Qué hacer la próxima vez

**Regla de oro: en el momento del aviso no se ha perdido nada todavía.** La conversación está intacta; lo
único que ha fallado es *una* respuesta. Las prisas son lo que cuesta trabajo, no la salvaguarda.

1. **No rebobines de entrada.** Primero mira si hace falta.
2. **Mándame un mensaje nuevo y corriente** («escribe la memoria de lo que llevamos»). El bloqueo es de **ese**
   mensaje, no de la sesión; con uno distinto suelo poder contestar. **Así se salva el trabajo en disco**, que
   es lo único que ningún rebobinado toca.
3. **Si quieres seguir sin perder nada:** doble `Esc` y **opción 3 (`Summarize up to here`)** — te quedas al
   final de la conversación y solo se comprime lo de antes.
4. **Si hay que volver atrás de verdad:** **opción 2 (`Summarize from here`)**, que conserva un resumen de lo
   trabajado, y aprovecha el campo «add context» para escribir en una línea qué se estaba haciendo.
5. **La opción 1 (`Restore conversation`) solo si quieres tirar a propósito** lo posterior a ese punto.
6. **Otra vía que sugiere el propio error:** doble `Esc` para **editar el último mensaje** y reformularlo.
   Evita el bloqueo sin tocar el historial.
7. **Después de cualquier rebobinado, avísame de que lo ha habido.** El servidor puede haber quedado por
   delante de la conversación (aquí: una imagen de 719 MB que yo ya no recordaba haber construido).

## 5 · Lo que se recuperó gracias a estas capturas

La captura 001 conserva el último hallazgo del tramo perdido, que ya se puede devolver al plan de RF-08:

> «Los cuatro prompts leídos. **Un matiz que corrige el plan (R9):** el plan dice «los cuatro prompts piden
> `descripcion`» — **`fingerprint` no tiene ese campo**; devuelve un informe de stack. No afecta al arreglo de
> `orchestrator.py:270` (que construye vulnerabilidades, no fingerprints), pero lo anoto porque la afirmación
> era inexacta.»

Y explica el misterio del log: el build salió «sin salida» a las 08:47:33 porque se lanzó **en segundo
plano** — «*Background command "Construir la imagen del módulo ia en la cocina" completed (exit code 0)*» —,
de ahí que la imagen quedara fechada a las 08:48:03.

## 6 · Moraleja de proceso

El rebobinado borró la conversación, **no el disco**. Lo que sobrevivió fue lo escrito: la memoria del
servidor, el diario y los commits. **Escribir en el momento, y no al cierre, es lo que convirtió una pérdida
de 28 minutos en una de 8.** Material para el apartado 12 (uso de herramientas de IA) ⚠️[corregido 9-oct: hoy se escribió «apartado 11 (proceso)» cinco veces y el 11 es «Reparto del trabajo»; verificado en `P3-memoria.typ:496`].
