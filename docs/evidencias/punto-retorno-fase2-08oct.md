# Evidencia · Punto de retorno antes de desplegar la Fase 2 (R8)

**Fecha:** 2026-10-08, 06:17:51 UTC (08:17 CEST) · **Entorno:** caja `91.98.143.219` (`www.hooksuite.de`)
· **Requisito:** apartado 8 (pruebas) y metodología · **Quién:** josemax lo ejecuta, Claude lo arma

**Qué muestra:** que antes de tocar producción existía una vuelta atrás **verificada**, no supuesta. R8 exige
asegurar el retorno *y comprobar que el respaldo sirve* antes de una operación irreversible.

**Por qué este bloque y no un `tar`:** la caja no necesita copia de ficheros —el código vive en git y el
estado real son las imágenes Docker ya construidas—. Etiquetar las imágenes es instantáneo y no duplica
disco; un `tar` de 1,1 GB habría tardado minutos y copiado lo que git ya guarda.

**R7:** el `.env` se copia sin mostrar ni un valor. Solo se imprime el número de líneas.

---

## Salida literal

```
=== PUNTO DE RETORNO FASE 2 ===
2026-10-08 06:17:51 UTC

-- 1) Estado de git al que habria que volver --
   HEAD actual: 485a22ec663cb332a6bdb02e269246c1fe65382d
   ficheros sin commitear: 0
   guardado en /root/VUELTA-ATRAS-fase1.txt

-- 2) Copia del .env (sus valores NO se muestran) --
   creada .env.pre-fase2 (modo 600, 6 lineas)

-- 3) Imagenes actuales etiquetadas como prefase2/ --
   backend -> prefase2/backend:07oct  (a613150b2391)
   frontend -> prefase2/frontend:07oct  (73df255b13bb)
   playwright -> prefase2/playwright:07oct  (cf6939e3a867)
   ia -> prefase2/ia:07oct  (e247c7ccc059)

-- 4) Verificacion de que el punto de retorno existe de verdad --
   etiquetas creadas: 4 de 4
=== FIN ===
```

## Qué queda guardado, y cómo se vuelve

| Pieza | Dónde | Para qué |
|---|---|---|
| `485a22ec` | `/root/VUELTA-ATRAS-fase1.txt` (en la caja) | `git reset --hard` al commit de la Fase 1 |
| `.env.pre-fase2` | `/root/hooksuite/`, modo 600 | recuperar el `.env` sin los 2 secretos nuevos |
| `prefase2/{backend,frontend,playwright,ia}:07oct` | imágenes Docker locales | volver a las imágenes servidas, sin reconstruir |

## Lo que NO prueba (honestidad del cerco)

El **paso 4 listó cero líneas**: el `--format` de `docker images` antepone espacios que Docker recorta, y el
`grep '^   prefase2/'` del script no casó. **No es que falten las etiquetas** — el contador de la línea
siguiente es un comando independiente y dio `4 de 4`, y el paso 3 nombra las cuatro con su ID corto. Queda
anotado porque esta línea ya se tropezó con un cerco en verde que no comprobaba nada (R4, 5-oct): un
listado vacío junto a un «4 de 4» es exactamente la clase de contradicción que no se deja pasar sin mirar.

**Arreglo para la próxima vez:** quitar los espacios del `--format` y del patrón, o usar
`docker images --filter=reference='prefase2/*'`.
