# Evidencia · Comprobación previa: ¿puede la caja generar las credenciales? (bloque 2a)

**Fecha:** 2026-10-08, 06:34:45 UTC (08:34 CEST) · **Entorno:** caja `91.98.143.219`, **solo lectura**
· **Requisito:** RF-12, apartado 8 · **Quién:** josemax lo ejecuta, Claude lo arma

**Qué muestra:** que antes de ejecutar el bloque que modifica producción se verificó que el generador de
credenciales **puede correr allí**. `tools/generar-credenciales.py` aborta al arrancar si falta `bcrypt`
(líneas 31-32), y lo hace **antes** de mirar si hay usuarios → arrancar con cero usuarios no evita la
dependencia.

**Por qué un bloque aparte y de solo lectura:** para no descubrir la falta a mitad del bloque 2, con el
código ya reseteado y los secretos sin poner. No instala nada a propósito: instalar es decisión de josemax.

**R7:** del `.env` solo se imprime si cada clave está presente o ausente. Ningún valor.

---

## Salida literal

```
=== 2a · PUEDE LA CAJA GENERAR LAS CREDENCIALES? ===
2026-10-08 06:34:45 UTC

-- python3 del host --
   Python 3.12.3

-- modulo bcrypt en el host --
   ✅ bcrypt disponible: 3.2.2
   -> el bloque 2 puede usar el script tal cual

-- el mismo modulo DENTRO del contenedor del backend (ahi si debe estar) --
ModuleNotFoundError: No module named 'bcrypt'

-- pip disponible en el host, por si hubiera que instalar --
   pip3: NO esta
   venv: disponible

-- hay ya un .env con estas claves puestas? (NO se muestra ningun valor) --
   JWT_SECRET: AUSENTE
   REGISTRO_CODIGO: AUSENTE
   HOOKSUITE_USERS: AUSENTE
   JWT_HORAS_VALIDEZ: AUSENTE
=== FIN 2a ===
```

## Lectura, dato por dato

| Dato | Lectura |
|---|---|
| `bcrypt 3.2.2` en el host | ✅ el generador puede correr tal cual |
| `ModuleNotFoundError` **en el contenedor** | ⚠️ **esperado**, no un fallo — ver abajo |
| `pip3: NO esta`, `venv: disponible` | irrelevante al final: no hay que instalar nada |
| Las 4 claves **AUSENTES** | ✅ el generador no abortará; y confirma que la Fase 2 no se ha desplegado |

### El `ModuleNotFoundError` del contenedor, explicado

Parecía el aviso de un despliegue abocado a un backend en bucle de reinicio y la API en 502. **No lo es, y se
comprobó en vez de suponerse (R9):**

1. Ese contenedor corre la **imagen vieja de la Fase 1**, que no tenía login ni necesitaba bcrypt.
2. `backend/requirements.txt:13` en `origin/main@3d3baba8` pide **`bcrypt==4.1.3`**.
3. El contenedor equivalente **de la cocina**, que ya sirve la Fase 2, lo tiene: `bcrypt 4.1.3` verificado en
   vivo (`docker exec proyecto-evolve-backend-1`).

→ El `--build` del bloque 3 construye la imagen nueva **con** la dependencia. El aviso era la pregunta
correcta; la respuesta es que no bloquea.

### La diferencia de versiones host (3.2.2) vs contenedor (4.1.3) no afecta

Son procesos distintos: el generador corre en el host, el backend dentro del contenedor. Y **con cero
usuarios de arranque el generador no produce ningún hash bcrypt** —solo `secrets.token_hex` y
`token_urlsafe`, biblioteca estándar—, así que no hay ningún valor derivado que tenga que interoperar entre
las dos versiones. Si algún día se añadieran usuarios de arranque desde el host, habría que volver a mirarlo.

## Decisión que sale de aquí

El bloque 2 usa el script **tal cual**, en el host, alimentado con una **línea vacía** (`printf '\n' |`) para
responder «ningún usuario de arranque». Comprobado en la cocina con un `.env` de usar y tirar: añade sin
sobrescribir, crea las 4 claves con 0 usuarios, y **aborta con código 1** si ya existían.
