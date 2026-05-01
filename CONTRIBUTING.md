# Guía de contribución — HookSuite

Este documento define las reglas de trabajo del repositorio. **Todos los miembros del equipo deben leerlo antes de hacer su primer commit.**

---

## Convención de commits

Todos los commits deben seguir este formato exacto:

```
tipo(scope): descripción en imperativo presente
```

### Tipos permitidos

| Tipo | Cuándo usarlo |
|------|--------------|
| `feat` | Nueva funcionalidad |
| `fix` | Corrección de errores |
| `docs` | Cambios en documentación |
| `refactor` | Reestructuración sin cambio de comportamiento |
| `test` | Añadir o modificar tests |
| `chore` | Tareas de mantenimiento (actualizar dependencias, .gitignore, etc.) |

### Scopes disponibles

```
frontend | backend | playwright | devtools | ia | infra | docs
```

### Ejemplos correctos

```
feat(frontend): panel de peticiones interceptadas con filtros
feat(backend): servidor FastAPI base con WebSockets
fix(backend): corregir timeout en proxy HTTP
chore(backend): actualizar requirements.txt
docs(ia): documentar prompts de análisis de SQLi
chore(infra): actualizar versión de nginx en docker-compose
```

### Ejemplos incorrectos

```
actualizado el frontend          ← sin tipo ni scope
feat: cosas varias               ← sin scope, descripción vaga
FEAT(FRONTEND): Panel            ← mayúsculas no permitidas
preparacion de entorno python    ← sin tipo ni scope
borrar gitignore                 ← sin tipo ni scope
no va el gitignore shit          ← sin tipo ni scope y lenguaje inapropiado
```

---

## Política de ramas

| Rama | Uso |
|------|-----|
| `main` | Rama principal protegida. Solo recibe merges mediante Pull Request aprobado por P5 |
| `feature/frontend` | Rama de trabajo de P1 |
| `feature/backend` | Rama de trabajo de P2 |
| `feature/playwright` | Rama de trabajo de P3 |
| `feature/devtools` | Rama de trabajo de P4 |
| `feature/ia` | Rama de trabajo de P5 |

**Regla fundamental:** Nunca hacer push directo a `main`. Todo cambio pasa por Pull Request.

---

## Pull Requests

Para mergear a `main`:
- Mínimo una revisión aprobada por P5
- Sin conflictos sin resolver
- Pipeline de GitHub Actions en verde

### Título del Pull Request

Mismo formato que los commits:
```
feat(backend): módulo proxy HTTP completo
```

---

## Nombres de archivos y carpetas

- Siempre en minúsculas
- Palabras separadas por guión bajo: `proxy_service.py`
- Sin espacios ni caracteres especiales

---

## Lo que nunca debe subirse al repositorio

- Archivos `.env` con credenciales reales
- API Keys o tokens de acceso
- Carpetas `venv/`, `node_modules/`, `__pycache__/`
- Archivos de prueba temporales (`prueba.txt`, `test123.py`, etc.)

El `.gitignore` ya está configurado para ignorar estos archivos. Si por error subes algo sensible, comunícalo inmediatamente a P5.

---

*Proyecto HookSuite — Módulo de Ciberseguridad Avanzada 2026*
