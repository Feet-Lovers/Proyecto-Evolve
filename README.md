# HookSuite

**Herramienta de auditoría de seguridad web con Inteligencia Artificial**

HookSuite es una plataforma de pentesting web que combina interceptación de tráfico HTTP en tiempo real, automatización de ataques con Playwright y análisis con inteligencia artificial para detectar vulnerabilidades de forma automatizada.

---

## Módulos del proyecto

| Módulo | Descripción | Rama |
|--------|-------------|------|
| Frontend | Dashboard React con interfaz de usuario | `feature/frontend` |
| Backend | API FastAPI con proxy HTTP y WebSockets | `feature/backend` |
| Playwright | Automatización de ataques con navegador | `feature/playwright` |
| DevTools | Captura de tráfico con Chrome DevTools Protocol | `feature/devtools` |
| IA | Análisis y orquestación con Claude API | `feature/ia` |

---

## Stack tecnológico

- **Frontend:** React 18 + Vite + Tailwind CSS
- **Backend:** Python 3.11 + FastAPI + mitmproxy + WebSockets
- **Automatización:** Playwright + asyncio
- **Captura de red:** Chrome DevTools Protocol (CDP)
- **Inteligencia Artificial:** Anthropic Claude API
- **Infraestructura:** Docker + Hetzner Cloud + Nginx + GitHub Actions

---

## Instalación y despliegue

Ver [`/docs/guia_despliegue.md`](docs/guia_despliegue.md)

---

## Reglas de contribución

Ver [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## Estructura del repositorio

```
hooksuite/
├── frontend/       ← Módulo P1 — React + Vite
├── backend/        ← Módulo P2 — FastAPI + mitmproxy
├── playwright/     ← Módulo P3 — Automatización
├── devtools/       ← Módulo P4 — Chrome DevTools Protocol
├── ia/             ← Módulo P5 — Claude API
├── infra/          ← Docker Compose + Nginx
├── docs/           ← Documentación e informe PDF
├── .github/
│   └── workflows/  ← Pipeline de GitHub Actions
├── .gitignore
├── CONTRIBUTING.md
├── docker-compose.yml
└── README.md
```

---

## Módulo: Ciberseguridad Avanzada | Curso 2026  
**Entrega:** 25 de Mayo de 2026
