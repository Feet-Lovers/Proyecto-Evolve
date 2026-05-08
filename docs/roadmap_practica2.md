# HookSuite — Road Map Práctica 2

## Fase 1 — Mejoras de rendimiento (semanas 1-2)

### 1. Caché de análisis de IA
Reusar resultados de análisis de IA para paquetes con el mismo URL pattern y tipo de payload.
Estimación: 3 días | Recursos: P5 | Reducción llamadas API: 40-60%

### 2. Procesamiento en batch para IA
Agrupar paquetes en lotes de 5-10 y enviarlos en una sola llamada a Claude.
Estimación: 2 días | Recursos: P5

---

## Fase 2 — Nuevas funcionalidades (semanas 3-4)

### 3. Interceptación de WebSockets
Capturar mensajes WebSocket con Network.webSocketFrameReceived del CDP.
Nuevo panel en frontend para visualizar tráfico WS.
Estimación: 5 días | Recursos: P4, P1, P5

### 4. Análisis de JavaScript estático con AST
Parsear el código JS de las páginas con esprima/acorn para detectar URLs hardcodeadas,
API keys expuestas y endpoints ocultos.
Estimación: 4 días | Recursos: P4, P5, P1

### 5. Detección de endpoints ocultos en JavaScript
Extraer automáticamente todas las URLs hardcodeadas en el código JavaScript
y explorarlas con el spider de P3.
Estimación: 3 días | Recursos: P4, P3

---

## Fase 3 — Integraciones externas

### 6. Integración con base de datos de CVEs (NVD)
Cruzar tecnologías detectadas con CVEs conocidos via API pública de NVD.
Estimación: 3 días | Recursos: P4, P1

### 7. Exportación de informes en formatos estándar
Exportar hallazgos en JSON, XML y PDF auto-generado con IA.
Estimación: 4 días | Recursos: P5, P1

---

## Mejoras de seguridad de la herramienta

### 8. Autenticación de usuarios con JWT
Sistema de login para que solo usuarios autorizados accedan a HookSuite.
Estimación: 2 días | Recursos: P2, P1

### 9. Cifrado de comunicaciones internas
TLS en todas las comunicaciones entre módulos del sistema.
Estimación: 1 día | Recursos: P2

### 10. Rate limiting anti-abuso en el Intruder
Limitar peticiones por usuario y por minuto para evitar uso no autorizado.
Estimación: 1 día | Recursos: P2

---

## Tabla resumen

| # | Mejora | Fase | Días | Responsable |
|---|--------|------|------|-------------|
| 1 | Caché análisis IA | 1 | 3 | P5 |
| 2 | Batch para IA | 1 | 2 | P5 |
| 3 | WebSockets | 2 | 5 | P4, P1, P5 |
| 4 | JS estático AST | 2 | 4 | P4, P5, P1 |
| 5 | Endpoints ocultos JS | 2 | 3 | P4, P3 |
| 6 | Integración CVEs | 3 | 3 | P4, P1 |
| 7 | Exportación estándar | 3 | 4 | P5, P1 |
| 8 | Autentic
