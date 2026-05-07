# Documentación técnica — HookSuite Playwright
## Stack tecnológico
- Python 3.11
- Playwright 1.44 (automatización de navegador)
- asyncio (paralelismo)
- httpx (comunicación con el backend)
## Módulos implementados
### Spider (modules/spider.py)
Crawler automático que mapea todas las URLs accesibles de la aplicación objetivo.
Algoritmo BFS con filtrado de dominios externos y extensiones de archivo
irrelevantes.
Límite configurable de páginas máximas para evitar loops infinitos.
### Form Discoverer (modules/forms.py)
Descubre todos los formularios HTML en las páginas mapeadas por el spider.
Identifica campos inyectables y descubre peticiones AJAX mediante simulación de
interacciones.
### Fingerprinter (modules/fingerprint.py)
Detecta tecnologías del servidor objetivo analizando headers HTTP, cookies y
contenido HTML.
Genera prioridades de ataque basadas en las tecnologías detectadas.
### Attacker (modules/attacker.py)
Automatiza el envío de payloads en formularios y detecta anomalías en las
respuestas.
Implementa Blind SQLi boolean-based y time-based.
Toma capturas de pantalla antes y después de cada ataque.
### Orchestrator Receiver (modules/orchestrator_receiver.py)
Recibe instrucciones del módulo de IA (P5) y las ejecuta.
Hace polling al backend cada 2 segundos para recibir nuevas instrucciones.
## Optimización de velocidad
Se usa page.fill() en vez de page.type() en todas las interacciones de texto.
Mejora medida: [X]x más rápido (ver benchmark en capturas).
La paralelización usa asyncio.Semaphore con límite de 3 páginas simultáneas.
## Limitaciones conocidas
- No funciona con aplicaciones que usan CAPTCHAs
- La autenticación de dos factores requiere intervención manual
- Aplicaciones con JavaScript muy complejo pueden requerir timeouts más largos
- El Blind SQLi time-based puede dar falsos positivos en servidores lentos
## Entorno de pruebas
DVWA (Damn Vulnerable Web Application) en Docker, nivel de seguridad Low.
docker run -d -p 8888:80 vulnerables/web-dvwa
