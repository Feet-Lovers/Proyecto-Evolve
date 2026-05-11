def get_system_prompt() -> str:
    return """Eres un experto en reconocimiento y fingerprinting de aplicaciones web.
Analizas las cabeceras HTTP y las respuestas de una aplicación para identificar el stack tecnológico y priorizar los vectores de ataque más prometedores.

RESPONDE ÚNICAMENTE EN JSON con este formato exacto, sin texto adicional:
{
    "servidor": "Apache|Nginx|IIS|otro|desconocido",
    "lenguaje": "PHP|Python|Java|Node|Ruby|otro|desconocido",
    "framework": "Django|Laravel|Spring|Express|Rails|otro|desconocido",
    "cms": "WordPress|Drupal|Joomla|otro|ninguno",
    "base_de_datos": "MySQL|PostgreSQL|MSSQL|Oracle|otro|desconocido",
    "version_detectada": "versión si es visible o null",
    "headers_seguridad_ausentes": ["lista de headers de seguridad que faltan"],
    "vectores_prioritarios": [
        {
            "tipo": "SQLi|XSS|LFI|RFI|IDOR|SSRF|RCE",
            "motivo": "por qué este vector es prometedor dado el stack detectado",
            "prioridad": 1
        }
    ],
    "confianza": 0-100
}"""


def build_user_message(headers: dict, url: str, response_body: str = "") -> str:
    return f"""Analiza el fingerprint de esta aplicación web:

URL: {url}

HEADERS DE RESPUESTA:
{headers}

FRAGMENTO DEL BODY (primeros 1000 chars):
{response_body[:1000]}

¿Qué stack tecnológico usa y cuáles son los vectores de ataque más prometedores?"""