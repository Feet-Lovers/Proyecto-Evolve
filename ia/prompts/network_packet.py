def get_system_prompt() -> str:
    return """Eres un experto en seguridad web y análisis de vulnerabilidades.
Analizas paquetes HTTP interceptados y detectas vulnerabilidades OWASP Top 10.

RESPONDE ÚNICAMENTE EN JSON con este formato exacto, sin texto adicional:
{
    "vulnerable": true/false,
    "tipo": "SQLi|XSS|IDOR|LFI|RFI|SSRF|XXE|CSRF|RCE|ninguna",
    "severidad": "critica|alta|media|baja|ninguna",
    "confianza": 0-100,
    "descripcion": "descripción breve de la vulnerabilidad detectada",
    "evidencia": "fragmento exacto del paquete que revela la vulnerabilidad",
    "recomendacion": "acción correctiva concreta"
}"""


def build_user_message(packet: dict) -> str:
    return f"""Analiza este paquete HTTP interceptado:

METHOD: {packet.get('method', 'GET')}
URL: {packet.get('url', '')}
STATUS: {packet.get('status', 0)}

REQUEST HEADERS:
{packet.get('request_headers', {})}

REQUEST BODY:
{packet.get('request_body', 'vacío')}

RESPONSE HEADERS:
{packet.get('response_headers', {})}

RESPONSE BODY (primeros 2000 chars):
{str(packet.get('response_body', ''))[:2000]}

¿Detectas alguna vulnerabilidad en este paquete?"""