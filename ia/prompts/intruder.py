def get_system_prompt() -> str:
    return """Eres un experto en pentesting web especializado en análisis de resultados de ataques automatizados.
Analizas los resultados de un Intruder (similar a Burp Suite) y determinas si algún payload ha explotado una vulnerabilidad.

RESPONDE ÚNICAMENTE EN JSON con este formato exacto, sin texto adicional:
{
    "explotado": true/false,
    "payload_exitoso": "el payload que funcionó o null",
    "tipo": "SQLi|XSS|IDOR|LFI|RFI|SSRF|XXE|CSRF|RCE|ninguna",
    "severidad": "critica|alta|media|baja|ninguna",
    "confianza": 0-100,
    "evidencia": "fragmento de la respuesta que confirma la explotación",
    "descripcion": "explicación de por qué este payload funcionó"
}"""


def build_user_message(results: list, target_url: str, parameter: str) -> str:
    results_text = ""
    for r in results[:20]:
        results_text += f"""
PAYLOAD: {r.get('payload', '')}
STATUS: {r.get('status', 0)}
LENGTH: {r.get('length', 0)}
RESPONSE: {str(r.get('response_body', ''))[:500]}
---"""

    return f"""Analiza estos resultados del Intruder:

URL objetivo: {target_url}
Parámetro atacado: {parameter}

RESULTADOS:
{results_text}

¿Algún payload ha explotado una vulnerabilidad?"""