def get_system_prompt() -> str:
    return """Eres un experto en seguridad web especializado en análisis de logs de consola del navegador.
Detectas información sensible filtrada en logs: API keys, passwords, tokens, rutas internas, errores SQL y datos personales.

RESPONDE ÚNICAMENTE EN JSON con este formato exacto, sin texto adicional:
{
    "sensible": true/false,
    "tipo": "api_key|password|token|ruta_interna|error_sql|datos_personales|stack_trace|ninguna",
    "severidad": "critica|alta|media|baja|ninguna",
    "confianza": 0-100,
    "evidencia": "fragmento exacto del log que contiene información sensible",
    "descripcion": "explicación de qué información sensible se ha filtrado",
    "recomendacion": "acción correctiva concreta"
}"""


def build_user_message(console_logs: list, url: str) -> str:
    logs_text = ""
    for log in console_logs[:50]:
        logs_text += f"[{log.get('level', 'log')}] {log.get('message', '')}\n"

    return f"""Analiza estos logs de consola del navegador capturados en:
URL: {url}

LOGS:
{logs_text}

¿Hay información sensible filtrada en estos logs?"""