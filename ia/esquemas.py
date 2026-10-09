"""
Esquemas JSON de las respuestas del modelo (RF-08, apartado 3).

GENERADO POR generar-esquemas.py — NO editar a mano: se regenera.
Las claves salen de los result.get(...) del clasificador, así que describen
lo que el código espera de verdad. Los tipos van abiertos a propósito salvo
"vulnerable" y "confianza", que son los únicos que el código interpreta;
additionalProperties queda en True para no romper si un prompt añade campos.
"""

ESQUEMA_PACKET = {
    "type": "object",
    "properties": {
        'vulnerable': {'type': 'boolean'},
        'confianza': {'type': 'number'},
        'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'severidad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'descripcion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'evidencia': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'recomendacion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
    },
    "additionalProperties": True,
}

ESQUEMA_INTRUDER = {
    "type": "object",
    "properties": {
        'explotado': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'confianza': {'type': 'number'},
        'payload_exitoso': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'severidad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'evidencia': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'descripcion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
    },
    "additionalProperties": True,
}

ESQUEMA_CONSOLE = {
    "type": "object",
    "properties": {
        'sensible': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'confianza': {'type': 'number'},
        'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'severidad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'evidencia': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'descripcion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'recomendacion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
    },
    "additionalProperties": True,
}

ESQUEMA_FINGERPRINT = {
    "type": "object",
    "properties": {

    },
    "additionalProperties": True,
}
