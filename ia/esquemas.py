"""
Esquemas JSON de las respuestas del modelo (RF-08, apartado 3).

GENERADO POR generar-esquemas.py — NO editar a mano: se regenera.
Las claves salen de los result.get(...) del clasificador, así que describen
lo que el código espera de verdad. Para los métodos que devuelven la respuesta
sin inspeccionarla (fingerprint) no hay nada que deducir y las claves van
declaradas en el generador, sacadas del informe del testigo del 10-oct.

Los tipos van CERRADOS en los campos que el código interpreta: las tres banderas
("vulnerable", "explotado", "sensible", que hacen el mismo papel con nombres
distintos) y "confianza", con el rango 0-100 que piden los cuatro prompts.
El resto queda abierto a propósito, y additionalProperties en True, para no
romper si un prompt añade campos.
"""

ESQUEMA_PACKET = {
    "type": "object",
    "properties": {
        'vulnerable': {'type': 'boolean'},
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
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
        'explotado': {'type': 'boolean'},
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
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
        'sensible': {'type': 'boolean'},
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
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
        'servidor': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'lenguaje': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'framework': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'cms': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'base_de_datos': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'version_detectada': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'headers_seguridad_ausentes': {'type': 'array'},
        'vectores_prioritarios': {'type': 'array', 'items': {'type': 'object', 'properties': {'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']}, 'motivo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']}, 'prioridad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']}}, 'additionalProperties': True}},
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
    },
    "additionalProperties": True,
}
