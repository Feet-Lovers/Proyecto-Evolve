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
additionalProperties va en False, y NO es una preferencia: la API rechaza con
400 los objetos abiertos en structured output. Hasta el 10-oct iba en True, a
propósito, para no romper si un prompt añadía campos; ese motivo era razonable
pero lo derrota una restricción externa, y el coste de no saberlo fue que las
nueve llamadas de la primera auditoría REAL se rechazaron enteras. Si un prompt
añade campos, lo que toca es regenerar este fichero, que para eso existe.
"""

ESQUEMA_PACKET = {
    "type": "object",
    "properties": {
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
        'vulnerable': {'type': 'boolean'},
        'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'severidad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'descripcion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'evidencia': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'recomendacion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
    },
    "additionalProperties": False,
}

ESQUEMA_INTRUDER = {
    "type": "object",
    "properties": {
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
        'explotado': {'type': 'boolean'},
        'payload_exitoso': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'severidad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'evidencia': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'descripcion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
    },
    "additionalProperties": False,
}

ESQUEMA_CONSOLE = {
    "type": "object",
    "properties": {
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
        'sensible': {'type': 'boolean'},
        'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'severidad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'evidencia': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'descripcion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
        'recomendacion': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']},
    },
    "additionalProperties": False,
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
        'vectores_prioritarios': {'type': 'array', 'items': {'type': 'object', 'properties': {'tipo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']}, 'motivo': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']}, 'prioridad': {'type': ['string', 'number', 'boolean', 'object', 'array', 'null']}}, 'additionalProperties': False}},
        'confianza': {'type': 'number', 'minimum': 0, 'maximum': 100},
    },
    "additionalProperties": False,
}
