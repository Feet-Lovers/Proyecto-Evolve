import json
import os
import time

import anthropic
from dotenv import load_dotenv

load_dotenv()


class RespuestaIA:
    """
    Resultado de una llamada al modelo.

    Existe para que el que llama pueda distinguir «he analizado esto y no hay
    nada» de «no he podido analizarlo». Antes las dos cosas eran un dict y se
    confundian: el clasificador leia result.get("vulnerable") sobre un dict de
    error, obtenia None, y devolvia None igual que cuando todo estaba limpio
    (RNF-06, apartado 3 del plan).
    """

    __slots__ = ("datos", "estado", "detalle")

    def __init__(self, datos: dict | None, estado: str, detalle: str = ""):
        self.datos = datos          # el JSON del modelo, o None si no lo hubo
        self.estado = estado        # "ok" | "degradado"
        self.detalle = detalle      # por que, cuando esta degradado

    @property
    def ok(self) -> bool:
        return self.estado == "ok"


class HookSuiteAIClient:
    """Cliente Anthropic con reintentos exponenciales para HookSuite."""

    # Configurable por entorno para poder comparar modelos sobre los mismos
    # paquetes sin tocar codigo (decision de josemax, 8-oct).
    MODEL = os.getenv("HOOKSUITE_IA_MODELO", "claude-sonnet-5")

    # El esfuerzo regula cuanto razona el modelo. "low" basta para clasificar y
    # mantiene a raya coste y latencia, que aqui importan: esto corre por
    # paquete. Valores validos: low | medium | high | xhigh | max.
    EFFORT = os.getenv("HOOKSUITE_IA_ESFUERZO", "low")

    # Techo de llamadas por auditoria (incidente de la P1: 5 EUR en pruebas).
    # Configurable para poder subirlo en una auditoria larga a sabiendas, en vez
    # de que alguien lo quite del codigo por las prisas.
    # 40 es PROVISIONAL: se fija con el dato de ia_llamadas de la primera
    # auditoria real, no a ojo.
    MAX_LLAMADAS = int(os.getenv("HOOKSUITE_IA_MAX_LLAMADAS", "40"))

    # En Claude 5 el pensamiento esta activado por defecto y max_tokens cubre
    # pensamiento Y respuesta, asi que un tope corto trunca el JSON a media
    # llave. Los 1000 de antes no daban para esto.
    MAX_TOKENS = int(os.getenv("HOOKSUITE_IA_MAX_TOKENS", "8000"))

    MAX_RETRIES = 3
    BASE_DELAY = 1.0

    def __init__(self):
        self.client = anthropic.Anthropic()
        self.llamadas = 0
        self.techo_alcanzado = False

    def reiniciar_presupuesto(self) -> None:
        """Lo llama el orquestador al empezar cada auditoria."""
        self.llamadas = 0
        self.techo_alcanzado = False

    def analyze(
        self,
        system_prompt: str,
        user_message: str,
        schema: dict,
        max_tokens: int | None = None,
    ) -> RespuestaIA:
        """
        Llama a la API y devuelve el JSON del modelo.

        `schema` es el JSON Schema de la respuesta esperada: la API garantiza
        que lo cumple, asi que no hay que limpiar vallas markdown a mano.

        `max_tokens` cubre pensamiento Y respuesta; por defecto MAX_TOKENS.
        """
        # El techo va PRIMERO: si se agoto, no se llama a la API. Mismo camino
        # degradado que RNF-06, asi que el corte se VE en el panel en vez de
        # quedarse una auditoria a medias disfrazada de «sin hallazgos».
        if self.llamadas >= self.MAX_LLAMADAS:
            self.techo_alcanzado = True
            return RespuestaIA(
                None,
                "degradado",
                f"techo de {self.MAX_LLAMADAS} llamadas por auditoria alcanzado",
            )

        # Cuenta analisis, no peticiones HTTP: los reintentos de abajo solo
        # ocurren ante 429, fallo de conexion o 5xx, respuestas que no se
        # facturan. Si algun dia se reintentara sobre un 200, este += 1 tendria
        # que moverse junto al messages.create.
        self.llamadas += 1

        tope = max_tokens if max_tokens is not None else self.MAX_TOKENS
        ultimo_error = ""

        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.client.messages.create(
                    model=self.MODEL,
                    max_tokens=tope,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_message}],
                    output_config={
                        "effort": self.EFFORT,
                        "format": {"type": "json_schema", "schema": schema},
                    },
                )

                # Las salvaguardas de ciberseguridad pueden rechazar un analisis:
                # llega HTTP 200, stop_reason "refusal" y content VACIO.
                # Comprobarlo ANTES de leer content, o es un IndexError. Se mira
                # stop_reason, nunca stop_details, que puede venir a None.
                if response.stop_reason == "refusal":
                    detalles = getattr(response, "stop_details", None)
                    motivo = getattr(detalles, "category", None) or "sin categoria"
                    return RespuestaIA(
                        None, "degradado", f"el modelo rechazo el analisis ({motivo})"
                    )

                # Si el tope se agoto, el JSON llega cortado. Decirlo con su
                # nombre en vez de dejar que parezca «respuesta no valida».
                if response.stop_reason == "max_tokens":
                    return RespuestaIA(
                        None,
                        "degradado",
                        f"respuesta truncada: agotado el tope de {tope} tokens "
                        "(pensamiento + respuesta); subir HOOKSUITE_IA_MAX_TOKENS",
                    )

                # No se puede asumir content[0]: con el pensamiento activado el
                # primer bloque puede ser 'thinking', que no tiene .text.
                texto = next(
                    (b.text for b in response.content if b.type == "text"), None
                )
                if texto is None:
                    return RespuestaIA(
                        None, "degradado", "la respuesta no traia ningun bloque de texto"
                    )

                # Con output_config.format la API garantiza JSON valido conforme
                # al esquema. Este json.loads no deberia fallar nunca; si falla,
                # degradamos igual en vez de reventar.
                try:
                    return RespuestaIA(json.loads(texto), "ok")
                except json.JSONDecodeError:
                    return RespuestaIA(
                        None, "degradado", "la respuesta no era JSON pese al esquema"
                    )

            # Orden deliberado: de lo mas especifico a lo mas general. En este
            # SDK NotFound/Authentication/BadRequest/RateLimit son subclases de
            # APIStatusError, asi que el orden es lo que hace que lo que NO es
            # reintentable salga en el primer intento en vez de gastar 3 s.
            except anthropic.NotFoundError:
                return RespuestaIA(
                    None, "degradado", f"modelo no encontrado: {self.MODEL}"
                )

            except anthropic.AuthenticationError:
                return RespuestaIA(None, "degradado", "clave de API invalida o ausente")

            except anthropic.BadRequestError as e:
                return RespuestaIA(None, "degradado", f"peticion mal formada: {e}")

            except (anthropic.RateLimitError, anthropic.APIConnectionError) as e:
                ultimo_error = type(e).__name__
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.BASE_DELAY * (2 ** attempt))

            except anthropic.APIStatusError as e:
                ultimo_error = f"HTTP {e.status_code}"
                if e.status_code >= 500 and attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.BASE_DELAY * (2 ** attempt))
                else:
                    return RespuestaIA(
                        None, "degradado", f"error de la API: {ultimo_error}"
                    )

        return RespuestaIA(
            None,
            "degradado",
            f"agotados {self.MAX_RETRIES} intentos ({ultimo_error})",
        )
