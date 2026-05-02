import anthropic
import time
import json
from dotenv import load_dotenv

load_dotenv()


class HookSuiteAIClient:
    """Cliente Anthropic con reintentos exponenciales para HookSuite."""

    MODEL = "claude-sonnet-4-20250514"
    MAX_RETRIES = 3
    BASE_DELAY = 1.0

    def __init__(self):
        self.client = anthropic.Anthropic()

    def analyze(self, system_prompt: str, user_message: str, max_tokens: int = 1000) -> dict:
        """
        Llama a la API de Anthropic con reintentos exponenciales.
        Devuelve siempre un dict parseado desde JSON.
        """
        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.client.messages.create(
                    model=self.MODEL,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "user", "content": user_message}
                    ],
                    system=system_prompt
                )
                raw_text = response.content[0].text
                clean_text = raw_text.replace("```json", "").replace("```", "").strip()
                return json.loads(clean_text)

            except json.JSONDecodeError:
                return {"error": "respuesta no es JSON válido", "raw": raw_text}

            except anthropic.RateLimitError:
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.BASE_DELAY * (2 ** attempt))
                else:
                    raise

            except anthropic.APIError as e:
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.BASE_DELAY * (2 ** attempt))
                else:
                    raise

        return {"error": "máximo de reintentos alcanzado"}