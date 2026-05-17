import asyncio
import os
from dotenv import load_dotenv
from orchestrator import AttackOrchestrator

load_dotenv()

SESSION_TOKEN = os.getenv("SESSION_TOKEN", "ia_session_default")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))

async def poll_for_instructions():
    import httpx
    orchestrator = AttackOrchestrator(session_token=SESSION_TOKEN)
    await orchestrator.check_backend()

    print(f"  Esperando instrucciones del backend...")

    while True:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{BACKEND_URL}/api/playwright/instruction/{SESSION_TOKEN}"
                )
                if response.status_code == 200:
                    data = response.json()
                    instruction = data.get("instruction") if isinstance(data, dict) else None

                    if instruction and instruction.get("type") == "full_audit":
                        target_url = instruction.get("url", "http://localhost:8888")
                        field_selector = instruction.get("selector", "input[name='id']")
                        print(f"\n  → Instrucción recibida: auditoría de {target_url}")
                        await orchestrator.run_full_audit(
                            target_url=target_url,
                            field_selector=field_selector,
                        )
                        orchestrator.save_results()
                    else:
                        print(f"  · Sin instrucciones — esperando {POLL_INTERVAL}s", end="\r")

        except Exception as e:
            print(f"  ⚠️  Error en polling: {e}")

        await asyncio.sleep(POLL_INTERVAL)

async def main():
    print(f"\n{'='*60}")
    print(f"  HookSuite IA — Módulo de análisis")
    print(f"  Backend: {BACKEND_URL}")
    print(f"  Sesión: {SESSION_TOKEN}")
    print(f"  Modo: polling de instrucciones")
    print(f"{'='*60}\n")

    await poll_for_instructions()

if __name__ == "__main__":
    asyncio.run(main())
