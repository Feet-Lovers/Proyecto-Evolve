import asyncio
import os
from dotenv import load_dotenv
from orchestrator import AttackOrchestrator
load_dotenv()
SESSION_TOKEN = os.getenv("SESSION_TOKEN", "ia_session")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))

async def poll_for_instructions():
    import httpx
    orchestrator = AttackOrchestrator(session_token=SESSION_TOKEN)
    await orchestrator.check_backend()
    print("  Esperando instrucciones del backend...")
    while True:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{BACKEND_URL}/api/playwright/instruction/{SESSION_TOKEN}"
                )
                if response.status_code == 200:
                    data = response.json()
                    instructions = data.get("instructions", [])
                    if instructions:
                        instruction = instructions[0]
                        if instruction.get("type") == "full_audit":
                            target_url = instruction.get("url", "http://dvwa:80")
                            field_selector = instruction.get("selector", "input[name=\'id\']")
                            print(f"\n  -> Instruccion recibida: auditoria de {target_url}")
                            await orchestrator.run_full_audit(
                                target_url=target_url,
                                field_selector=field_selector,
                            )
                            orchestrator.save_results()
        except Exception as e:
            print(f"  Error en polling: {e}")
        await asyncio.sleep(POLL_INTERVAL)

async def wait_for_backend():
    import httpx
    for i in range(30):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{BACKEND_URL}/api/playwright/instruction/test")
                if r.status_code == 200:
                    print("Backend disponible")
                    return True
        except Exception:
            pass
        print(f"Esperando backend... ({i+1}/30)")
        await asyncio.sleep(2)
    return False

async def main():
    print(f"\n{60*'='}")
    print("  HookSuite IA - Modulo de analisis")
    print(f"  Backend: {BACKEND_URL}")
    print(f"  Sesion: {SESSION_TOKEN}")
    print("  Modo: polling de instrucciones")
    print(f"{60*'='}\n")
    await wait_for_backend()
    await poll_for_instructions()

if __name__ == "__main__":
    asyncio.run(main())
