import asyncio
import os
from dotenv import load_dotenv
from modules.orchestrator_receiver import InstructionReceiver

load_dotenv()

SESSION_TOKEN = os.getenv("SESSION_TOKEN", "playwright_default")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

async def main():
    print(f"\n{'='*60}")
    print(f"  HookSuite — Módulo Playwright")
    print(f"  Backend: {BACKEND_URL}")
    print(f"  Sesión: {SESSION_TOKEN}")
    print(f"  Modo: polling de instrucciones")
    print(f"{'='*60}\n")

    receiver = InstructionReceiver(session_token=SESSION_TOKEN)
    await receiver.poll_for_instructions()

if __name__ == "__main__":
    asyncio.run(main())
