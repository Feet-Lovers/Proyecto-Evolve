import asyncio
import os
from dotenv import load_dotenv
from ia.orchestrator import AttackOrchestrator

load_dotenv()

TARGET_URL = os.getenv("DVWA_URL", "http://localhost:8888")
FIELD_SELECTOR = "input[name='id']"
SESSION_TOKEN = "ia_session_default"

async def main():
    orchestrator = AttackOrchestrator(session_token=SESSION_TOKEN)
    await orchestrator.run_full_audit(
        target_url=TARGET_URL,
        field_selector=FIELD_SELECTOR,
    )

if __name__ == "__main__":
    asyncio.run(main())