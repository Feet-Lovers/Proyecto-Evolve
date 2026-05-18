from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
from services.session_service import session_manager

router = APIRouter()

pending_instructions: Dict[str, list] = {}

class PlaywrightInstruction(BaseModel):
    type: str
    url: str
    selector: Optional[str] = None
    payload: Optional[str] = None
    verify: Optional[str] = None
    session_token: str

@router.post("/instruction/{session_token}")
async def receive_instruction(session_token: str, instruction: PlaywrightInstruction):
    if session_token not in pending_instructions:
        pending_instructions[session_token] = []
    pending_instructions[session_token].append(instruction.model_dump())
    await session_manager.emit(session_token, "playwright_instruction", instruction.model_dump())
    return {"queued": True, "session_token": session_token}

@router.get("/instruction/{session_token}")
async def get_pending_instructions(session_token: str):
    instructions = pending_instructions.get(session_token, [])
    pending_instructions[session_token] = []
    return {"instructions": instructions}

@router.post("/result/{session_token}")
async def receive_result(session_token: str, result: Dict[str, Any]):
    session = session_manager.get_session(session_token)
    session.setdefault("playwright_results", []).append(result)
    await session_manager.emit(session_token, "playwright_result", result)
    return {"received": True}

@router.get("/result/{session_token}")
async def get_playwright_results(session_token: str):
    session = session_manager.get_session(session_token)
    results = session.get("playwright_results", [])
    session["playwright_results"] = []
    return results
