from fastapi import APIRouter, BackgroundTasks
from models.schemas import IntruderConfig
from services.intruder_service import intruder_engine
from services.payloads import get_payloads
from services.session_service import session_manager

router = APIRouter()

@router.post("/start")
async def start_attack(config: IntruderConfig, background_tasks: BackgroundTasks):
	background_tasks.add_task(
		intruder_engine.run_attack,
		session_token=config.session_token,
		url=config.url,
		injection_point=config.injection_point,
		attack_type=config.attack_type,
		concurrency=config.concurrency,
		delay_ms=config.delay_ms,
		method=config.method,
		body=config.body,
		headers=config.headers,
	)
	return {"status": "started", "message": "Ataque iniciado en segundo plano"}

@router.post("/pause/{token}")
async def pause_attack(token: str):
	intruder_engine.pause(token)
	return {"status": "paused"}

@router.post("/resume/{token}")
async def resume_attack(token: str):
	session = session_manager.get_session(token)
	session["intruder_status"] = "running"
	return {"status": "resumed"}

@router.post("/cancel/{token}")
async def cancel_attack(token: str):
	intruder_engine.cancel(token)
	return {"status": "cancelled"}

@router.get("/results/{token}")
async def get_results(token: str):
	session = session_manager.get_session(token)
	return {
		"status": session.get("intruder_status", "idle"),
		"results": session.get("intruder_results", []),
	}

@router.get("/payloads/{attack_type}")
async def get_payloads_list(attack_type: str):
	return {"payloads": get_payloads(attack_type)}