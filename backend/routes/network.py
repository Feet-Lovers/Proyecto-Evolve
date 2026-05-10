from fastapi import APIRouter
from models.schemas import NetworkPacket
from services.session_service import session_manager

router = APIRouter()

pending_packets = []

@router.post("/packet")
async def receive_network_packet(packet: NetworkPacket):
	packet_dict = packet.model_dump()

	for token, session in session_manager.sessions.items():
		session.setdefault("network_packets", []).append(packet_dict)
		await session_manager.emit(token, "network_packet", packet_dict)

	return {"received": True, "id": packet.id}

@router.post("/packet/{session_token}")
async def receive_packet_for_session(session_token: str, packet: NetworkPacket):
	packet_dict = packet.model_dump()

	session = session_manager.get_session(session_token)
	session.setdefault("network_packets", []).append(packet_dict)

	await session_manager.emit(session_token, "network_packet", packet_dict)

	return {"received": True, "id": packet.id}

@router.get("/packets/{session_token}")
async def get_packets(session_token: str):
	session = session_manager.get_session(session_token)
	return session.get("network_packets", [])[-500:]