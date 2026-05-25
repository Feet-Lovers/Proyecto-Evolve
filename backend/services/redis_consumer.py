import json
import asyncio
import redis.asyncio as aioredis
from services.session_service import session_manager

async def start_redis_consumer():
    r = aioredis.Redis(host='redis', port=6379)
    pubsub = r.pubsub()
    await pubsub.subscribe("traffic")
    print("✓ Redis consumer escuchando canal 'traffic'")
    async for message in pubsub.listen():
        if message["type"] == "message":
            try:
                data = json.loads(message["data"])
                await session_manager.emit_all("request_intercepted", data)
            except Exception as e:
                print(f"Error procesando mensaje Redis: {e}")
