import asyncio
import httpx
import time
from typing import Optional
from services.payloads import get_payloads
from services.session_service import session_manager
from services.proxy_service import is_suspicious, get_session_client
from routes.network import session_cookies


class IntruderEngine:
    def __init__(self):
        self.active_tasks = {}

    async def run_attack(
        self,
        session_token: str,
        url: str,
        injection_point: str,
        attack_type: str,
        concurrency: int = 5,
        delay_ms: int = 0,
        method: str = "GET",
        body: str = "",
        headers: dict = {},
    ):
        session = session_manager.get_session(session_token)
        session["intruder_status"] = "running"
        session["intruder_results"] = []

        payloads = get_payloads(attack_type)

        semaphore = asyncio.Semaphore(concurrency)

        await session_manager.emit(session_token, "intruder_status", {
            "status": "running",
            "total": len(payloads),
            "type": attack_type,
        })

        async def test_payload(index: int, payload: str):
            async with semaphore:
                if session.get("intruder_status") != "running":
                    return

                if delay_ms:
                    await asyncio.sleep(delay_ms / 1000)

                if "*" in url:
                    injected_url = url.replace("*", payload)
                else:
                    injected_url = url + ("&" if "?" in url else "?") + f"{injection_point}={payload}"

                start = time.time()

                try:
                    client = get_session_client(session_token)
                    merged_headers = {}
                    merged_headers.update(headers)
                    injected_body = body.replace("[injection_point]", payload) if body else None
                    response = await client.request(method, injected_url, headers=merged_headers, content=injected_body.encode() if injected_body else None)
                    elapsed = int((time.time() - start) * 1000)

                    try:
                        response_body = response.text
                    except Exception:
                        response_body = ""

                    sqli_patterns = ['First name:', 'Surname:', 'sql syntax', 'mysql_fetch', 'ORA-', 'pg_query', 'sqlite_', 'You have an error']
                    is_vuln = any(p.lower() in response_body.lower() for p in sqli_patterns)
                    payload_result = {
                        "id": index,
                        "payload": payload,
                        "url": injected_url,
                        "status": response.status_code,
                        "time": elapsed,
                        "length": len(response.content),
                        "snippet": response_body[:200],
                        "validated": is_vuln,
                        "vulnerable": is_vuln,
                    }

                except Exception as e:
                    payload_result = {
                        "id": index,
                        "payload": payload,
                        "url": injected_url,
                        "status": 0,
                        "time": int((time.time() - start) * 1000),
                        "length": 0,
                        "snippet": "",
                        "validated": False,
                        "error": str(e),
                    }

                session["intruder_results"].append(payload_result)

                await session_manager.emit(session_token, "intruder_result", {
                    "progress": index,
                    "total": len(payloads),
                })

        tasks = [test_payload(i + 1, payload) for i, payload in enumerate(payloads)]
        await asyncio.gather(*tasks)

        if session.get("intruder_status") == "running":
            session["intruder_status"] = "complete"
            await session_manager.emit(session_token, "intruder_complete", {
                "results": len(session["intruder_results"])
            })

    def pause(self, session_token: str):
        session = session_manager.get_session(session_token)
        session["intruder_status"] = "paused"

    def resume(self, session_token: str):
        session = session_manager.get_session(session_token)
        session["intruder_status"] = "running"


intruder_engine = IntruderEngine()
