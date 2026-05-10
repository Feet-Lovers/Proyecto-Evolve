from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
import asyncio
import uuid
from datetime import datetime
from services.session_service import session_manager
from services.proxy_service import is_suspicious

intercepted_requests = []
session_callbacks = []

class HookSuiteAddon:
    def __init__(self):
        self.request_data = {}
        self.session_map = {}

    def request(self, flow: http.HTTPFlow):
        request_id = str(uuid.uuid4())
        flow.request.headers["X-HookSuite-ID"] = request_id

        session_cookie = flow.request.cookies.get("hooksuite_session", "")

        self.request_data[request_id] = {
            "id": request_id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text(strict=False),
            "timestamp": datetime.utcnow().isoformat(),
            "session_token": session_cookie,
        }

    def response(self, flow: http.HTTPFlow):
        request_id = flow.request.headers.get("X-HookSuite-ID", "")
        if request_id not in self.request_data:
            return

        req_data = self.request_data.pop(request_id)
        response_body = flow.response.get_text(strict=False)[:50000]

        packet = {
            **req_data,
            "status": flow.response.status_code,
            "size": len(flow.response.content),
            "time": int(flow.response.elapsed.total_seconds() * 1000) if flow.response.elapsed else 0,
            "response_headers": dict(flow.response.headers),
            "response_body": response_body,
            "suspicious": is_suspicious(req_data["url"], response_body, flow.response.status_code),
            "vulnerable": False,
        }

        session_token = req_data.get("session_token", "")
        if session_token:
            asyncio.create_task(
                session_manager.emit(session_token, "request_intercepted", packet)
            )

        intercepted_requests.append(packet)
        for callback in session_callbacks:
            asyncio.create_task(callback(packet))

async def start_proxy(port: int = 8080):
    opts = Options(listen_host="0.0.0.0", listen_port=port)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(HookSuiteAddon())
    await master.run()