import uuid
import time
from datetime import datetime
from typing import Dict, Optional

IGNORED_DOMAINS = [
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
    'cdnjs.cloudflare.com', 'cdn.cloudflare.com',
]

IGNORED_RESOURCE_TYPES = ['Image', 'Stylesheet', 'Font', 'Media', 'Ping']

IGNORED_EXTENSIONS = ['.css', '.woff', '.woff2', '.ttf', '.ico',
                      '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp']

class PacketBuilder:
    def __init__(self):
        self.pending_requests: Dict[str, dict] = {}
        self.completed_packets = []

    def should_filter(self, url: str, resource_type: str = "") -> bool:
        url_lower = url.lower()
        for domain in IGNORED_DOMAINS:
            if domain in url_lower:
                return True
        for ext in IGNORED_EXTENSIONS:
            if url_lower.split('?')[0].endswith(ext):
                return True
        if resource_type in IGNORED_RESOURCE_TYPES:
            return True
        return False

    def on_request_sent(self, params: dict):
        request_id = params.get("requestId")
        request = params.get("request", {})
        url = request.get("url", "")
        resource_type = params.get("type", "")
        if self.should_filter(url, resource_type):
            return None
        self.pending_requests[request_id] = {
            "id": str(uuid.uuid4()),
            "request_id": request_id,
            "method": request.get("method", "GET"),
            "url": url,
            "request_headers": dict(request.get("headers", {})),
            "request_body": request.get("postData"),
            "timestamp": datetime.utcnow().isoformat(),
            "start_time": time.time(),
        }
        return request_id

    def on_response_received(self, params: dict):
        request_id = params.get("requestId")
        if request_id not in self.pending_requests:
            return
        response = params.get("response", {})
        self.pending_requests[request_id].update({
            "status": response.get("status", 0),
            "response_headers": dict(response.get("headers", {})),
            "mime_type": response.get("mimeType", ""),
        })

    def build_packet(self, request_id: str, response_body: str = "") -> Optional[dict]:
        if request_id not in self.pending_requests:
            return None
        req_data = self.pending_requests.pop(request_id)
        elapsed = int((time.time() - req_data["start_time"]) * 1000)
        packet = {
            "id": req_data["id"],
            "method": req_data["method"],
            "url": req_data["url"],
            "status": req_data.get("status", 0),
            "size": len(response_body.encode("utf-8", errors="replace")),
            "time": elapsed,
            "timestamp": req_data["timestamp"],
            "request_headers": req_data["request_headers"],
            "request_body": req_data["request_body"],
            "response_headers": req_data.get("response_headers", {}),
            "response_body": response_body[:50000],
            "suspicious": False,
            "vulnerable": False,
        }
        self.completed_packets.append(packet)
        return packet

    def get_completed_packets(self) -> list:
        return self.completed_packets.copy()
