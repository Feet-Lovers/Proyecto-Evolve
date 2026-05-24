import asyncio
from typing import List, Callable, Dict
from core.cdp_client import CDPClient
from core.packet_builder import PacketBuilder

SECURITY_HEADERS_REQUIRED = [
    "content-security-policy", "x-frame-options",
    "strict-transport-security", "x-content-type-options", "referrer-policy",
]

SESSION_COOKIE_NAMES = ["phpsessid", "jsessionid", "session", "token", "auth", "sessionid"]

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax", "mysql_fetch", "ora-", "pg_query",
    "sqlite_", "unclosed quotation mark", "syntax error", "database error",
]

class NetworkAnalyzer:
    def __init__(self, cdp_client: CDPClient):
        self.cdp = cdp_client
        self.packet_builder = PacketBuilder()
        self.packet_callbacks: List[Callable] = []

    def on_packet(self, callback: Callable):
        self.packet_callbacks.append(callback)

    def _check_suspicious(self, packet: dict) -> list:
        reasons = []
        url = packet.get("url", "").lower()
        body = (packet.get("response_body") or "").lower()
        req_body = (packet.get("request_body") or "").lower()
        status = packet.get("status", 0)
        if status >= 500:
            reasons.append(f"HTTP_ERROR_{status}")
        for pattern in SQL_ERROR_PATTERNS:
            if pattern in body:
                reasons.append(f"SQL_ERROR_IN_RESPONSE")
                break
        for char in ["'", '"', '<script', 'union select', '--', '1=1']:
            if char in url or char in req_body:
                reasons.append(f"INJECTION_CHAR_IN_REQUEST")
                break
        if packet.get("time", 0) > 5000:
            reasons.append(f"SLOW_RESPONSE: {packet['time']}ms")
        return reasons

    def _check_security_headers(self, packet: dict) -> list:
        issues = []
        headers = {k.lower(): v for k, v in (packet.get("response_headers") or {}).items()}
        for h in SECURITY_HEADERS_REQUIRED:
            if h not in headers:
                issues.append(f"MISSING_HEADER: {h}")
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            name_lower = set_cookie.lower().split("=")[0].strip()
            if any(n in name_lower for n in SESSION_COOKIE_NAMES):
                if "httponly" not in set_cookie.lower():
                    issues.append("SESSION_COOKIE_MISSING_HTTPONLY")
                if "secure" not in set_cookie.lower():
                    issues.append("SESSION_COOKIE_MISSING_SECURE")
        return issues

    async def _handle_request_sent(self, params: dict):
        self.packet_builder.on_request_sent(params)

    async def _handle_response_received(self, params: dict):
        self.packet_builder.on_response_received(params)

    async def _handle_loading_finished(self, params: dict):
        request_id = params.get("requestId")
        if request_id not in self.packet_builder.pending_requests:
            return
        response_body = ""
        try:
            response_body = await self.cdp.get_response_body(request_id)
        except Exception:
            pass
        packet = self.packet_builder.build_packet(request_id, response_body)
        if not packet:
            return
        suspicious_reasons = self._check_suspicious(packet)
        security_issues = self._check_security_headers(packet)
        if suspicious_reasons:
            packet["suspicious"] = True
            packet["suspicious_reasons"] = suspicious_reasons
            print(f"  ⚠️  Sospechoso: {packet['url'][:60]} → {suspicious_reasons}")
        if security_issues:
            packet["security_issues"] = security_issues
        for callback in self.packet_callbacks:
            await callback(packet)

    async def _handle_loading_failed(self, params: dict):
        request_id = params.get("requestId")
        error_text = params.get("errorText", "Unknown error")
        if request_id in self.packet_builder.pending_requests:
            packet = self.packet_builder.build_packet(request_id, f"ERROR: {error_text}")
            if packet:
                packet["network_error"] = error_text
                for callback in self.packet_callbacks:
                    await callback(packet)

    async def start(self):
        await self.cdp.enable_network()
        await self.cdp.enable_page()
        self.cdp.on("Network.requestWillBeSent", self._handle_request_sent)
        self.cdp.on("Network.responseReceived", self._handle_response_received)
        self.cdp.on("Network.loadingFinished", self._handle_loading_finished)
        self.cdp.on("Network.loadingFailed", self._handle_loading_failed)
        print("✓ Analizador de red activo")

    def get_statistics(self) -> dict:
        packets = self.packet_builder.get_completed_packets()
        suspicious = [p for p in packets if p.get("suspicious")]
        return {
            "total_packets": len(packets),
            "suspicious_packets": len(suspicious),
            "average_time_ms": sum(p.get("time", 0) for p in packets) // max(len(packets), 1),
        }
