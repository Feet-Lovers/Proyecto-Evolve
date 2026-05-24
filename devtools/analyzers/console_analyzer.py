import re
from typing import List, Dict, Callable
from core.cdp_client import CDPClient

SENSITIVE_PATTERNS = [
    (r'/var/www/', "SERVER_PATH_EXPOSED"),
    (r'/home/\w+/', "SERVER_PATH_EXPOSED"),
    (r'C:\\\\', "SERVER_PATH_EXPOSED"),
    (r'api[_-]?key\s*[:=]\s*["\']?[\w-]{10,}', "API_KEY_EXPOSED"),
    (r'password\s*[:=]\s*["\']?\w+', "PASSWORD_EXPOSED"),
    (r'token\s*[:=]\s*["\']?[\w.-]{20,}', "TOKEN_EXPOSED"),
    (r'mysql_fetch|pg_query|sqlite_exec', "DB_FUNCTION_EXPOSED"),
    (r'You have an error in your SQL', "SQL_ERROR_EXPOSED"),
    (r'ORA-\d{5}', "ORACLE_ERROR_EXPOSED"),
    (r'Stack trace:', "STACK_TRACE_EXPOSED"),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "INTERNAL_IP_EXPOSED"),
]

class ConsoleAnalyzer:
    def __init__(self, cdp_client: CDPClient):
        self.cdp = cdp_client
        self.findings: List[Dict] = []
        self.all_messages: List[Dict] = []
        self.finding_callbacks: List[Callable] = []

    def on_finding(self, callback: Callable):
        self.finding_callbacks.append(callback)

    def _analyze_message(self, text: str) -> List[str]:
        detections = []
        for pattern, detection_type in SENSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                detections.append(detection_type)
        return detections

    async def _handle_console_message(self, params: dict):
        message = params.get("message", {})
        level = message.get("level", "log")
        text = message.get("text", "")
        msg_data = {
            "level": level,
            "text": text,
            "url": message.get("url", ""),
            "line": message.get("line", 0)
        }
        self.all_messages.append(msg_data)
        if level in ["error", "warning"]:
            detections = self._analyze_message(text)
            if detections:
                finding = {
                    **msg_data,
                    "detections": detections,
                    "severity": "high" if any(
                        d in ["API_KEY_EXPOSED", "PASSWORD_EXPOSED", "TOKEN_EXPOSED"]
                        for d in detections
                    ) else "medium"
                }
                self.findings.append(finding)
                print(f"  🔍 Consola [{level.upper()}]: {detections} → {text[:80]}")
                for callback in self.finding_callbacks:
                    await callback(finding)

    async def start(self):
        await self.cdp.enable_console()
        self.cdp.on("Console.messageAdded", self._handle_console_message)
        print("✓ Analizador de consola activo")

    def get_findings(self) -> List[Dict]:
        return self.findings.copy()

    def get_summary(self) -> dict:
        return {
            "total_messages": len(self.all_messages),
            "errors": len([m for m in self.all_messages if m.get("level") == "error"]),
            "sensitive_findings": len(self.findings),
        }
