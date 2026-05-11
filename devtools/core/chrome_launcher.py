import subprocess
import sys
import os
import time
import httpx
import asyncio
from dotenv import load_dotenv

load_dotenv()

DEBUG_PORT = int(os.getenv("CHROME_DEBUG_PORT", 9222))

def get_chrome_path() -> str:
    if sys.platform == "darwin":
        return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    elif sys.platform == "win32":
        for path in [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]:
            if os.path.exists(path):
                return path
    else:
        for path in ["/usr/bin/google-chrome", "/usr/bin/chromium-browser", "/usr/bin/chromium"]:
            if os.path.exists(path):
                return path
    return "google-chrome"

def launch_chrome_with_debugging(url: str = "about:blank") -> subprocess.Popen:
    chrome_path = get_chrome_path()
    args = [
        chrome_path,
        f"--remote-debugging-port={DEBUG_PORT}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        url,
    ]
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL,
stderr=subprocess.DEVNULL)
    print(f"✓ Chrome lanzado con debugging en puerto {DEBUG_PORT} (PID: {process.pid})")
    time.sleep(1)
    return process

async def verify_cdp_connection(max_retries: int = 10, wait_seconds: float = 1.0) -> bool:
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"http://localhost:{DEBUG_PORT}/json")
                tabs = response.json()
                if tabs:
                    print(f"✓ CDP activo. {len(tabs)} pestaña(s) disponible(s)")
                    for tab in tabs:
                        print(f"  → {tab.get('title', 'Sin título')} — {tab.get('url', '')}")
                    return True
        except Exception as e:
            print(f"  Intento {attempt + 1}/{max_retries} fallido, esperando {wait_seconds}s...")
            await asyncio.sleep(wait_seconds)
    print(f"✗ CDP no disponible en puerto {DEBUG_PORT} tras {max_retries} intentos")
    return False