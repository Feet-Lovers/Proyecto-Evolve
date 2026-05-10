import asyncio
import os
from dotenv import load_dotenv
from core.chrome_launcher import launch_chrome_with_debugging, verify_cdp_connection
from core.cdp_client import CDPClient
from analyzers.network_analyzer import NetworkAnalyzer
from analyzers.console_analyzer import ConsoleAnalyzer
from utils.reporter import PacketReporter

load_dotenv()

TARGET_URL = os.getenv("DVWA_URL", "http://localhost:8888")
SESSION_TOKEN = os.getenv("SESSION_TOKEN", "devtools_session")

async def run_capture(target_url: str, duration_seconds: int = 60, session_token: str = None):
    print(f"\n{'='*60}")
    print(f"  HookSuite — Captura Chrome DevTools")
    print(f"  Objetivo: {target_url} | Duración: {duration_seconds}s")
    print(f"{'='*60}\n")

    reporter = PacketReporter(session_token or SESSION_TOKEN)
    await reporter.check_backend()

    print("Lanzando Chrome con debugging activo...")
    chrome_process = launch_chrome_with_debugging(target_url)
    await asyncio.sleep(3)

    connected = await verify_cdp_connection()
    if not connected:
        print("✗ No se pudo conectar al CDP.")
        chrome_process.terminate()
        return

    cdp = CDPClient()
    connected = await cdp.connect(target_url)
    if not connected:
        print("✗ No se pudo establecer la conexión WebSocket con CDP.")
        chrome_process.terminate()
        return

    network_analyzer = NetworkAnalyzer(cdp)
    console_analyzer = ConsoleAnalyzer(cdp)

    async def on_packet(packet):
        flag = "⚠️ " if packet.get("suspicious") else "   "
        print(f"  {flag}[{packet['method']}] {packet['url'][:70]} → {packet['status']} ({packet['time']}ms)")
        await reporter.send_packet(packet)

    async def on_console_finding(finding):
        print(f"  🔍 CONSOLA [{finding['level'].upper()}]: {finding['detections']}")
        await reporter.send_console_finding(finding)

    network_analyzer.on_packet(on_packet)
    console_analyzer.on_finding(on_console_finding)

    await network_analyzer.start()
    await console_analyzer.start()

    print(f"\n✓ Captura activa. Navega en Chrome para capturar tráfico.")
    print(f"  Duración máxima: {duration_seconds}s | Presiona Ctrl+C para detener.\n")

    try:
        await asyncio.sleep(duration_seconds)
    except asyncio.CancelledError:
        pass

    net_stats = network_analyzer.get_statistics()
    console_summary = console_analyzer.get_summary()

    print(f"\n{'='*60}")
    print(f"  CAPTURA COMPLETADA")
    print(f"  Paquetes: {net_stats['total_packets']} | Sospechosos: {net_stats['suspicious_packets']}")
    print(f"  Tiempo medio: {net_stats['average_time_ms']}ms")
    print(f"  Consola — Mensajes: {console_summary['total_messages']} | Hallazgos: {console_summary['sensitive_findings']}")
    print(f"{'='*60}\n")

    reporter.flush()
    await cdp.close()
    chrome_process.terminate()

if __name__ == "__main__":
    asyncio.run(run_capture(TARGET_URL, duration_seconds=60))
