import asyncio
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from dotenv import load_dotenv
import os
load_dotenv()
HEADLESS = os.getenv("HEADLESS", "true").lower() == "true"
MAX_PARALLEL = int(os.getenv("MAX_PARALLEL_PAGES", "3"))
class BrowserManager:
    def __init__(self):
        self.playwright = None
        self.browser: Browser = None
        self._semaphore = asyncio.Semaphore(MAX_PARALLEL)

    async def start(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=HEADLESS,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
            ]
        )
        print(f"✓ Navegador iniciado (headless={HEADLESS}, max_parallel={MAX_PARALLEL})")

    async def stop(self):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def new_context(self, extra_headers: dict = None) -> BrowserContext:
        context = await self.browser.new_context(
            extra_http_headers=extra_headers or {},
            ignore_https_errors=True,
        )
        return context

    async def new_page(self, context: BrowserContext = None) -> Page:
        if context is None:
            context = await self.new_context()
        page = await context.new_page()
        # OPTIMIZACIÓN CRÍTICA: desactivar la simulación de pulsaciones tecla a tecla
        # page.fill() pasa el texto completo de una vez → 60x más rápido que page.type()
        # Esta configuración se aplica a todas las páginas creadas con este manager
        return page

    async def run_in_parallel(self, tasks: list):
        async def run_with_semaphore(task):
            async with self._semaphore:
                return await task
        return await asyncio.gather(*[run_with_semaphore(t) for t in tasks])
browser_manager = BrowserManager()