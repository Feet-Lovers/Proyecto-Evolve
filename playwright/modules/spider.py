import asyncio
from urllib.parse import urlparse, urljoin
from playwright.async_api import Page
from typing import Set, List, Dict
import json
import os

class Spider:
    def __init__(self, base_url: str, max_pages: int = 50):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.queue: List[str] = [base_url]
        self.discovered_urls: List[str] = []

    def is_same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ''

    def normalize_url(self, url: str, current_url: str) -> str:
        if url.startswith('http'):
            return url.split('#')[0]
        if url.startswith('/'):
            parsed = urlparse(current_url)
            return f"{parsed.scheme}://{parsed.netloc}{url.split('#')[0]}"
        return urljoin(current_url, url).split('#')[0]

    def should_skip(self, url: str) -> bool:
        skip_extensions = ['.css', '.js', '.png', '.jpg', '.gif', '.svg',
                           '.ico', '.woff', '.woff2', '.ttf', '.pdf', '.zip']
        skip_patterns = ['logout', 'javascript:', 'mailto:', 'tel:']
        url_lower = url.lower()
        for ext in skip_extensions:
            if url_lower.endswith(ext):
                return True
        for pattern in skip_patterns:
            if pattern in url_lower:
                return True
        return False

    async def crawl_page(self, page: Page, url: str) -> List[str]:
        if url in self.visited or len(self.visited) >= self.max_pages:
            return []
        self.visited.add(url)
        found_urls = []
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            links = await page.query_selector_all('a[href]')
            for link in links:
                href = await link.get_attribute('href')
                if not href:
                    continue
                normalized = self.normalize_url(href, url)
                if (self.is_same_domain(normalized) and
                    normalized not in self.visited and
                    normalized not in self.queue and
                    not self.should_skip(normalized)):
                    found_urls.append(normalized)
            print(f" → {url} ({len(found_urls)} enlaces nuevos)")
        except Exception as e:
            print(f" ✗ Error en {url}: {e}")
        return found_urls

    async def run(self, page: Page) -> List[str]:
        print(f"\n🕷 Iniciando spider en {self.base_url}")
        print(f" Máximo de páginas: {self.max_pages}")
        while self.queue and len(self.visited) < self.max_pages:
            current_url = self.queue.pop(0)
            new_urls = await self.crawl_page(page, current_url)
            self.queue.extend(new_urls)
        self.discovered_urls = list(self.visited)
        print(f"\n✓ Spider completado: {len(self.discovered_urls)} URLs descubiertas")
        return self.discovered_urls

    def save_results(self, filepath: str = "results/spider_results.json"):
        os.makedirs("results", exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump({
                "base_url": self.base_url,
                "discovered_urls": self.discovered_urls,
                "total": len(self.discovered_urls)
            }, f, indent=2)
        print(f"✓ Resultados del spider guardados en {filepath}")