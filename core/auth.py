from playwright.async_api import Page, BrowserContext
from dotenv import load_dotenv
import os

load_dotenv()


async def login_dvwa(page: Page) -> bool:
    dvwa_url = os.getenv("DVWA_URL", "http://localhost:8888")
    username = os.getenv("DVWA_USER", "admin")
    password = os.getenv("DVWA_PASS", "password")
    try:
        await page.goto(f"{dvwa_url}/login.php", wait_until="networkidle")
        await page.fill('input[name="username"]', username)
        await page.fill('input[name="password"]', password)
        await page.click('input[type="submit"]')
        await page.wait_for_load_state("networkidle")
        if "login.php" not in page.url:
            print(f"✓ Login exitoso en DVWA como {username}")
            return True
        else:
            print("✗ Login fallido en DVWA")
            return False
    except Exception as e:
        print(f"✗ Error durante el login: {e}")
        return False


async def login_generic(page: Page, login_url: str, username: str, password: str,
                        username_selector: str = 'input[name="username"]',
                        password_selector: str = 'input[name="password"]',
                        submit_selector: str = 'input[type="submit"]') -> bool:
    try:
        await page.goto(login_url, wait_until="networkidle")
        await page.fill(username_selector, username)
        await page.fill(password_selector, password)
        await page.click(submit_selector)
        await page.wait_for_load_state("networkidle")
        return login_url not in page.url
    except Exception as e:
        print(f"✗ Error en login genérico: {e}")
        return False


async def save_session(context: BrowserContext, filepath: str = "results/session.json"):
    await context.storage_state(path=filepath)
    print(f"✓ Sesión guardada en {filepath}")


async def load_session(browser_manager, filepath: str = "results/session.json"):
    if not os.path.exists(filepath):
        return None
    context = await browser_manager.browser.new_context(
        storage_state=filepath,
        ignore_https_errors=True,
    )
    print(f"✓ Sesión cargada desde {filepath}")
    return context