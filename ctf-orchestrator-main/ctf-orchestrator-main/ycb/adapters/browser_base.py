"""浏览器型平台适配器的公共能力：选择器加载、Playwright actor 生命周期。"""

from __future__ import annotations

import asyncio
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ycb.adapters.base import PlatformError
from ycb.config import Config
from ycb.platform.browser import BrowserSession, PlatformActor

_SELECTOR_DIR = Path(__file__).parent / "selectors"


@dataclass(frozen=True)
class SelectorBook:
    data: dict[str, dict[str, list[str]]]

    def get(self, section: str, key: str) -> list[str]:
        values = self.data.get(section, {}).get(key, [])
        if isinstance(values, str):
            return [values]
        return [str(value) for value in values]

    def first(self, section: str, key: str, default: str | None = None) -> str | None:
        values = self.get(section, key)
        return values[0] if values else default


def load_selectors(name: str) -> SelectorBook:
    path = _SELECTOR_DIR / f"{name}.toml"
    if not path.is_file():
        raise PlatformError(f"缺少选择器配置：{path}")
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    data: dict[str, dict[str, list[str]]] = {}
    for section, values in raw.items():
        if not isinstance(values, dict):
            continue
        data[str(section)] = {
            str(key): [str(item) for item in val] if isinstance(val, list) else [str(val)]
            for key, val in values.items()
        }
    return SelectorBook(data)


async def first_visible(page, selectors: list[str], *, timeout: float = 1.0):
    """返回第一个存在的 locator；都找不到返回 None。"""
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if await locator.count() and await locator.is_visible(timeout=int(timeout * 1000)):
                return locator
        except Exception:
            continue
    return None


async def fill_first(page, selectors: list[str], value: str) -> bool:
    locator = await first_visible(page, selectors, timeout=2.0)
    if locator is None:
        return False
    await locator.fill(value)
    return True


class BrowserAdapterBase:
    """持有 BrowserSession/PlatformActor 的适配器基类。"""

    def __init__(self, config: Config):
        self.config = config
        self.browser = BrowserSession(config)
        self.actor = PlatformActor(self.browser)
        self.selectors = load_selectors(self.name)

    async def start_browser(self) -> None:
        await self.actor.start()

    async def close(self) -> None:
        await self.actor.close()

    async def debug_snapshot(self, name: str) -> dict[str, str]:
        """保存截图与 HTML，返回路径；用于登录失败/选择器漂移排查。"""
        paths: dict[str, str] = {}
        try:
            paths["screenshot"] = str(await self.browser.screenshot(name))
        except Exception:
            pass
        try:
            paths["html"] = str(await self.browser.save_html(name))
        except Exception:
            pass
        return paths

    async def settle(self, page, *, timeout_ms: int = 2500) -> None:
        """等待 SPA 渲染；networkidle 在长连接页面可能永不触发。"""
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
        except Exception:
            pass
        await asyncio.sleep(1.0)
