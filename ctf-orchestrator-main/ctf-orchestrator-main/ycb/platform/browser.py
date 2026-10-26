"""Playwright 持久化浏览器与串行 actor。

- 同一 profile 只允许一个进程打开（``var/profile.lock``，flock）；
- 所有页面操作走一个优先级队列，避免同一 page 被并发使用；
- job 超时后重建 page，浏览器崩溃时整栈重启；
- 默认 headless，可用 ``YCB_HEADLESS=0`` + xvfb/桌面做人工登录。
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import logging
import os
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Awaitable, Callable

from ycb.adapters.base import PlatformError
from ycb.config import Config
from ycb.platform.recorder import NetworkRecorder

log = logging.getLogger(__name__)

# Playwright 的 page()/evaluate 等调用不会自己超时；给 actor 内部调用加硬上限。
_PAGE_TIMEOUT_SECONDS = 45.0
_SUBMIT_GRACE_SECONDS = 90.0


class Priority(IntEnum):
    LOGIN = 0
    HEALTH = 10
    SUBMIT = 20
    TARGET = 30
    DISCOVER = 40
    DOWNLOAD = 50


@dataclass(order=True)
class _Job:
    priority: int
    seq: int
    name: str = field(compare=False)
    timeout: float = field(compare=False)
    factory: Callable[[Any], Awaitable[Any]] = field(compare=False)
    future: asyncio.Future = field(compare=False)


class ProfileLock:
    """跨进程 profile 独占锁；进程崩溃后 flock 自动释放。"""

    def __init__(self, path: Path):
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise PlatformError(f"浏览器 profile 已被其他进程占用：{self.path}") from exc
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        os.fsync(fd)
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        with contextlib.suppress(OSError):
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(self._fd)
        self._fd = None


def _bundled_chromium() -> Path | None:
    root = Path(
        os.environ.get("PLAYWRIGHT_BROWSERS_PATH", str(Path.home() / ".cache" / "ms-playwright"))
    )
    for pattern in ("chromium-*/chrome-linux/chrome", "chromium-*/chrome-linux64/chrome"):
        for path in sorted(root.glob(pattern), reverse=True):
            if path.is_file():
                return path
    return None


def resolve_chromium(config: Config) -> Path | None:
    """优先配置，其次 Playwright 自带，最后系统 chromium。"""
    if config.browser.chromium_path:
        path = Path(config.browser.chromium_path).expanduser()
        if not path.is_file():
            raise PlatformError(f"YCB_CHROMIUM_PATH 指向的文件不存在：{path}")
        return path
    bundled = _bundled_chromium()
    if bundled is not None:
        return bundled
    for candidate in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"):
        path = Path(candidate)
        if path.is_file():
            return path
    return None


class BrowserSession:
    def __init__(self, config: Config):
        self.config = config
        self.recorder = NetworkRecorder(config.debug_dir)
        self._pw = None
        self._ctx = None
        self._page = None
        self._lock = ProfileLock(config.data_dir / "profile.lock")
        self._lock_held = False
        self._started = False
        self._start_lock = asyncio.Lock()

    @property
    def started(self) -> bool:
        return self._started

    async def start(self) -> None:
        async with self._start_lock:
            if self._started:
                return
            try:
                from playwright.async_api import async_playwright
            except Exception as exc:  # pragma: no cover - 依赖缺失
                raise PlatformError(f"未安装 playwright：{exc}") from exc

            self.config.profile_dir.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                self.config.profile_dir.chmod(0o700)
            if not self._lock_held:
                self._lock.acquire()
                self._lock_held = True

            executable = resolve_chromium(self.config)
            launch: dict[str, Any] = {
                "user_data_dir": str(self.config.profile_dir),
                "headless": self.config.browser.headless,
                "viewport": {"width": 1440, "height": 900},
                "locale": "zh-CN",
                "timezone_id": "Asia/Shanghai",
                "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            }
            if executable is not None:
                launch["executable_path"] = str(executable)
            if self.config.browser.slow_mo_ms:
                launch["slow_mo"] = self.config.browser.slow_mo_ms

            try:
                self._pw = await async_playwright().start()
                self._ctx = await self._pw.chromium.launch_persistent_context(**launch)
                self._ctx.set_default_timeout(int(self.config.browser.timeout_seconds * 1000))
                pages = list(self._ctx.pages)
                self._page = pages[0] if pages else await self._ctx.new_page()
                for extra in pages[1:]:
                    with contextlib.suppress(Exception):
                        await extra.close()
                self._configure_page(self._page)
                self._started = True
                log.info(
                    "浏览器已启动 profile=%s executable=%s headless=%s",
                    self.config.profile_dir,
                    executable or "playwright-bundled",
                    self.config.browser.headless,
                )
            except Exception:
                await self._teardown(release_lock=True)
                self._lock_held = False
                raise

    def _configure_page(self, page) -> None:
        self.recorder.attach(page)
        page.on("pageerror", lambda exc: log.debug("页面 JS 错误：%s", exc))

    async def page(self):
        if not self._started:
            await self.start()
        if self._page is None or self._page.is_closed():
            await self.recreate_page()
        return self._page

    async def recreate_page(self):
        """关闭当前 page 后新建；适用于单次操作超时。"""
        if not self._started or self._ctx is None:
            await self.start()
        old = self._page
        self._page = None
        if old is not None:
            with contextlib.suppress(Exception):
                await old.close()
        try:
            self._page = await self._ctx.new_page()
            self._configure_page(self._page)
        except Exception as exc:
            log.warning("重建 page 失败，尝试重启浏览器：%s", exc)
            await self.restart()
        return self._page

    async def restart(self) -> None:
        """重建 context（profile 锁保持），用于浏览器崩溃。"""
        log.warning("重启 Playwright 浏览器")
        await self._teardown(release_lock=False)
        self._started = False
        await self.start()

    @property
    def context(self):
        return self._ctx

    async def cookies(self) -> list[dict[str, Any]]:
        if self._ctx is None:
            return []
        return await self._ctx.cookies()

    async def close(self) -> None:
        await self.recorder.close()
        await self._teardown(release_lock=True)

    async def _teardown(self, *, release_lock: bool) -> None:
        self._started = False
        page, self._page = self._page, None
        ctx, self._ctx = self._ctx, None
        pw, self._pw = self._pw, None
        if page is not None:
            with contextlib.suppress(Exception):
                await page.close()
        if ctx is not None:
            with contextlib.suppress(Exception):
                await ctx.close()
        if pw is not None:
            with contextlib.suppress(Exception):
                await pw.stop()
        if release_lock:
            self._lock.release()
            self._lock_held = False

    async def screenshot(self, name: str) -> Path:
        """保存调试截图；调用方应已持有 page 操作权。"""
        page = await self.page()
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)[:80]
        path = self.config.debug_dir / f"{time.strftime('%Y%m%d-%H%M%S')}-{safe}.png"
        try:
            await page.screenshot(path=str(path), full_page=True)
            path.chmod(0o600)
        except Exception as exc:  # pragma: no cover
            log.warning("截图失败 %s: %s", path, exc)
        return path

    async def save_html(self, name: str) -> Path:
        page = await self.page()
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)[:80]
        path = self.config.debug_dir / f"{time.strftime('%Y%m%d-%H%M%S')}-{safe}.html"
        try:
            path.write_text(await page.content(), encoding="utf-8")
            path.chmod(0o600)
        except Exception as exc:  # pragma: no cover
            log.warning("保存 HTML 失败 %s: %s", path, exc)
        return path


class PlatformActor:
    """单个浏览器 page 的串行执行器。"""

    def __init__(self, browser: BrowserSession):
        self.browser = browser
        self._queue: asyncio.PriorityQueue[_Job] = asyncio.PriorityQueue()
        self._seq = 0
        self._worker: asyncio.Task | None = None
        self._start_lock = asyncio.Lock()
        self._closed = False

    async def start(self) -> None:
        if self._closed:
            raise PlatformError("PlatformActor 已关闭")
        async with self._start_lock:
            if self._worker is None or self._worker.done():
                await self.browser.start()
                self._worker = asyncio.create_task(self._run(), name="platform-actor")

    async def submit(
        self,
        name: str,
        factory: Callable[[Any], Awaitable[Any]],
        *,
        priority: int = Priority.DISCOVER,
        timeout: float | None = None,
    ):
        await self.start()
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._seq += 1
        job = _Job(
            priority=int(priority),
            seq=self._seq,
            name=name,
            timeout=timeout or (self.browser.config.browser.timeout_seconds * 2 + 15),
            factory=factory,
            future=future,
        )
        await self._queue.put(job)
        try:
            # 兜底：worker 若卡在 page 重建等不可中断的调用里，调用方也不能永远等待。
            return await asyncio.wait_for(future, timeout=job.timeout + _SUBMIT_GRACE_SECONDS)
        except asyncio.TimeoutError as exc:
            future.cancel()
            raise PlatformError(
                f"平台任务未返回：{job.name}（等待 {job.timeout + _SUBMIT_GRACE_SECONDS:.0f}s）"
            ) from exc

    async def _run(self) -> None:
        while True:
            job = await self._queue.get()
            try:
                if job.future.cancelled():
                    continue
                try:
                    # page()/recreate_page() 内部是 Playwright 调用，没有超时；
                    # 浏览器卡死时必须在这里截断，否则整个 actor 队列永久停摆。
                    page = await asyncio.wait_for(self.browser.page(), timeout=_PAGE_TIMEOUT_SECONDS)
                    result = await asyncio.wait_for(job.factory(page), timeout=job.timeout)
                except asyncio.TimeoutError:
                    log.error("平台任务超时 name=%s timeout=%ss，重建 page", job.name, job.timeout)
                    if not job.future.done():
                        job.future.set_exception(
                            PlatformError(f"平台任务超时：{job.name}（{job.timeout:.0f}s）")
                        )
                    # 先交付异常再修复浏览器，修复本身失败也不能再拖住队列。
                    with contextlib.suppress(asyncio.TimeoutError, Exception):
                        await asyncio.wait_for(
                            self.browser.recreate_page(), timeout=_PAGE_TIMEOUT_SECONDS
                        )
                    if self.browser.context is None:  # pragma: no cover - 重建失败后的兜底
                        with contextlib.suppress(asyncio.TimeoutError, Exception):
                            await asyncio.wait_for(
                                self.browser.restart(), timeout=_PAGE_TIMEOUT_SECONDS * 3
                            )
                except asyncio.CancelledError:
                    if not job.future.done():
                        job.future.cancel()
                    raise
                except Exception as exc:
                    if not job.future.done():
                        job.future.set_exception(exc)
                else:
                    if not job.future.done():
                        job.future.set_result(result)
            finally:
                self._queue.task_done()

    async def close(self) -> None:
        self._closed = True
        if self._worker is not None:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._worker
            self._worker = None
        while not self._queue.empty():
            job = self._queue.get_nowait()
            if not job.future.done():
                job.future.set_exception(PlatformError("PlatformActor 已关闭"))
            self._queue.task_done()
        await self.browser.close()
