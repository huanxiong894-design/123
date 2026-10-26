"""平台浏览器层：actor 串行/优先级/超时、profile 独占锁、适配器构造。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from tests.helpers import make_config
from ycb.adapters.base import PlatformError
from ycb.adapters.ycb import YCBAdapter
from ycb.platform.browser import PlatformActor, Priority, ProfileLock, resolve_chromium


class FakeBrowser:
    def __init__(self):
        self.config = SimpleNamespace(browser=SimpleNamespace(timeout_seconds=1.0))
        self.starts = 0
        self.recreates = 0
        self.closed = False

    async def start(self):
        self.starts += 1

    async def page(self):
        return object()

    async def recreate_page(self):
        self.recreates += 1

    async def close(self):
        self.closed = True


async def test_actor_runs_one_job_at_a_time_with_priority():
    browser = FakeBrowser()
    actor = PlatformActor(browser)
    order: list[str] = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def blocker(_page):
        order.append("blocker")
        started.set()
        await release.wait()

    async def job(name):
        order.append(name)
        return name

    blocker_task = asyncio.create_task(actor.submit("blocker", blocker, priority=Priority.LOGIN))
    await started.wait()

    low = asyncio.create_task(
        actor.submit("low", lambda page: job("low"), priority=Priority.DOWNLOAD)
    )
    while actor._queue.qsize() < 1:
        await asyncio.sleep(0.001)
    high = asyncio.create_task(
        actor.submit("high", lambda page: job("high"), priority=Priority.HEALTH)
    )
    while actor._queue.qsize() < 2:
        await asyncio.sleep(0.001)
    release.set()

    assert await blocker_task is None
    assert await high == "high"
    assert await low == "low"
    assert order == ["blocker", "high", "low"]
    await actor.close()
    assert browser.closed is True


async def test_actor_timeout_recreates_page_and_continues():
    browser = FakeBrowser()
    actor = PlatformActor(browser)

    async def slow(_page):
        await asyncio.sleep(0.3)

    async def fast(_page):
        return 42

    with pytest.raises(PlatformError, match="超时"):
        await actor.submit("slow", slow, timeout=0.05)
    assert browser.recreates == 1
    assert await actor.submit("fast", fast, timeout=1) == 42
    await actor.close()


async def test_actor_propagates_job_errors_and_stays_alive():
    browser = FakeBrowser()
    actor = PlatformActor(browser)

    async def boom(_page):
        raise ValueError("boom")

    async def ok(_page):
        return "ok"

    with pytest.raises(ValueError, match="boom"):
        await actor.submit("boom", boom, timeout=1)
    assert await actor.submit("ok", ok, timeout=1) == "ok"
    await actor.close()


def test_profile_lock_is_exclusive_and_reusable(tmp_path):
    lock = ProfileLock(tmp_path / "profile.lock")
    lock.acquire()
    assert (tmp_path / "profile.lock").read_text() == str(__import__("os").getpid())
    second = ProfileLock(tmp_path / "profile.lock")
    with pytest.raises(PlatformError, match="占用"):
        second.acquire()
    lock.release()
    lock.acquire()
    lock.release()


def test_resolve_chromium_configured_path(tmp_path):
    config = make_config(tmp_path)
    missing = tmp_path / "missing-chrome"
    config.browser.chromium_path = str(missing)
    with pytest.raises(PlatformError, match="不存在"):
        resolve_chromium(config)
    fake = tmp_path / "chrome"
    fake.write_text("#!/bin/sh\n")
    config.browser.chromium_path = str(fake)
    assert resolve_chromium(config) == fake


async def test_ycb_adapter_constructs_without_browser_launch(tmp_path):
    config = make_config(tmp_path)
    adapter = YCBAdapter(config)
    assert adapter.name == "ycb"
    assert adapter.session.state == "unknown"
    assert adapter.selectors.first("login", "username")
    assert adapter.login_url.endswith("/1749/login")
    await adapter.close()


async def test_ycb_auth_headers_include_competition_scope(tmp_path):
    config = make_config(tmp_path)
    adapter = YCBAdapter(config)

    class TokenPage:
        async def evaluate(self, _script):
            return "jwt-value"

    class EmptyPage:
        async def evaluate(self, _script):
            return ""

    assert await adapter._auth_headers(TokenPage()) == {
        "matchId": "1749",
        "authorization": "jwt-value",
    }
    assert await adapter._auth_headers(EmptyPage()) == {"matchId": "1749"}
    await adapter.close()
