"""M4 mock 平台端到端：FlagWatcher → 提交队列 → mock 平台真实提交。"""

from __future__ import annotations

import asyncio

import httpx
import pytest_asyncio

from mock_platform.data import CRYPTO_FLAG
from tests.helpers import make_config
from ycb.adapters.mock import MockAdapter
from ycb.events import EventBus
from ycb.models import Status
from ycb.submission.service import SubmissionService
from ycb.submission.watcher import FlagWatcher


async def _insert(db, adapter, platform_id: str, *, status=Status.SOLVING):
    challenge = next(item for item in await adapter.discover() if item.platform_id == platform_id)
    workspace = adapter.config.workspace_dir / platform_id
    workspace.mkdir(parents=True, exist_ok=True)
    challenge_id = await db.insert_challenge(
        challenge,
        seq_no=1,
        workspace=str(workspace),
        flag_regex=adapter.config.submission.flag_regex,
    )
    if status != Status.DISCOVERED:
        await db.force_status(challenge_id, status)
    return challenge_id, workspace


@pytest_asyncio.fixture
async def live_adapter(mock_app, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    config.submission.min_interval_seconds = 0.0
    config.submission.per_challenge_interval_seconds = 0.0
    config.submission.stable_seconds = 0.0
    adapter = MockAdapter(config, transport=httpx.ASGITransport(app=mock_app))
    await adapter.login()
    try:
        yield adapter
    finally:
        await adapter.close()


async def test_watcher_submits_wrong_then_correct_flag(db, mock_app, live_adapter):
    bus = EventBus(db)
    await bus.start()
    service = SubmissionService(live_adapter.config, db, bus, live_adapter)
    watcher = FlagWatcher(live_adapter.config, db, bus, service)
    await service.start()
    try:
        challenge_id, workspace = await _insert(db, live_adapter, "crypto-warmup-rsa")

        (workspace / "flag.txt").write_text("DASCTF{wrong_guess_2026}\n", encoding="utf-8")
        assert await watcher.scan_once() == 0
        assert await watcher.scan_once() == 1
        # 队列异步处理：等平台把该题标记为未解，且状态回到 SOLVED
        for _ in range(100):
            if (await db.get_challenge(challenge_id)).status == Status.SOLVED:
                break
            await asyncio.sleep(0.02)
        challenge = await db.get_challenge(challenge_id)
        assert challenge.status == Status.SOLVED
        rows = await db.list_submissions(challenge_id)
        assert rows[-1]["status"] == "rejected"

        (workspace / "flag.txt").write_text(CRYPTO_FLAG + "\n", encoding="utf-8")
        assert await watcher.scan_once() == 0  # 内容变化，重新计时
        assert await watcher.scan_once() == 1
        for _ in range(100):
            if (await db.get_challenge(challenge_id)).status == Status.SUBMITTED:
                break
            await asyncio.sleep(0.02)
        challenge = await db.get_challenge(challenge_id)
        assert challenge.status == Status.SUBMITTED
        rows = await db.list_submissions(challenge_id)
        assert rows[-1]["status"] == "accepted"
        assert await live_adapter.is_solved(challenge) is True
    finally:
        await service.stop()

    types = [event.type for event in await db.recent_events(100)]
    assert "flag.detected" in types
    assert "submit.result" in types
    assert "status.changed" in types


async def test_quota_stops_further_automatic_submits(db, mock_app, live_adapter):
    bus = EventBus(db)
    await bus.start()
    live_adapter.config.submission.max_auto_submits = 2
    service = SubmissionService(live_adapter.config, db, bus, live_adapter)
    await service.start()
    try:
        first, _ = await _insert(db, live_adapter, "crypto-warmup-rsa")
        second, _ = await _insert(db, live_adapter, "misc-nested-archive")
        third, _ = await _insert(db, live_adapter, "pwn-baby-echo")

        results = [
            await service.enqueue(first, "DASCTF{wrong_one_2026}", wait=True, timeout=5),
            await service.enqueue(second, "DASCTF{wrong_two_2026}", wait=True, timeout=5),
            await service.enqueue(third, "DASCTF{wrong_three_2026}", wait=True, timeout=5),
        ]
    finally:
        await service.stop()
    assert [item["status"] for item in results] == ["rejected", "rejected", "quota"]
    assert (await db.get_challenge(third)).status == Status.NEEDS_HUMAN
    assert await db.count_live_submissions() == 2
