from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
import pytest_asyncio

from tests.helpers import make_challenge, make_config
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import SessionState, Status, SubmitResult
from ycb.submission.service import SubmissionService
from ycb.submission.watcher import FlagWatcher

REGEX = r"^DASCTF\{[^{}\r\n]{4,200}\}$"


class RecordingAdapter:
    name = "recording"
    capabilities: set[str] = set()

    def __init__(self):
        self.calls: list[str] = []
        self.session = SessionState(state="logged_in", detail="recording")

    async def submit(self, challenge, flag):
        self.calls.append(flag)
        return SubmitResult("accepted", "ok")

    async def is_solved(self, challenge):
        return False

    async def login(self):
        return None


async def seed(db, workspace: Path, *, status=Status.SOLVING):
    challenge = make_challenge("watch1")
    challenge_id = await db.insert_challenge(
        challenge, seq_no=1, workspace=str(workspace), flag_regex=REGEX
    )
    await db.force_status(challenge_id, status)
    return challenge_id


def write_flag(workspace: Path, flag: str) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "flag.txt").write_text(flag + "\n", encoding="utf-8")


@pytest_asyncio.fixture
async def bus(db):
    event_bus = EventBus(db)
    await event_bus.start()
    return event_bus


async def test_watcher_requires_stability_then_dedupes(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=True)
    config.submission.stable_seconds = 0.05
    config.submission.watch_interval_seconds = 0.01
    adapter = RecordingAdapter()
    service = SubmissionService(config, db, bus, adapter)
    workspace = tmp_path / "ws"
    challenge_id = await seed(db, workspace)
    watcher = FlagWatcher(config, db, bus, service)
    write_flag(workspace, "DASCTF{watcher_stable_flag_1}")

    assert await watcher.scan_once() == 0  # 首次只记录 hash/时间
    await asyncio.sleep(0.06)
    assert await watcher.scan_once() == 1
    assert await watcher.scan_once() == 0  # 进程内 _handled 去重

    rows = await db.list_submissions(challenge_id)
    assert len(rows) == 1 and rows[0]["status"] == "dry_run"
    assert adapter.calls == []  # dry_run 不请求平台
    events = [event.type for event in await db.recent_events(30)]
    assert events.count("flag.detected") == 1
    assert "flag.detected" in events


async def test_watcher_resets_stability_when_content_changes(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=True)
    config.submission.stable_seconds = 0.05
    adapter = RecordingAdapter()
    service = SubmissionService(config, db, bus, adapter)
    workspace = tmp_path / "ws2"
    challenge_id = await seed(db, workspace)
    watcher = FlagWatcher(config, db, bus, service)

    write_flag(workspace, "DASCTF{first_candidate_111}")
    assert await watcher.scan_once() == 0
    await asyncio.sleep(0.06)
    write_flag(workspace, "DASCTF{second_candidate_222}")
    assert await watcher.scan_once() == 0  # 内容变化，重新计时
    await asyncio.sleep(0.06)
    assert await watcher.scan_once() == 1
    rows = await db.list_submissions(challenge_id)
    assert len(rows) == 1
    assert rows[0]["flag"] == "DASCTF{second_candidate_222}"


async def test_watcher_skips_invalid_and_submitted(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=True)
    config.submission.stable_seconds = 0.0
    adapter = RecordingAdapter()
    service = SubmissionService(config, db, bus, adapter)
    workspace = tmp_path / "ws3"
    challenge_id = await seed(db, workspace)
    watcher = FlagWatcher(config, db, bus, service)

    write_flag(workspace, "flag{not_dasctf}")  # 不匹配配置正则
    assert await watcher.scan_once() == 0
    assert await db.list_submissions(challenge_id) == []

    write_flag(workspace, "DASCTF{proper_flag_333}")
    assert await watcher.scan_once() == 0
    assert await watcher.scan_once() == 1

    await db.force_status(challenge_id, Status.SUBMITTED)
    assert await watcher.scan_once() == 0


async def test_watcher_does_not_follow_symlink(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=True)
    config.submission.stable_seconds = 0.0
    adapter = RecordingAdapter()
    service = SubmissionService(config, db, bus, adapter)
    workspace = tmp_path / "ws4"
    workspace.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("DASCTF{symlink_must_not_work}\n", encoding="utf-8")
    os.symlink(outside, workspace / "flag.txt")
    challenge_id = await seed(db, workspace)
    watcher = FlagWatcher(config, db, bus, service)
    assert await watcher.scan_once() == 0
    assert await db.list_submissions(challenge_id) == []


async def test_watcher_start_stop_is_idempotent(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=True)
    config.submission.watch_interval_seconds = 0.01
    adapter = RecordingAdapter()
    service = SubmissionService(config, db, bus, adapter)
    watcher = FlagWatcher(config, db, bus, service)
    await watcher.start()
    await watcher.start()
    await asyncio.sleep(0.02)
    await watcher.stop()
    await watcher.stop()
    assert watcher._task is None
