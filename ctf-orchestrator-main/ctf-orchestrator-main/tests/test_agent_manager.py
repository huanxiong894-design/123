from __future__ import annotations

import asyncio

import pytest

from tests.helpers import make_challenge, make_config
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import SessionState, Status
from ycb.scheduling.manager import ChallengeManager


class StubAdapter:
    name = "stub"
    capabilities: set[str] = set()

    def __init__(self) -> None:
        self.session = SessionState(state="logged_in")

    async def ensure_target(self, challenge):
        return None


class RecordingBackend:
    instances: list["RecordingBackend"] = []

    def __init__(self, spec, config, emit, run_id=None):
        self.spec = spec
        self.config = config
        self.emit = emit
        self.run_id = run_id
        self.session_id = spec.session_id or f"sess-{run_id}"
        self.pid = 1000 + (run_id or 0)
        self.pgid = self.pid
        self.raw_path = None
        self.alive = False
        self.sent: list[str] = []
        self.exit_code: int | None = None
        self._exit = asyncio.Event()
        RecordingBackend.instances.append(self)

    async def start(self) -> None:
        self.alive = True

    async def send(self, text: str) -> bool:
        if not self.alive:
            return False
        self.sent.append(text)
        return True

    def finish(self, code: int) -> None:
        self.exit_code = code
        self.alive = False
        self._exit.set()

    async def interrupt(self, *, control_timeout: float = 3.0) -> bool:
        self.finish(0)
        return True

    async def stop(self) -> None:
        if self.alive:
            self.finish(0)

    async def wait(self) -> int | None:
        await self._exit.wait()
        return self.exit_code

    async def close(self) -> None:
        self.alive = False


class FlagBackend(RecordingBackend):
    async def send(self, text: str) -> bool:
        ok = await super().send(text)
        if ok:
            (self.spec.workspace / "flag.txt").write_text(
                "DASCTF{manager_found_it}\n", encoding="utf-8"
            )
            self.finish(0)
        return ok


@pytest.fixture
async def env(tmp_path):
    config = make_config(tmp_path)
    db = Database(config.db_path)
    await db.connect()
    bus = EventBus(db)
    await bus.start()
    challenge = make_challenge("m1", title="Manager Test", category="Misc")
    workspace = config.challenges_dir / "01_misc_manager_test"
    workspace.mkdir(parents=True, exist_ok=True)
    challenge_id = await db.insert_challenge(
        challenge,
        seq_no=1,
        workspace=str(workspace),
        flag_regex=r"^DASCTF\{[^{}]+\}$",
    )
    RecordingBackend.instances.clear()
    manager = ChallengeManager(config, db, bus, StubAdapter())
    yield config, db, bus, manager, challenge_id, workspace
    await manager.close()
    await db.close()


async def test_start_pause_resume_stop_restart(env):
    _, db, _, manager, challenge_id, _ = env
    manager._factory = RecordingBackend
    result = await manager.start(challenge_id)
    assert result["started"] is True
    first = RecordingBackend.instances[-1]
    assert first.sent and "开始分析" in first.sent[0]
    assert first.spec.resume is False

    challenge = await db.get_challenge(challenge_id)
    assert challenge.status == Status.SOLVING
    runs = await db.runs_for_challenge(challenge_id)
    assert runs[-1]["status"] == "RUNNING"
    assert runs[-1]["pid"] == first.pid

    sent = await manager.send_operator_message(challenge_id, "换个思路看看")
    assert sent["delivered"] is True
    assert first.sent[-1] == "换个思路看看"

    await manager.pause(challenge_id)
    challenge = await db.get_challenge(challenge_id)
    assert challenge.status == Status.PAUSED
    assert (await db.runs_for_challenge(challenge_id))[-1]["status"] == "PAUSED"

    resumed = await manager.start(challenge_id, resume=True)
    assert resumed["started"] is True
    second = RecordingBackend.instances[-1]
    assert second is not first
    assert second.spec.resume is True
    assert second.spec.session_id == first.session_id
    assert "继续解题" in second.sent[0]
    assert (await db.get_challenge(challenge_id)).status == Status.SOLVING

    await manager.stop(challenge_id)
    assert (await db.get_challenge(challenge_id)).status == Status.STOPPED

    fresh = await manager.restart(challenge_id, "fresh")
    assert fresh["started"] is True
    third = RecordingBackend.instances[-1]
    assert third.spec.resume is False
    assert third.spec.session_id != first.session_id
    assert "新会话" in third.sent[0] or "重新" in third.sent[0]
    assert (await db.get_challenge(challenge_id)).status == Status.SOLVING


async def test_flag_detection_marks_solved(env):
    _, db, _, manager, challenge_id, _ = env
    manager._factory = FlagBackend
    await manager.start(challenge_id)
    for _ in range(50):
        challenge = await db.get_challenge(challenge_id)
        if challenge.status == Status.SOLVED:
            break
        await asyncio.sleep(0.02)
    assert challenge.status == Status.SOLVED
    types = [event.type for event in await db.events_for_challenge(challenge_id)]
    assert "flag.detected" in types
    assert "run.exited" in types


async def test_exit_zero_without_flag_needs_human(env):
    _, db, _, manager, challenge_id, _ = env
    manager._factory = RecordingBackend
    original_send = RecordingBackend.send

    async def send_then_exit(self, text):
        ok = await original_send(self, text)
        if ok:
            self.finish(0)
        return ok

    RecordingBackend.send = send_then_exit
    try:
        await manager.start(challenge_id)
        for _ in range(50):
            challenge = await db.get_challenge(challenge_id)
            if challenge.status == Status.NEEDS_HUMAN:
                break
            await asyncio.sleep(0.02)
    finally:
        RecordingBackend.send = original_send
    assert challenge.status == Status.NEEDS_HUMAN
    events = [event.type for event in await db.events_for_challenge(challenge_id)]
    assert "alert" in events


async def test_reconcile_startup_interrupts_stale_runs(env):
    _, db, _, manager, challenge_id, _ = env
    run_id = await db.create_run(challenge_id, backend="cli", session_id="stale")
    await db.force_status(challenge_id, Status.SOLVING)
    await manager.reconcile_startup()
    assert (await db.get_challenge(challenge_id)).status == Status.STOPPED
    assert (await db.get_run(run_id))["status"] == "INTERRUPTED"


async def test_message_starts_agent_and_resume_all(env):
    _, db, _, manager, challenge_id, _ = env
    manager._factory = RecordingBackend
    result = await manager.send_operator_message(challenge_id, "从提示开始")
    assert result["delivered"] is True
    assert RecordingBackend.instances[-1].sent == ["从提示开始"]
    await manager.stop(challenge_id)
    resumed = await manager.resume_all()
    assert resumed["count"] == 1
    assert (await db.get_challenge(challenge_id)).status == Status.SOLVING
