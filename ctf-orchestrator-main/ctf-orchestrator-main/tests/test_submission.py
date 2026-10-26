from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from tests.helpers import make_challenge, make_config
from ycb.events import EventBus
from ycb.models import SessionState, Status, SubmitResult
from ycb.submission.service import SubmissionError, SubmissionService

FLAG_A = "DASCTF{correct_flag_2026_a}"
FLAG_B = "DASCTF{correct_flag_2026_b}"
REGEX = r"^DASCTF\{[^{}\r\n]{4,200}\}$"


class FakeManager:
    def __init__(self):
        self.stops: list[int] = []
        self.starts: list[tuple[int, bool, str | None]] = []

    async def stop_for_submission(self, challenge_id: int) -> None:
        self.stops.append(challenge_id)

    async def start(self, challenge_id: int, *, resume=False, message=None, **_kwargs):
        self.starts.append((challenge_id, resume, message))
        return {"started": True}


class ScriptedAdapter:
    name = "scripted"
    capabilities: set[str] = set()

    def __init__(self, results=None):
        self.results = list(results or [])
        self.calls: list[tuple[int, str]] = []
        self.logins = 0
        self.solved = False
        self.session = SessionState(state="logged_in", detail="scripted")

    async def submit(self, challenge, flag):
        self.calls.append((challenge.db_id, flag))
        if self.results:
            return self.results.pop(0)
        return SubmitResult("unknown", "no scripted result")

    async def is_solved(self, challenge):
        return self.solved

    async def login(self):
        self.logins += 1


async def seed(db, key="sub1", *, status=Status.SOLVED, workspace="/tmp/ws"):
    challenge = make_challenge(key)
    challenge_id = await db.insert_challenge(
        challenge, seq_no=1, workspace=workspace, flag_regex=REGEX
    )
    if status != Status.DISCOVERED:
        await db.force_status(challenge_id, status)
    return challenge_id


@pytest_asyncio.fixture
async def bus(db):
    event_bus = EventBus(db)
    await event_bus.start()
    return event_bus


def make_service(config, db, bus, adapter, manager=None):
    service = SubmissionService(config, db, bus, adapter, manager=manager)
    return service


async def test_dry_run_records_without_calling_platform(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=True)
    adapter = ScriptedAdapter([SubmitResult("accepted")])
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    try:
        result = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await service.stop()
    assert result["status"] == "dry_run" and result["dry_run"] is True
    assert adapter.calls == []
    rows = await db.list_submissions(challenge_id)
    assert len(rows) == 1 and rows[0]["status"] == "dry_run" and rows[0]["dry_run"] == 1
    types = [event.type for event in await db.recent_events(20)]
    assert "submit.result" in types


async def test_dry_run_record_is_promoted_after_switch_to_live(db, bus, tmp_path):
    dry_config = make_config(tmp_path, dry_run=True)
    adapter = ScriptedAdapter([SubmitResult("accepted", "Flag 正确")])
    challenge_id = await seed(db)
    dry_service = make_service(dry_config, db, bus, adapter)
    first = await dry_service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    await dry_service.stop()
    assert first["status"] == "dry_run" and adapter.calls == []

    dry_config.submission.dry_run = False
    live_service = make_service(dry_config, db, bus, adapter)
    await live_service.start()
    try:
        result = await live_service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await live_service.stop()
    assert result["status"] == "accepted"
    assert len(adapter.calls) == 1
    rows = await db.list_submissions(challenge_id)
    assert len(rows) == 1 and rows[0]["status"] == "accepted" and rows[0]["dry_run"] == 0


async def test_live_accept_marks_submitted_and_dedupes(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter([SubmitResult("accepted", "Flag 正确，得分！")])
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    await service.start()
    try:
        result = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
        again = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await service.stop()
    assert result["status"] == "accepted"
    assert again["status"] == "already_solved"  # 已 SUBMITTED，不再入库/提交
    assert len(adapter.calls) == 1
    challenge = await db.get_challenge(challenge_id)
    assert challenge.status == Status.SUBMITTED
    row = (await db.list_submissions(challenge_id))[-1]
    assert row["status"] == "accepted" and row["dry_run"] == 0


async def test_rejected_returns_to_solved(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter([SubmitResult("rejected", "Flag 错误")])
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    await service.start()
    try:
        result = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await service.stop()
    assert result["status"] == "rejected"
    challenge = await db.get_challenge(challenge_id)
    assert challenge.status == Status.SOLVED
    row = (await db.list_submissions(challenge_id))[-1]
    assert row["status"] == "rejected"


async def test_unknown_checks_is_solved_and_never_retries(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter([SubmitResult("unknown", "网关超时")])
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    await service.start()
    try:
        result = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
        duplicate = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await service.stop()
    assert result["status"] == "unknown"
    assert duplicate.get("duplicate") is True
    assert len(adapter.calls) == 1  # 绝不自动重试
    challenge = await db.get_challenge(challenge_id)
    assert challenge.status == Status.NEEDS_HUMAN


async def test_unknown_but_platform_says_solved_is_accepted(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter([SubmitResult("unknown", "响应超时")])
    adapter.solved = True
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    await service.start()
    try:
        result = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await service.stop()
    assert result["status"] == "accepted"
    assert (await db.get_challenge(challenge_id)).status == Status.SUBMITTED


async def test_rate_limited_retries_then_accepts(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter(
        [
            SubmitResult("rate_limited", "提交过快", {"retry_after": 3}),
            SubmitResult("accepted", "Flag 正确"),
        ]
    )
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    service._retry_delay = lambda *_args: 0.01  # type: ignore[method-assign]
    await service.start()
    try:
        result = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await service.stop()
    assert result["status"] == "accepted"
    assert len(adapter.calls) == 2
    types = [event.type for event in await db.recent_events(30)]
    assert "submit.retry" in types


async def test_session_expired_relogins_once(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter(
        [SubmitResult("session_expired", "会话过期"), SubmitResult("accepted", "ok")]
    )
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    await service.start()
    try:
        result = await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
    finally:
        await service.stop()
    assert result["status"] == "accepted"
    assert adapter.logins == 1
    assert len(adapter.calls) == 2


async def test_quota_is_reserved_atomically(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    config.submission.max_auto_submits = 1
    adapter = ScriptedAdapter([SubmitResult("accepted"), SubmitResult("accepted")])
    first = await seed(db, "q1")
    second = await seed(db, "q2")
    service = make_service(config, db, bus, adapter)
    await service.start()
    try:
        ok = await service.enqueue(first, FLAG_A, wait=True, timeout=5)
        blocked = await service.enqueue(second, FLAG_B, wait=True, timeout=5)
    finally:
        await service.stop()
    assert ok["status"] == "accepted"
    assert blocked["status"] == "quota"
    assert len(adapter.calls) == 1
    assert (await db.get_challenge(second)).status == Status.NEEDS_HUMAN


async def test_manual_submit_rejects_invalid_flag(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=True)
    adapter = ScriptedAdapter()
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    with pytest.raises(SubmissionError) as exc:
        await service.submit_manual(challenge_id, "DASCTF{test}")
    assert exc.value.status_code == 422
    await service.stop()


async def test_rejection_threshold_escalates_to_human(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    config.submission.max_auto_submits = 10
    flags = [f"DASCTF{{wrong_attempt_{i}_2026}}" for i in range(1, 6)]
    adapter = ScriptedAdapter([SubmitResult("rejected", "Flag 错误") for _ in flags])
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    await service.start()
    try:
        results = [
            await service.enqueue(challenge_id, flag, wait=True, timeout=5) for flag in flags
        ]
    finally:
        await service.stop()
    assert [item["status"] for item in results] == ["rejected"] * 5
    assert (await db.get_challenge(challenge_id)).status == Status.NEEDS_HUMAN
    assert len(adapter.calls) == 5


async def test_accepted_stops_agent_and_rejected_resumes_it(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    config.submission.max_auto_submits = 5
    manager = FakeManager()
    adapter = ScriptedAdapter(
        [SubmitResult("rejected", "Flag 错误"), SubmitResult("accepted", "Flag 正确")]
    )
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter, manager=manager)
    await service.start()
    try:
        await service.enqueue(challenge_id, FLAG_A, wait=True, timeout=5)
        for _ in range(50):
            if manager.starts and manager.stops:
                break
            await asyncio.sleep(0.01)
        assert manager.stops == [challenge_id]
        assert manager.starts and manager.starts[0][1] is True  # resume 原会话
        assert "拒绝" in (manager.starts[0][2] or "")

        await db.force_status(challenge_id, Status.SOLVED)
        await service.enqueue(challenge_id, FLAG_B, wait=True, timeout=5)
        for _ in range(50):
            if manager.stops.count(challenge_id) >= 2:
                break
            await asyncio.sleep(0.01)
    finally:
        await service.stop()
    assert manager.stops.count(challenge_id) >= 2


async def test_startup_recovery_marks_pending_unknown(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter()
    challenge_id = await seed(db, status=Status.SUBMITTING)
    submission_id, reason = await db.reserve_live_submission(
        challenge_id, flag=FLAG_A, flag_sha256="a" * 64, max_live=5
    )
    assert reason == "ok" and submission_id is not None
    service = make_service(config, db, bus, adapter)
    await service.recover_startup()
    row = await db.get_submission(submission_id)
    assert row is not None
    assert row["status"] == "unknown"
    assert (await db.get_challenge(challenge_id)).status == Status.NEEDS_HUMAN
    assert adapter.calls == []


async def test_shutdown_resolves_queued_waiters(db, bus, tmp_path):
    config = make_config(tmp_path, dry_run=False)
    adapter = ScriptedAdapter()
    challenge_id = await seed(db)
    service = make_service(config, db, bus, adapter)
    # 不启动 worker：任务留在队列里，关闭服务时必须给等待者一个结论
    task = asyncio.create_task(service.enqueue(challenge_id, FLAG_A, wait=True, timeout=30))
    for _ in range(100):
        if not service._queue.empty():
            break
        await asyncio.sleep(0.01)
    assert not service._queue.empty()
    await service.stop()
    result = await asyncio.wait_for(task, timeout=2)
    assert result["status"] == "unknown"
