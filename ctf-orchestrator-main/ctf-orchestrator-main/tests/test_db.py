from __future__ import annotations

import os

import pytest

from tests.helpers import make_challenge
from ycb.models import Attachment, Event, Status, Target


async def _insert(db, challenge=None, key="c1"):
    challenge = challenge or make_challenge(key)
    seq = await db.allocate_seq_no(challenge.platform, challenge.competition_id)
    challenge_id = await db.insert_challenge(
        challenge, seq_no=seq, workspace=f"/tmp/ws/{key}", flag_regex=r"^DASCTF\{.*\}$"
    )
    return challenge_id, seq


async def test_insert_get_and_permissions(db, tmp_path):
    challenge_id, seq = await _insert(db)
    assert seq == 1
    loaded = await db.get_challenge(challenge_id)
    assert loaded is not None
    assert loaded.title == "Challenge c1"
    assert loaded.status is Status.DISCOVERED
    assert loaded.db_id == challenge_id
    assert loaded.seq_no == 1
    assert loaded.workspace == "/tmp/ws/c1"
    assert await db.get_challenge_by_uid("mock:1749:c1") is not None
    assert await db.total_challenges() == 1
    if os.name == "posix":
        assert (db.path.stat().st_mode & 0o777) == 0o600


async def test_duplicate_uid_rejected(db):
    await _insert(db, key="dup")
    with pytest.raises(Exception):
        await _insert(db, key="dup")


async def test_seq_no_is_monotonic(db):
    assert await db.allocate_seq_no("mock", "1749") == 1
    assert await db.allocate_seq_no("mock", "1749") == 2
    assert await db.allocate_seq_no("mock", "other") == 1


async def test_cas_status(db):
    challenge_id, _ = await _insert(db)
    assert await db.cas_status(challenge_id, Status.DISCOVERED, Status.PREPARING)
    assert (await db.get_challenge(challenge_id)).status is Status.PREPARING

    # 期望值不匹配 -> 失败
    assert not await db.cas_status(challenge_id, Status.DISCOVERED, Status.READY)
    # 非法迁移 -> 失败
    assert not await db.cas_status(challenge_id, Status.PREPARING, Status.SUBMITTED)
    assert (await db.get_challenge(challenge_id)).status is Status.PREPARING

    # force 允许平台真相覆盖
    assert await db.cas_status(challenge_id, Status.PREPARING, Status.SUBMITTED, force=True, solved=True)
    loaded = await db.get_challenge(challenge_id)
    assert loaded.status is Status.SUBMITTED

    # 终态不允许普通回退
    assert not await db.cas_status(challenge_id, Status.SUBMITTED, Status.SOLVING)


async def test_update_from_platform_preserves_local_state(db):
    challenge_id, _ = await _insert(db)
    assert await db.cas_status(challenge_id, Status.DISCOVERED, Status.PREPARING)
    assert await db.cas_status(challenge_id, Status.PREPARING, Status.READY)
    assert await db.cas_status(challenge_id, Status.READY, Status.SOLVING)
    await db.set_workspace(challenge_id, "/tmp/custom")

    before = await db.get_challenge(challenge_id)
    updated = make_challenge("c1", score=800, description_md="new desc")
    updated.db_id = challenge_id
    assert await db.update_challenge_from_platform(updated)
    after = await db.get_challenge(challenge_id)
    assert after.score == 800
    assert after.description_md == "new desc"
    assert after.status is Status.SOLVING
    assert after.workspace == "/tmp/custom"

    # 相同快照不再更新
    updated.raw = after.raw
    assert not await db.update_challenge_from_platform(updated)


async def test_update_attachments_and_target(db):
    challenge_id, _ = await _insert(db)
    challenge = make_challenge(
        "c1",
        attachments=[Attachment(name="a.zip", url="/x", size=5, sha256="b" * 64)],
        target=Target(kind="tcp", host="10.0.0.1", port=1234),
        container_available=True,
    )
    assert await db.update_challenge_from_platform(challenge)
    loaded = await db.get_challenge(challenge_id)
    assert loaded.attachments[0].name == "a.zip"
    assert loaded.target is not None and loaded.target.port == 1234
    assert loaded.container_available is True


async def test_events_roundtrip(db):
    challenge_id, _ = await _insert(db)
    e1 = Event(seq=1, ts="2026-10-24T02:00:00+00:00", type="challenge.discovered", challenge_id=challenge_id, payload={"x": 1})
    e2 = Event(seq=2, ts="2026-10-24T02:00:01+00:00", type="system.ready", payload={"v": "m1"})
    await db.insert_event(e1)
    await db.insert_event(e2)
    assert await db.max_event_seq() == 2
    events = await db.events_after(0)
    assert [e.seq for e in events] == [1, 2]
    assert events[0].payload == {"x": 1}
    assert [e.type for e in await db.events_for_challenge(challenge_id)] == ["challenge.discovered"]
    assert [e.seq for e in await db.recent_events(limit=1)] == [2]
    assert [e.seq for e in await db.recent_events(limit=10, upto_seq=1)] == [1]


async def test_messages_and_delivery(db):
    challenge_id, _ = await _insert(db)
    message_id = await db.add_message(
        challenge_id, direction="operator", content="继续", delivered=False
    )
    messages = await db.list_messages(challenge_id)
    assert len(messages) == 1
    assert messages[0]["content"] == "继续"
    assert messages[0]["delivered"] == 0
    await db.mark_message_delivered(message_id)
    assert (await db.list_messages(challenge_id))[0]["delivered"] == 1


async def test_submissions_unique_per_flag(db):
    challenge_id, _ = await _insert(db)
    kwargs = dict(flag="DASCTF{abc}", flag_sha256="a" * 64, status="rejected", dry_run=False)
    first = await db.add_submission(challenge_id, **kwargs)
    second = await db.add_submission(challenge_id, **kwargs)
    assert first is not None and second is None
    assert await db.flag_already_tried(challenge_id, "a" * 64)
    stats = await db.submission_stats()
    assert stats == {"total": 1, "accepted": 0, "rejected": 1, "live": 1}
    assert len(await db.list_submissions(challenge_id)) == 1


async def test_counts(db):
    await _insert(db, key="a")
    await _insert(db, key="b")
    await db.cas_status(1, Status.DISCOVERED, Status.PREPARING)
    counts = await db.counts_by_status()
    assert counts["PREPARING"] == 1
    assert counts["DISCOVERED"] == 1
