from __future__ import annotations

from pathlib import Path

import httpx

from tests.helpers import make_config
from ycb.adapters.mock import MockAdapter
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import Status
from ycb.scheduling.discovery_loop import DiscoveryLoop


async def _make_loop(tmp_path, mock_app, **hooks):
    config = make_config(tmp_path, discovery_enabled=True, confirm_passes=2, interval=0.01)
    db = Database(config.db_path)
    await db.connect()
    bus = EventBus(db)
    await bus.start()
    adapter = MockAdapter(config, transport=httpx.ASGITransport(app=mock_app))
    loop = DiscoveryLoop(config, db, bus, adapter, **hooks)
    return config, db, bus, adapter, loop


async def test_hooks_fire_for_new_and_solved(tmp_path, mock_app):
    new_ids: list[int] = []
    solved_ids: list[int] = []

    async def on_new(challenge_id: int) -> None:
        new_ids.append(challenge_id)

    async def on_solved(challenge_id: int) -> None:
        solved_ids.append(challenge_id)

    config, db, bus, adapter, loop = await _make_loop(
        tmp_path, mock_app, on_new_challenge=on_new, on_solved=on_solved
    )
    try:
        await loop.tick()
        await loop.tick()
        challenges = await db.list_challenges()
        assert set(new_ids) == {challenge.db_id for challenge in challenges}

        challenge = challenges[0]
        mock_app.state.mock_state.challenges[challenge.platform_id].solved_by.add("player")
        await loop.tick()
        assert solved_ids == [challenge.db_id]
    finally:
        await adapter.close()
        await db.close()


async def test_two_pass_discovery_creates_workspaces_and_attachments(tmp_path, mock_app):
    config, db, bus, adapter, loop = await _make_loop(tmp_path, mock_app)
    try:
        await loop.tick()
        assert await db.total_challenges() == 0  # 第一轮仅确认，不建目录
        assert loop.status.state == "running"
        assert loop.status.last_tick_new == 0
        assert loop.status.ticks == 1

        await loop.tick()
        challenges = await db.list_challenges()
        assert len(challenges) == 3
        assert [challenge.seq_no for challenge in challenges] == [1, 2, 3]
        assert loop.status.ticks == 2
        assert loop.status.total_known == 3
        assert loop.status.last_tick_new == 3
        assert loop.status.last_error is None
        assert loop.status.session.get("state") == "logged_in"

        for challenge in challenges:
            workspace = Path(challenge.workspace)
            assert workspace.is_dir()
            assert (workspace / "description.md").is_file()
            assert (workspace / "notes.md").is_file()
            assert (workspace / "attachments").is_dir()
            assert list((workspace / "attachments").iterdir()), challenge.title
            # 附件内即使有 CLAUDE.md，也不会被解压到题目根目录
            assert not (workspace / "CLAUDE.md").exists()
            assert not (workspace / ".claude").exists()
            text = (workspace / "description.md").read_text(encoding="utf-8")
            assert "不可信数据" in text

        crypto = next(challenge for challenge in challenges if challenge.category == "Crypto")
        assert (Path(crypto.workspace) / "attachments" / "warmup_rsa.zip").is_file()

        events = await db.events_after(0)
        discovered = [event for event in events if event.type == "challenge.discovered"]
        assert len(discovered) == 3
        assert {event.challenge_id for event in discovered} == {challenge.db_id for challenge in challenges}
        assert all(event.payload.get("attachments_saved") for event in discovered)

        # 第三轮不重复建题
        await loop.tick()
        assert await db.total_challenges() == 3
        assert loop.status.last_tick_new == 0
    finally:
        await adapter.close()
        await db.close()


async def test_platform_solved_forces_submitted(tmp_path, mock_app):
    config, db, bus, adapter, loop = await _make_loop(tmp_path, mock_app)
    try:
        await loop.tick()
        await loop.tick()
        challenge = (await db.list_challenges())[0]
        assert challenge.status is Status.DISCOVERED

        # 模拟平台侧已解出（例如人工在网页提交成功）
        mock_app.state.mock_state.challenges[challenge.platform_id].solved_by.add("player")
        await loop.tick()

        refreshed = await db.get_challenge(challenge.db_id)
        assert refreshed.status is Status.SUBMITTED
        assert refreshed.solved_on_platform is True

        status_events = [event for event in await db.events_after(0) if event.type == "status.changed"]
        assert any(event.challenge_id == challenge.db_id for event in status_events)
    finally:
        await adapter.close()
        await db.close()


async def test_workspace_preserved_on_rediscovery(tmp_path, mock_app):
    config, db, bus, adapter, loop = await _make_loop(tmp_path, mock_app)
    try:
        await loop.tick()
        await loop.tick()
        challenge = (await db.list_challenges())[0]
        notes = Path(challenge.workspace) / "notes.md"
        notes.write_text("agent progress", encoding="utf-8")

        await loop.tick()
        refreshed = await db.get_challenge(challenge.db_id)
        assert refreshed.workspace == challenge.workspace
        assert notes.read_text(encoding="utf-8") == "agent progress"
    finally:
        await adapter.close()
        await db.close()
