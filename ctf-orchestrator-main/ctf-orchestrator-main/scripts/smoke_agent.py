#!/usr/bin/env python3
"""M3 冒烟：用本机 claude CLI 解一道本地简单题，确认能写出 flag.txt。

不连接真实平台、不提交、不使用平台凭据；在 /tmp 下建临时库和工作区。
运行会真实调用 Claude（消耗订阅/额度），默认最多等 240 秒：

    .venv/bin/python scripts/smoke_agent.py

成功输出 flag 内容与临时目录路径；退出码 0/1。
"""

from __future__ import annotations

import asyncio
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ycb.config import load_config  # noqa: E402
from ycb.db import Database  # noqa: E402
from ycb.events import EventBus  # noqa: E402
from ycb.models import Challenge, SessionState, Status  # noqa: E402
from ycb.scheduling.manager import ChallengeManager  # noqa: E402
from ycb.submission.validator import read_flag_candidate  # noqa: E402

FLAG = "DASCTF{m3_cli_smoke_2026}"
WAIT_SECONDS = 240


class LocalAdapter:
    name = "local-smoke"
    capabilities: set[str] = set()

    def __init__(self) -> None:
        self.session = SessionState(state="logged_in", detail="本地冒烟，无平台")

    async def ensure_target(self, challenge):
        return None


async def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="ycb-m3-smoke-"))
    root.chmod(0o700)
    config = load_config(ROOT / "config.toml")
    config.root = root
    config.config_path = root / "config.toml"
    config.data_dir = root / "var"
    config.workspace_dir = root / "workspace"
    config.agent.auto_start = False
    config.agent.stall_warn_seconds = 120
    config.agent.stall_interrupt_seconds = 300
    config.ensure_dirs()

    workspace = config.challenges_dir / "01_misc_smoke"
    workspace.mkdir(parents=True, exist_ok=True)
    workspace.chmod(0o700)
    (workspace / "description.md").write_text(
        "# 本地冒烟题\n\n"
        "这是一道用于验证编排链路的本地题，不需要任何攻击技巧。\n\n"
        f"flag 就是 `{FLAG}`。\n\n"
        "请把这一行写入同目录的 flag.txt（不要写其他内容，不要提交）。\n",
        encoding="utf-8",
    )

    db = Database(config.db_path)
    await db.connect()
    bus = EventBus(db)
    await bus.start()

    challenge = Challenge(
        uid=f"local:m3:{secrets.token_hex(4)}",
        platform="local",
        competition_id="smoke",
        platform_id="smoke",
        title="M3 Local Smoke",
        category="Misc",
        score=1,
        description_md="本地冒烟题，flag 已写在 description.md。",
    )
    challenge_id = await db.insert_challenge(
        challenge,
        seq_no=1,
        workspace=str(workspace),
        flag_regex=config.submission.flag_regex,
    )
    manager = ChallengeManager(config, db, bus, LocalAdapter())

    sub = bus.subscribe(maxsize=1000)

    async def printer() -> None:
        while True:
            try:
                event = await sub.get()
            except Exception:
                return
            if event.type.endswith(".delta") or event.type in {"heartbeat", "discovery.tick"}:
                continue
            payload = event.payload or {}
            brief = ""
            if event.type == "agent.text":
                brief = str(payload.get("text", "")).replace("\n", " ")[:120]
            elif event.type == "agent.tool_use":
                brief = f"{payload.get('name')} {str(payload.get('input'))[:100]}"
            elif event.type == "agent.tool_result":
                brief = str(payload.get("output", "")).replace("\n", " ")[:100]
            elif event.type in {"run.started", "run.exited", "flag.detected", "agent.error", "alert"}:
                brief = str(payload)[:200]
            print(f"[{event.type}] {brief}", flush=True)

    printer_task = asyncio.create_task(printer())
    print(f"临时目录：{root}")
    print(f"启动真实 Claude CLI（等待最多 {WAIT_SECONDS}s）……", flush=True)
    result = await manager.start(challenge_id)
    print(f"启动结果：{result}", flush=True)

    candidate = None
    for _ in range(WAIT_SECONDS):
        await asyncio.sleep(1)
        candidate = read_flag_candidate(workspace, config.submission.flag_regex)
        if candidate is not None:
            break
        state = await db.get_challenge(challenge_id)
        if state is None or state.status in {Status.FAILED, Status.NEEDS_HUMAN, Status.STOPPED}:
            break

    if candidate is not None:
        print(f"\nOK flag.txt = {candidate.flag}")
        print(f"sha256 = {candidate.sha256}")
        await manager.stop(challenge_id)
        code = 0
    else:
        state = await db.get_challenge(challenge_id)
        print(f"\nFAIL：未在限定时间内看到合法 flag.txt（状态 {state.status.value if state else '?'}）")
        await manager.stop(challenge_id)
        code = 1

    printer_task.cancel()
    sub.close()
    await manager.close()
    await db.close()
    print(f"清理时保留现场：{root}（确认后可 rm -rf）")
    return code


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("中断", file=sys.stderr)
        sys.exit(130)
