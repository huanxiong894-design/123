"""FlagWatcher：轮询各题 flag.txt，校验并稳定后交给提交队列。

- 只扫描已有工作区且未进入 SUBMITTING/SUBMITTED 的题目；
- 同一内容需连续稳定 ``stable_seconds``（默认 1s）才认可，避免读到写了一半的文件；
- 同一 (challenge, sha256) 进程内只入队一次；跨进程由 submissions 表 UNIQUE 去重。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time

from ycb.agents.normalize import mask_flag
from ycb.config import Config
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import Challenge, Status
from ycb.submission.service import SubmissionService
from ycb.submission.validator import read_flag_candidate

log = logging.getLogger(__name__)

# 提交中的题目不要重复入队；其余状态都扫描（人工放 flag.txt / 上次崩溃遗留也能接上）
_SKIP_STATUSES = {Status.SUBMITTING, Status.SUBMITTED}


class FlagWatcher:
    def __init__(
        self,
        config: Config,
        db: Database,
        bus: EventBus,
        submissions: SubmissionService,
    ) -> None:
        self.config = config
        self.db = db
        self.bus = bus
        self.submissions = submissions
        self._task: asyncio.Task | None = None
        self._closing = False
        self._stable: dict[int, tuple[str, float]] = {}
        self._handled: set[tuple[int, str]] = set()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._closing = False
        self._task = asyncio.create_task(self._run(), name="flag-watcher")

    async def stop(self) -> None:
        self._closing = True
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    async def _run(self) -> None:
        interval = max(0.1, self.config.submission.watch_interval_seconds)
        while True:
            await asyncio.sleep(interval)
            try:
                await self.scan_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover - 单轮失败不应终止监听
                log.exception("flag 轮询异常")

    async def scan_once(self) -> int:
        """扫描一轮，返回本轮新入队数量。"""
        challenges = await self.db.list_challenges()
        now = time.monotonic()
        queued = 0
        for challenge in challenges:
            if challenge.db_id is None or not challenge.workspace:
                continue
            if challenge.status in _SKIP_STATUSES:
                continue
            candidate = read_flag_candidate(
                challenge.workspace,
                challenge.flag_regex or self.config.submission.flag_regex,
            )
            if candidate is None:
                continue
            challenge_id = challenge.db_id
            last = self._stable.get(challenge_id)
            if last is None or last[0] != candidate.sha256:
                self._stable[challenge_id] = (candidate.sha256, now)
                continue
            if now - last[1] < max(0.0, self.config.submission.stable_seconds):
                continue
            key = (challenge_id, candidate.sha256)
            if key in self._handled:
                continue
            self._handled.add(key)
            await self._announce(challenge, candidate.flag, candidate.sha256)
            try:
                await self.submissions.enqueue(
                    challenge_id,
                    candidate.flag,
                    run_id=None,
                )
            except Exception as exc:
                log.warning("flag 入队失败 challenge=%s: %s", challenge_id, exc)
                await self.bus.emit(
                    "alert",
                    {
                        "level": "warning",
                        "message": f"{challenge.title}：检测到 flag 但入队失败：{exc}",
                    },
                    challenge_id=challenge_id,
                )
                continue
            queued += 1
        return queued

    async def _announce(self, challenge: Challenge, flag: str, sha256: str) -> None:
        if challenge.db_id is None:
            return
        await self.bus.emit(
            "flag.detected",
            {
                "flag_masked": mask_flag(flag),
                "sha256": sha256,
                "path": f"{challenge.workspace}/flag.txt",
                "source": "watcher",
            },
            challenge_id=challenge.db_id,
        )
