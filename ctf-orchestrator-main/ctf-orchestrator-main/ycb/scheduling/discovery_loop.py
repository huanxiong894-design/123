"""增量发现循环。

- 每 interval ± jitter 秒拉一次平台快照；
- 同一题连续 confirm_passes 轮指纹一致才建目录/入库（避免半渲染、动态分抖动）；
- 已存在题只更新平台侧字段，不动 status/workspace；
- 平台显示已解 -> 本地强制 SUBMITTED 并广播（M3 会同时停 Agent）。
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from ycb.adapters.base import PlatformAdapter, SessionExpired
from ycb.config import Config
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import Challenge, Status, now_iso
from ycb.workspace.layout import prepare_challenge_dir

log = logging.getLogger(__name__)

# 单题同步（含大附件下载）硬上限：任何一次卡住都不能让整个发现循环停摆。
_SYNC_TIMEOUT_SECONDS = 300.0


@dataclass
class DiscoveryStatus:
    state: str = "idle"  # idle | running | logging_in | error | disabled | stopped
    last_tick_at: str | None = None
    last_success_at: str | None = None
    last_error: str | None = None
    ticks: int = 0
    last_tick_new: int = 0
    last_tick_updated: int = 0
    last_tick_skipped: int = 0
    total_known: int = 0
    session: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DiscoveryLoop:
    def __init__(
        self,
        config: Config,
        db: Database,
        bus: EventBus,
        adapter: PlatformAdapter,
        *,
        on_new_challenge: Callable[[int], Awaitable[None]] | None = None,
        on_solved: Callable[[int], Awaitable[None]] | None = None,
    ):
        self.config = config
        self.db = db
        self.bus = bus
        self.adapter = adapter
        self.on_new_challenge = on_new_challenge
        self.on_solved = on_solved
        self.status = DiscoveryStatus(session=adapter.session.to_dict())
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._previous: dict[str, str] = {}
        self._streak: dict[str, int] = {}
        self._last_state_key: tuple[str, str] | None = None

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        if not self.config.discovery.enabled:
            self.status.state = "disabled"
            log.info("发现循环已禁用（discovery.enabled=false）")
            return
        self._task = asyncio.create_task(self._run(), name="discovery-loop")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        self.status.state = "stopped"

    async def _run(self) -> None:
        log.info(
            "发现循环启动 interval=%.1fs jitter=%.1fs confirm=%d",
            self.config.discovery.interval_seconds,
            self.config.discovery.jitter_seconds,
            self.config.discovery.confirm_passes,
        )
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # 单轮失败不终止循环
                self.status.state = "error"
                self.status.last_error = f"{type(exc).__name__}: {exc}"
                log.exception("发现轮次失败")
                await self._safe_alert("error", f"发现失败：{exc}")
            elapsed = time.monotonic() - started
            delay = max(
                0.5,
                self.config.discovery.interval_seconds
                + random.uniform(0, max(0.0, self.config.discovery.jitter_seconds))
                - elapsed,
            )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

    # ------------------------------------------------------------------ one tick
    async def tick(self) -> None:
        self.status.state = "running"
        self.status.last_tick_at = now_iso()
        started = time.monotonic()
        new_count = updated_count = skipped = 0

        try:
            await self._ensure_session()
            candidates = await asyncio.wait_for(
                self.adapter.discover(), timeout=_SYNC_TIMEOUT_SECONDS
            )
            details: list[Challenge] = []
            for challenge in candidates:
                try:
                    details.append(await self._fetch_with_relogin(challenge))
                except Exception as exc:
                    skipped += 1
                    log.warning("拉取详情失败 uid=%s: %s", challenge.uid, exc)
                    await self._safe_alert("warning", f"拉取题目详情失败：{challenge.title}（{exc}）")

            for challenge in details:
                try:
                    created = await asyncio.wait_for(
                        self._sync_challenge(challenge), timeout=_SYNC_TIMEOUT_SECONDS
                    )
                except asyncio.TimeoutError:
                    skipped += 1
                    log.error(
                        "同步题目超时 uid=%s title=%s（%.0fs），跳过并继续下一题",
                        challenge.uid,
                        challenge.title,
                        _SYNC_TIMEOUT_SECONDS,
                    )
                    await self._safe_alert(
                        "warning", f"同步题目超时：{challenge.title}（已跳过，下轮重试）"
                    )
                except Exception as exc:
                    skipped += 1
                    log.exception("同步题目失败 uid=%s", challenge.uid)
                    await self._safe_alert("error", f"同步题目失败：{challenge.title}（{exc}）")
                    continue
                if created == "new":
                    new_count += 1
                elif created == "updated":
                    updated_count += 1

            self.status.state = "running"
            self.status.last_error = None
            self.status.last_success_at = now_iso()
            self.status.ticks += 1
            self.status.last_tick_new = new_count
            self.status.last_tick_updated = updated_count
            self.status.last_tick_skipped = skipped
            self.status.total_known = await self.db.total_challenges()
            self.status.session = self.adapter.session.to_dict()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # 先把状态落到 error，finally 广播时看板才能看到失败原因
            self.status.state = "error"
            self.status.last_error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            await self.bus.emit(
                "discovery.tick",
                {
                    "new": new_count,
                    "updated": updated_count,
                    "skipped": skipped,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "status": self.status.to_dict(),
                },
                persist=False,
            )
            await self._emit_state_if_changed()

    async def _ensure_session(self) -> None:
        session = await self.adapter.health()
        if session.logged_in:
            self.status.session = session.to_dict()
            return
        self.status.state = "logging_in"
        self.status.session = session.to_dict()
        await self._emit_state_if_changed()
        log.info("平台未登录（%s），尝试登录", session.detail)
        await self.adapter.login()
        session = await self.adapter.health()
        self.status.session = session.to_dict()
        if not session.logged_in:
            raise RuntimeError(f"登录后健康检查仍失败：{session.detail}")

    async def _fetch_with_relogin(self, challenge: Challenge) -> Challenge:
        try:
            return await self.adapter.fetch_detail(challenge)
        except SessionExpired:
            log.info("详情请求会话过期，重新登录后重试 uid=%s", challenge.uid)
            await self.adapter.login()
            return await self.adapter.fetch_detail(challenge)

    async def _sync_challenge(self, challenge: Challenge) -> str:
        existing = await self.db.get_challenge_by_uid(challenge.uid)
        fingerprint = challenge.fingerprint()

        if existing is None:
            previous = self._previous.get(challenge.uid)
            streak = self._streak.get(challenge.uid, 0) + 1 if previous == fingerprint else 1
            self._streak[challenge.uid] = streak
            self._previous[challenge.uid] = fingerprint
            if streak < self.config.discovery.confirm_passes:
                log.debug(
                    "题目待确认 uid=%s streak=%d/%d",
                    challenge.uid,
                    streak,
                    self.config.discovery.confirm_passes,
                )
                return "pending"
            await self._create_challenge(challenge)
            self._streak.pop(challenge.uid, None)
            return "new"

        self._previous[challenge.uid] = fingerprint
        self._streak[challenge.uid] = 0
        challenge.db_id = existing.db_id
        challenge.seq_no = existing.seq_no
        challenge.status = existing.status
        challenge.workspace = existing.workspace
        challenge.discovered_at = existing.discovered_at

        changed = await self.db.update_challenge_from_platform(challenge)
        status_changed = False
        if challenge.solved_on_platform and existing.status not in {Status.SUBMITTED}:
            status_changed = await self.db.cas_status(
                existing.db_id, existing.status, Status.SUBMITTED, force=True, solved=True
            )
        if changed or status_changed:
            fresh = await self.db.get_challenge(existing.db_id)
            if fresh is not None:
                if status_changed:
                    await self.bus.emit(
                        "status.changed",
                        {
                            "previous": existing.status.value,
                            "status": fresh.status.value,
                            "challenge": fresh.to_dict(),
                        },
                        challenge_id=existing.db_id,
                    )
                if changed:
                    await self.bus.emit(
                        "challenge.updated",
                        {"challenge": fresh.to_dict()},
                        challenge_id=existing.db_id,
                    )
        if status_changed and existing.db_id is not None:
            await self._notify(self.on_solved, existing.db_id, "on_solved")
        return "updated" if (changed or status_changed) else "unchanged"

    async def _create_challenge(self, challenge: Challenge) -> None:
        seq_no = await self.db.allocate_seq_no(challenge.platform, challenge.competition_id)
        challenge.seq_no = seq_no
        workspace = prepare_challenge_dir(
            self.config.challenges_dir,
            challenge,
            seq_no=seq_no,
            flag_regex=self.config.submission.flag_regex,
        )
        saved: list[str] = []
        if challenge.attachments:
            try:
                saved = await self._download_attachments(challenge, workspace)
            except Exception as exc:
                log.warning("附件下载失败 uid=%s: %s", challenge.uid, exc)
                await self._safe_alert(
                    "warning", f"附件下载失败：{challenge.title}（{exc}）；已建目录，稍后可手动补齐"
                )
        challenge_id = await self.db.insert_challenge(
            challenge,
            seq_no=seq_no,
            workspace=str(workspace),
            flag_regex=self.config.submission.flag_regex,
        )
        fresh = await self.db.get_challenge(challenge_id)
        if fresh is None:  # pragma: no cover - 不应发生
            raise RuntimeError("题目入库后读取失败")
        await self.bus.emit(
            "challenge.discovered",
            {
                "challenge": fresh.to_dict(),
                "fingerprint": challenge.fingerprint(),
                "attachments_saved": saved,
            },
            challenge_id=challenge_id,
        )
        log.info(
            "发现新题 #%02d %s [%s] score=%s workspace=%s",
            seq_no,
            fresh.title,
            fresh.category,
            fresh.score,
            workspace,
        )
        await self._notify(self.on_new_challenge, challenge_id, "on_new_challenge")

    async def _notify(
        self,
        hook: Callable[[int], Awaitable[None]] | None,
        challenge_id: int,
        name: str,
    ) -> None:
        if hook is None:
            return
        try:
            await hook(challenge_id)
        except Exception:  # 钩子失败不能影响发现循环
            log.exception("发现钩子 %s 失败 challenge=%s", name, challenge_id)

    async def _download_attachments(self, challenge: Challenge, workspace: Path) -> list[str]:
        """下载附件到 attachments/；会话过期时重登一次。"""
        try:
            paths = await self.adapter.download(challenge, workspace / "attachments")
        except SessionExpired:
            await self.adapter.login()
            paths = await self.adapter.download(challenge, workspace / "attachments")
        log.info("附件已下载 uid=%s files=%s", challenge.uid, [p.name for p in paths])
        return [p.name for p in paths]

    # ------------------------------------------------------------------ helpers
    async def _safe_alert(self, level: str, message: str) -> None:
        try:
            await self.bus.emit("alert", {"level": level, "message": message})
        except Exception:  # pragma: no cover
            log.exception("告警事件发送失败")

    async def _emit_state_if_changed(self) -> None:
        session_state = str(self.status.session.get("state", "unknown"))
        key = (session_state, self.status.state)
        if key == self._last_state_key:
            return
        self._last_state_key = key
        await self.bus.emit(
            "platform.state",
            {"session": self.status.session, "discovery": self.status.to_dict()},
            persist=False,
        )

    def status_dict(self) -> dict[str, Any]:
        return self.status.to_dict()
