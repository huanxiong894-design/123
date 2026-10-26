"""提交队列：去重、额度、dry-run、三源判定与失败恢复。

设计要点：
- 单 worker 串行提交，遵守全局/单题最小间隔，避免触发平台风控；
- 真实提交先在 DB 原子占用额度（``dry_run=0`` 的行数），再入队；
- 同一 (challenge, flag_sha256) 只尝试一次（DB UNIQUE），重启后也不盲目重试；
- accepted / already_solved → SUBMITTED 并停 Agent；
- unknown → 只查询 is_solved，绝不再提交；仍不确定就转人工；
- rejected → 回到 SOLVED，把拒绝原因反馈给 Agent（连续 3 次告警、5 次转人工）；
- dry_run=true 时只落库 + 发事件，不请求平台。
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from ycb.adapters.base import (
    LoginFailed,
    NeedsHuman,
    PlatformAdapter,
    PlatformError,
    PlatformRateLimited,
    SessionExpired,
)
from ycb.agents.normalize import mask_flag
from ycb.config import Config
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import Challenge, Status, SubmitResult
from ycb.submission.validator import validate_flag_text

log = logging.getLogger(__name__)

# 会占用真实提交额度、且已不再变化的状态
_FINAL_LIVE = {"accepted", "already_solved", "rejected", "unknown"}
_ACCEPTED = {"accepted", "already_solved"}
_MAX_ATTEMPTS = 3
_SESSION_RELOGIN_ATTEMPTS = 1


class SubmissionError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 409):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class _Job:
    submission_id: int | None
    challenge_id: int
    flag: str
    sha256: str
    run_id: int | None = None
    manual: bool = False
    future: asyncio.Future | None = None
    attempts: int = 0


@dataclass
class SubmissionService:
    config: Config
    db: Database
    bus: EventBus
    adapter: PlatformAdapter
    manager: Any = None
    _queue: asyncio.Queue = field(default_factory=asyncio.Queue, init=False)
    _task: asyncio.Task | None = field(default=None, init=False)
    _current: _Job | None = field(default=None, init=False)
    _closing: bool = field(default=False, init=False)
    _last_global: float = field(default=0.0, init=False)
    _last_challenge: dict[int, float] = field(default_factory=dict, init=False)
    _background: set[asyncio.Task] = field(default_factory=set, init=False)

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        if self._task is not None:
            return
        self._closing = False
        self._task = asyncio.create_task(self._worker(), name="submission-worker")

    async def stop(self) -> None:
        self._closing = True
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        for task in list(self._background):
            task.cancel()
        if self._background:
            await asyncio.gather(*list(self._background), return_exceptions=True)
        self._background.clear()
        while not self._queue.empty():
            item = self._queue.get_nowait()
            self._queue.task_done()
            if item is not None:
                self._resolve(
                    item,
                    {
                        "ok": False,
                        "status": "unknown",
                        "message": "服务关闭，提交未执行",
                        "challenge_id": item.challenge_id,
                    },
                )

    async def recover_startup(self) -> None:
        """对账：上次进程留下的 pending 提交结果未知，不自动重试。"""
        for row in await self.db.pending_submissions():
            submission_id = int(row["id"])
            challenge_id = int(row["challenge_id"])
            await self.db.update_submission(
                submission_id,
                status="unknown",
                message="进程重启，无法确认是否送达平台；不会自动重试",
            )
            challenge = await self.db.get_challenge(challenge_id)
            if challenge is None:
                continue
            solved = await self._probe_solved(challenge)
            if solved is True:
                await self.db.update_submission(
                    submission_id, status="accepted", message="重启对账：平台显示已解出"
                )
                await self._mark_submitted(challenge_id)
                await self._emit(
                    "submit.result",
                    {
                        "submission_id": submission_id,
                        "status": "accepted",
                        "message": "重启对账：平台显示已解出",
                        "reconciled": True,
                    },
                    challenge_id=challenge_id,
                )
                continue
            await self._emit(
                "submit.result",
                {
                    "submission_id": submission_id,
                    "status": "unknown",
                    "message": "进程重启，提交结果未知；请人工确认",
                    "reconciled": True,
                },
                challenge_id=challenge_id,
            )
            if challenge.status in {Status.SUBMITTING, Status.SOLVED, Status.SOLVING}:
                await self._set_status(challenge_id, Status.NEEDS_HUMAN, force=True)
                await self._emit(
                    "alert",
                    {
                        "level": "warning",
                        "message": f"{challenge.title}：上次提交结果未知，已转人工确认（不会自动重试）",
                    },
                    challenge_id=challenge_id,
                )

    # ------------------------------------------------------------------ queue API
    async def enqueue(
        self,
        challenge_id: int,
        flag: str,
        *,
        run_id: int | None = None,
        manual: bool = False,
        wait: bool = False,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None:
            raise SubmissionError("题目不存在", status_code=404)
        flag_regex = challenge.flag_regex or self.config.submission.flag_regex
        clean = validate_flag_text(flag, flag_regex)
        if clean is None:
            raise SubmissionError("flag 格式不合法（正则不匹配或疑似占位符）", status_code=422)
        sha = hashlib.sha256(clean.encode("utf-8")).hexdigest()

        if challenge.status == Status.SUBMITTED:
            return {
                "ok": True,
                "queued": False,
                "status": "already_solved",
                "message": "题目已提交，不再重复提交",
                "challenge_id": challenge_id,
            }

        existing = await self.db.find_submission(challenge_id, sha)
        submission_id: int | None = None
        if existing is not None:
            status = str(existing.get("status") or "")
            if status == "dry_run" and not self.config.submission.dry_run:
                # 09:30 dry_run 已记录、10:00 关闭 dry_run：把旧记录升级成真实提交
                promoted = await self.db.promote_dry_run_submission(
                    int(existing["id"]), max_live=self.config.submission.max_auto_submits
                )
                if promoted == "quota":
                    return await self._quota_blocked(challenge)
                if promoted != "ok":
                    return self._existing_result(challenge, existing)
                submission_id = int(existing["id"])
            else:
                return self._existing_result(challenge, existing)

        if self.config.submission.dry_run:
            submission_id = await self.db.add_submission(
                challenge_id,
                flag=clean,
                flag_sha256=sha,
                status="dry_run",
                message="dry_run=true：仅记录，未提交平台",
                dry_run=True,
                run_id=run_id,
            )
            if submission_id is None:
                again = await self.db.find_submission(challenge_id, sha)
                if again is not None:
                    return self._existing_result(challenge, again)
            await self._emit(
                "submit.result",
                {
                    "submission_id": submission_id,
                    "status": "dry_run",
                    "message": "dry_run=true：仅记录，未提交平台",
                    "flag_masked": mask_flag(clean),
                    "sha256": sha,
                    "dry_run": True,
                },
                challenge_id=challenge_id,
                run_id=run_id,
            )
            return {
                "ok": True,
                "queued": False,
                "dry_run": True,
                "submission_id": submission_id,
                "status": "dry_run",
                "message": "dry_run=true：仅记录，未提交平台",
                "challenge_id": challenge_id,
            }

        if submission_id is None:
            submission_id, reason = await self.db.reserve_live_submission(
                challenge_id,
                flag=clean,
                flag_sha256=sha,
                max_live=self.config.submission.max_auto_submits,
                run_id=run_id,
            )
            if reason == "duplicate":
                again = await self.db.find_submission(challenge_id, sha)
                if again is not None:
                    return self._existing_result(challenge, again)
                return {
                    "ok": False,
                    "queued": False,
                    "status": "duplicate",
                    "message": "同一 flag 已提交过",
                    "challenge_id": challenge_id,
                }
            if reason == "quota":
                return await self._quota_blocked(challenge)

        assert submission_id is not None
        if not await self._mark_submitting(challenge_id):
            await self.db.update_submission(
                submission_id, status="unknown", message="无法进入 SUBMITTING，提交未执行"
            )
            return {
                "ok": False,
                "queued": False,
                "status": "unknown",
                "message": "题目状态已变化，提交未执行",
                "challenge_id": challenge_id,
            }

        job = _Job(
            submission_id=submission_id,
            challenge_id=challenge_id,
            flag=clean,
            sha256=sha,
            run_id=run_id,
            manual=manual,
        )
        if wait:
            job.future = asyncio.get_running_loop().create_future()
        await self._queue.put(job)
        await self._emit(
            "submit.queued",
            {
                "submission_id": submission_id,
                "flag_masked": mask_flag(clean),
                "sha256": sha,
                "manual": manual,
            },
            challenge_id=challenge_id,
            run_id=run_id,
        )
        # Agent 已产出可提交的 flag：停止它，避免继续消耗
        self._stop_agent_soon(challenge_id)
        if wait and job.future is not None:
            try:
                return await asyncio.wait_for(job.future, timeout=timeout)
            except asyncio.TimeoutError:
                return {
                    "ok": True,
                    "queued": True,
                    "status": "pending",
                    "message": "已入队，等待平台结果超时；结果会显示在看板",
                    "submission_id": submission_id,
                    "challenge_id": challenge_id,
                }
        return {
            "ok": True,
            "queued": True,
            "status": "pending",
            "message": "已加入提交队列",
            "submission_id": submission_id,
            "challenge_id": challenge_id,
        }

    async def submit_manual(self, challenge_id: int, flag: str, *, timeout: float = 120.0) -> dict[str, Any]:
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None:
            raise SubmissionError("题目不存在", status_code=404)
        if challenge.status == Status.SUBMITTED:
            raise SubmissionError("题目已提交，不能重复提交")
        self._closing = False
        if self._task is None:
            await self.start()
        return await self.enqueue(challenge_id, flag, manual=True, wait=True, timeout=timeout)

    # ------------------------------------------------------------------ worker
    async def _worker(self) -> None:
        while True:
            job = await self._queue.get()
            self._current = job
            try:
                result = await self._process(job)
            except asyncio.CancelledError:
                self._resolve(
                    job,
                    {
                        "ok": False,
                        "status": "unknown",
                        "message": "服务关闭，提交结果未知",
                        "submission_id": job.submission_id,
                        "challenge_id": job.challenge_id,
                    },
                )
                raise
            except Exception as exc:  # pragma: no cover - 兜底
                log.exception("提交流程异常 submission=%s", job.submission_id)
                result = {
                    "ok": False,
                    "status": "unknown",
                    "message": f"提交异常：{type(exc).__name__}: {exc}",
                    "submission_id": job.submission_id,
                    "challenge_id": job.challenge_id,
                }
                if job.submission_id is not None:
                    await self.db.update_submission(
                        job.submission_id, status="unknown", message=str(result["message"])[:500]
                    )
            finally:
                self._current = None
                self._queue.task_done()
            self._resolve(job, result)

    def _resolve(self, job: _Job, result: dict[str, Any]) -> None:
        if job.future is not None and not job.future.done():
            job.future.set_result(result)

    async def _process(self, job: _Job) -> dict[str, Any]:
        challenge = await self.db.get_challenge(job.challenge_id)
        if challenge is None:
            return {"ok": False, "status": "unknown", "message": "题目不存在", "challenge_id": job.challenge_id}
        await self._pace(job.challenge_id)
        if job.submission_id is not None:
            await self.db.update_submission(job.submission_id, status="submitting")

        result = SubmitResult("unknown", "未获得平台响应")
        for attempt in range(_MAX_ATTEMPTS):
            job.attempts = attempt + 1
            result = await self._call_submit(challenge, job.flag)
            if result.status == "rate_limited" and attempt < _MAX_ATTEMPTS - 1:
                delay = self._retry_delay(result, attempt)
                await self._emit(
                    "submit.retry",
                    {
                        "submission_id": job.submission_id,
                        "status": "rate_limited",
                        "message": result.message,
                        "retry_in_seconds": delay,
                        "attempt": job.attempts,
                    },
                    challenge_id=job.challenge_id,
                )
                await asyncio.sleep(delay)
                continue
            if result.status == "session_expired" and attempt < _SESSION_RELOGIN_ATTEMPTS:
                relogged = await self._relogin()
                if relogged:
                    continue
                result = SubmitResult("unknown", "会话过期且重新登录失败", result.evidence)
                break
            break

        return await self._finalize(challenge, job, result)

    async def _call_submit(self, challenge: Challenge, flag: str) -> SubmitResult:
        try:
            return await self.adapter.submit(challenge, flag)
        except SessionExpired as exc:
            return SubmitResult("session_expired", str(exc) or "会话过期")
        except PlatformRateLimited as exc:
            evidence = {"retry_after": exc.retry_after}
            return SubmitResult("rate_limited", str(exc) or "平台限流", evidence)
        except (NeedsHuman, LoginFailed) as exc:
            return SubmitResult("unknown", f"需要人工：{exc}")
        except PlatformError as exc:
            return SubmitResult("unknown", str(exc))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - adapter 兜底
            log.exception("adapter.submit 异常")
            return SubmitResult("unknown", f"{type(exc).__name__}: {exc}")

    async def _relogin(self) -> bool:
        try:
            await self.adapter.login()
            return True
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("提交时会话过期，重新登录失败：%s", exc)
            return False

    @staticmethod
    def _retry_delay(result: SubmitResult, attempt: int) -> float:
        raw = result.evidence.get("retry_after")
        try:
            if raw is not None:
                return max(1.0, min(float(raw), 60.0))
        except (TypeError, ValueError):
            pass
        return min(60.0, 5.0 * (2**attempt))

    # ------------------------------------------------------------------ outcome
    async def _finalize(self, challenge: Challenge, job: _Job, result: SubmitResult) -> dict[str, Any]:
        challenge_id = job.challenge_id
        status = result.status if result.status in _FINAL_LIVE else "unknown"
        message = result.message or ""
        evidence = dict(result.evidence or {})

        if status == "unknown":
            solved = await self._probe_solved(challenge)
            if solved is True:
                status = "accepted"
                message = "平台状态复查：已解出"
                evidence["checked_is_solved"] = True
            else:
                evidence["checked_is_solved"] = solved

        if job.submission_id is not None:
            await self.db.update_submission(
                job.submission_id, status=status, message=message[:1000], evidence=evidence
            )

        payload = {
            "submission_id": job.submission_id,
            "status": status,
            "message": message,
            "flag_masked": mask_flag(job.flag),
            "sha256": job.sha256,
            "attempts": job.attempts,
            "manual": job.manual,
        }
        if evidence:
            payload["evidence"] = evidence
        await self._emit(
            "submit.result",
            payload,
            challenge_id=challenge_id,
            run_id=job.run_id,
        )

        if status in _ACCEPTED:
            await self._mark_submitted(challenge_id)
            self._stop_agent_soon(challenge_id)
            return {
                "ok": True,
                "queued": False,
                "status": status,
                "message": message or "Flag 已通过",
                "submission_id": job.submission_id,
                "challenge_id": challenge_id,
            }

        if status == "rejected":
            await self._handle_rejected(challenge, message)
            return {
                "ok": False,
                "queued": False,
                "status": status,
                "message": message or "Flag 被拒绝",
                "submission_id": job.submission_id,
                "challenge_id": challenge_id,
            }

        # unknown：不再重试；能确认已解则已在上方处理，否则转人工
        if status == "unknown":
            await self._set_status(challenge_id, Status.NEEDS_HUMAN, force=True)
            await self._emit(
                "alert",
                {
                    "level": "error",
                    "message": f"{challenge.title}：提交结果无法确认，已转人工（不会自动重试）",
                },
                challenge_id=challenge_id,
            )
            self._stop_agent_soon(challenge_id)
        return {
            "ok": False,
            "queued": False,
            "status": status,
            "message": message or "提交结果未知",
            "submission_id": job.submission_id,
            "challenge_id": challenge_id,
        }

    async def _handle_rejected(self, challenge: Challenge, message: str) -> None:
        challenge_id = challenge.db_id
        if challenge_id is None:
            return
        await self._set_status(challenge_id, Status.SOLVED, force=True)
        rejections = await self.db.count_rejections(challenge_id)
        if rejections >= 5:
            await self._set_status(challenge_id, Status.NEEDS_HUMAN, force=True)
            await self._emit(
                "alert",
                {
                    "level": "error",
                    "message": f"{challenge.title}：已连续被拒 {rejections} 次，停止自动重试，请人工介入",
                },
                challenge_id=challenge_id,
            )
            return
        if rejections >= 3:
            await self._emit(
                "alert",
                {
                    "level": "warning",
                    "message": f"{challenge.title}：已被拒 {rejections} 次，请关注 Agent 方向",
                },
                challenge_id=challenge_id,
            )
        self._resume_agent_after_rejection(challenge_id, message)

    def _resume_agent_after_rejection(self, challenge_id: int, message: str) -> None:
        if self.manager is None:
            return
        feedback = (
            "平台拒绝了上一条 flag"
            + (f"（平台消息：{message[:200]}）" if message else "")
            + "。请检查思路，确认正确后覆盖 flag.txt；不要重复提交同一 flag。"
        )
        task = asyncio.create_task(
            self._safe_resume(challenge_id, feedback),
            name=f"submission-resume-{challenge_id}",
        )
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _safe_resume(self, challenge_id: int, message: str) -> None:
        try:
            await self.manager.start(challenge_id, resume=True, message=message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("flag 被拒后自动恢复 Agent 失败 challenge=%s: %s", challenge_id, exc)
            await self._emit(
                "alert",
                {"level": "warning", "message": f"flag 被拒后自动恢复 Agent 失败：{exc}"},
                challenge_id=challenge_id,
            )

    # ------------------------------------------------------------------ status/helpers
    async def _quota_blocked(self, challenge: Challenge) -> dict[str, Any]:
        message = (
            f"自动提交额度已用尽（{self.config.submission.max_auto_submits} 次，"
            f"平台硬上限 50），请人工处理"
        )
        await self._emit(
            "alert",
            {"level": "error", "message": f"{challenge.title}：{message}"},
            challenge_id=challenge.db_id,
        )
        if challenge.db_id is not None:
            await self._set_status(challenge.db_id, Status.NEEDS_HUMAN, force=True)
        return {
            "ok": False,
            "queued": False,
            "status": "quota",
            "message": message,
            "challenge_id": challenge.db_id,
        }

    async def _probe_solved(self, challenge: Challenge) -> bool | None:
        try:
            return bool(await self.adapter.is_solved(challenge))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("is_solved 复查失败 challenge=%s: %s", challenge.uid, exc)
            return None

    async def _mark_submitted(self, challenge_id: int) -> None:
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None:
            return
        if challenge.status == Status.SUBMITTED:
            return
        if challenge.status == Status.SUBMITTING:
            if await self._set_status(challenge_id, Status.SUBMITTED, solved=True):
                return
        await self._set_status(challenge_id, Status.SUBMITTED, force=True, solved=True)

    async def _mark_submitting(self, challenge_id: int) -> bool:
        for _ in range(4):
            challenge = await self.db.get_challenge(challenge_id)
            if challenge is None:
                return False
            if challenge.status == Status.SUBMITTING:
                return True
            if challenge.status == Status.SUBMITTED:
                return False
            if challenge.status == Status.SOLVED:
                if await self._set_status(challenge_id, Status.SUBMITTING):
                    return True
            elif challenge.status == Status.SOLVING:
                if await self._set_status(challenge_id, Status.SOLVED, solved=True) and await self._set_status(
                    challenge_id, Status.SUBMITTING
                ):
                    return True
            else:
                if await self._set_status(challenge_id, Status.SOLVED, force=True, solved=True) and await self._set_status(
                    challenge_id, Status.SUBMITTING
                ):
                    return True
        return False

    async def _set_status(
        self,
        challenge_id: int,
        target: Status,
        *,
        force: bool = False,
        solved: bool = False,
    ) -> bool:
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None:
            return False
        if challenge.status == target:
            return True
        if not await self.db.cas_status(
            challenge_id, challenge.status, target, force=force, solved=solved
        ):
            return False
        fresh = await self.db.get_challenge(challenge_id)
        if fresh is not None:
            await self._emit(
                "status.changed",
                {
                    "previous": challenge.status.value,
                    "status": target.value,
                    "challenge": fresh.to_dict(),
                },
                challenge_id=challenge_id,
            )
        return True

    async def _pace(self, challenge_id: int) -> None:
        loop = asyncio.get_running_loop()
        now = loop.time()
        wait = max(
            0.0,
            self._last_global + self.config.submission.min_interval_seconds - now,
            self._last_challenge.get(challenge_id, 0.0)
            + self.config.submission.per_challenge_interval_seconds
            - now,
        )
        if wait > 0:
            await asyncio.sleep(wait)
        stamp = loop.time()
        self._last_global = stamp
        self._last_challenge[challenge_id] = stamp

    def _stop_agent_soon(self, challenge_id: int) -> None:
        if self.manager is None:
            return
        task = asyncio.create_task(
            self._safe_stop_agent(challenge_id), name=f"submission-stop-{challenge_id}"
        )
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _safe_stop_agent(self, challenge_id: int) -> None:
        try:
            await self.manager.stop_for_submission(challenge_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - 停 Agent 失败不影响提交结果
            log.exception("停止 Agent 失败 challenge=%s", challenge_id)

    def _existing_result(self, challenge: Challenge, row: dict[str, Any]) -> dict[str, Any]:
        status = str(row.get("status") or "unknown")
        return {
            "ok": status in _ACCEPTED | {"dry_run", "pending", "submitting"},
            "queued": status in {"pending", "submitting"},
            "submission_id": row.get("id"),
            "status": status,
            "message": str(row.get("message") or "该 flag 已处理过"),
            "duplicate": True,
            "challenge_id": challenge.db_id,
            "dry_run": bool(row.get("dry_run")),
        }

    async def _emit(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        challenge_id: int | None = None,
        run_id: int | None = None,
    ) -> None:
        await self.bus.emit(event_type, payload, challenge_id=challenge_id, run_id=run_id)
