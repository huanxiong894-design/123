"""每题 Agent 的生命周期编排。

- 发现新题自动启动（可配 auto_start / stagger），也可由看板手动重开；
- 状态机：DISCOVERED/STOPPED/... → PREPARING → READY → SOLVING；
- pause = interrupt 并保留 session；resume = ``--resume`` 原会话；fresh = 新会话；
- Agent 正常退出且 flag.txt 合法 → SOLVED（真正的提交在 M4）；
- 平台显示已解 → 立即停 Agent，不再重启。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from ycb.adapters.base import PlatformAdapter
from ycb.agents.base import AgentBackend, AgentError, EmitFn
from ycb.agents.cli_backend import ClaudeCLIBackend
from ycb.agents.normalize import mask_flag
from ycb.agents.prompt import ensure_agent_files
from ycb.agents.spec import AgentSpec
from ycb.config import Config
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import Challenge, Status, now_iso
from ycb.submission.validator import read_flag_candidate
from ycb.workspace.layout import prepare_challenge_dir, write_target_info

log = logging.getLogger(__name__)

BackendFactory = Callable[[AgentSpec, Config, EmitFn, int], AgentBackend]

_STOPPED_LIKE = {Status.STOPPED, Status.PAUSED}

_LOCAL_FIRST_NOTICE = (
    "当前比赛容器配额已满（每队最多 3 台）。请先只使用本地附件做静态分析、"
    "本地复现和 exploit 脚本编写，不要假设远程靶机已可用。"
    "靶机就绪后系统会通过新消息通知你，地址也会写入 target.txt 和 description.md；"
    "收到通知后再做远程验证。"
)


async def _target_alive(target: Any, timeout: float = 4.0, attempts: int = 2) -> bool:
    host = getattr(target, "host", None)
    port = getattr(target, "port", None)
    if not host or not port:
        return False
    for attempt in range(attempts):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return True
        except Exception:
            if attempt + 1 < attempts:
                await asyncio.sleep(1.0)
    return False


@dataclass
class ActiveAgent:
    challenge_id: int
    run_id: int
    backend: AgentBackend
    session_id: str
    task: asyncio.Task | None = None
    stop_reason: str | None = None
    started_monotonic: float = field(default_factory=time.monotonic)


class ChallengeManager:
    def __init__(
        self,
        config: Config,
        db: Database,
        bus: EventBus,
        adapter: PlatformAdapter,
        *,
        backend_factory: BackendFactory | None = None,
    ) -> None:
        self.config = config
        self.db = db
        self.bus = bus
        self.adapter = adapter
        self._factory = backend_factory or self._default_factory
        self._active: dict[int, ActiveAgent] = {}
        self._locks: dict[int, asyncio.Lock] = {}
        self._background: set[asyncio.Task] = set()
        self._closing = False
        # 容器创建串行化：避免多题同时通过“有空位”检查后一起 build 撑爆配额。
        self._container_alloc_lock = asyncio.Lock()
        self._container_pump_lock = asyncio.Lock()

    # ------------------------------------------------------------------ lifecycle
    async def reconcile_startup(self) -> None:
        """上次异常退出遗留：活跃 run 标 INTERRUPTED，半途状态回 STOPPED。"""
        for run in await self.db.active_runs():
            await self.db.update_run(
                int(run["id"]), status="INTERRUPTED", ended_at=now_iso()
            )
        for challenge in await self.db.list_challenges():
            if challenge.db_id is None:
                continue
            if challenge.status in {Status.PREPARING, Status.READY, Status.SOLVING}:
                await self.db.force_status(challenge.db_id, Status.STOPPED)
                log.info("启动对账：题目 %s 从 %s 置为 STOPPED", challenge.uid, challenge.status.value)

    async def close(self) -> None:
        self._closing = True
        for task in list(self._background):
            task.cancel()
        await asyncio.gather(*list(self._background), return_exceptions=True)
        self._background.clear()
        actives = list(self._active.values())
        for active in actives:
            active.stop_reason = "shutdown"
        await asyncio.gather(
            *(self._stop_active(active, reason="shutdown") for active in actives),
            return_exceptions=True,
        )
        self._active.clear()

    def _default_factory(
        self, spec: AgentSpec, config: Config, emit: EmitFn, run_id: int
    ) -> AgentBackend:
        return ClaudeCLIBackend(spec, config, emit, run_id=run_id)

    def _lock(self, challenge_id: int) -> asyncio.Lock:
        lock = self._locks.get(challenge_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[challenge_id] = lock
        return lock

    @property
    def running_count(self) -> int:
        return sum(1 for active in self._active.values() if active.backend.alive)

    def is_running(self, challenge_id: int) -> bool:
        active = self._active.get(challenge_id)
        return bool(active and active.backend.alive)

    # ------------------------------------------------------------------ events
    async def _emit(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        challenge_id: int | None = None,
        run_id: int | None = None,
    ) -> None:
        await self.bus.emit(
            event_type, payload, challenge_id=challenge_id, run_id=run_id
        )

    async def _emit_status(self, challenge: Challenge, previous: Status, current: Status) -> None:
        if challenge.db_id is None:
            return
        await self._emit(
            "status.changed",
            {
                "previous": previous.value,
                "status": current.value,
                "challenge": challenge.to_dict(),
            },
            challenge_id=challenge.db_id,
        )

    async def _transition(self, challenge_id: int, target: Status, *, force: bool = False) -> bool:
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None or challenge.db_id is None:
            return False
        if challenge.status == target:
            return True
        ok = await self.db.cas_status(challenge_id, challenge.status, target, force=force)
        if not ok:
            return False
        fresh = await self.db.get_challenge(challenge_id)
        if fresh is not None:
            await self._emit_status(fresh, challenge.status, target)
        return True

    # ------------------------------------------------------------------ containers
    async def _container_slots_used(self) -> int:
        challenges = await self.db.list_challenges()
        return sum(
            1
            for challenge in challenges
            if challenge.container_available and challenge.target is not None
        )

    async def release_container(
        self,
        challenge_id: int,
        force: bool = False,
        *,
        exclude: set[int] | None = None,
    ) -> None:
        """销毁该题平台实例并释放配额；成功后自动启动下一道等待中的容器题。

        force=True 时即使本地没有靶机地址也调用平台销毁接口（用于清理残留实例）。
        """
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None or not challenge.container_available:
            return
        if challenge.target is None and not force:
            await self._pump_container_queue(exclude=exclude)
            return
        ok = await self.adapter.expire_target(challenge)
        if not ok:
            await self._emit(
                "alert",
                {
                    "level": "warning",
                    "message": f"{challenge.title}：释放容器失败，配额仍被占用",
                },
                challenge_id=challenge_id,
            )
            return
        await self.db.set_target(challenge_id, None)
        challenge.target = None
        await self._emit(
            "container.released", {"message": "已释放靶机，等待容器题可自动启动"},
            challenge_id=challenge_id,
        )
        await self._pump_container_queue(exclude=exclude)

    async def _pump_container_queue(self, *, exclude: set[int] | None = None) -> None:
        if self._closing:
            return
        async with self._container_pump_lock:
            if self._closing:
                return
            max_containers = self.config.platform.max_containers
            used = await self._container_slots_used()
            free = max_containers - used
            if free <= 0:
                return
            excluded = exclude or set()
            challenges = await self.db.list_challenges()
            waiting = [
                challenge
                for challenge in challenges
                if challenge.container_available
                and challenge.target is None
                and challenge.db_id is not None
                and challenge.db_id not in excluded
                and (
                    challenge.status == Status.SOLVING
                    or challenge.status
                    in {Status.DISCOVERED, Status.STOPPED, Status.FAILED, Status.NEEDS_HUMAN}
                )
            ]
            waiting.sort(key=lambda item: (item.seq_no or 10_000, item.db_id or 0))
            for challenge in waiting[:free]:
                if challenge.status == Status.SOLVING:
                    log.info("容器配额有空位，为本地分析中的题目分配靶机 %s", challenge.db_id)
                    task = asyncio.create_task(
                        self._attach_container_task(challenge.db_id),
                        name=f"container-attach-{challenge.db_id}",
                    )
                else:
                    log.info("容器配额有空位，自动启动等待题目 %s", challenge.db_id)
                    task = asyncio.create_task(
                        self._auto_start_task(challenge.db_id),
                        name=f"container-queue-{challenge.db_id}",
                    )
                self._background.add(task)
                task.add_done_callback(self._background.discard)

    async def _attach_container_task(self, challenge_id: int) -> None:
        try:
            await self._attach_container(challenge_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - 后台任务兜底
            log.exception("分配靶机异常 challenge=%s", challenge_id)

    async def _attach_container(self, challenge_id: int) -> None:
        """给已在本地分析的 Agent 补上靶机地址，并通知它继续远程验证。"""
        target = None
        async with self._lock(challenge_id):
            challenge = await self.db.get_challenge(challenge_id)
            if (
                challenge is None
                or not challenge.container_available
                or challenge.target is not None
                or challenge.status != Status.SOLVING
            ):
                return
            async with self._container_alloc_lock:
                used = await self._container_slots_used()
                if used >= self.config.platform.max_containers:
                    return
                try:
                    target = await self.adapter.ensure_target(challenge)
                except Exception as exc:
                    log.warning("补分配靶机失败 challenge=%s: %s", challenge_id, exc)
                    await self._emit(
                        "alert",
                        {"level": "warning", "message": f"靶机启动失败：{exc}"},
                        challenge_id=challenge_id,
                    )
                    return
                if target is None:
                    return
                await self.db.set_target(challenge_id, target)
                challenge.target = target
            if challenge.workspace:
                write_target_info(Path(challenge.workspace), target)
            await self._emit(
                "container.ready",
                {"target": target.to_dict()},
                challenge_id=challenge_id,
            )
        await self.send_operator_message(
            challenge_id,
            f"靶机已就绪：{target.address()}。地址已写入 target.txt 和 description.md，"
            "现在可以做远程验证/利用；此前请继续本地分析。",
        )

    # ------------------------------------------------------------------ start
    async def start(
        self,
        challenge_id: int,
        *,
        resume: bool = False,
        fresh: bool = False,
        message: str | None = None,
        stagger: bool = False,
    ) -> dict[str, Any]:
        async with self._lock(challenge_id):
            if self._closing:
                raise AgentError("系统正在关闭")
            active = self._active.get(challenge_id)
            if active is not None and active.backend.alive:
                delivered = False
                if message:
                    delivered = await active.backend.send(message)
                return {
                    "started": False,
                    "running": True,
                    "delivered": delivered,
                    "run_id": active.run_id,
                    "message": "Agent 已在运行，消息已投递" if delivered else "Agent 已在运行",
                }

            challenge = await self.db.get_challenge(challenge_id)
            if challenge is None:
                raise AgentError("题目不存在")
            if challenge.status in {Status.SUBMITTED, Status.SUBMITTING}:
                raise AgentError("题目已提交，不能启动 Agent")
            if challenge.workspace is None:
                raise AgentError("题目工作区尚未创建")

            if stagger:
                if (
                    self.config.agent.max_agents > 0
                    and self.running_count >= self.config.agent.max_agents
                ):
                    raise AgentError("已达到 agent.max_agents 并发上限")
                low = max(0.0, self.config.agent.stagger_min_seconds)
                high = max(low, self.config.agent.stagger_max_seconds)
                if high > 0:
                    await asyncio.sleep(random.uniform(low, high))

            stored_session = await self._last_session_id(challenge_id)
            resume_run = bool(resume and stored_session and not fresh)
            if not await self._enter_preparing(challenge_id):
                current = await self.db.get_challenge(challenge_id)
                raise AgentError(
                    f"当前状态 {current.status.value if current else '?'} 不能启动 Agent"
                )

            challenge = await self.db.get_challenge(challenge_id)
            if challenge is None:
                raise AgentError("题目不存在")
            try:
                spec = await self._prepare_spec(challenge, resume_run=resume_run)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception("准备 Agent 失败 challenge=%s", challenge_id)
                await self._transition(challenge_id, Status.FAILED, force=True)
                await self._emit(
                    "agent.error",
                    {"message": f"准备 Agent 失败：{exc}"},
                    challenge_id=challenge_id,
                )
                raise AgentError(f"准备 Agent 失败：{exc}") from exc
            if not await self._transition(challenge_id, Status.READY):
                current = await self.db.get_challenge(challenge_id)
                raise AgentError(
                    f"无法进入 READY（当前 {current.status.value if current else '?'}）"
                )
            if not await self._transition(challenge_id, Status.SOLVING):
                current = await self.db.get_challenge(challenge_id)
                raise AgentError(
                    f"无法进入 SOLVING（当前 {current.status.value if current else '?'}）"
                )

            run_id = await self.db.create_run(
                challenge_id,
                backend=self.config.agent.backend,
                session_id=spec.session_id,
                resume_of=None,
            )

            async def emit_for_run(event_type: str, payload: dict[str, Any]) -> None:
                await self._emit(
                    event_type, payload, challenge_id=challenge_id, run_id=run_id
                )

            backend = self._factory(spec, self.config, emit_for_run, run_id)
            active = ActiveAgent(
                challenge_id=challenge_id,
                run_id=run_id,
                backend=backend,
                session_id=backend.session_id,
            )
            self._active[challenge_id] = active
            try:
                await backend.start()
            except Exception as exc:
                self._active.pop(challenge_id, None)
                await self.db.update_run(
                    run_id, status="FAILED", ended_at=now_iso(), meta_json=str(exc)[:1000]
                )
                await self._transition(challenge_id, Status.FAILED)
                await self._emit(
                    "agent.error",
                    {"message": f"Agent 启动失败：{exc}"},
                    challenge_id=challenge_id,
                    run_id=run_id,
                )
                raise AgentError(f"Agent 启动失败：{exc}") from exc

            await self.db.update_run(
                run_id,
                status="RUNNING",
                pid=backend.pid,
                pgid=backend.pgid,
                raw_path=backend.raw_path,
                session_id=backend.session_id,
            )
            active.session_id = backend.session_id
            active.task = asyncio.create_task(
                self._supervise(active), name=f"agent-supervise-{challenge_id}"
            )
            await self._emit(
                "run.started",
                {
                    "backend": self.config.agent.backend,
                    "session_id": backend.session_id,
                    "pid": backend.pid,
                    "resume": spec.resume,
                    "cwd": str(spec.workspace),
                    "raw_path": backend.raw_path,
                },
                challenge_id=challenge_id,
                run_id=run_id,
            )
            text = message or (
                spec.resume_message()
                if spec.resume
                else spec.fresh_message()
                if fresh
                else spec.initial_message()
            )
            waiting_container = bool(challenge.container_available and spec.target is None)
            if waiting_container:
                text = f"{text}\n\n---\n{_LOCAL_FIRST_NOTICE}"
            delivered = await backend.send(text)
            if not delivered:
                await self._emit(
                    "agent.error",
                    {"message": "初始消息写入 Agent stdin 失败"},
                    challenge_id=challenge_id,
                    run_id=run_id,
                )
            log.info(
                "题目 %s 启动 Agent run=%s pid=%s resume=%s",
                challenge_id,
                run_id,
                backend.pid,
                spec.resume,
            )
            return {
                "started": True,
                "running": True,
                "delivered": delivered,
                "run_id": run_id,
                "session_id": backend.session_id,
                "resume": spec.resume,
                "queued": waiting_container,
                "message": (
                    "Agent 已启动（先本地分析，等待容器）"
                    if waiting_container
                    else "Agent 已启动"
                ),
            }

    async def auto_start(self, challenge_id: int) -> None:
        """发现钩子：立即返回，后台错峰启动，避免拖慢发现循环。"""
        if not self.config.agent.auto_start or self._closing:
            return
        task = asyncio.create_task(
            self._auto_start_task(challenge_id), name=f"agent-autostart-{challenge_id}"
        )
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _auto_start_task(self, challenge_id: int) -> None:
        try:
            await self.start(challenge_id, stagger=True)
        except asyncio.CancelledError:
            raise
        except AgentError as exc:
            log.warning("自动启动 Agent 失败 challenge=%s: %s", challenge_id, exc)
            await self._emit(
                "alert",
                {"level": "warning", "message": f"自动启动 Agent 失败：{exc}"},
                challenge_id=challenge_id,
            )
        except Exception:  # pragma: no cover - 后台任务兜底
            log.exception("自动启动 Agent 异常 challenge=%s", challenge_id)

    async def _enter_preparing(self, challenge_id: int) -> bool:
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None:
            return False
        status = challenge.status
        if status in {Status.DISCOVERED, Status.STOPPED, Status.FAILED, Status.NEEDS_HUMAN}:
            return await self._transition(challenge_id, Status.PREPARING)
        if status == Status.PREPARING:
            return True
        if status in {Status.PAUSED, Status.READY}:
            # PAUSED 不能直接 PREPARING：先 READY，准备动作仍会执行
            return await self._transition(challenge_id, Status.READY)
        if status == Status.SOLVED:
            # flag 被平台拒绝后继续解题：从 SOLVED 退回准备流程
            return await self._transition(challenge_id, Status.PREPARING)
        if status == Status.SOLVING:
            # 进程已不在（对账前的兜底）：强制回到 STOPPED 再准备
            await self.db.force_status(challenge_id, Status.STOPPED)
            return await self._transition(challenge_id, Status.PREPARING)
        return False

    async def _prepare_spec(self, challenge: Challenge, *, resume_run: bool) -> AgentSpec:
        assert challenge.db_id is not None
        workspace = Path(challenge.workspace) if challenge.workspace else prepare_challenge_dir(
            self.config.challenges_dir,
            challenge,
            seq_no=challenge.seq_no or 1,
            flag_regex=self.config.submission.flag_regex,
        )
        if not challenge.workspace:
            await self.db.set_workspace(challenge.db_id, str(workspace))

        if (
            challenge.container_available
            and challenge.target is not None
            and not await _target_alive(challenge.target)
        ):
            log.info(
                "已存靶机地址不可达，重新获取 challenge=%s target=%s",
                challenge.db_id,
                challenge.target.address(),
            )
            challenge.target = None

        if challenge.container_available and challenge.target is None:
            # 容器获取串行化；拿不到容器不阻塞 Agent：先本地分析，配额释放后再 attach。
            async with self._container_alloc_lock:
                used = await self._container_slots_used()
                max_containers = self.config.platform.max_containers
                if used >= max_containers:
                    log.info(
                        "容器配额已满（%s/%s），先本地分析 challenge=%s",
                        used,
                        max_containers,
                        challenge.db_id,
                    )
                    await self._emit(
                        "alert",
                        {
                            "level": "info",
                            "message": (
                                f"{challenge.title}：容器配额已满（{used}/{max_containers}），"
                                "先本地分析，释放后自动分配靶机"
                            ),
                        },
                        challenge_id=challenge.db_id,
                    )
                else:
                    try:
                        target = await self.adapter.ensure_target(challenge)
                    except Exception as exc:
                        log.warning("启动容器失败 challenge=%s: %s", challenge.db_id, exc)
                        await self._emit(
                            "alert",
                            {"level": "warning", "message": f"靶机启动失败，先本地分析：{exc}"},
                            challenge_id=challenge.db_id,
                        )
                        target = None
                    if target is None:
                        await self._emit(
                            "alert",
                            {
                                "level": "warning",
                                "message": "平台未返回可用靶机地址，先本地分析",
                            },
                            challenge_id=challenge.db_id,
                        )
                    else:
                        challenge.target = target
                        await self.db.set_target(challenge.db_id, target)
                        write_target_info(workspace, target)
                        await self._emit(
                            "container.ready",
                            {"target": target.to_dict()},
                            challenge_id=challenge.db_id,
                        )

        stored = await self._last_session_id(challenge.db_id) if resume_run else None
        spec = AgentSpec(
            challenge_id=challenge.db_id,
            uid=challenge.uid,
            title=challenge.title,
            category=challenge.category,
            score=challenge.score,
            workspace=workspace,
            description_md=challenge.description_md,
            attachments=challenge.attachments,
            target=challenge.target,
            flag_regex=challenge.flag_regex or self.config.submission.flag_regex,
            deadline=self.config.schedule.end.isoformat(),
            session_id=stored,
            resume=bool(stored),
            system_prompt=self.config.agent.append_system_prompt,
        )
        ensure_agent_files(spec)
        return spec

    async def _last_session_id(self, challenge_id: int) -> str | None:
        runs = await self.db.runs_for_challenge(challenge_id, limit=20)
        for run in reversed(runs):
            session = run.get("session_id")
            if session:
                return str(session)
        return None

    # ------------------------------------------------------------------ supervise
    async def _supervise(self, active: ActiveAgent) -> None:
        code: int | None = None
        try:
            code = await active.backend.wait()
        except asyncio.CancelledError:
            active.stop_reason = active.stop_reason or "shutdown"
            raise
        except Exception as exc:  # pragma: no cover
            log.exception("等待 Agent 退出失败")
            await self._emit(
                "agent.error",
                {"message": f"等待 Agent 退出失败：{exc}"},
                challenge_id=active.challenge_id,
                run_id=active.run_id,
            )
        finally:
            with contextlib.suppress(Exception):
                await active.backend.close()
            if self._active.get(active.challenge_id) is active:
                self._active.pop(active.challenge_id, None)
            await self._finish_run(active, code)

    async def _finish_run(self, active: ActiveAgent, code: int | None) -> None:
        challenge_id = active.challenge_id
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None:
            return
        reason = active.stop_reason
        if reason is None and challenge.status in {Status.SUBMITTING, Status.SUBMITTED}:
            # 提交队列已接管状态，Agent 自然退出不能再把 SUBMITTING 改回 SOLVED
            reason = "submission"
        target: Status | None = None
        run_status = "FINISHED"
        if reason == "pause":
            target = Status.PAUSED
            run_status = "PAUSED"
        elif reason in {"stop", "restart"}:
            target = Status.STOPPED
            run_status = "STOPPED"
        elif reason in {"shutdown", "platform_solved", "submission"}:
            target = None
            run_status = "INTERRUPTED" if reason == "shutdown" else "STOPPED"
        else:
            candidate = read_flag_candidate(
                challenge.workspace or "", challenge.flag_regex or self.config.submission.flag_regex
            )
            if candidate is not None:
                target = Status.SOLVED
                run_status = "FINISHED"
                await self._emit(
                    "flag.detected",
                    {
                        "flag_masked": mask_flag(candidate.flag),
                        "sha256": candidate.sha256,
                        "path": str(candidate.path),
                    },
                    challenge_id=challenge_id,
                    run_id=active.run_id,
                )
            elif code == 0:
                target = Status.NEEDS_HUMAN
                run_status = "FINISHED"
                await self._emit(
                    "alert",
                    {
                        "level": "warning",
                        "message": f"{challenge.title}：Agent 正常结束，但 flag.txt 缺失或格式不合法",
                    },
                    challenge_id=challenge_id,
                    run_id=active.run_id,
                )
            else:
                target = Status.FAILED
                run_status = "FAILED"

        if target is not None and not await self._transition(challenge_id, target):
            current = await self.db.get_challenge(challenge_id)
            if (
                current is not None
                and current.status != target
                and current.status not in {Status.SUBMITTED, Status.SUBMITTING}
            ):
                log.warning(
                    "Agent 结束后状态迁移失败 challenge=%s %s -> %s",
                    challenge_id,
                    current.status.value,
                    target.value,
                )
                await self._transition(challenge_id, target, force=True)
        await self.db.update_run(
            active.run_id,
            status=run_status,
            ended_at=now_iso(),
        )
        await self._emit(
            "run.exited",
            {
                "status": run_status,
                "code": code,
                "reason": reason,
                "duration_seconds": round(
                    max(0.0, time.monotonic() - active.started_monotonic), 1
                ),
            },
            challenge_id=challenge_id,
            run_id=active.run_id,
        )
        if reason in {"stop", "submission", "platform_solved"} or target in {
            Status.SOLVED,
            Status.FAILED,
            Status.NEEDS_HUMAN,
        }:
            await self.release_container(challenge_id, exclude={challenge_id})

    # ------------------------------------------------------------------ operator actions
    async def send_operator_message(self, challenge_id: int, content: str) -> dict[str, Any]:
        challenge = await self.db.get_challenge(challenge_id)
        if challenge is None:
            raise AgentError("题目不存在")
        active = self._active.get(challenge_id)
        run_id = active.run_id if active is not None else None
        message_id = await self.db.add_message(
            challenge_id,
            direction="operator",
            content=content,
            delivered=False,
            run_id=run_id,
        )
        delivered = False
        reason: str | None = None
        if challenge.status in {Status.SUBMITTED, Status.SUBMITTING}:
            reason = "题目已提交，不再投递"
        elif active is not None and active.backend.alive:
            delivered = await active.backend.send(content)
            reason = None if delivered else "写入 Agent stdin 失败"
        else:
            resume = await self._last_session_id(challenge_id) is not None
            try:
                result = await self.start(
                    challenge_id, resume=resume, message=content
                )
                delivered = bool(result.get("delivered"))
                run_id = result.get("run_id", run_id)
                if not delivered:
                    reason = str(result.get("message") or "消息未送达")
            except AgentError as exc:
                reason = str(exc)
        if delivered:
            await self.db.mark_message_delivered(message_id)
        await self._emit(
            "operator.message",
            {
                "content": content,
                "message_id": message_id,
                "delivered": delivered,
                "reason": reason,
            },
            challenge_id=challenge_id,
            run_id=run_id,
        )
        return {
            "ok": True,
            "message_id": message_id,
            "delivered": delivered,
            "run_id": run_id,
            "message": reason or "消息已投递",
        }

    async def pause(self, challenge_id: int) -> dict[str, Any]:
        async with self._lock(challenge_id):
            active = self._active.get(challenge_id)
            if active is None or not active.backend.alive:
                challenge = await self.db.get_challenge(challenge_id)
                if challenge is None:
                    raise AgentError("题目不存在")
                if challenge.status == Status.SOLVING:
                    await self._transition(challenge_id, Status.PAUSED, force=True)
                    return {"ok": True, "message": "Agent 未运行，状态已置为 PAUSED"}
                raise AgentError("Agent 未在运行")
            active.stop_reason = "pause"
            await active.backend.interrupt()
            await self._await_supervisor(active)
            if not await self._transition(challenge_id, Status.PAUSED):
                await self._transition(challenge_id, Status.PAUSED, force=True)
            return {"ok": True, "message": "已暂停 Agent（保留会话，可 resume）"}

    async def stop(self, challenge_id: int) -> dict[str, Any]:
        async with self._lock(challenge_id):
            challenge = await self.db.get_challenge(challenge_id)
            if challenge is None:
                raise AgentError("题目不存在")
            if challenge.status in {Status.SUBMITTED, Status.SUBMITTING}:
                raise AgentError("题目已提交，不能停止/修改")
            active = self._active.get(challenge_id)
            if active is not None and active.backend.alive:
                await self._stop_active(active, reason="stop")
            else:
                await self._transition(challenge_id, Status.STOPPED, force=True)
            return {"ok": True, "message": "已停止 Agent（状态 STOPPED，可重开）"}

    async def restart(self, challenge_id: int, mode: str) -> dict[str, Any]:
        if mode not in {"resume", "fresh"}:
            raise AgentError("mode 必须是 resume 或 fresh")
        async with self._lock(challenge_id):
            active = self._active.get(challenge_id)
            if active is not None and active.backend.alive:
                await self._stop_active(active, reason="restart")
            challenge = await self.db.get_challenge(challenge_id)
            if challenge is not None and challenge.status == Status.SOLVING:
                await self._transition(challenge_id, Status.STOPPED, force=True)
        result = await self.start(
            challenge_id,
            resume=mode == "resume",
            fresh=mode == "fresh",
        )
        if not result.get("queued"):
            result["message"] = f"已按 {mode} 重开"
        return result

    async def stop_all(self) -> dict[str, Any]:
        actives = [active for active in self._active.values() if active.backend.alive]
        await asyncio.gather(
            *(self._stop_active(active, reason="stop") for active in actives),
            return_exceptions=True,
        )
        return {"ok": True, "count": len(actives), "message": f"已停止 {len(actives)} 个 Agent"}

    async def pause_all(self) -> dict[str, Any]:
        actives = [active for active in self._active.values() if active.backend.alive]
        results = await asyncio.gather(
            *(self.pause(active.challenge_id) for active in actives),
            return_exceptions=True,
        )
        count = sum(1 for item in results if not isinstance(item, Exception))
        return {"ok": True, "count": count, "message": f"已暂停 {count} 个 Agent"}

    async def resume_all(self) -> dict[str, Any]:
        challenges = await self.db.list_challenges()
        targets = [
            challenge
            for challenge in challenges
            if challenge.status in _STOPPED_LIKE and challenge.db_id is not None
        ]
        results = await asyncio.gather(
            *(self.start(challenge.db_id, resume=True) for challenge in targets if challenge.db_id),
            return_exceptions=True,
        )
        count = sum(1 for item in results if isinstance(item, dict) and item.get("started"))
        return {"ok": True, "count": count, "message": f"已恢复 {count} 个 Agent"}

    async def _stop_active(self, active: ActiveAgent, *, reason: str) -> None:
        active.stop_reason = reason
        await active.backend.stop()
        await self._await_supervisor(active)
        if self._active.get(active.challenge_id) is active:
            # 进程未能按时退出：清掉引用，避免卡住后续重开
            self._active.pop(active.challenge_id, None)

    async def _await_supervisor(self, active: ActiveAgent) -> None:
        if active.task is not None and not active.task.done():
            with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError, Exception):
                await asyncio.wait_for(asyncio.shield(active.task), timeout=10.0)

    async def stop_for_submission(self, challenge_id: int) -> None:
        """提交队列接管该题：停 Agent，但不改题目状态（由提交服务维护）。"""
        active = self._active.get(challenge_id)
        if active is None or not active.backend.alive:
            return
        await self._stop_active(active, reason="submission")

    # ------------------------------------------------------------------ platform hooks
    async def on_challenge_solved(self, challenge_id: int) -> None:
        """平台显示已解：后台停 Agent，不阻塞发现循环。"""
        active = self._active.get(challenge_id)
        if active is None or not active.backend.alive:
            return
        task = asyncio.create_task(
            self._stop_active(active, reason="platform_solved"),
            name=f"agent-platform-solved-{challenge_id}",
        )
        self._background.add(task)
        task.add_done_callback(self._background.discard)
