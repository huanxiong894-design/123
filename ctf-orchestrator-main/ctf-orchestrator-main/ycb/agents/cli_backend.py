"""本机 claude CLI backend（stream-json 双向流）。

设计要点：
- 每题一个进程，cwd = 题目工作区；``start_new_session=True`` 便于按进程组停止；
- 不传 ``--model`` / ``--max-budget-usd`` / ``--max-turns``，沿用本机默认配置；
- stdin 写 stream-json 用户消息，stdout 逐行解析并归一化；
- interrupt 先走 control_request，3s 无响应再 SIGINT → SIGTERM → SIGKILL；
- 原始 stdout 每 run 一份 JSONL（0600，50MB 轮转），归一化事件落库并广播。
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from ycb.agents.base import AgentError, EmitFn
from ycb.agents.normalize import normalize_stream_event, redact_text, truncate
from ycb.agents.spec import AgentSpec
from ycb.config import Config
from ycb.models import now_iso

log = logging.getLogger(__name__)

_STREAM_LIMIT = 64 * 1024 * 1024
_WATCH_INTERVAL = 5.0
_GRACE_SECONDS = 5.0


class ClaudeCLIBackend:
    def __init__(
        self,
        spec: AgentSpec,
        config: Config,
        emit: EmitFn,
        *,
        run_id: int | None = None,
    ) -> None:
        self.spec = spec
        self.config = config
        self.emit = emit
        self.run_id = run_id
        self.session_id = spec.session_id or str(uuid.uuid4())
        self.pid: int | None = None
        self.pgid: int | None = None
        self.raw_path: str | None = None

        self._proc: asyncio.subprocess.Process | None = None
        self._stdout_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self._watch_task: asyncio.Task | None = None
        self._stall_task: asyncio.Task | None = None
        self._exit_future: asyncio.Future[int | None] | None = None
        self._pending_control: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._stderr_tail: deque[str] = deque(maxlen=40)
        self._raw = None
        self._raw_size = 0
        self._last_output = time.monotonic()
        self._stall_warned = False
        self._stopping = False
        self._returncode: int | None = None
        self._closed = False

    # ------------------------------------------------------------------ lifecycle
    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    def _command(self) -> list[str]:
        prompt = (self.spec.system_prompt or self.config.agent.append_system_prompt or "").strip()
        cmd = [
            self.config.agent.claude_bin,
            "-p",
            "--verbose",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--include-partial-messages",
            "--replay-user-messages",
            "--permission-mode",
            "bypassPermissions",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
        ]
        if prompt:
            cmd.extend(["--append-system-prompt", prompt])
        if self.spec.resume and self.spec.session_id:
            cmd.extend(["--resume", self.spec.session_id])
        else:
            cmd.extend(["--session-id", self.session_id])
        return cmd

    async def start(self) -> None:
        if self._proc is not None:
            raise AgentError("Agent 已启动")
        workspace = self.spec.workspace
        if not workspace.is_dir():
            raise AgentError(f"工作区不存在：{workspace}")
        self._open_raw()
        env = self.spec.build_env()
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._command(),
                cwd=str(workspace),
                env=env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                limit=_STREAM_LIMIT,
            )
        except FileNotFoundError as exc:
            self._close_raw()
            raise AgentError(f"找不到 Claude CLI：{self.config.agent.claude_bin}") from exc
        except Exception:
            self._close_raw()
            raise
        self.pid = self._proc.pid
        try:
            self.pgid = os.getpgid(self._proc.pid)
        except OSError:
            self.pgid = self._proc.pid
        self._exit_future = asyncio.get_running_loop().create_future()
        self._last_output = time.monotonic()
        self._stdout_task = asyncio.create_task(self._read_stdout(), name=f"agent-stdout-{self.run_id}")
        self._stderr_task = asyncio.create_task(self._read_stderr(), name=f"agent-stderr-{self.run_id}")
        self._watch_task = asyncio.create_task(self._watch_process(), name=f"agent-watch-{self.run_id}")
        self._stall_task = asyncio.create_task(self._watch_stall(), name=f"agent-stall-{self.run_id}")
        log.info(
            "Agent 已启动 run=%s pid=%d session=%s cwd=%s resume=%s",
            self.run_id,
            self.pid,
            self.session_id,
            workspace,
            self.spec.resume,
        )

    async def send(self, text: str) -> bool:
        if not self.alive or self._proc is None or self._proc.stdin is None:
            return False
        payload = {
            "type": "user",
            "message": {"role": "user", "content": [{"type": "text", "text": text}]},
        }
        try:
            self._proc.stdin.write(
                (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            )
            await self._proc.stdin.drain()
            return True
        except (BrokenPipeError, ConnectionResetError, RuntimeError):
            return False

    async def wait(self) -> int | None:
        if self._exit_future is None:
            return self._returncode
        return await self._exit_future

    async def interrupt(self, *, control_timeout: float = 3.0) -> bool:
        """先发 control_request；无响应/未退出则升级为信号。返回是否已退出。"""
        if not self.alive:
            return True
        self._stopping = True
        loop = asyncio.get_running_loop()
        request_id = f"int-{uuid.uuid4().hex[:10]}"
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending_control[request_id] = future
        wrote = await self._write_control(
            {"type": "control_request", "request_id": request_id, "request": {"subtype": "interrupt"}}
        )
        if wrote:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(future, timeout=max(0.1, control_timeout))
            self._pending_control.pop(request_id, None)
            if await self._wait_exit(timeout=_GRACE_SECONDS):
                return True
        await self._terminate_escalation()
        return not self.alive

    async def stop(self) -> None:
        if not self.alive:
            return
        await self.interrupt(control_timeout=1.0)
        if self.alive:
            await self._terminate_escalation()
        # 让 stdout 读完后端再关闭原始日志
        for task in (self._stdout_task, self._stderr_task, self._watch_task, self._stall_task):
            if task is not None and not task.done():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await asyncio.wait_for(task, timeout=3.0)

    async def close(self) -> None:
        if self._closed:
            return
        if self.alive:
            await self.stop()
        self._closed = True
        self._close_raw()

    # ------------------------------------------------------------------ process io
    async def _write_control(self, payload: dict[str, Any]) -> bool:
        if not self.alive or self._proc is None or self._proc.stdin is None:
            return False
        try:
            self._proc.stdin.write(
                (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            )
            await self._proc.stdin.drain()
            return True
        except (BrokenPipeError, ConnectionResetError, RuntimeError):
            return False

    async def _read_stdout(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stream = self._proc.stdout
        while True:
            try:
                raw = await stream.readline()
            except ValueError as exc:  # 单行超过 64MB，无法安全跳过，结束读取
                log.warning("Agent stdout 单行过大，停止读取：%s", exc)
                await self.emit("agent.error", {"message": "stdout 单行超过 64MB，已停止读取该流"})
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover
                log.warning("读取 Agent stdout 失败：%s", exc)
                return
            if not raw:
                return
            self._last_output = time.monotonic()
            self._stall_warned = False
            self._write_raw(raw)
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                log.debug("Agent 非 JSON 输出：%s", line[:200])
                continue
            if not isinstance(data, dict):
                continue
            if data.get("type") == "control_response":
                self._resolve_control(data)
                continue
            try:
                for event_type, payload in normalize_stream_event(data):
                    await self.emit(event_type, payload)
            except Exception:  # 单条事件异常不影响后续
                log.exception("Agent 事件归一化失败")

    async def _read_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        stream = self._proc.stderr
        while True:
            try:
                raw = await stream.readline()
            except asyncio.CancelledError:
                raise
            except Exception:
                return
            if not raw:
                return
            text = raw.decode("utf-8", errors="replace").rstrip()
            if text:
                self._stderr_tail.append(redact_text(text))
                log.debug("Agent stderr: %s", truncate(text, 500))

    async def _watch_process(self) -> None:
        assert self._proc is not None
        code = await self._proc.wait()
        self._returncode = code
        # 给 stdout 一个收尾窗口，避免最后一条 result 丢失
        if self._stdout_task is not None:
            with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError, Exception):
                await asyncio.wait_for(asyncio.shield(self._stdout_task), timeout=3.0)
        if code not in (0, None) and not self._stopping:
            tail = "\n".join(list(self._stderr_tail)[-8:])
            await self.emit(
                "agent.error",
                {"message": f"Claude CLI 退出码 {code}", "stderr": truncate(tail, 2000)},
            )
        signal_name = None
        if code is not None and code < 0:
            with contextlib.suppress(ValueError):
                signal_name = signal.Signals(-code).name
        await self.emit(
            "agent.exited",
            {
                "code": code,
                "signal": signal_name,
                "session_id": self.session_id,
                "duration_seconds": round(time.monotonic() - self._started_at(), 1),
                "at": now_iso(),
            },
        )
        if self._stall_task is not None:
            self._stall_task.cancel()
        if self._exit_future is not None and not self._exit_future.done():
            self._exit_future.set_result(code)

    def _started_at(self) -> float:
        return getattr(self, "_start_monotonic", time.monotonic())

    async def _watch_stall(self) -> None:
        warn = self.config.agent.stall_warn_seconds
        interrupt_after = self.config.agent.stall_interrupt_seconds
        while self.alive:
            await asyncio.sleep(_WATCH_INTERVAL)
            if not self.alive:
                return
            idle = time.monotonic() - self._last_output
            if warn > 0 and idle >= warn and not self._stall_warned:
                self._stall_warned = True
                await self.emit("agent.stalled", {"seconds": int(idle), "action": "warning"})
            if interrupt_after > 0 and idle >= interrupt_after:
                await self.emit("agent.stalled", {"seconds": int(idle), "action": "interrupting"})
                await self.interrupt(control_timeout=3.0)
                return

    def _resolve_control(self, data: dict[str, Any]) -> None:
        request_id = (
            data.get("request_id")
            or (data.get("response") or {}).get("request_id")
            or (data.get("response") or {}).get("requestId")
        )
        future = self._pending_control.pop(str(request_id), None)
        if future is None and len(self._pending_control) == 1:
            future = next(iter(self._pending_control.values()))
        if future is not None and not future.done():
            future.set_result(data)

    async def _terminate_escalation(self) -> None:
        for sig, wait_seconds in (
            (signal.SIGINT, _GRACE_SECONDS),
            (signal.SIGTERM, _GRACE_SECONDS),
            (signal.SIGKILL, 3.0),
        ):
            if not self.alive:
                return
            await self._signal_group(sig)
            if await self._wait_exit(timeout=wait_seconds):
                return

    async def _signal_group(self, sig: signal.Signals) -> None:
        if not self.alive or self._proc is None:
            return
        target = self.pgid or self.pid
        try:
            if target:
                os.killpg(target, sig)
            else:  # pragma: no cover
                self._proc.send_signal(sig)
        except ProcessLookupError:
            return
        except Exception as exc:  # pragma: no cover
            log.warning("发送信号 %s 失败：%s", sig.name, exc)

    async def _wait_exit(self, *, timeout: float) -> bool:
        if self._exit_future is None:
            return not self.alive
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(self._exit_future), timeout=timeout)
        return not self.alive

    # ------------------------------------------------------------------ raw log
    def _open_raw(self) -> None:
        runs_dir = self.config.runs_dir
        runs_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            runs_dir.chmod(0o700)
        name = f"run-{self.run_id if self.run_id is not None else 'manual'}.jsonl"
        path = runs_dir / name
        self._raw = open(path, "ab", buffering=0)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        self.raw_path = str(path)
        self._raw_size = path.stat().st_size if path.exists() else 0
        self._start_monotonic = time.monotonic()

    def _write_raw(self, raw: bytes) -> None:
        if self._raw is None:
            return
        limit = max(1, int(self.config.agent.raw_log_max_bytes))
        if self._raw_size + len(raw) > limit:
            self._rotate_raw()
        try:
            self._raw.write(raw if raw.endswith(b"\n") else raw + b"\n")
            self._raw_size += len(raw)
        except OSError as exc:  # pragma: no cover
            log.warning("写 Agent 原始日志失败：%s", exc)

    def _rotate_raw(self) -> None:
        if self._raw is None or not self.raw_path:
            return
        self._close_raw()
        path = Path(self.raw_path)
        with contextlib.suppress(OSError):
            os.replace(path, path.with_name(path.name + ".1"))
        self._raw = open(path, "ab", buffering=0)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        self._raw_size = 0

    def _close_raw(self) -> None:
        if self._raw is not None:
            with contextlib.suppress(OSError):
                self._raw.close()
            self._raw = None
