"""Agent backend 协议；SDK backend 可在 P1 按同一接口接入。"""

from __future__ import annotations

from typing import Awaitable, Callable, Protocol, runtime_checkable

EmitFn = Callable[[str, dict], Awaitable[None]]


class AgentError(RuntimeError):
    """Agent 启动/输入/停止失败。"""


class AgentNotRunning(AgentError):
    """没有可用的运行中进程。"""


@runtime_checkable
class AgentBackend(Protocol):
    session_id: str
    pid: int | None
    pgid: int | None
    raw_path: str | None

    @property
    def alive(self) -> bool: ...

    async def start(self) -> None: ...

    async def send(self, text: str) -> bool: ...

    async def interrupt(self, *, control_timeout: float = 3.0) -> bool: ...

    async def stop(self) -> None: ...

    async def wait(self) -> int | None: ...

    async def close(self) -> None: ...
