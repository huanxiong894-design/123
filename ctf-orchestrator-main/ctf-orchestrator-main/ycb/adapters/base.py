"""平台适配器协议与异常。

解题内核对平台的全部认知都收敛在这里；新增平台只需实现本协议并注册。
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from ycb.models import Challenge, SessionState, SubmitResult, Target


class PlatformError(RuntimeError):
    """平台操作失败（可重试/需降级）。"""


class SessionExpired(PlatformError):
    """跳转到登录页 / 401；由平台 actor 统一重新登录。"""


class LoginFailed(PlatformError):
    """账号、验证码或人工介入问题。"""


class NeedsHuman(PlatformError):
    """验证码/风控/页面结构变化需要人工处理。"""


class PlatformRateLimited(PlatformError):
    def __init__(self, message: str = "rate limited", retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


@runtime_checkable
class PlatformAdapter(Protocol):
    name: str
    capabilities: set[str]

    async def login(self) -> None: ...

    async def health(self) -> SessionState: ...

    async def discover(self) -> list[Challenge]: ...

    async def fetch_detail(self, challenge: Challenge) -> Challenge: ...

    async def download(self, challenge: Challenge, dest: Path) -> list[Path]: ...

    async def ensure_target(self, challenge: Challenge) -> Target | None: ...

    async def refresh_target(self, challenge: Challenge) -> Target | None: ...

    async def expire_target(self, challenge: Challenge) -> bool:
        """销毁/释放平台实例；平台无此概念时返回 False。"""
        return False

    async def submit(self, challenge: Challenge, flag: str) -> SubmitResult: ...

    async def is_solved(self, challenge: Challenge) -> bool: ...

    async def close(self) -> None: ...
