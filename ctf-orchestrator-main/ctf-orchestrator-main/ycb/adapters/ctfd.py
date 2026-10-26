"""通用 CTFd 适配器占位（Milestone 2 之后）。

CTFd 系平台（大量社区赛）共用 /api/v1/challenges、/api/v1/challenges/{id}、
/api/v1/challenges/attempt 等端点，通常无需浏览器；验证码/SSO 场景再回退到
browser_base。先在 registry 中保留名字与能力声明，换平台时补实现即可。
"""

from __future__ import annotations

from pathlib import Path

from ycb.adapters.base import LoginFailed
from ycb.config import Config
from ycb.models import Challenge, SessionState, SubmitResult, Target


class CTFDAdapter:
    name = "ctfd"
    capabilities = {"attachments", "submit_api", "dynamic_score"}

    def __init__(self, config: Config):
        self.config = config
        self._session = SessionState(state="unknown", detail="CTFd adapter 尚未实现")

    async def login(self) -> None:
        raise LoginFailed("CTFd 适配器尚未实现（预留位置）")

    async def health(self) -> SessionState:
        return self._session

    async def discover(self) -> list[Challenge]:
        raise NotImplementedError

    async def fetch_detail(self, challenge: Challenge) -> Challenge:
        raise NotImplementedError

    async def download(self, challenge: Challenge, dest: Path) -> list[Path]:
        raise NotImplementedError

    async def ensure_target(self, challenge: Challenge) -> Target | None:
        return None

    async def refresh_target(self, challenge: Challenge) -> Target | None:
        return None

    async def submit(self, challenge: Challenge, flag: str) -> SubmitResult:
        raise NotImplementedError

    async def is_solved(self, challenge: Challenge) -> bool:
        raise NotImplementedError

    async def close(self) -> None:
        return None
