from __future__ import annotations

import os
from dataclasses import dataclass

from ycb.config import DEFAULT_FLAG_REGEX


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class MockSettings:
    host: str = "127.0.0.1"
    port: int = 8898
    username: str = "player"
    password: str = "mock-pass-2026"
    submit_limit: int = 50
    submit_interval_seconds: float = 1.0
    debug_captcha: bool = False
    session_ttl_seconds: int = 12 * 3600
    captcha_ttl_seconds: int = 300
    flag_regex: str = DEFAULT_FLAG_REGEX

    @classmethod
    def from_env(cls) -> "MockSettings":
        return cls(
            host=os.environ.get("MOCK_HOST", "127.0.0.1"),
            port=int(os.environ.get("MOCK_PORT", "8898")),
            username=os.environ.get("MOCK_USERNAME", "player"),
            password=os.environ.get("MOCK_PASSWORD", "mock-pass-2026"),
            submit_limit=int(os.environ.get("MOCK_SUBMIT_LIMIT", "50")),
            submit_interval_seconds=float(os.environ.get("MOCK_SUBMIT_INTERVAL", "1.0")),
            debug_captcha=_bool(os.environ.get("MOCK_DEBUG_CAPTCHA"), False),
        )
