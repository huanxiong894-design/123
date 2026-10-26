"""日志：控制台 + 轮转文件，统一脱敏 flag/密码/Cookie/Token。"""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

_FLAG_RE = re.compile(r"(?i)\b(DASCTF|flag)\{[^}\r\n]{0,200}\}")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|authorization|cookie|set-cookie)"
    r"(\s*[=:]\s*)([^\s,;\"']+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}")

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s [%(threadName)s] %(message)s"


def redact(text: str) -> str:
    text = _FLAG_RE.sub(lambda m: f"{m.group(1)}{{***}}", text)
    text = _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)} ***", text)
    return text


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        return redact(super().format(record))


def setup_logging(log_dir: Path, level: str = "INFO", console: bool = True) -> None:
    """幂等配置根 logger。日志文件 10MB × 5 轮转。"""
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        log_dir.chmod(0o700)
    except OSError:  # pragma: no cover
        pass

    root = logging.getLogger()
    if getattr(root, "_ycb_configured", False):
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        return

    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    formatter = RedactingFormatter(_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

    file_handler = RotatingFileHandler(
        log_dir / "ycb.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        root.addHandler(stream)

    # 第三方库降噪
    for noisy in ("uvicorn.access", "httpx", "httpcore", "asyncio", "aiosqlite"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, root.level))

    root._ycb_configured = True  # type: ignore[attr-defined]
    logging.getLogger(__name__).info("日志初始化完成 dir=%s level=%s", log_dir, level)
