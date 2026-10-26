"""flag.txt 读取与最小校验（M3 用于判断 Agent 是否解出；M4 扩展提交策略）。

安全要求：普通文件、非软链、<64KB、恰好一行、匹配配置的 flag 正则、拒绝占位词。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

MAX_FLAG_BYTES = 64 * 1024
# 只拒绝“整段就是占位词”的情况；真实 flag 里经常含 flag/test 等字样，不能子串匹配
PLACEHOLDER_WORDS = {
    "example",
    "example_flag",
    "test",
    "test_flag",
    "todo",
    "placeholder",
    "your_flag",
    "yourflag",
    "changeme",
    "flag",
}


@dataclass(slots=True)
class FlagCandidate:
    flag: str
    sha256: str
    path: Path


def _looks_placeholder(flag: str) -> bool:
    body = flag
    if "{" in body and body.endswith("}"):
        body = body.split("{", 1)[1][:-1]
    lowered = body.strip().lower()
    if not lowered:
        return True
    if lowered in PLACEHOLDER_WORDS:
        return True
    if lowered.startswith(("xxxx", "example_", "test_", "your_flag", "changeme")):
        return True
    return set(lowered) <= {"x", "0", "_", "-"}


def validate_flag_text(flag: str, flag_regex: str) -> str | None:
    """校验外部输入（手动提交/建议答案）；不合法返回 None。"""
    value = str(flag or "").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 4096:
        return None
    try:
        if not re.fullmatch(flag_regex, value):
            return None
    except re.error:
        return None
    if _looks_placeholder(value):
        return None
    return value


def read_flag_candidate(workspace: str | Path, flag_regex: str) -> FlagCandidate | None:
    path = Path(workspace) / "flag.txt"
    try:
        stat = path.lstat()
    except OSError:
        return None
    if not path.is_file() or path.is_symlink():
        return None
    if stat.st_size <= 0 or stat.st_size > MAX_FLAG_BYTES:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    flag = validate_flag_text(lines[0], flag_regex)
    if flag is None:
        return None
    return FlagCandidate(
        flag=flag,
        sha256=hashlib.sha256(flag.encode("utf-8")).hexdigest(),
        path=path,
    )
