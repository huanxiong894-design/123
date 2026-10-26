"""把 Claude CLI 的 stream-json 归一化为看板事件。

- 事件 payload 会持久化到 SQLite，默认 flag 打码、敏感键递归替换；
  `server.unmask_flags = true` 时 flag 保留明文（敏感键仍打码）；
- 完整原始流另存 var/runs/*.jsonl（0600），供事后排查；
- text.delta 只广播不落库（由 EventBus 的 .delta 规则处理）。
"""

from __future__ import annotations

import json
import re
from typing import Any

FLAG_PATTERNS = (
    re.compile(r"DASCTF\{[^{}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"flag\{[^{}\r\n]{1,200}\}", re.IGNORECASE),
)
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "jwt",
    "credential",
    "credentials",
}
TOOL_INPUT_LIMIT = 4000
TOOL_OUTPUT_LIMIT = 4000
TEXT_LIMIT = 8000
THINKING_LIMIT = 4000

_MASK_FLAGS = True


def set_flag_masking(enabled: bool) -> None:
    """关闭后事件/提交记录中的 flag 保留明文（敏感键仍打码）。"""
    global _MASK_FLAGS
    _MASK_FLAGS = bool(enabled)


def flag_masking_enabled() -> bool:
    return _MASK_FLAGS


def mask_flag(flag: str) -> str:
    flag = str(flag or "")
    if not _MASK_FLAGS:
        return flag
    if len(flag) <= 14:
        return flag[:4] + "***"
    return f"{flag[:9]}…{flag[-4:]}"


def redact_text(text: str) -> str:
    value = str(text or "")
    for pattern in FLAG_PATTERNS:
        value = pattern.sub(lambda match: mask_flag(match.group(0)), value)
    return value


def truncate(text: str, limit: int) -> str:
    value = str(text or "")
    if len(value) <= limit:
        return value
    return value[:limit] + f"…（截断 {len(value) - limit} 字）"


def redact_value(value: Any, *, depth: int = 0) -> Any:
    """递归打码：敏感键整体替换，字符串中的 flag 打码。"""
    if depth > 8:
        return "…"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                result[str(key)] = "***"
            else:
                result[str(key)] = redact_value(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_value(item, depth=depth + 1) for item in value[:200]]
    if isinstance(value, str):
        return redact_text(value)
    return value


def json_text(value: Any, limit: int) -> str:
    if isinstance(value, str):
        return truncate(redact_text(value), limit)
    try:
        blob = json.dumps(redact_value(value), ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = str(value)
    return truncate(redact_text(blob), limit)


def content_text(content: Any) -> str:
    """tool_result.content 可能是字符串、文本块数组或任意 JSON。"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                kind = item.get("type")
                if kind == "text":
                    parts.append(str(item.get("text", "")))
                elif kind == "image":
                    parts.append("[image]")
                elif "content" in item:
                    parts.append(content_text(item.get("content")))
                else:
                    parts.append(json.dumps(item, ensure_ascii=False, default=str))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part)
    if content is None:
        return ""
    return json.dumps(content, ensure_ascii=False, default=str)


def _assistant_events(message: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    content = message.get("content")
    if not isinstance(content, list):
        return events
    for block in content:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "text":
            text = str(block.get("text", ""))
            if text:
                events.append(("agent.text", {"text": truncate(redact_text(text), TEXT_LIMIT)}))
        elif kind == "thinking":
            thinking = str(block.get("thinking", "") or "")
            if thinking.strip():
                events.append(
                    ("agent.thinking", {"text": truncate(redact_text(thinking), THINKING_LIMIT)})
                )
        elif kind == "tool_use":
            events.append(
                (
                    "agent.tool_use",
                    {
                        "id": str(block.get("id", "")),
                        "name": str(block.get("name", "tool")),
                        "input": json_text(block.get("input"), TOOL_INPUT_LIMIT),
                    },
                )
            )
    return events


def _user_events(message: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    content = message.get("content")
    if not isinstance(content, list):
        return events
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        events.append(
            (
                "agent.tool_result",
                {
                    "tool_use_id": str(block.get("tool_use_id", "")),
                    "is_error": bool(block.get("is_error")),
                    "output": truncate(redact_text(content_text(block.get("content"))), TOOL_OUTPUT_LIMIT),
                },
            )
        )
    return events


def normalize_stream_event(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """返回 [(event_type, payload)]；未知结构忽略（原始流仍保留）。"""
    if not isinstance(data, dict):
        return []
    kind = data.get("type")
    if kind == "system":
        subtype = data.get("subtype")
        if subtype == "init":
            return [
                (
                    "agent.init",
                    {
                        "model": data.get("model"),
                        "session_id": data.get("session_id"),
                        "cwd": data.get("cwd"),
                        "permission_mode": data.get("permissionMode"),
                        "cli_version": data.get("claude_code_version"),
                        "tools": len(data.get("tools") or []),
                        "mcp_servers": len(data.get("mcp_servers") or []),
                    },
                )
            ]
        if subtype == "informational":
            return [
                (
                    "agent.notice",
                    {
                        "level": data.get("level", "info"),
                        "text": truncate(redact_text(str(data.get("content", ""))), TEXT_LIMIT),
                    },
                )
            ]
        return []
    if kind == "assistant":
        message = data.get("message") or {}
        return _assistant_events(message)
    if kind == "user":
        message = data.get("message") or {}
        return _user_events(message)
    if kind == "stream_event":
        event = data.get("event") or {}
        if event.get("type") == "content_block_delta":
            delta = event.get("delta") or {}
            if delta.get("type") == "text_delta" and delta.get("text"):
                return [("agent.text.delta", {"text": str(delta.get("text"))})]
        return []
    if kind == "result":
        result_text = data.get("result")
        if not isinstance(result_text, str):
            result_text = json_text(result_text, TEXT_LIMIT)
        return [
            (
                "agent.result",
                {
                    "subtype": data.get("subtype"),
                    "is_error": bool(data.get("is_error")),
                    "text": truncate(redact_text(result_text), TEXT_LIMIT),
                    "duration_ms": data.get("duration_ms"),
                    "cost_usd": data.get("total_cost_usd"),
                    "num_turns": data.get("num_turns"),
                    "session_id": data.get("session_id"),
                },
            )
        ]
    return []
