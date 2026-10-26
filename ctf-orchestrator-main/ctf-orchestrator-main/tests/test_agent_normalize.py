from __future__ import annotations

import json

from ycb.agents.normalize import (
    normalize_stream_event,
    redact_text,
    redact_value,
    set_flag_masking,
)
from ycb.submission.validator import read_flag_candidate


def test_init_is_normalized():
    events = normalize_stream_event(
        {
            "type": "system",
            "subtype": "init",
            "model": "test-model",
            "session_id": "s1",
            "cwd": "/tmp/x",
            "permissionMode": "bypassPermissions",
            "claude_code_version": "2.1.0",
            "tools": ["Bash", "Read"],
            "mcp_servers": [],
        }
    )
    assert events == [
        (
            "agent.init",
            {
                "model": "test-model",
                "session_id": "s1",
                "cwd": "/tmp/x",
                "permission_mode": "bypassPermissions",
                "cli_version": "2.1.0",
                "tools": 2,
                "mcp_servers": 0,
            },
        )
    ]


def test_flag_masking_can_be_disabled():
    message = {
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": "flag：DASCTF{supersecretvalue} token=abc"}]},
    }
    set_flag_masking(False)
    try:
        text = normalize_stream_event(message)[0][1]["text"]
        assert "DASCTF{supersecretvalue}" in text  # flag 明文
    finally:
        set_flag_masking(True)
    assert "supersecretvalue" not in normalize_stream_event(message)[0][1]["text"]


def test_assistant_blocks_and_flag_masking():
    events = normalize_stream_event(
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "text": "找到 flag：DASCTF{supersecretvalue}，token=abc"},
                    {"type": "thinking", "thinking": "先看附件"},
                    {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}},
                ]
            },
        }
    )
    types = [kind for kind, _ in events]
    assert types == ["agent.text", "agent.thinking", "agent.tool_use"]
    assert "supersecretvalue" not in events[0][1]["text"]
    assert "DASCTF{" in events[0][1]["text"] and "…" in events[0][1]["text"]
    assert events[2][1]["input"] == '{"command": "ls"}'


def test_sensitive_keys_are_redacted_recursively():
    value = {
        "headers": {"Authorization": "Bearer abc", "Cookie": "sid=1"},
        "nested": [{"password": "p@ss"}, {"ok": "flag{abcdefgh}"}],
    }
    redacted = redact_value(value)
    assert redacted["headers"]["Authorization"] == "***"
    assert redacted["headers"]["Cookie"] == "***"
    assert redacted["nested"][0]["password"] == "***"
    assert "abcdefgh" not in json.dumps(redacted, ensure_ascii=False)


def test_tool_result_and_result():
    tool_events = normalize_stream_event(
        {
            "type": "user",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "t1",
                        "is_error": False,
                        "content": [{"type": "text", "text": "ok DASCTF{abcdefgh}"}],
                    }
                ]
            },
        }
    )
    assert tool_events[0][0] == "agent.tool_result"
    assert "abcdefgh" not in tool_events[0][1]["output"]

    result = normalize_stream_event(
        {"type": "result", "subtype": "success", "result": "done", "session_id": "s1"}
    )
    assert result[0][0] == "agent.result"
    assert result[0][1]["text"] == "done"


def test_partial_delta_and_unknown_events():
    events = normalize_stream_event(
        {
            "type": "stream_event",
            "event": {
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": "he"},
            },
        }
    )
    assert events == [("agent.text.delta", {"text": "he"})]
    assert normalize_stream_event({"type": "unknown"}) == []
    assert normalize_stream_event({"type": "system", "subtype": "other"}) == []


def test_redact_text_handles_both_flag_forms():
    text = redact_text("a DASCTF{aaaa1111} b flag{bbbb2222}")
    assert "aaaa1111" not in text and "bbbb2222" not in text
    assert "DASCTF{" in text and "flag" in text


def test_flag_candidate_validation(tmp_path):
    (tmp_path / "flag.txt").write_text("DASCTF{real_flag_123}\n", encoding="utf-8")
    candidate = read_flag_candidate(tmp_path, r"^DASCTF\{[^{}]+\}$")
    assert candidate is not None
    assert candidate.flag == "DASCTF{real_flag_123}"
    assert len(candidate.sha256) == 64

    (tmp_path / "flag.txt").write_text("DASCTF{example_flag}\n", encoding="utf-8")
    assert read_flag_candidate(tmp_path, r"^DASCTF\{[^{}]+\}$") is None

    (tmp_path / "flag.txt").write_text("no flag here\n", encoding="utf-8")
    assert read_flag_candidate(tmp_path, r"^DASCTF\{[^{}]+\}$") is None

    (tmp_path / "flag.txt").write_text("DASCTF{a}\nDASCTF{b}\n", encoding="utf-8")
    assert read_flag_candidate(tmp_path, r"^DASCTF\{[^{}]+\}$") is None

    (tmp_path / "flag.txt").unlink()
    (tmp_path / "flag.txt").symlink_to(tmp_path / "other")
    assert read_flag_candidate(tmp_path, r"^DASCTF\{[^{}]+\}$") is None
