from __future__ import annotations

import asyncio
import json
import stat
import sys
from pathlib import Path

import pytest

from tests.helpers import make_config
from ycb.agents.cli_backend import ClaudeCLIBackend
from ycb.agents.spec import AgentSpec

FAKE_CLAUDE = r'''#!{python}
import json, os, sys

with open(os.environ["FAKE_ARGV_PATH"], "w", encoding="utf-8") as fh:
    json.dump(sys.argv, fh)
with open(os.environ["FAKE_CWD_PATH"], "w", encoding="utf-8") as fh:
    fh.write(os.getcwd())
with open(os.environ["FAKE_ENV_PATH"], "w", encoding="utf-8") as fh:
    json.dump(dict(os.environ), fh)

session_id = "fake-session-1"
print(json.dumps({{
    "type": "system", "subtype": "init", "model": "fake-model",
    "session_id": session_id, "cwd": os.getcwd(),
    "permissionMode": "bypassPermissions", "tools": ["Bash"],
}}), flush=True)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    data = json.loads(line)
    if data.get("type") == "user":
        text = data["message"]["content"][0]["text"]
        print(json.dumps({{
            "type": "assistant",
            "message": {{"content": [{{"type": "text", "text": "收到：" + text + " DASCTF{{fake_secret_value}}"}}]}},
        }}), flush=True)
        print(json.dumps({{"type": "result", "subtype": "success", "result": "done",
                           "session_id": session_id, "duration_ms": 1}}), flush=True)
    elif data.get("type") == "control_request":
        rid = data.get("request_id")
        print(json.dumps({{"type": "control_response",
                           "response": {{"request_id": rid, "subtype": "success"}}}}), flush=True)
        sys.exit(0)
'''


def make_script(tmp_path: Path) -> Path:
    path = tmp_path / "fake-claude"
    path.write_text(FAKE_CLAUDE.format(python=sys.executable), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def make_spec(tmp_path: Path, **overrides) -> AgentSpec:
    workspace = tmp_path / "work"
    workspace.mkdir(exist_ok=True)
    data = dict(
        challenge_id=1,
        uid="mock:1749:c1",
        title="Fake",
        category="Misc",
        score=100,
        workspace=workspace,
        description_md="desc",
        attachments=[],
        target=None,
        flag_regex=r"^DASCTF\{[^{}]+\}$",
        deadline="2026-10-24T14:00:00+08:00",
        system_prompt="只写 flag.txt",
    )
    data.update(overrides)
    return AgentSpec(**data)


async def test_backend_round_trip(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    script = make_script(tmp_path)
    config.agent.claude_bin = str(script)
    argv_path = tmp_path / "argv.json"
    cwd_path = tmp_path / "cwd.txt"
    env_path = tmp_path / "env.json"
    monkeypatch.setenv("FAKE_ARGV_PATH", str(argv_path))
    monkeypatch.setenv("FAKE_CWD_PATH", str(cwd_path))
    monkeypatch.setenv("FAKE_ENV_PATH", str(env_path))
    monkeypatch.setenv("YCB_SECRET_LEAK", "should-not-leak")
    monkeypatch.setenv("MOCK_PASSWORD", "should-not-leak")
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("CLAUDE_CODE_NESTED_MARKER", "1")

    spec = make_spec(tmp_path)
    events: list[tuple[str, dict]] = []
    got_result = asyncio.Event()

    async def emit(event_type: str, payload: dict) -> None:
        events.append((event_type, payload))
        if event_type == "agent.result":
            got_result.set()

    backend = ClaudeCLIBackend(spec, config, emit, run_id=77)
    await backend.start()
    try:
        assert backend.pid and backend.pgid
        assert await backend.send("你好") is True
        await asyncio.wait_for(got_result.wait(), timeout=10)
        await asyncio.sleep(0.1)
        assert await backend.interrupt(control_timeout=5) is True
        assert await asyncio.wait_for(backend.wait(), timeout=5) == 0
    finally:
        await backend.close()

    types = [kind for kind, _ in events]
    assert "agent.init" in types
    assert "agent.text" in types
    assert "agent.result" in types
    text_event = next(payload for kind, payload in events if kind == "agent.text")
    assert "fake_secret_value" not in text_event["text"]
    assert "…" in text_event["text"]

    argv = json.loads(argv_path.read_text(encoding="utf-8"))
    assert "--model" not in argv
    assert "--max-turns" not in argv and "--max-budget-usd" not in argv
    assert argv[argv.index("--input-format") + 1] == "stream-json"
    assert argv[argv.index("--output-format") + 1] == "stream-json"
    assert argv[argv.index("--permission-mode") + 1] == "bypassPermissions"
    assert "--append-system-prompt" in argv
    assert argv[argv.index("--session-id") + 1]
    assert "--resume" not in argv

    assert cwd_path.read_text(encoding="utf-8") == str(spec.workspace)
    child_env = json.loads(env_path.read_text(encoding="utf-8"))
    assert "YCB_SECRET_LEAK" not in child_env
    assert "MOCK_PASSWORD" not in child_env
    assert "CLAUDECODE" not in child_env
    assert "CLAUDE_CODE_NESTED_MARKER" not in child_env
    assert "PATH" in child_env
    assert child_env["CTF_CHALLENGE_UID"] == spec.uid
    assert child_env["CTF_WORKSPACE"] == str(spec.workspace)
    assert child_env["PWD"] == str(spec.workspace)

    raw = Path(backend.raw_path or "")
    assert raw.is_file()
    assert stat.S_IMODE(raw.stat().st_mode) == 0o600
    lines = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines() if line]
    assert any(item.get("type") == "system" for item in lines)
    assert any(item.get("type") == "result" for item in lines)


def test_command_uses_resume_when_spec_says_so(tmp_path):
    config = make_config(tmp_path)
    config.agent.claude_bin = "/usr/bin/false"
    spec = make_spec(tmp_path, session_id="sess-abc", resume=True)
    backend = ClaudeCLIBackend(spec, config, lambda *_: None, run_id=1)
    argv = backend._command()
    assert argv[argv.index("--resume") + 1] == "sess-abc"
    assert "--session-id" not in argv
    assert "--model" not in argv


async def test_start_fails_cleanly_when_binary_missing(tmp_path):
    config = make_config(tmp_path)
    config.agent.claude_bin = str(tmp_path / "does-not-exist")
    spec = make_spec(tmp_path)

    async def emit(*_args, **_kwargs):
        return None

    backend = ClaudeCLIBackend(spec, config, emit, run_id=1)
    with pytest.raises(Exception):
        await backend.start()
    assert backend.alive is False
    await backend.close()
