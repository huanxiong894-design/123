from __future__ import annotations

import json

import pytest

from ycb.config import (
    DEFAULT_FLAG_REGEX,
    ConfigError,
    load_config,
    with_overrides,
)

BASE_TOML = """
data_dir = "data"
workspace_dir = "workspace"

[server]
host = "127.0.0.1"
port = 8788
log_level = "info"

[platform]
active = "mock"
competition_id = "1749"
base_url = "https://ycb-qy.dasctf.com"

[mock]
username = "player"
password = "mock-pass-2026"
submit_limit = 50

[discovery]
enabled = false
interval_seconds = 5
jitter_seconds = 0
confirm_passes = 2

[submission]
dry_run = true
max_auto_submits = 45

[schedule]
start_time = "2026-10-24T10:00:00+08:00"
end_time = "2026-10-24T14:00:00+08:00"
"""


def write_config(tmp_path, body: str = BASE_TOML):
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_load_defaults_and_paths(tmp_path):
    path = write_config(tmp_path)
    config = load_config(path)

    assert config.server.host == "127.0.0.1"
    assert config.server.port == 8788
    assert config.server.log_level == "INFO"
    assert config.platform.active == "mock"
    assert config.platform.competition_id == "1749"
    assert config.platform.mock_url == "http://127.0.0.1:8898"
    assert config.submission.dry_run is True
    assert config.submission.flag_regex == DEFAULT_FLAG_REGEX
    assert config.submission.watch_interval_seconds == 1.0
    assert config.submission.stable_seconds == 1.0
    assert str(config.data_dir) == str((tmp_path / "data").resolve())
    assert str(config.workspace_dir) == str((tmp_path / "workspace").resolve())
    assert str(config.db_path) == str((tmp_path / "data" / "ycb.db").resolve())


def test_env_overrides_toml(tmp_path, monkeypatch):
    path = write_config(tmp_path)
    monkeypatch.setenv("YCB_PORT", "9999")
    monkeypatch.setenv("YCB_PLATFORM", "ycb")
    monkeypatch.setenv("YCB_DRY_RUN", "false")
    monkeypatch.setenv("YCB_WATCH_INTERVAL", "0.5")
    monkeypatch.setenv("YCB_FLAG_STABLE", "2")
    monkeypatch.setenv("MOCK_PASSWORD", "from-env")
    monkeypatch.setenv("MOCK_PORT", "9998")

    config = load_config(path)
    assert config.server.port == 9999
    assert config.platform.active == "ycb"
    assert config.submission.dry_run is False
    assert config.submission.watch_interval_seconds == 0.5
    assert config.submission.stable_seconds == 2.0
    assert config.mock.password == "from-env"
    assert config.mock.port == 9998


def test_dotenv_loaded_without_overriding_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("YCB_USERNAME", raising=False)
    monkeypatch.delenv("YCB_PASSWORD", raising=False)
    path = write_config(tmp_path)
    env_path = tmp_path / ".env"
    env_path.write_text("YCB_USERNAME=alice\nYCB_PASSWORD=secret-pass\n", encoding="utf-8")
    env_path.chmod(0o600)

    config = load_config(path)
    assert config.platform.username == "alice"
    assert config.platform.password == "secret-pass"


def test_dotenv_permission_warning(tmp_path, monkeypatch):
    monkeypatch.delenv("YCB_USERNAME", raising=False)
    path = write_config(tmp_path)
    env_path = tmp_path / ".env"
    env_path.write_text("YCB_USERNAME=alice\n", encoding="utf-8")
    env_path.chmod(0o644)

    with pytest.warns(UserWarning, match="chmod 600"):
        load_config(path)


def test_non_loopback_without_token_allowed(tmp_path, monkeypatch):
    body = BASE_TOML.replace('host = "127.0.0.1"', 'host = "0.0.0.0"')
    path = write_config(tmp_path, body)
    config = load_config(path)
    assert config.server.loopback is False
    assert config.server.token == ""

    monkeypatch.setenv("YCB_DASH_TOKEN", "secret-token")
    config = load_config(path)
    assert config.server.token == "secret-token"


def test_unmask_flags_option(tmp_path, monkeypatch):
    body = BASE_TOML.replace('log_level = "info"', 'log_level = "info"\nunmask_flags = true')
    path = write_config(tmp_path, body)
    assert load_config(path).server.unmask_flags is True

    monkeypatch.setenv("YCB_UNMASK_FLAGS", "false")
    assert load_config(path).server.unmask_flags is False


def test_invalid_values_rejected(tmp_path):
    path = write_config(tmp_path, BASE_TOML.replace("max_auto_submits = 45", "max_auto_submits = 51"))
    with pytest.raises(ConfigError, match="max_auto_submits"):
        load_config(path)

    path = write_config(tmp_path, BASE_TOML.replace('max_auto_submits = 45', 'max_auto_submits = 45\nflag_regex = "(["'))
    with pytest.raises(ConfigError, match="flag_regex"):
        load_config(path)

    path = write_config(
        tmp_path,
        BASE_TOML.replace(
            'start_time = "2026-10-24T10:00:00+08:00"', 'start_time = "2026-10-24T10:00:00"'
        ),
    )
    with pytest.raises(ConfigError, match="时区"):
        load_config(path)

    path = write_config(
        tmp_path,
        BASE_TOML.replace(
            'start_time = "2026-10-24T10:00:00+08:00"', 'start_time = "2026-10-24T15:00:00+08:00"'
        ),
    )
    with pytest.raises(ConfigError, match="晚于"):
        load_config(path)


def test_safe_dict_has_no_secrets(tmp_path):
    path = write_config(tmp_path)
    config = load_config(path)
    config.platform.username = "real-user"
    config.platform.password = "real-password"

    payload = json.dumps(config.safe_dict(), ensure_ascii=False)
    assert "real-user" not in payload
    assert "real-password" not in payload
    assert "mock-pass-2026" not in payload
    assert config.safe_dict()["dry_run"] is True
    assert "***" in repr(config.platform)
    assert "real-password" not in repr(config.platform)
    assert "***" in repr(config.mock)


def test_with_overrides(tmp_path):
    path = write_config(tmp_path)
    config = load_config(path)

    with_overrides(config, host="127.0.0.1", port=9000, dry_run=False, platform="YCB", discovery_interval=1.5)
    assert config.server.port == 9000
    assert config.submission.dry_run is False
    assert config.platform.active == "ycb"
    assert config.discovery.interval_seconds == 1.5

    with_overrides(config, host="0.0.0.0")
    assert config.server.host == "0.0.0.0"
    assert config.server.token == ""
