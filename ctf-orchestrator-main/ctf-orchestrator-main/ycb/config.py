"""配置加载：TOML + .env/环境变量覆盖。

原则：
- 真实平台账号密码只来自环境变量（可用项目根目录的 .env），不写进 config.toml，也不入库。
- 相对路径一律相对 config.toml 所在目录解析。
- 所有运行时目录在启动时创建并收紧权限（数据目录 0700，DB 0600）。
"""

from __future__ import annotations

import logging
import os
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - 3.11+ 部署环境
    raise RuntimeError("需要 Python 3.11+（tomllib）") from exc

log = logging.getLogger(__name__)

DEFAULT_FLAG_REGEX = r"^(DASCTF\{[^{}\r\n]{4,200}\}|flag\{[^{}\r\n]{4,200}\})$"


class ConfigError(RuntimeError):
    """配置错误（启动即失败，不静默继续）。"""


def _client_host(host: str) -> str:
    """监听地址是通配地址时，客户端仍应连回环地址。"""
    return "127.0.0.1" if host in {"", "0.0.0.0", "::", "[::]"} else host


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _as_int(value: Any, default: int, field_name: str) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} 必须是整数，得到 {value!r}") from exc


def _as_float(value: Any, default: float, field_name: str) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} 必须是数字，得到 {value!r}") from exc


def _as_str(value: Any, default: str) -> str:
    return default if value is None else str(value)


def _parse_dt(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise ConfigError(f"{field_name} 不是合法 ISO-8601 时间：{value!r}") from exc
    if dt.tzinfo is None:
        raise ConfigError(f"{field_name} 必须带时区（例如 +08:00）：{value!r}")
    return dt


def load_dotenv(path: Path) -> None:
    """极简 .env 加载器；不覆盖已存在的环境变量。"""
    if not path.is_file():
        return
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            warnings.warn(
                f"{path} 权限为 {mode:o}，建议 chmod 600（当前对同组/其他用户可读）",
                stacklevel=2,
            )
    except OSError:
        pass
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)


@dataclass(slots=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    log_level: str = "INFO"
    token: str = ""  # YCB_DASH_TOKEN；设置后启用看板 token 校验
    unmask_flags: bool = False  # 看板/事件中是否显示明文 flag

    @property
    def loopback(self) -> bool:
        return self.host in {"127.0.0.1", "localhost", "::1"}


@dataclass(slots=True)
class PlatformConfig:
    active: str = "mock"
    competition_id: str = "1749"
    base_url: str = "https://ycb-qy.dasctf.com"
    mock_url: str = "http://127.0.0.1:8898"
    username: str = ""
    password: str = ""
    max_containers: int = 3

    def __repr__(self) -> str:  # 避免把密码写进日志
        return (
            f"PlatformConfig(active={self.active!r}, competition_id={self.competition_id!r}, "
            f"base_url={self.base_url!r}, mock_url={self.mock_url!r}, "
            f"max_containers={self.max_containers}, "
            f"username={'***' if self.username else ''!r}, password={'***' if self.password else ''!r})"
        )


@dataclass(slots=True)
class MockConfig:
    host: str = "127.0.0.1"
    port: int = 8898
    username: str = "player"
    password: str = "mock-pass-2026"
    submit_limit: int = 50
    submit_interval_seconds: float = 1.0
    debug_captcha: bool = True

    def __repr__(self) -> str:
        return (
            f"MockConfig(host={self.host!r}, port={self.port}, username={self.username!r}, "
            f"password='***', submit_limit={self.submit_limit})"
        )


@dataclass(slots=True)
class BrowserConfig:
    headless: bool = True
    chromium_path: str = ""  # 空 = 自动探测 Playwright 自带 / 系统 chromium
    slow_mo_ms: int = 0
    timeout_seconds: float = 30.0
    captcha_retries: int = 5

    def __repr__(self) -> str:
        return (
            f"BrowserConfig(headless={self.headless}, chromium_path={self.chromium_path!r}, "
            f"slow_mo_ms={self.slow_mo_ms}, timeout_seconds={self.timeout_seconds}, "
            f"captcha_retries={self.captcha_retries})"
        )


@dataclass(slots=True)
class DiscoveryConfig:
    enabled: bool = True
    interval_seconds: float = 20.0
    jitter_seconds: float = 5.0
    confirm_passes: int = 2


@dataclass(slots=True)
class AgentConfig:
    backend: str = "cli"
    claude_bin: str = "claude"
    stall_warn_seconds: int = 600
    stall_interrupt_seconds: int = 1800
    append_system_prompt: str = ""
    auto_start: bool = True
    max_agents: int = 0  # 0 = 不设上限
    stagger_min_seconds: float = 1.0
    stagger_max_seconds: float = 2.0
    raw_log_max_bytes: int = 50 * 1024 * 1024


@dataclass(slots=True)
class SubmissionConfig:
    dry_run: bool = True
    max_auto_submits: int = 45
    min_interval_seconds: float = 3.0
    per_challenge_interval_seconds: float = 5.0
    flag_regex: str = DEFAULT_FLAG_REGEX
    watch_interval_seconds: float = 1.0
    stable_seconds: float = 1.0


@dataclass(slots=True)
class ScheduleConfig:
    start: datetime = field(default_factory=lambda: datetime.fromisoformat("2026-10-24T10:00:00+08:00"))
    end: datetime = field(default_factory=lambda: datetime.fromisoformat("2026-10-24T14:00:00+08:00"))

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise ConfigError("schedule.end_time 必须晚于 start_time")


@dataclass(slots=True)
class Config:
    root: Path
    config_path: Path
    server: ServerConfig
    platform: PlatformConfig
    browser: BrowserConfig
    mock: MockConfig
    discovery: DiscoveryConfig
    agent: AgentConfig
    submission: SubmissionConfig
    schedule: ScheduleConfig
    data_dir: Path
    workspace_dir: Path

    # ---- 常用路径 ----
    @property
    def db_path(self) -> Path:
        return self.data_dir / "ycb.db"

    @property
    def lock_path(self) -> Path:
        return self.data_dir / "ycb.lock"

    @property
    def profile_dir(self) -> Path:
        return self.data_dir / "profile"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def events_dir(self) -> Path:
        return self.data_dir / "events"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def debug_dir(self) -> Path:
        return self.data_dir / "debug" / "platform"

    @property
    def challenges_dir(self) -> Path:
        return self.workspace_dir / "challenges"

    def ensure_dirs(self) -> None:
        """创建运行时目录；数据目录收紧到 0700。"""
        private = [
            self.data_dir,
            self.profile_dir,
            self.runs_dir,
            self.events_dir,
            self.logs_dir,
            self.debug_dir,
            self.data_dir / "mock",
        ]
        for path in private:
            path.mkdir(parents=True, exist_ok=True)
            try:
                path.chmod(0o700)
            except OSError:  # pragma: no cover - 非 POSIX/受限文件系统
                pass
        for path in (self.workspace_dir, self.challenges_dir):
            path.mkdir(parents=True, exist_ok=True)

    def safe_dict(self) -> dict[str, Any]:
        """可以安全发给看板前端的配置子集（绝不含凭据）。"""
        return {
            "platform": self.platform.active,
            "competition_id": self.platform.competition_id,
            "dry_run": self.submission.dry_run,
            "max_auto_submits": self.submission.max_auto_submits,
            "flag_regex": self.submission.flag_regex,
            "agent_backend": self.agent.backend,
            "discovery_interval": self.discovery.interval_seconds,
            "schedule": {
                "start": self.schedule.start.isoformat(),
                "end": self.schedule.end.isoformat(),
            },
            "workspace_dir": str(self.workspace_dir),
        }


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] 必须是表（table）")
    return value


def _check_bound_port(*values: int) -> None:
    for value in values:
        if not (0 <= value <= 65535):
            raise ConfigError(f"端口越界：{value}")


def load_config(path: str | Path | None = None) -> Config:
    """加载配置；路径缺省为 YCB_CONFIG 或 ./config.toml。"""
    root_hint = Path(path or os.environ.get("YCB_CONFIG") or "config.toml").expanduser()
    if not root_hint.is_absolute():
        root_hint = (Path.cwd() / root_hint).resolve()
    root = root_hint.parent
    load_dotenv(root / ".env")

    try:
        raw = tomllib.loads(root_hint.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"找不到配置文件：{root_hint}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"config.toml 解析失败：{exc}") from exc

    server_raw = _section(raw, "server")
    platform_raw = _section(raw, "platform")
    mock_raw = _section(raw, "mock")
    browser_raw = _section(raw, "browser")
    discovery_raw = _section(raw, "discovery")
    agent_raw = _section(raw, "agent")
    submission_raw = _section(raw, "submission")
    schedule_raw = _section(raw, "schedule")

    # ---- server ----
    host = _as_str(os.environ.get("YCB_HOST"), _as_str(server_raw.get("host"), "127.0.0.1"))
    port = _as_int(os.environ.get("YCB_PORT"), _as_int(server_raw.get("port"), 8787, "server.port"), "server.port")
    log_level = _as_str(os.environ.get("YCB_LOG_LEVEL"), _as_str(server_raw.get("log_level"), "INFO")).upper()
    token = _as_str(os.environ.get("YCB_DASH_TOKEN"), _as_str(server_raw.get("token"), ""))
    unmask_flags = _as_bool(
        os.environ.get("YCB_UNMASK_FLAGS"), _as_bool(server_raw.get("unmask_flags"), False)
    )
    _check_bound_port(port)
    server = ServerConfig(
        host=host, port=port, log_level=log_level, token=token, unmask_flags=unmask_flags
    )

    # ---- mock ----
    mock_host = _as_str(os.environ.get("MOCK_HOST"), _as_str(mock_raw.get("host"), "127.0.0.1"))
    mock_port = _as_int(
        os.environ.get("MOCK_PORT"), _as_int(mock_raw.get("port"), 8898, "mock.port"), "mock.port"
    )
    _check_bound_port(mock_port)
    mock = MockConfig(
        host=mock_host,
        port=mock_port,
        username=_as_str(os.environ.get("MOCK_USERNAME"), _as_str(mock_raw.get("username"), "player")),
        password=_as_str(os.environ.get("MOCK_PASSWORD"), _as_str(mock_raw.get("password"), "mock-pass-2026")),
        submit_limit=_as_int(
            os.environ.get("MOCK_SUBMIT_LIMIT"),
            _as_int(mock_raw.get("submit_limit"), 50, "mock.submit_limit"),
            "mock.submit_limit",
        ),
        submit_interval_seconds=_as_float(
            os.environ.get("MOCK_SUBMIT_INTERVAL"),
            _as_float(mock_raw.get("submit_interval_seconds"), 1.0, "mock.submit_interval_seconds"),
            "mock.submit_interval_seconds",
        ),
        debug_captcha=_as_bool(
            os.environ.get("MOCK_DEBUG_CAPTCHA"), _as_bool(mock_raw.get("debug_captcha"), True)
        ),
    )

    # ---- platform ----
    platform = PlatformConfig(
        active=_as_str(os.environ.get("YCB_PLATFORM"), _as_str(platform_raw.get("active"), "mock")).lower(),
        competition_id=_as_str(
            os.environ.get("YCB_COMPETITION_ID"), _as_str(platform_raw.get("competition_id"), "1749")
        ),
        base_url=_as_str(os.environ.get("YCB_BASE_URL"), _as_str(platform_raw.get("base_url"), "https://ycb-qy.dasctf.com")),
        mock_url=_as_str(
            os.environ.get("YCB_MOCK_URL"),
            _as_str(
                platform_raw.get("mock_url"),
                f"http://{_client_host(mock.host)}:{mock.port}",
            ),
        ),
        username=_as_str(os.environ.get("YCB_USERNAME"), ""),
        password=_as_str(os.environ.get("YCB_PASSWORD"), ""),
        max_containers=_as_int(
            os.environ.get("YCB_MAX_CONTAINERS"),
            _as_int(platform_raw.get("max_containers"), 3, "platform.max_containers"),
            "platform.max_containers",
        ),
    )

    # ---- browser ----
    browser = BrowserConfig(
        headless=_as_bool(os.environ.get("YCB_HEADLESS"), _as_bool(browser_raw.get("headless"), True)),
        chromium_path=_as_str(
            os.environ.get("YCB_CHROMIUM_PATH"), _as_str(browser_raw.get("chromium_path"), "")
        ),
        slow_mo_ms=_as_int(
            os.environ.get("YCB_SLOW_MO"),
            _as_int(browser_raw.get("slow_mo_ms"), 0, "browser.slow_mo_ms"),
            "browser.slow_mo_ms",
        ),
        timeout_seconds=_as_float(
            os.environ.get("YCB_BROWSER_TIMEOUT"),
            _as_float(browser_raw.get("timeout_seconds"), 30.0, "browser.timeout_seconds"),
            "browser.timeout_seconds",
        ),
        captcha_retries=_as_int(
            os.environ.get("YCB_CAPTCHA_RETRIES"),
            _as_int(browser_raw.get("captcha_retries"), 5, "browser.captcha_retries"),
            "browser.captcha_retries",
        ),
    )
    if browser.timeout_seconds <= 0:
        raise ConfigError("browser.timeout_seconds 必须 > 0")
    if not (1 <= browser.captcha_retries <= 20):
        raise ConfigError("browser.captcha_retries 必须在 1..20")

    # ---- discovery ----
    discovery = DiscoveryConfig(
        enabled=_as_bool(os.environ.get("YCB_DISCOVERY_ENABLED"), _as_bool(discovery_raw.get("enabled"), True)),
        interval_seconds=_as_float(
            os.environ.get("YCB_DISCOVERY_INTERVAL"),
            _as_float(discovery_raw.get("interval_seconds"), 20.0, "discovery.interval_seconds"),
            "discovery.interval_seconds",
        ),
        jitter_seconds=_as_float(
            os.environ.get("YCB_DISCOVERY_JITTER"),
            _as_float(discovery_raw.get("jitter_seconds"), 5.0, "discovery.jitter_seconds"),
            "discovery.jitter_seconds",
        ),
        confirm_passes=_as_int(
            os.environ.get("YCB_DISCOVERY_PASSES"),
            _as_int(discovery_raw.get("confirm_passes"), 2, "discovery.confirm_passes"),
            "discovery.confirm_passes",
        ),
    )
    if discovery.interval_seconds <= 0:
        raise ConfigError("discovery.interval_seconds 必须 > 0")
    if discovery.confirm_passes < 1:
        raise ConfigError("discovery.confirm_passes 必须 >= 1")

    # ---- agent ----
    agent = AgentConfig(
        backend=_as_str(os.environ.get("YCB_AGENT_BACKEND"), _as_str(agent_raw.get("backend"), "cli")).lower(),
        claude_bin=_as_str(os.environ.get("YCB_CLAUDE_BIN"), _as_str(agent_raw.get("claude_bin"), "claude")),
        stall_warn_seconds=_as_int(
            os.environ.get("YCB_STALL_WARN"),
            _as_int(agent_raw.get("stall_warn_seconds"), 600, "agent.stall_warn_seconds"),
            "agent.stall_warn_seconds",
        ),
        stall_interrupt_seconds=_as_int(
            os.environ.get("YCB_STALL_INTERRUPT"),
            _as_int(agent_raw.get("stall_interrupt_seconds"), 1800, "agent.stall_interrupt_seconds"),
            "agent.stall_interrupt_seconds",
        ),
        append_system_prompt=_as_str(
            os.environ.get("YCB_APPEND_SYSTEM_PROMPT"), _as_str(agent_raw.get("append_system_prompt"), "")
        ),
        auto_start=_as_bool(
            os.environ.get("YCB_AUTO_START"), _as_bool(agent_raw.get("auto_start"), True)
        ),
        max_agents=_as_int(
            os.environ.get("YCB_MAX_AGENTS"),
            _as_int(agent_raw.get("max_agents"), 0, "agent.max_agents"),
            "agent.max_agents",
        ),
        stagger_min_seconds=_as_float(
            os.environ.get("YCB_STAGGER_MIN"),
            _as_float(agent_raw.get("stagger_min_seconds"), 1.0, "agent.stagger_min_seconds"),
            "agent.stagger_min_seconds",
        ),
        stagger_max_seconds=_as_float(
            os.environ.get("YCB_STAGGER_MAX"),
            _as_float(agent_raw.get("stagger_max_seconds"), 2.0, "agent.stagger_max_seconds"),
            "agent.stagger_max_seconds",
        ),
        raw_log_max_bytes=_as_int(
            os.environ.get("YCB_RAW_LOG_MAX_BYTES"),
            _as_int(agent_raw.get("raw_log_max_bytes"), 50 * 1024 * 1024, "agent.raw_log_max_bytes"),
            "agent.raw_log_max_bytes",
        ),
    )
    if agent.max_agents < 0:
        raise ConfigError("agent.max_agents 必须 >= 0（0 表示不设上限）")
    if agent.stagger_min_seconds < 0 or agent.stagger_max_seconds < agent.stagger_min_seconds:
        raise ConfigError("agent.stagger_* 必须满足 0 <= min <= max")
    if agent.raw_log_max_bytes < 1024 * 1024:
        raise ConfigError("agent.raw_log_max_bytes 至少 1MB")

    # ---- submission ----
    submission = SubmissionConfig(
        dry_run=_as_bool(os.environ.get("YCB_DRY_RUN"), _as_bool(submission_raw.get("dry_run"), True)),
        max_auto_submits=_as_int(
            os.environ.get("YCB_MAX_SUBMITS"),
            _as_int(submission_raw.get("max_auto_submits"), 45, "submission.max_auto_submits"),
            "submission.max_auto_submits",
        ),
        min_interval_seconds=_as_float(
            os.environ.get("YCB_SUBMIT_INTERVAL"),
            _as_float(submission_raw.get("min_interval_seconds"), 3.0, "submission.min_interval_seconds"),
            "submission.min_interval_seconds",
        ),
        per_challenge_interval_seconds=_as_float(
            os.environ.get("YCB_SUBMIT_INTERVAL_PER_CHALLENGE"),
            _as_float(
                submission_raw.get("per_challenge_interval_seconds"),
                5.0,
                "submission.per_challenge_interval_seconds",
            ),
            "submission.per_challenge_interval_seconds",
        ),
        flag_regex=_as_str(
            os.environ.get("YCB_FLAG_REGEX"),
            _as_str(submission_raw.get("flag_regex"), DEFAULT_FLAG_REGEX),
        ),
        watch_interval_seconds=_as_float(
            os.environ.get("YCB_WATCH_INTERVAL"),
            _as_float(submission_raw.get("watch_interval_seconds"), 1.0, "submission.watch_interval_seconds"),
            "submission.watch_interval_seconds",
        ),
        stable_seconds=_as_float(
            os.environ.get("YCB_FLAG_STABLE"),
            _as_float(submission_raw.get("stable_seconds"), 1.0, "submission.stable_seconds"),
            "submission.stable_seconds",
        ),
    )
    if not (1 <= submission.max_auto_submits <= 50):
        raise ConfigError("submission.max_auto_submits 必须在 1..50（平台硬上限 50）")
    if submission.watch_interval_seconds <= 0:
        raise ConfigError("submission.watch_interval_seconds 必须 > 0")
    if submission.stable_seconds < 0:
        raise ConfigError("submission.stable_seconds 必须 >= 0")
    try:
        import re

        re.compile(submission.flag_regex)
    except re.error as exc:
        raise ConfigError(f"submission.flag_regex 非法：{exc}") from exc

    # ---- schedule ----
    schedule = ScheduleConfig(
        start=_parse_dt(schedule_raw.get("start_time", "2026-10-24T10:00:00+08:00"), "schedule.start_time"),
        end=_parse_dt(schedule_raw.get("end_time", "2026-10-24T14:00:00+08:00"), "schedule.end_time"),
    )

    # ---- paths ----
    data_dir = _resolve_path(_as_str(os.environ.get("YCB_DATA_DIR"), _as_str(raw.get("data_dir"), "var")), root)
    workspace_dir = _resolve_path(
        _as_str(os.environ.get("YCB_WORKSPACE_DIR"), _as_str(raw.get("workspace_dir"), "workspace")), root
    )

    return Config(
        root=root,
        config_path=root_hint,
        server=server,
        platform=platform,
        browser=browser,
        mock=mock,
        discovery=discovery,
        agent=agent,
        submission=submission,
        schedule=schedule,
        data_dir=data_dir,
        workspace_dir=workspace_dir,
    )


def _resolve_path(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def with_overrides(
    config: Config,
    *,
    host: str | None = None,
    port: int | None = None,
    dry_run: bool | None = None,
    platform: str | None = None,
    discovery_interval: float | None = None,
) -> Config:
    """CLI 覆盖（run.py 使用），返回原对象（原地修改，启动前调用）。"""
    if host is not None:
        config.server.host = host
    if port is not None:
        config.server.port = port
    if dry_run is not None:
        config.submission.dry_run = dry_run
    if platform is not None:
        config.platform.active = platform.lower()
    if discovery_interval is not None:
        config.discovery.interval_seconds = discovery_interval
    return config


def log_config_summary(config: Config) -> None:
    log.info(
        "配置 root=%s platform=%s competition=%s dry_run=%s dashboard=%s:%d workspace=%s",
        config.root,
        config.platform.active,
        config.platform.competition_id,
        config.submission.dry_run,
        config.server.host,
        config.server.port,
        config.workspace_dir,
    )
