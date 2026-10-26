#!/usr/bin/env python3
"""CTF 自动化解题编排系统入口（2026 羊城杯）。

用法：
    python run.py --mock                 # 启动内置 mock 平台 + 看板（开发/联调）
    python run.py --platform ycb         # 连接真实平台
    python run.py --mock --live          # 关闭 dry_run（仅在验证过提交后使用）

约束：
- uvicorn 单 worker（事件总线与 SQLite 均在进程内，不能多进程共享）。
- 同一份 var/ 只能有一个实例（fcntl 锁）。
- mock 平台是本进程的子进程，退出时一并回收。
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ycb.config import (  # noqa: E402
    Config,
    ConfigError,
    _client_host,
    load_config,
    log_config_summary,
    with_overrides,
)
from ycb.logging import setup_logging  # noqa: E402
from ycb.web.app import create_app  # noqa: E402

log = logging.getLogger("ycb.run")

MOCK_HEALTH_TIMEOUT = 25.0


class InstanceLock:
    """单实例锁：防止两个进程同时写同一个 SQLite / 端口。"""

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._fh.seek(0)
            owner = self._fh.read().strip() or "unknown"
            self._fh.close()
            self._fh = None
            raise RuntimeError(f"已有实例在运行（锁 {self.path}，pid={owner}）") from exc
        with contextlib.suppress(OSError):
            self.path.chmod(0o600)
        self._fh.seek(0)
        self._fh.truncate()
        self._fh.write(str(os.getpid()))
        self._fh.flush()

    def release(self) -> None:
        if self._fh is None:
            return
        with contextlib.suppress(OSError):
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        self._fh.close()
        self._fh = None


def _probe_mock(url: str) -> bool:
    try:
        resp = httpx.get(f"{url}/api/health", timeout=1.0)
        if resp.status_code != 200:
            return False
        return (resp.json() or {}).get("platform") == "mock"
    except Exception:
        return False


def _mock_env(config: Config) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "MOCK_HOST": config.mock.host,
            "MOCK_PORT": str(config.mock.port),
            "MOCK_USERNAME": config.mock.username,
            "MOCK_PASSWORD": config.mock.password,
            "MOCK_SUBMIT_LIMIT": str(config.mock.submit_limit),
            "MOCK_SUBMIT_INTERVAL": str(config.mock.submit_interval_seconds),
            "MOCK_DEBUG_CAPTCHA": "1" if config.mock.debug_captcha else "0",
        }
    )
    return env


def _spawn_mock(config: Config) -> subprocess.Popen:
    cmd = [
        sys.executable,
        "-m",
        "mock_platform.app",
        "--host",
        config.mock.host,
        "--port",
        str(config.mock.port),
        "--log-level",
        "warning",
    ]
    log.info("启动 mock 平台 %s:%d", config.mock.host, config.mock.port)
    return subprocess.Popen(
        cmd,
        cwd=str(PROJECT_ROOT),
        env=_mock_env(config),
        stdin=subprocess.DEVNULL,
        stdout=sys.stderr,
        stderr=sys.stderr,
    )


def _wait_mock(config: Config, proc: subprocess.Popen | None) -> None:
    url = config.platform.mock_url
    deadline = time.monotonic() + MOCK_HEALTH_TIMEOUT
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(
                f"mock 平台启动失败（退出码 {proc.returncode}），请检查端口 {config.mock.port} 是否被占用"
            )
        if _probe_mock(url):
            return
        time.sleep(0.25)
    raise RuntimeError(f"mock 平台在 {MOCK_HEALTH_TIMEOUT:.0f}s 内未就绪：{url}/api/health")


def _stop_mock(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    log.info("停止 mock 平台 pid=%d", proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        log.warning("mock 平台未在 8s 内退出，强制结束")
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)


def _prepare_mock(config: Config) -> subprocess.Popen | None:
    """确保 mock 平台可用：已在运行则复用，否则拉起子进程。"""
    if _probe_mock(config.platform.mock_url):
        log.warning("复用已在运行的 mock 平台：%s", config.platform.mock_url)
        return None
    proc = _spawn_mock(config)
    try:
        _wait_mock(config, proc)
    except Exception:
        _stop_mock(proc)
        raise
    log.info("mock 平台就绪：%s/1749/login", config.platform.mock_url)
    return proc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CTF 自动化解题编排系统（2026 羊城杯）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config", default=None, help="配置文件路径（默认 YCB_CONFIG 或 ./config.toml）")
    parser.add_argument("--mock", action="store_true", help="启动内置 mock 平台并连接到它")
    parser.add_argument("--platform", choices=["mock", "ycb", "ctfd"], default=None, help="覆盖 platform.active")
    parser.add_argument("--host", default=None, help="看板监听地址")
    parser.add_argument("--port", type=int, default=None, help="看板监听端口")
    parser.add_argument("--mock-host", default=None, help="mock 平台监听地址（--mock 时生效）")
    parser.add_argument("--mock-port", type=int, default=None, help="mock 平台端口（--mock 时生效）")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", dest="dry_run", action="store_true", default=None, help="只识别不提交（默认）")
    group.add_argument("--live", dest="dry_run", action="store_false", default=None, help="允许真实提交（谨慎）")
    parser.add_argument("--discovery-interval", type=float, default=None, help="发现周期秒数")
    parser.add_argument(
        "--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="日志级别"
    )
    parser.add_argument("--check", action="store_true", help="只校验配置并退出")
    return parser


def _apply_args(config: Config, args: argparse.Namespace) -> Config:
    if args.mock and args.platform and args.platform != "mock":
        raise ConfigError("--mock 不能与 --platform ycb/ctfd 同时使用")
    platform = "mock" if args.mock else args.platform

    with_overrides(
        config,
        host=args.host,
        port=args.port,
        dry_run=args.dry_run,
        platform=platform,
        discovery_interval=args.discovery_interval,
    )
    if args.log_level:
        config.server.log_level = args.log_level

    if args.mock_host:
        config.mock.host = args.mock_host
    if args.mock_port is not None:
        if not (0 <= args.mock_port <= 65535):
            raise ConfigError(f"mock 端口越界：{args.mock_port}")
        config.mock.port = args.mock_port
    if args.mock or args.mock_host or args.mock_port is not None:
        config.platform.mock_url = f"http://{_client_host(config.mock.host)}:{config.mock.port}"

    if args.mock and args.discovery_interval is None:
        # 开发联调默认更快，仍然保留 confirm_passes=2
        config.discovery.interval_seconds = 3.0
        config.discovery.jitter_seconds = 1.0
    return config


async def _serve(config: Config, mock_proc: subprocess.Popen | None) -> None:
    app = create_app(config)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=config.server.host,
            port=config.server.port,
            log_config=None,
            log_level=config.server.log_level.lower(),
            access_log=False,
            workers=1,
            lifespan="on",
        )
    )
    try:
        await server.serve()
    finally:
        _stop_mock(mock_proc)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        _apply_args(config, args)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2

    if args.check:
        print(f"OK {config.config_path}")
        print(
            f"platform={config.platform.active} competition={config.platform.competition_id} "
            f"dry_run={config.submission.dry_run} dashboard={config.server.host}:{config.server.port}"
        )
        print(f"data_dir={config.data_dir}")
        print(f"workspace_dir={config.workspace_dir}")
        return 0

    try:
        config.ensure_dirs()
    except OSError as exc:
        print(f"无法创建运行时目录：{exc}", file=sys.stderr)
        return 2

    setup_logging(config.logs_dir, level=config.server.log_level)
    log_config_summary(config)
    if not config.server.loopback and not config.server.token:
        log.warning(
            "看板监听 %s 且未设置 YCB_DASH_TOKEN：局域网内任何人都可访问并操作看板",
            config.server.host,
        )

    lock = InstanceLock(config.lock_path)
    try:
        lock.acquire()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    mock_proc: subprocess.Popen | None = None
    try:
        if args.mock:
            mock_proc = _prepare_mock(config)
        elif config.platform.active == "mock":
            log.info("使用外部 mock 平台：%s（未加 --mock，不自动启动）", config.platform.mock_url)

        log.info(
            "看板地址 http://%s:%d%s",
            config.server.host,
            config.server.port,
            "?token=<YCB_DASH_TOKEN>" if config.server.token else "",
        )
        asyncio.run(_serve(config, mock_proc))
        return 0
    except KeyboardInterrupt:
        log.info("收到中断，退出")
        return 0
    except RuntimeError as exc:
        log.error("启动失败：%s", exc)
        return 2
    finally:
        _stop_mock(mock_proc)
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
