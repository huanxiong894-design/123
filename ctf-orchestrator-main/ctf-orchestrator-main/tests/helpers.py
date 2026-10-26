"""测试辅助：构造临时配置/领域对象、登录 mock 平台。"""

from __future__ import annotations

import httpx

from ycb.config import (
    AgentConfig,
    BrowserConfig,
    Config,
    DiscoveryConfig,
    MockConfig,
    PlatformConfig,
    ScheduleConfig,
    ServerConfig,
    SubmissionConfig,
)
from ycb.models import Challenge


def make_config(
    root,
    *,
    mock_url: str = "http://mock.local",
    discovery_enabled: bool = False,
    confirm_passes: int = 2,
    interval: float = 0.01,
    dry_run: bool = True,
) -> Config:
    config = Config(
        root=root,
        config_path=root / "config.toml",
        server=ServerConfig(),
        platform=PlatformConfig(active="mock", mock_url=mock_url),
        browser=BrowserConfig(),
        mock=MockConfig(),
        discovery=DiscoveryConfig(
            enabled=discovery_enabled,
            interval_seconds=interval,
            jitter_seconds=0.0,
            confirm_passes=confirm_passes,
        ),
        agent=AgentConfig(auto_start=False),
        submission=SubmissionConfig(
            dry_run=dry_run,
            min_interval_seconds=0.0,
            per_challenge_interval_seconds=0.0,
        ),
        schedule=ScheduleConfig(),
        data_dir=root / "var",
        workspace_dir=root / "workspace",
    )
    config.ensure_dirs()
    return config


def make_challenge(key: str = "c1", **overrides) -> Challenge:
    data = {
        "uid": f"mock:1749:{key}",
        "platform": "mock",
        "competition_id": "1749",
        "platform_id": key,
        "title": f"Challenge {key}",
        "category": "Misc",
        "score": 500,
        "description_md": "测试题目说明",
    }
    data.update(overrides)
    return Challenge(**data)


async def login_mock_client(
    client: httpx.AsyncClient, *, username: str = "player", password: str = "mock-pass-2026"
) -> dict:
    captcha = (await client.get("/api/captcha")).json()
    assert "captcha_id" in captcha and captcha.get("answer"), captcha
    resp = await client.post(
        "/api/login",
        json={
            "username": username,
            "password": password,
            "captcha_id": captcha["captcha_id"],
            "captcha": captcha["answer"],
        },
    )
    assert resp.status_code == 200, resp.text
    return captcha
