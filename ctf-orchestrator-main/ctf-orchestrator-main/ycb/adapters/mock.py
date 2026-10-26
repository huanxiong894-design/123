"""本地 mock 平台适配器（Milestone 1）。

通过 HTTP API 驱动 mock_platform，形态与真实 adapter 一致：
登录（验证码走 debug 答案，真实平台由 M2 的 ddddocr 承担）、发现、详情、下载、
容器、提交。cookie 持久化到 var/mock/cookies.json，验证“持久化登录”路径。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from ycb.adapters.base import (
    LoginFailed,
    PlatformError,
    PlatformRateLimited,
    SessionExpired,
)
from ycb.config import Config
from ycb.models import (
    Attachment,
    Challenge,
    SessionState,
    SubmitResult,
    Target,
    make_uid,
)
from ycb.workspace.layout import safe_filename

log = logging.getLogger(__name__)

MAX_ATTACHMENT_BYTES = 256 * 1024 * 1024
_SUBMIT_MAP = {"accepted", "rejected", "already_solved", "rate_limited", "session_expired", "unknown"}


class MockAdapter:
    name = "mock"
    capabilities = {"captcha", "attachments", "container", "submit_api", "dynamic_score"}

    def __init__(self, config: Config, *, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self.base_url = config.platform.mock_url.rstrip("/")
        self._cookies_path = config.data_dir / "mock" / "cookies.json"
        kwargs: dict = {
            "base_url": self.base_url,
            "timeout": httpx.Timeout(30.0, connect=10.0),
            "follow_redirects": True,
            "headers": {"User-Agent": "ycb-solver/0.1 (mock adapter)"},
        }
        if transport is not None:
            kwargs["transport"] = transport
        self._client = httpx.AsyncClient(**kwargs)
        self._session = SessionState(state="unknown", detail="mock adapter 初始化")
        self._load_cookies()

    # ------------------------------------------------------------------ session
    @property
    def session(self) -> SessionState:
        return self._session

    def _cookie_host(self) -> str:
        return urlparse(self.base_url).hostname or "127.0.0.1"

    def _load_cookies(self) -> None:
        try:
            data = json.loads(self._cookies_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return
        host = self._cookie_host()
        for item in data:
            try:
                self._client.cookies.set(
                    item["name"], item["value"], domain=item.get("domain") or host, path=item.get("path", "/")
                )
            except (KeyError, TypeError):
                continue

    def _save_cookies(self) -> None:
        self._cookies_path.parent.mkdir(parents=True, exist_ok=True)
        items = [
            {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
            for c in self._client.cookies.jar
        ]
        self._cookies_path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            self._cookies_path.chmod(0o600)
        except OSError:  # pragma: no cover
            pass

    async def health(self) -> SessionState:
        try:
            resp = await self._client.get("/api/me")
        except httpx.HTTPError as exc:
            self._session = SessionState(state="error", detail=f"mock 平台不可达：{exc}")
            return self._session
        if resp.status_code == 200:
            data = resp.json()
            self._session = SessionState(
                state="logged_in", detail="mock 会话有效", username=str(data.get("username", ""))
            )
        elif resp.status_code == 401:
            self._session = SessionState(state="logged_out", detail="mock 会话过期或未登录")
        else:
            self._session = SessionState(state="error", detail=f"mock /api/me -> {resp.status_code}")
        return self._session

    async def login(self) -> None:
        state = await self.health()
        if state.logged_in:
            return
        last_error = ""
        for attempt in range(5):
            try:
                captcha = await self._get_json("/api/captcha")
            except PlatformError as exc:
                last_error = str(exc)
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            answer = captcha.get("answer")
            if not answer:
                raise LoginFailed(
                    "mock 验证码答案未暴露：请以 MOCK_DEBUG_CAPTCHA=1 启动 mock 平台；"
                    "真实平台将在 M2 接入 ddddocr/人工"
                )
            resp = await self._client.post(
                "/api/login",
                json={
                    "username": self.config.mock.username,
                    "password": self.config.mock.password,
                    "captcha_id": captcha.get("captcha_id"),
                    "captcha": answer,
                },
            )
            if resp.status_code == 200 and resp.json().get("ok"):
                self._save_cookies()
                self._session = SessionState(
                    state="logged_in",
                    detail=f"mock 登录成功（第 {attempt + 1} 次）",
                    username=self.config.mock.username,
                )
                log.info("mock 登录成功 user=%s", self.config.mock.username)
                return
            last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            await asyncio.sleep(0.2 * (attempt + 1))
        self._session = SessionState(state="needs_human", detail=f"mock 登录失败：{last_error}")
        raise LoginFailed(f"mock 登录失败（重试 5 次）：{last_error}")

    # ------------------------------------------------------------------ discovery
    async def discover(self) -> list[Challenge]:
        data = await self._get_json("/api/challenges")
        items = data.get("challenges", []) if isinstance(data, dict) else []
        return [self._to_challenge(item) for item in items if isinstance(item, dict)]

    async def fetch_detail(self, challenge: Challenge) -> Challenge:
        data = await self._get_json(f"/api/challenges/{challenge.platform_id}")
        detail = self._to_challenge(data)
        detail.seq_no = challenge.seq_no
        detail.db_id = challenge.db_id
        detail.status = challenge.status
        detail.workspace = challenge.workspace
        return detail

    # ------------------------------------------------------------------ files
    async def download(self, challenge: Challenge, dest: Path) -> list[Path]:
        dest.mkdir(parents=True, exist_ok=True)
        resolved_dest = dest.resolve()
        paths: list[Path] = []
        for attachment in challenge.attachments:
            url = urljoin(self.base_url + "/", attachment.url)
            resp = await self._client.get(url)
            if resp.status_code == 401:
                self._session = SessionState(state="logged_out", detail="下载时 401")
                raise SessionExpired("下载附件会话过期")
            if resp.status_code >= 400:
                raise PlatformError(f"下载 {attachment.name} 失败：HTTP {resp.status_code}")
            content = resp.content
            if len(content) > MAX_ATTACHMENT_BYTES:
                raise PlatformError(f"{attachment.name} 超过 {MAX_ATTACHMENT_BYTES} 字节，拒绝下载")
            if attachment.size is not None and len(content) != attachment.size:
                raise PlatformError(
                    f"{attachment.name} 大小不符：期望 {attachment.size}，实际 {len(content)}"
                )
            if attachment.sha256:
                digest = hashlib.sha256(content).hexdigest()
                if digest != attachment.sha256:
                    raise PlatformError(f"{attachment.name} SHA-256 不符：{digest}")
            path = (resolved_dest / safe_filename(attachment.name)).resolve()
            if resolved_dest not in path.parents:
                raise PlatformError(f"附件文件名越界：{attachment.name!r}")
            part = path.with_name(path.name + ".part")
            part.write_bytes(content)
            part.replace(path)
            paths.append(path)
        return paths

    # ------------------------------------------------------------------ target
    async def ensure_target(self, challenge: Challenge) -> Target | None:
        if not challenge.container_available:
            return None
        resp = await self._client.post(f"/api/challenges/{challenge.platform_id}/container")
        if resp.status_code == 401:
            self._session = SessionState(state="logged_out", detail="启动容器时 401")
            raise SessionExpired("启动容器会话过期")
        if resp.status_code == 429:
            raise PlatformRateLimited("启动容器被限流", retry_after=_retry_after(resp))
        if resp.status_code >= 400:
            raise PlatformError(f"启动容器失败：HTTP {resp.status_code} {resp.text[:200]}")
        data = resp.json()
        target = Target.from_dict(data.get("target"))
        if target is None:
            raise PlatformError("容器启动响应缺少 target")
        challenge.target = target
        return target

    async def refresh_target(self, challenge: Challenge) -> Target | None:
        return await self.ensure_target(challenge)

    # ------------------------------------------------------------------ submit
    async def submit(self, challenge: Challenge, flag: str) -> SubmitResult:
        resp = await self._client.post(
            f"/api/challenges/{challenge.platform_id}/submit", json={"flag": flag}
        )
        if resp.status_code == 401:
            self._session = SessionState(state="logged_out", detail="提交时 401")
            return SubmitResult("session_expired", "提交时会话过期", {"http": 401})
        if resp.status_code == 429:
            return SubmitResult(
                "rate_limited",
                "平台限流",
                {"http": 429, "retry_after": _retry_after(resp)},
            )
        if resp.status_code >= 500:
            return SubmitResult("unknown", f"平台 5xx：{resp.status_code}", {"http": resp.status_code})
        try:
            data = resp.json()
        except ValueError:
            return SubmitResult("unknown", f"无法解析提交响应：{resp.text[:200]}", {"http": resp.status_code})
        status = str(data.get("status", "unknown"))
        if status not in _SUBMIT_MAP:
            status = "unknown"
        return SubmitResult(status, str(data.get("message", "")), {"http": resp.status_code})

    async def is_solved(self, challenge: Challenge) -> bool:
        data = await self._get_json(f"/api/challenges/{challenge.platform_id}")
        return bool(data.get("solved"))

    # ------------------------------------------------------------------ internal
    async def _get_json(self, path: str) -> dict:
        try:
            resp = await self._client.get(path)
        except httpx.HTTPError as exc:
            raise PlatformError(f"请求 {path} 失败：{exc}") from exc
        if resp.status_code == 401:
            self._session = SessionState(state="logged_out", detail=f"{path} 401")
            raise SessionExpired(f"{path} 需要登录")
        if resp.status_code == 429:
            raise PlatformRateLimited(f"{path} 限流", retry_after=_retry_after(resp))
        if resp.status_code >= 400:
            raise PlatformError(f"{path} -> HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError as exc:
            raise PlatformError(f"{path} 返回非 JSON") from exc

    def _to_challenge(self, data: dict) -> Challenge:
        pid = str(data.get("id", ""))
        container = data.get("container") or {}
        target = Target.from_dict(data.get("target"))
        return Challenge(
            uid=make_uid(self.name, self.config.platform.competition_id, pid),
            platform=self.name,
            competition_id=self.config.platform.competition_id,
            platform_id=pid,
            title=str(data.get("title") or pid),
            category=str(data.get("category") or ""),
            score=int(data["score"]) if data.get("score") is not None else None,
            description_md=str(data.get("description_md") or ""),
            attachments=[Attachment.from_dict(a) for a in data.get("attachments") or []],
            target=target,
            flag_regex=data.get("flag_regex"),
            raw=data,
            container_available=bool(container.get("available")),
            solved_on_platform=bool(data.get("solved")),
        )

    async def close(self) -> None:
        self._save_cookies()
        await self._client.aclose()


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None
