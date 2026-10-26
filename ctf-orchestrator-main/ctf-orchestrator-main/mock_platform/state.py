"""mock 平台内存状态：验证码、会话、提交计数、容器服务。

mock 状态不落盘（重启即重置），便于反复跑 e2e；真实平台状态由 adapter 负责。
"""

from __future__ import annotations

import asyncio
import io
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from mock_platform.data import (
    MISC_FLAG,
    PWN_FLAG,
    PWN_TOKEN,
    SeedChallenge,
    seed_challenges,
)
from mock_platform.settings import MockSettings

CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
)


@dataclass
class Captcha:
    answer: str
    image: bytes
    expires_at: float


@dataclass
class MockChallengeState:
    seed: SeedChallenge
    score: int
    solved_by: set[str] = field(default_factory=set)
    solves: int = 0
    target: dict[str, Any] | None = None


@dataclass(frozen=True)
class SubmitOutcome:
    status: str
    message: str
    http_status: int = 200


class MockState:
    def __init__(self, settings: MockSettings):
        self.settings = settings
        self.challenges: dict[str, MockChallengeState] = {
            seed.id: MockChallengeState(seed=seed, score=seed.score) for seed in seed_challenges()
        }
        self.captchas: dict[str, Captcha] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.submit_attempts = 0
        self.last_submit_at = 0.0
        self._lock = asyncio.Lock()
        self._container_server: asyncio.AbstractServer | None = None
        self.container_port: int | None = None
        self.started_at = time.time()

    # ------------------------------------------------------------------ captcha
    def new_captcha(self) -> tuple[str, str, bytes]:
        self._gc()
        captcha_id = secrets.token_urlsafe(12)
        answer = "".join(secrets.choice(CAPTCHA_ALPHABET) for _ in range(4))
        image = _render_captcha(answer)
        self.captchas[captcha_id] = Captcha(
            answer=answer,
            image=image,
            expires_at=time.time() + self.settings.captcha_ttl_seconds,
        )
        return captcha_id, answer, image

    def verify_captcha(self, captcha_id: str, answer: str) -> bool:
        captcha = self.captchas.pop(captcha_id, None)  # 一次性
        if captcha is None or captcha.expires_at < time.time():
            return False
        return secrets.compare_digest(captcha.answer.upper(), (answer or "").strip().upper())

    def captcha_image(self, captcha_id: str) -> bytes | None:
        captcha = self.captchas.get(captcha_id)
        if captcha is None or captcha.expires_at < time.time():
            return None
        return captcha.image

    def debug_answer(self, captcha_id: str) -> str | None:
        if not self.settings.debug_captcha:
            return None
        captcha = self.captchas.get(captcha_id)
        return captcha.answer if captcha else None

    def _gc(self) -> None:
        now = time.time()
        for key in [k for k, v in self.captchas.items() if v.expires_at < now]:
            self.captchas.pop(key, None)
        for key in [k for k, v in self.sessions.items() if v["expires_at"] < now]:
            self.sessions.pop(key, None)

    # ------------------------------------------------------------------ sessions
    def login(self, username: str, password: str) -> bool:
        return secrets.compare_digest(username, self.settings.username) and secrets.compare_digest(
            password, self.settings.password
        )

    def create_session(self, username: str) -> str:
        token = secrets.token_urlsafe(24)
        self.sessions[token] = {
            "username": username,
            "expires_at": time.time() + self.settings.session_ttl_seconds,
        }
        return token

    def get_session(self, token: str | None) -> str | None:
        if not token:
            return None
        item = self.sessions.get(token)
        if item is None:
            return None
        if item["expires_at"] < time.time():
            self.sessions.pop(token, None)
            return None
        return str(item["username"])

    def delete_session(self, token: str | None) -> None:
        if token:
            self.sessions.pop(token, None)

    # ------------------------------------------------------------------ challenges
    def challenge(self, challenge_id: str) -> MockChallengeState | None:
        return self.challenges.get(challenge_id)

    def challenge_json(self, challenge_id: str) -> dict[str, Any] | None:
        item = self.challenges.get(challenge_id)
        if item is None:
            return None
        seed = item.seed
        attachments = [
            {
                "name": att.name,
                "url": f"/api/challenges/{challenge_id}/attachments/{att.name}",
                "size": att.size,
                "sha256": att.sha256,
            }
            for att in seed.attachments
        ]
        return {
            "id": seed.id,
            "title": seed.title,
            "category": seed.category,
            "score": item.score,
            "description_md": seed.description_md,
            "attachments": attachments,
            "container": {"available": seed.container, "running": item.target is not None},
            "target": item.target,
            "solved": bool(item.solved_by),
            "flag_regex": self.settings.flag_regex,
            "solves": item.solves,
        }

    def challenge_list(self) -> list[dict[str, Any]]:
        return [self.challenge_json(cid) for cid in self.challenges]  # type: ignore[misc]

    # ------------------------------------------------------------------ submission
    async def submit(self, challenge_id: str, flag: str, username: str) -> SubmitOutcome:
        item = self.challenges.get(challenge_id)
        if item is None:
            return SubmitOutcome("unknown", "题目不存在", 404)
        flag = (flag or "").strip()
        async with self._lock:
            if self.submit_attempts >= self.settings.submit_limit:
                return SubmitOutcome(
                    "rejected",
                    f"提交次数已达平台上限（{self.settings.submit_limit} 次）",
                )
            now = time.monotonic()
            if (
                self.settings.submit_interval_seconds > 0
                and self.last_submit_at
                and now - self.last_submit_at < self.settings.submit_interval_seconds
            ):
                return SubmitOutcome("rate_limited", "提交过快，请稍后重试", 429)
            self.submit_attempts += 1
            self.last_submit_at = now

            if flag == item.seed.flag:
                if username in item.solved_by:
                    return SubmitOutcome("already_solved", "该题已解出")
                item.solved_by.add(username)
                item.solves += 1
                item.score = max(500, item.score - 100)  # 动态分
                return SubmitOutcome("accepted", "Flag 正确，得分！")
            return SubmitOutcome("rejected", "Flag 错误")

    # ------------------------------------------------------------------ container
    async def ensure_container(self, challenge_id: str) -> SubmitOutcome | dict[str, Any]:
        item = self.challenges.get(challenge_id)
        if item is None:
            return SubmitOutcome("unknown", "题目不存在", 404)
        if not item.seed.container:
            return SubmitOutcome("rejected", "该题没有容器", 400)
        async with self._lock:
            if item.target is not None:
                return item.target
            await self._start_container()
            assert self.container_port is not None
            expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec="seconds")
            item.target = {
                "kind": "tcp",
                "host": "127.0.0.1",
                "port": self.container_port,
                "url": None,
                "creds": {},
                "expires_at": expires,
            }
            return item.target

    async def _start_container(self) -> None:
        if self._container_server is not None:
            return

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                writer.write(b"=== Baby Echo (mock) ===\nSend token: ")
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=15)
                token = line.decode("utf-8", "replace").strip()
                if token == PWN_TOKEN:
                    writer.write(f"OK\n{PWN_FLAG}\n".encode())
                else:
                    writer.write(b"invalid token\n")
                await writer.drain()
            except (asyncio.TimeoutError, ConnectionError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

        self._container_server = await asyncio.start_server(handle, "127.0.0.1", 0)
        sockets = self._container_server.sockets or []
        self.container_port = int(sockets[0].getsockname()[1]) if sockets else None

    async def close(self) -> None:
        if self._container_server is not None:
            self._container_server.close()
            await self._container_server.wait_closed()
            self._container_server = None


def _render_captcha(answer: str) -> bytes:
    width, height = 128, 44
    image = Image.new("RGB", (width, height), (244, 247, 252))
    draw = ImageDraw.Draw(image)
    font = _load_font(28)
    for index, char in enumerate(answer):
        x = 14 + index * 26 + secrets.randbelow(5)
        y = 6 + secrets.randbelow(7)
        draw.text((x, y), char, font=font, fill=(18 + secrets.randbelow(60), 32, 70 + secrets.randbelow(80)))
    for _ in range(6):
        draw.line(
            (
                secrets.randbelow(width),
                secrets.randbelow(height),
                secrets.randbelow(width),
                secrets.randbelow(height),
            ),
            fill=(170 + secrets.randbelow(70), 180 + secrets.randbelow(50), 200),
            width=1,
        )
    for _ in range(60):
        draw.point((secrets.randbelow(width), secrets.randbelow(height)), fill=(200, 205, 215))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _load_font(size: int) -> ImageFont.ImageFont:
    for path in _FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()
