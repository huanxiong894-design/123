from __future__ import annotations

import asyncio
import hashlib

import httpx

from mock_platform.app import create_mock_app
from mock_platform.data import (
    CRYPTO_FLAG,
    MISC_FLAG,
    PWN_FLAG,
    PWN_TOKEN,
    seed_challenges,
)
from mock_platform.settings import MockSettings
from tests.helpers import login_mock_client


async def test_health_root_and_captcha(mock_client, mock_app):
    health = (await mock_client.get("/api/health")).json()
    assert health["platform"] == "mock"
    assert health["challenges"] == 3
    assert health["debug_captcha"] is True

    root = await mock_client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/compete/1749"

    captcha = (await mock_client.get("/api/captcha")).json()
    assert captcha["captcha_id"]
    assert captcha["answer"]
    image = await mock_client.get(f"/captcha/{captcha['captcha_id']}.png")
    assert image.status_code == 200
    assert image.headers["content-type"] == "image/png"
    assert image.content.startswith(b"\x89PNG")
    debug = await mock_client.get(f"/api/debug/captcha/{captcha['captcha_id']}")
    assert debug.json()["answer"] == captcha["answer"]


async def test_login_requires_fresh_captcha(mock_client):
    captcha = (await mock_client.get("/api/captcha")).json()
    wrong = await mock_client.post(
        "/api/login",
        json={
            "username": "player",
            "password": "mock-pass-2026",
            "captcha_id": captcha["captcha_id"],
            "captcha": "XXXX" if captcha["answer"] != "XXXX" else "YYYY",
        },
    )
    assert wrong.status_code == 400

    # 验证码一次性：即使答案正确，已失败的 captcha 也不能复用
    reused = await mock_client.post(
        "/api/login",
        json={
            "username": "player",
            "password": "mock-pass-2026",
            "captcha_id": captcha["captcha_id"],
            "captcha": captcha["answer"],
        },
    )
    assert reused.status_code == 400


async def test_auth_and_challenge_list(mock_client):
    assert (await mock_client.get("/api/challenges")).status_code == 401
    assert (await mock_client.get("/api/me")).status_code == 401

    await login_mock_client(mock_client)
    me = await mock_client.get("/api/me")
    assert me.status_code == 200 and me.json()["username"] == "player"

    data = (await mock_client.get("/api/challenges")).json()
    assert len(data["challenges"]) == 3
    ids = {item["id"] for item in data["challenges"]}
    assert ids == {"crypto-warmup-rsa", "misc-nested-archive", "pwn-baby-echo"}

    detail = (await mock_client.get("/api/challenges/crypto-warmup-rsa")).json()
    assert detail["title"] == "Warmup RSA"
    assert detail["attachments"][0]["url"].startswith("/api/challenges/crypto-warmup-rsa/attachments/")
    assert detail["attachments"][0]["sha256"]
    pwn = (await mock_client.get("/api/challenges/pwn-baby-echo")).json()
    assert pwn["container"]["available"] is True

    attachment = await mock_client.get(detail["attachments"][0]["url"])
    assert attachment.status_code == 200
    assert hashlib.sha256(attachment.content).hexdigest() == detail["attachments"][0]["sha256"]


async def test_submission_flow_and_dynamic_score(mock_client):
    await login_mock_client(mock_client)
    wrong = await mock_client.post(
        "/api/challenges/crypto-warmup-rsa/submit", json={"flag": "DASCTF{wrong}"}
    )
    assert wrong.status_code == 200
    assert wrong.json()["status"] == "rejected"

    accepted = await mock_client.post(
        "/api/challenges/crypto-warmup-rsa/submit", json={"flag": CRYPTO_FLAG}
    )
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "accepted"

    detail = (await mock_client.get("/api/challenges/crypto-warmup-rsa")).json()
    assert detail["solved"] is True
    assert detail["score"] == 900  # 动态扣分：1000 -> 900

    again = await mock_client.post(
        "/api/challenges/crypto-warmup-rsa/submit", json={"flag": CRYPTO_FLAG}
    )
    assert again.json()["status"] == "already_solved"


async def test_submit_rate_limit(mock_settings):
    mock_settings.submit_interval_seconds = 60.0
    app = create_mock_app(mock_settings)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://mock.local") as client:
            await login_mock_client(client)
            first = await client.post(
                "/api/challenges/misc-nested-archive/submit", json={"flag": "DASCTF{wrong}"}
            )
            assert first.status_code == 200
            second = await client.post(
                "/api/challenges/misc-nested-archive/submit", json={"flag": "DASCTF{wrong2}"}
            )
            assert second.status_code == 429
            assert second.json()["status"] == "rate_limited"
    finally:
        await app.state.mock_state.close()


async def test_submit_hard_limit(mock_settings):
    mock_settings.submit_limit = 2
    app = create_mock_app(mock_settings)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://mock.local") as client:
            await login_mock_client(client)
            for index in range(2):
                resp = await client.post(
                    "/api/challenges/misc-nested-archive/submit",
                    json={"flag": f"DASCTF{{wrong{index}}}"},
                )
                assert resp.status_code == 200
                assert resp.json()["status"] == "rejected"
            blocked = await client.post(
                "/api/challenges/misc-nested-archive/submit", json={"flag": MISC_FLAG}
            )
            assert blocked.json()["status"] == "rejected"
            assert "上限" in blocked.json()["message"]
            assert app.state.mock_state.submit_attempts == 2
    finally:
        await app.state.mock_state.close()


async def test_container_target_and_echo_service(mock_client):
    await login_mock_client(mock_client)
    no_container = await mock_client.post("/api/challenges/crypto-warmup-rsa/container")
    assert no_container.status_code == 400

    started = await mock_client.post("/api/challenges/pwn-baby-echo/container")
    assert started.status_code == 200
    target = started.json()["target"]
    assert target["kind"] == "tcp"
    assert target["host"] == "127.0.0.1"
    assert target["port"] > 0

    again = await mock_client.post("/api/challenges/pwn-baby-echo/container")
    assert again.json()["target"]["port"] == target["port"]

    reader, writer = await asyncio.open_connection(target["host"], target["port"])
    try:
        banner = await asyncio.wait_for(reader.readuntil(b"Send token: "), timeout=3)
        assert b"Baby Echo" in banner
        writer.write((PWN_TOKEN + "\n").encode())
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), timeout=3)
        assert PWN_FLAG.encode() in reply
    finally:
        writer.close()
        await writer.wait_closed()

    # 错误 token 不给 flag
    reader, writer = await asyncio.open_connection(target["host"], target["port"])
    try:
        await asyncio.wait_for(reader.readuntil(b"Send token: "), timeout=3)
        writer.write(b"wrong\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), timeout=3)
        assert PWN_FLAG.encode() not in reply
        assert b"invalid token" in reply
    finally:
        writer.close()
        await writer.wait_closed()


async def test_seed_data_is_deterministic():
    first = seed_challenges()
    second = seed_challenges()
    assert [item.id for item in first] == [item.id for item in second]
    for left, right in zip(first, second):
        assert [a.name for a in left.attachments] == [a.name for a in right.attachments]
        for a, b in zip(left.attachments, right.attachments):
            assert a.content == b.content
            assert a.sha256 == b.sha256
    seeded = {item.id: item for item in first}
    assert seeded["pwn-baby-echo"].container is True
    assert seeded["crypto-warmup-rsa"].flag == CRYPTO_FLAG
