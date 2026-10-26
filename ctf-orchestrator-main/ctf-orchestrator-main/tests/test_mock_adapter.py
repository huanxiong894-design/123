from __future__ import annotations

import asyncio
import hashlib
import json
import os

import httpx
import pytest

from mock_platform.data import CRYPTO_FLAG, PWN_FLAG, PWN_TOKEN
from tests.helpers import make_config
from ycb.adapters.base import SessionExpired
from ycb.adapters.mock import MockAdapter


async def test_login_discover_detail_download(mock_adapter, tmp_path, mock_app):
    state = await mock_adapter.health()
    assert state.state == "logged_out"

    await mock_adapter.login()
    assert (await mock_adapter.health()).logged_in

    challenges = await mock_adapter.discover()
    assert len(challenges) == 3
    by_id = {challenge.platform_id: challenge for challenge in challenges}
    assert set(by_id) == {"crypto-warmup-rsa", "misc-nested-archive", "pwn-baby-echo"}

    crypto = by_id["crypto-warmup-rsa"]
    detail = await mock_adapter.fetch_detail(crypto)
    assert detail.title == "Warmup RSA"
    assert detail.attachments and detail.attachments[0].name == "warmup_rsa.zip"
    assert detail.attachments[0].sha256

    dest = tmp_path / "downloads"
    paths = await mock_adapter.download(detail, dest)
    assert [path.name for path in paths] == ["warmup_rsa.zip"]
    assert hashlib.sha256(paths[0].read_bytes()).hexdigest() == detail.attachments[0].sha256

    cookie_path = mock_adapter.config.data_dir / "mock" / "cookies.json"
    assert cookie_path.is_file()
    assert json.loads(cookie_path.read_text(encoding="utf-8"))
    if os.name == "posix":
        assert (cookie_path.stat().st_mode & 0o777) == 0o600


async def test_cookie_persistence_across_adapter_instances(tmp_path, mock_app):
    config = make_config(tmp_path)
    transport = httpx.ASGITransport(app=mock_app)

    first = MockAdapter(config, transport=transport)
    try:
        await first.login()
        assert (await first.health()).logged_in
    finally:
        await first.close()

    second = MockAdapter(config, transport=transport)
    try:
        state = await second.health()
        assert state.logged_in, state.detail
    finally:
        await second.close()


async def test_submit_and_solved_state(mock_adapter):
    await mock_adapter.login()
    crypto = next(
        challenge for challenge in await mock_adapter.discover() if challenge.platform_id == "crypto-warmup-rsa"
    )

    wrong = await mock_adapter.submit(crypto, "DASCTF{wrong}")
    assert wrong.status == "rejected"

    accepted = await mock_adapter.submit(crypto, CRYPTO_FLAG)
    assert accepted.status == "accepted"
    assert await mock_adapter.is_solved(crypto)

    again = await mock_adapter.submit(crypto, CRYPTO_FLAG)
    assert again.status == "already_solved"


async def test_session_expiry_is_reported(mock_adapter, mock_app):
    await mock_adapter.login()
    mock_adapter._client.cookies.clear()  # 模拟 cookie 丢失/会话过期

    state = await mock_adapter.health()
    assert state.state == "logged_out"
    with pytest.raises(SessionExpired):
        await mock_adapter.discover()


async def test_container_target(mock_adapter):
    await mock_adapter.login()
    pwn = next(
        challenge for challenge in await mock_adapter.discover() if challenge.container_available
    )
    target = await mock_adapter.ensure_target(pwn)
    assert target is not None
    assert target.kind == "tcp"
    assert target.port

    reader, writer = await asyncio.open_connection(target.host, target.port)
    try:
        await asyncio.wait_for(reader.readuntil(b"Send token: "), timeout=3)
        writer.write((PWN_TOKEN + "\n").encode())
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), timeout=3)
        assert PWN_FLAG.encode() in reply
    finally:
        writer.close()
        await writer.wait_closed()

    again = await mock_adapter.refresh_target(pwn)
    assert again is not None and again.port == target.port
