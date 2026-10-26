"""共享 fixture。"""

from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio

from mock_platform.app import create_mock_app
from mock_platform.settings import MockSettings
from tests.helpers import make_config
from ycb.adapters.mock import MockAdapter
from ycb.db import Database


@pytest.fixture(autouse=True)
def restore_environment():
    """防止 .env / 环境变量测试污染后续用例。"""
    before = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(before)


@pytest_asyncio.fixture
async def db(tmp_path):
    database = Database(tmp_path / "ycb.db")
    await database.connect()
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
def mock_settings() -> MockSettings:
    return MockSettings(
        username="player",
        password="mock-pass-2026",
        submit_limit=50,
        submit_interval_seconds=0.0,
        debug_captcha=True,
    )


@pytest_asyncio.fixture
async def mock_app(mock_settings):
    app = create_mock_app(mock_settings)
    try:
        yield app
    finally:
        await app.state.mock_state.close()


@pytest_asyncio.fixture
async def mock_client(mock_app):
    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://mock.local") as client:
        yield client


@pytest_asyncio.fixture
async def mock_adapter(tmp_path, mock_app):
    config = make_config(tmp_path)
    transport = httpx.ASGITransport(app=mock_app)
    adapter = MockAdapter(config, transport=transport)
    try:
        yield adapter
    finally:
        await adapter.close()
