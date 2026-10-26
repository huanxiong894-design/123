"""YCB 答题页入口：赛段列表解析与 /competePage/{stageId} 导航。"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tests.helpers import make_config
from ycb.adapters.base import SessionExpired
from ycb.adapters.ycb import YCBAdapter, pick_ctf_stage, stage_list_body


class FakeResponse:
    def __init__(self, status: int, payload):
        self.status = status
        self._payload = payload
        self.ok = status < 400

    async def json(self):
        return self._payload


class FakeRequest:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.calls: list[tuple[str, dict]] = []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class FakePage:
    def __init__(self, response: FakeResponse, *, redirect=None):
        self.request = FakeRequest(response)
        self.context = SimpleNamespace(request=self.request)
        self.url = "about:blank"
        self.gotos: list[str] = []
        self.redirect = redirect or {}

    async def goto(self, url, **_kwargs):
        self.gotos.append(url)
        self.url = self.redirect.get(url, url)

    async def evaluate(self, _script):
        return "jwt-value"

    async def wait_for_load_state(self, *_args, **_kwargs):
        return None


def _payload(stages, *, stringify=False):
    tbody = json.dumps(stages, ensure_ascii=False) if stringify else stages
    return {"code": "00000", "data": {"tbody": tbody}}


def test_pick_ctf_stage_prefers_underway():
    stages = [
        {"id": 1, "mode": "AWD", "status": "UNDERWAY"},
        {"id": 2, "mode": "CTF", "status": "PENDING"},
        {"id": 3, "mode": "CTF", "status": "UNDERWAY"},
    ]
    assert pick_ctf_stage(stages)["id"] == 3
    assert pick_ctf_stage([{"id": 9, "mode": "CTF", "status": "END"}])["id"] == 9
    assert pick_ctf_stage([{"id": 1, "mode": "AWD"}]) is None


def test_stage_list_body_accepts_double_encoded_tbody():
    body = stage_list_body(_payload([{"id": 7, "mode": "CTF"}], stringify=True))
    assert body == [{"id": 7, "mode": "CTF"}]
    assert stage_list_body({"data": [{"id": 8}]}) == [{"id": 8}]
    assert stage_list_body({"data": None}) == []


async def _adapter(tmp_path):
    adapter = YCBAdapter(make_config(tmp_path))

    async def noop_settle(_page, **_kwargs):
        return None

    adapter.settle = noop_settle
    return adapter


async def test_goto_answer_page_navigates_to_active_stage(tmp_path):
    stage = {"id": 321, "mode": "CTF", "status": "UNDERWAY"}
    page = FakePage(FakeResponse(200, _payload([stage])))
    adapter = await _adapter(tmp_path)

    assert await adapter._goto_answer_page(page) is True
    assert page.url == "https://ycb-qy.dasctf.com/1749/competePage/321"
    assert adapter._answer_url == page.url
    url, kwargs = page.request.calls[0]
    assert url.endswith("/slab-match/api/v1/match/open/stage-list")
    assert kwargs["params"] == {"id": "1749", "matchId": "1749"}
    assert kwargs["headers"]["matchId"] == "1749"
    assert kwargs["headers"]["authorization"] == "jwt-value"
    await adapter.close()


async def test_goto_answer_page_returns_false_before_release(tmp_path):
    stage = {"id": 321, "mode": "CTF", "status": "PENDING"}
    page = FakePage(FakeResponse(200, _payload([stage], stringify=True)))
    adapter = await _adapter(tmp_path)

    assert await adapter._goto_answer_page(page) is False
    # 未开始时不应白跑一趟详情页
    assert page.gotos == []
    assert adapter._answer_url is None
    await adapter.close()


async def test_goto_answer_page_401_raises_session_expired(tmp_path):
    page = FakePage(FakeResponse(401, {}))
    adapter = await _adapter(tmp_path)

    with pytest.raises(SessionExpired):
        await adapter._goto_answer_page(page)
    await adapter.close()


async def test_discover_job_returns_empty_when_answer_page_absent(tmp_path):
    adapter = await _adapter(tmp_path)

    async def not_yet(_page):
        return False

    adapter._goto_answer_page = not_yet
    assert await adapter._discover_job(object()) == []
    await adapter.close()


async def test_cached_answer_url_is_revalidated(tmp_path):
    stage = {"id": 654, "mode": "CTF", "status": "UNDERWAY"}
    page = FakePage(FakeResponse(200, _payload([stage])))
    adapter = await _adapter(tmp_path)
    cached = "https://ycb-qy.dasctf.com/1749/competePage/321"
    adapter._answer_url = cached

    # 旧赛段 URL 失效（被重定向到登录页）时放弃缓存，按赛段列表重新导航
    page.redirect[cached] = "https://ycb-qy.dasctf.com/1749/login"
    assert await adapter._goto_answer_page(page) is True
    assert page.url == "https://ycb-qy.dasctf.com/1749/competePage/654"
    await adapter.close()
