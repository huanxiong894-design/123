from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tests.helpers import make_challenge, make_config
from ycb.db import Database
from ycb.models import SessionState, SubmitResult
from ycb.web.app import create_app


class FakeBackend:
    """不启动真实 CLI 的 Agent backend，供看板接口测试。"""

    instances: list["FakeBackend"] = []

    def __init__(self, spec, config, emit, run_id=None):
        self.spec = spec
        self.config = config
        self.emit = emit
        self.run_id = run_id
        self.session_id = spec.session_id or f"fake-session-{run_id}"
        self.pid = 4242
        self.pgid = 4242
        self.raw_path = None
        self.alive = False
        self.sent: list[str] = []
        self._exit = asyncio.Event()
        FakeBackend.instances.append(self)

    async def start(self) -> None:
        self.alive = True

    async def send(self, text: str) -> bool:
        if not self.alive:
            return False
        self.sent.append(text)
        return True

    async def interrupt(self, *, control_timeout: float = 3.0) -> bool:
        self.alive = False
        self._exit.set()
        return True

    async def stop(self) -> None:
        await self.interrupt()

    async def wait(self) -> int | None:
        await self._exit.wait()
        return 0

    async def close(self) -> None:
        self.alive = False


class FakeAdapter:
    name = "fake"
    capabilities: set[str] = {"attachments"}

    def __init__(self) -> None:
        self.session = SessionState(state="logged_in", detail="fake 会话")

    async def login(self) -> None:
        self.session = SessionState(state="logged_in", detail="fake 登录")

    async def health(self) -> SessionState:
        return self.session

    async def discover(self):
        return []

    async def fetch_detail(self, challenge):
        return challenge

    async def download(self, challenge, dest):
        return []

    async def ensure_target(self, challenge):
        return None

    async def refresh_target(self, challenge):
        return None

    async def submit(self, challenge, flag):
        return SubmitResult("unknown", "fake")

    async def is_solved(self, challenge):
        return False

    async def close(self) -> None:
        pass


def seed_challenge(config) -> int:
    async def _seed() -> int:
        db = Database(config.db_path)
        await db.connect()
        try:
            seq = await db.allocate_seq_no("mock", "1749")
            challenge = make_challenge(
                "c1", title="Warmup RSA", category="Crypto", score=1000, description_md="mock desc"
            )
            challenge_id = await db.insert_challenge(
                challenge,
                seq_no=seq,
                workspace=str(config.challenges_dir / "01_crypto_warmup_rsa_deadbeef"),
                flag_regex=r"^DASCTF\{.*\}$",
            )
            return challenge_id
        finally:
            await db.close()

    return asyncio.run(_seed())


@pytest.fixture
def dashboard(tmp_path):
    config = make_config(tmp_path, discovery_enabled=False)
    challenge_id = seed_challenge(config)
    app = create_app(
        config,
        adapter_factory=lambda cfg: FakeAdapter(),
        agent_factory=FakeBackend,
    )
    with TestClient(app) as client:
        yield client, config, challenge_id


def test_index_headers_and_static(dashboard):
    client, _, _ = dashboard
    index = client.get("/")
    assert index.status_code == 200
    assert "2026 年" in index.text
    csp = index.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert index.headers["x-frame-options"] == "DENY"
    assert index.headers["x-content-type-options"] == "nosniff"

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "WebSocket" in script.text
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/favicon.ico").status_code == 204


def test_overview_and_challenge_api(dashboard):
    client, _, challenge_id = dashboard
    health = client.get("/api/health").json()
    assert health["ok"] is True
    assert health["platform"] == "mock"
    assert health["dry_run"] is True

    overview = client.get("/api/overview").json()
    assert overview["total"] == 1
    assert overview["counts"]["DISCOVERED"] == 1
    assert overview["features"]["agent_control"] is True
    assert overview["features"]["auto_submit"] is True
    assert overview["features"]["flag_watch"] is True
    assert overview["agents_running"] == 0
    assert overview["session"]["state"] == "logged_in"
    assert overview["dry_run"] is True

    challenges = client.get("/api/challenges").json()["challenges"]
    assert len(challenges) == 1
    assert challenges[0]["id"] == challenge_id
    assert challenges[0]["title"] == "Warmup RSA"

    detail = client.get(f"/api/challenges/{challenge_id}").json()
    assert detail["challenge"]["workspace"].endswith("01_crypto_warmup_rsa_deadbeef")
    assert detail["messages"] == []
    assert detail["runs"] == []
    assert client.get("/api/challenges/99999").status_code == 404


def test_message_starts_agent_and_controls(dashboard):
    client, _, challenge_id = dashboard
    response = client.post(f"/api/challenges/{challenge_id}/message", json={"content": "先看附件"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["delivered"] is True
    assert payload["run_id"] is not None

    detail = client.get(f"/api/challenges/{challenge_id}").json()
    assert detail["challenge"]["status"] == "SOLVING"
    assert len(detail["messages"]) == 1
    assert detail["messages"][0]["content"] == "先看附件"
    assert detail["messages"][0]["direction"] == "operator"
    assert detail["messages"][0]["delivered"] == 1
    assert detail["runs"][-1]["status"] == "RUNNING"

    assert client.post(f"/api/challenges/{challenge_id}/message", json={"content": "   "}).status_code == 422
    assert client.post(f"/api/challenges/{challenge_id}/message", json={"content": ""}).status_code == 422

    pause = client.post(f"/api/challenges/{challenge_id}/pause")
    assert pause.status_code == 200
    assert client.get(f"/api/challenges/{challenge_id}").json()["challenge"]["status"] == "PAUSED"

    resumed = client.post(f"/api/challenges/{challenge_id}/resume")
    assert resumed.status_code == 200
    assert resumed.json()["started"] is True
    assert client.get(f"/api/challenges/{challenge_id}").json()["challenge"]["status"] == "SOLVING"

    stopped = client.post(f"/api/challenges/{challenge_id}/stop")
    assert stopped.status_code == 200
    assert client.get(f"/api/challenges/{challenge_id}").json()["challenge"]["status"] == "STOPPED"

    restarted = client.post(f"/api/challenges/{challenge_id}/restart", json={"mode": "fresh"})
    assert restarted.status_code == 200
    assert restarted.json()["started"] is True

    # dry_run=true：手动提交只落库，不请求平台
    submit = client.post(
        f"/api/challenges/{challenge_id}/submit", json={"flag": "DASCTF{manual_probe_2026}"}
    )
    assert submit.status_code == 200
    payload = submit.json()
    assert payload["status"] == "dry_run" and payload["dry_run"] is True
    detail = client.get(f"/api/challenges/{challenge_id}").json()
    assert detail["submissions"][-1]["status"] == "dry_run"
    assert detail["submissions"][-1]["flag_masked"] != "DASCTF{manual_probe_2026}"

    # 同一 flag 不重复入库
    again = client.post(
        f"/api/challenges/{challenge_id}/submit", json={"flag": "DASCTF{manual_probe_2026}"}
    )
    assert again.status_code == 200
    assert again.json().get("duplicate") is True

    # 占位符/非法格式在入队前就被拒绝
    bad = client.post(f"/api/challenges/{challenge_id}/submit", json={"flag": "DASCTF{test}"})
    assert bad.status_code == 422

    assert client.post("/api/actions/pause-all").status_code == 200
    assert client.post("/api/actions/resume-all").status_code == 200
    assert client.post("/api/actions/stop-all").status_code == 200


def test_websocket_hello_replay_and_ping(dashboard):
    client, _, challenge_id = dashboard

    with client.websocket_connect("/ws") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        assert hello["payload"]["resync"] is True
        assert hello["payload"]["overview"]["total"] == 1
        assert hello["payload"]["challenges"][0]["id"] == challenge_id
        # resync 时附带最近持久化事件，首次打开看板也能看到启动/发现历史
        assert [e["type"] for e in hello["payload"]["events"]] == ["system.ready"]
        ws.send_json({"type": "ping", "ts": 123})
        pong = ws.receive_json()
        assert pong["type"] == "pong"
        assert pong["payload"]["ts"] == 123

    # since_seq=0 时补发启动事件 system.ready
    with client.websocket_connect("/ws?since_seq=0") as ws:
        hello = ws.receive_json()
        assert hello["payload"]["resync"] is False
        assert hello["payload"]["events"] == []  # 增量补发，历史事件走 replay
        replayed = ws.receive_json()
        assert replayed["type"] == "system.ready"

    # 越界 since_seq 强制 resync
    with client.websocket_connect("/ws?since_seq=999999") as ws:
        hello = ws.receive_json()
        assert hello["payload"]["resync"] is True


def test_websocket_live_operator_message(dashboard):
    client, _, challenge_id = dashboard

    with client.websocket_connect("/ws?since_seq=1") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        response = client.post(f"/api/challenges/{challenge_id}/message", json={"content": "实时消息"})
        assert response.status_code == 200
        # 启动 Agent 会先产生 status.changed / run.started，找到投递事件即可
        seen: list[str] = []
        for _ in range(20):
            event = ws.receive_json()
            seen.append(event["type"])
            if event["type"] == "operator.message":
                break
        else:  # pragma: no cover - 便于失败时排查
            raise AssertionError(f"未收到 operator.message：{seen}")
        assert event["challenge_id"] == challenge_id
        assert event["payload"]["content"] == "实时消息"
        assert event["payload"]["delivered"] is True


class OneChallengeAdapter(FakeAdapter):
    async def discover(self):
        return [make_challenge("auto", title="Auto Start", category="Misc", score=100)]

    async def fetch_detail(self, challenge):
        return challenge


def test_discovery_auto_starts_agent(tmp_path):
    config = make_config(tmp_path, discovery_enabled=True, confirm_passes=2, interval=0.01)
    config.agent.auto_start = True
    config.agent.stagger_min_seconds = 0
    config.agent.stagger_max_seconds = 0
    app = create_app(
        config,
        adapter_factory=lambda cfg: OneChallengeAdapter(),
        agent_factory=FakeBackend,
    )
    with TestClient(app) as client:
        status = None
        for _ in range(100):
            challenges = client.get("/api/challenges").json()["challenges"]
            if challenges and challenges[0]["status"] == "SOLVING":
                status = challenges[0]["status"]
                break
            time.sleep(0.05)
        assert status == "SOLVING"
        overview = client.get("/api/overview").json()
        assert overview["agents_running"] == 1
        assert FakeBackend.instances[-1].sent


def test_create_app_applies_unmask_setting(tmp_path):
    from ycb.agents.normalize import flag_masking_enabled, set_flag_masking

    config = make_config(tmp_path, discovery_enabled=False)
    config.server.unmask_flags = True
    try:
        create_app(config, adapter_factory=lambda cfg: FakeAdapter())
        assert flag_masking_enabled() is False
    finally:
        set_flag_masking(True)


def test_unmask_submission_flag():
    from ycb.web.api import _mask_submission

    row = {"flag": "DASCTF{plain_flag_2026}"}
    masked = _mask_submission(dict(row))
    assert masked["flag_masked"] != row["flag"] and "flag" not in masked
    plain = _mask_submission(dict(row), unmask=True)
    assert plain["flag"] == row["flag"] and plain["flag_masked"] == row["flag"]


def test_token_auth(tmp_path):
    config = make_config(tmp_path, discovery_enabled=False)
    config.server.token = "top-secret"
    seed_challenge(config)
    app = create_app(config, adapter_factory=lambda cfg: FakeAdapter())

    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 401
        assert client.get("/api/health", headers={"Authorization": "Bearer top-secret"}).status_code == 200
        assert client.get("/api/health?token=top-secret").status_code == 200
        assert client.get("/api/health", headers={"Authorization": "Bearer wrong"}).status_code == 401

        # 首页带 token 会种 HttpOnly cookie，之后的 API 请求可复用
        page = client.get("/?token=top-secret")
        assert page.status_code == 200
        assert client.get("/api/health").status_code == 200

        client.cookies.clear()
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws"):
                pass
