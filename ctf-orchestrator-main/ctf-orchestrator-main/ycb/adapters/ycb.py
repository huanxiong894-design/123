"""2026 羊城杯 / DASCTF 平台适配器。

- Playwright 持久化 profile + ddddocr 登录，失败保留截图转人工；
- 只读调用页面自身的赛段列表接口定位 /competePage/{stageId}；
  题目发现以被动网络响应为主、DOM 点击为兜底；
- 下载附件、启动容器、提交均走浏览器 actor 串行执行；
- 平台细节只存在于本文件和 selectors/ycb.toml，内核不感知。

已知边界（M2 逐步校准）：
- 题目释放前答题页不可用，discover() 返回空列表而不是报错；
- 容器/提交选择器在真实题目出现后按 var/debug/platform 的快照校准。
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import html
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

import httpx

from ycb.adapters.base import (
    LoginFailed,
    NeedsHuman,
    PlatformError,
    SessionExpired,
)
from ycb.adapters.browser_base import BrowserAdapterBase, first_visible, fill_first
from ycb.agents.normalize import redact_text
from ycb.models import (
    Attachment,
    Challenge,
    SessionState,
    SubmitResult,
    Target,
    make_uid,
    now_iso,
    platform_key,
)
from ycb.platform.browser import Priority
from ycb.platform.captcha import CaptchaSolver
from ycb.platform.recorder import redact
from ycb.workspace.layout import safe_filename

log = logging.getLogger(__name__)

_MAX_WALK_NODES = 5000
_MAX_DETAIL_CLICKS = 60
_LOGIN_TIMEOUT_MS = 15000
_MAX_ATTACHMENT_BYTES = 512 * 1024 * 1024
_LOGIN_HUMAN_COOLDOWN = 300.0
_STAGE_LIST_PATH = "/slab-match/api/v1/match/open/stage-list"
_EXERCISE_LIST_PATH = "/slab-match/api/v1/player/ctf/exercise-list"
_EXERCISE_DETAIL_PATH = "/slab-match/api/v1/player/ctf/exercise"
_BUILD_ENV_PATH = "/slab-match/api/v1/player/ctf/build-exercise-env"
# 前端把 recover 端点用于“销毁靶机”，expire 端点实际是“延迟/续期”。
_EXPIRE_ENV_PATH = "/slab-match/api/v1/player/ctf/recover-exercise-env"
_ANSWER_PATH = "/slab-match/api/v1/player/answer-panel/answer"
_MONITOR_ANSWER_PATH = "/slab-match/api/v1/player/answer-panel/monitor-answer-result"
_ACTIVE_STAGE_STATUS = "UNDERWAY"

_ID_KEYS = ("exerciseId", "corpusId", "topicId", "questionId", "id")
_NAME_KEYS = ("exerciseName", "name", "title", "topicName", "corpusName", "questionName")
_SCORE_KEYS = ("exerciseScore", "score", "topicScore", "baseScore", "integral", "points")
_DESC_KEYS = (
    "exerciseDesc",
    "description",
    "topicDesc",
    "questionContent",
    "content",
    "desc",
    "introduction",
)
_CATEGORY_KEYS = (
    "corpusClassify",
    "classify",
    "category",
    "categoryName",
    "typeName",
    "moduleName",
    "topicType",
    "exerciseType",
)
_ATTACH_KEYS = ("attachment", "attachments", "exerciseAttachments", "fileList", "files")
_SOLVED_KEYS = ("hasSolved", "isSolved", "solved", "answered", "hasAnswered", "isAnswered")
_CONTAINER_KEYS = ("endpoints", "endpointList", "isNeedInit", "isNeedCheck", "hasEndpoint")

_LABEL_TITLE = ("题目名称", "题目", "名称", "题目标题")
_LABEL_DESC = ("题目内容", "题目描述", "描述", "题目说明")
_LABEL_SCORE = ("题目分值", "分值", "分数", "基础分值")
_LABEL_CATEGORY = ("题目类型", "类型", "分类")


# --------------------------------------------------------------------------- utils
def decode_data_url(src: str | None) -> bytes:
    """解码 ``data:image/...;base64,...``；非 base64 data URL 返回空。"""
    if not src or not src.startswith("data:"):
        return b""
    header, _, payload = src.partition(",")
    if ";base64" not in header or not payload:
        return b""
    try:
        return base64.b64decode(payload, validate=False)
    except (ValueError, binascii.Error):
        return b""


def html_to_text(value: Any) -> str:
    """把平台富文本说明压成可读文本，保留链接/图片的 Markdown 形式。"""
    text = str(value or "")
    if "<" not in text or ">" not in text:
        return text.strip()
    text = re.sub(
        r'(?is)<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        lambda m: f"[{re.sub(r'<[^>]+>', '', m.group(2)).strip()}]({m.group(1)})",
        text,
    )
    text = re.sub(r'(?is)<img\s+[^>]*src=["\']([^"\']+)["\'][^>]*>', r"![](\1)", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</(div|li|tr)\s*>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _first(mapping: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    match = re.search(r"-?\d+", str(value))
    return int(match.group()) if match else None


def _score_int(value: Any) -> int | None:
    """分数字段可能是“已答出0次，当前分值500.0”这类文案，取当前分值。"""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    match = re.search(r"(?:当前分值|初始分值|解出分值)\s*([0-9]+(?:\.[0-9]+)?)", str(value))
    if match:
        return int(float(match.group(1)))
    return _as_int(value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "solved", "answered"}


def _boolish(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "success", "correct"}:
        return True
    if text in {"false", "0", "no", "n", "fail", "failed", "wrong"}:
        return False
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    match = re.search(r"-?\d+(?:\.\d+)?", str(value))
    return float(match.group()) if match else None


_FLAG_WRAP_RE = re.compile(r"^(?:DASCTF|flag)\{(.*)\}$", re.DOTALL)


def _answer_value(flag: str) -> str:
    """平台答题框只填大括号内的内容，例如 DASCTF{abc} -> abc。"""
    text = flag.strip()
    match = _FLAG_WRAP_RE.match(text)
    return match.group(1).strip() if match else text


def _detail_solved(detail: Any) -> bool:
    data = detail.get("data") if isinstance(detail, dict) else None
    if not isinstance(data, dict):
        return False
    return _as_bool(data.get("hasSolved"))


def _maybe_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in '[{"':
        return value
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return value


def _category_name(value: Any) -> str:
    value = _maybe_json(value)
    if isinstance(value, dict):
        for key in ("name", "label", "title", "value", "classifyName"):
            if value.get(key):
                return str(value[key])
        return ""
    if isinstance(value, list):
        parts = [_category_name(item) for item in value]
        return "/".join(part for part in parts if part)
    return str(value or "").strip()


def _attachment_list(value: Any, base_url: str) -> list[Attachment]:
    value = _maybe_json(value)
    if isinstance(value, (str, dict)):
        value = [value]
    if not isinstance(value, list):
        return []
    out: list[Attachment] = []
    seen: set[str] = set()
    for item in value:
        if isinstance(item, str):
            name, url, size = item, "", None
        elif isinstance(item, dict):
            name = str(_first(item, ("name", "fileName", "filename", "title", "code")) or "").strip()
            url = str(_first(item, ("url", "downloadUrl", "href", "path")) or "").strip()
            size = _as_int(_first(item, ("size", "fileSize", "length")))
            if not name and url:
                name = Path(urlparse(url).path).name
        else:
            continue
        name = safe_filename(name or "attachment.bin")
        if not name or name in seen:
            continue
        if url and not url.startswith(("http://", "https://", "data:")):
            url = urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
        seen.add(name)
        out.append(Attachment(name=name, url=url, size=size))
    return out


def _endpoint_host_port(endpoint: dict[str, Any]) -> tuple[str, int | None] | None:
    ips = endpoint.get("exposeIps") or endpoint.get("exposeIps".lower()) or []
    if isinstance(ips, str):
        ips = [part for part in re.split(r"[,，、\s]+", ips) if part]
    host = ""
    port: int | None = None
    for ip in ips if isinstance(ips, list) else []:
        text = str(ip).strip()
        match = re.match(r"^([^:]+):(\d+)$", text)
        if match:
            host, port = match.group(1), int(match.group(2))
            break
        if text and not host:
            host = text

    mappings = endpoint.get("portMappings") or endpoint.get("portMapping") or []
    proxy_port: int | None = None
    for mapping in mappings:
        if isinstance(mapping, dict):
            for key in ("proxy", "hostPort", "publicPort", "mappedPort"):
                value = _as_int(mapping.get(key))
                if value:
                    proxy_port = proxy_port or value
                    break
            if proxy_port:
                break
    if proxy_port:
        # 平台创建过程中 exposeIps 可能先是容器内网地址，公网代理端口在
        # portMappings[].proxy；能用公网地址时优先用公网地址。
        proxy_hosts = endpoint.get("proxyIps") or []
        if isinstance(proxy_hosts, str):
            proxy_hosts = [proxy_hosts]
        if proxy_hosts:
            host = str(proxy_hosts[0]).strip() or host
        if port is None:
            port = proxy_port

    for mapping in mappings:
        if isinstance(mapping, dict) and port is None:
            for key in ("port", "targetPort"):
                value = _as_int(mapping.get(key))
                if value:
                    port = value
                    break
        elif isinstance(mapping, str) and port is None:
            match = re.search(r"(\d+)\s*$", mapping)
            if match:
                port = int(match.group(1))
    if not host:
        return None
    return host, port


def target_from_payload(payload: Any) -> Target | None:
    """从任意外层响应里寻找 endpoint/exposeIps 并归一化为 Target。"""
    found: list[Target] = []
    nodes = [payload]
    seen = 0
    while nodes and seen < _MAX_WALK_NODES:
        node = nodes.pop()
        seen += 1
        if isinstance(node, str):
            parsed = _maybe_json(node)
            if isinstance(parsed, (dict, list)):
                nodes.append(parsed)
            continue
        if isinstance(node, dict):
            if "exposeIps" in node or "portMappings" in node:
                pair = _endpoint_host_port(node)
                if pair:
                    host, port = pair
                    found.append(Target(kind="tcp", host=host, port=port))
            nodes.extend(node.values())
        elif isinstance(node, list):
            nodes.extend(node)
    return found[0] if found else None


def _raw_subset(data: dict[str, Any]) -> dict[str, Any]:
    keys = {
        *_ID_KEYS,
        *_NAME_KEYS,
        *_SCORE_KEYS,
        *_CATEGORY_KEYS,
        *_SOLVED_KEYS,
        *_CONTAINER_KEYS,
        "difficulty",
        "status",
        "mode",
        "isOpen",
        "hasEndpoint",
        "isEndpointUp",
    }
    out: dict[str, Any] = {}
    for key in keys:
        if key in data:
            value = data[key]
            if isinstance(value, str) and len(value) > 20000:
                continue
            out[key] = value
    return out


def normalize_candidate(
    data: dict[str, Any], *, base_url: str, competition_id: str
) -> Challenge | None:
    name = _first(data, _NAME_KEYS)
    raw_id = _first(data, _ID_KEYS)
    if raw_id is None or isinstance(raw_id, bool):
        return None
    if not name:
        return None
    title = html_to_text(name).strip()
    if not title:
        return None

    score = _score_int(_first(data, _SCORE_KEYS))
    description = html_to_text(_first(data, _DESC_KEYS))
    attachments = _attachment_list(_first(data, _ATTACH_KEYS), base_url)
    category = _category_name(_first(data, _CATEGORY_KEYS)) or "misc"
    # 只有“题目”才具备分值/说明/附件；纯分类 tab（name+id+corpus）不满足
    if score is None and not description and not attachments:
        return None

    pid = str(raw_id)
    key = platform_key(pid)
    solved = any(_as_bool(data.get(item)) for item in _SOLVED_KEYS if item in data)
    endpoints = _first(data, ("endpoints", "endpointList"))
    container = bool(endpoints) or any(_as_bool(data.get(item)) for item in ("isNeedInit", "isNeedCheck", "hasEndpoint") if item in data)
    target = target_from_payload(endpoints) if endpoints else None

    return Challenge(
        uid=make_uid("ycb", competition_id, key),
        platform="ycb",
        competition_id=competition_id,
        platform_id=pid,
        title=title,
        category=category,
        score=score,
        description_md=description,
        attachments=attachments,
        target=target,
        container_available=container,
        solved_on_platform=solved,
        raw=_raw_subset(data),
    )


def category_hints(payload: Any) -> dict[str, str]:
    """从 ``typeList[].corpus``（可能是 JSON 字符串）提取 id -> 分类名。"""
    hints: dict[str, str] = {}
    nodes = [payload]
    seen = 0
    while nodes and seen < _MAX_WALK_NODES:
        node = nodes.pop()
        seen += 1
        if isinstance(node, str):
            parsed = _maybe_json(node)
            if isinstance(parsed, (dict, list)):
                nodes.append(parsed)
            continue
        if isinstance(node, dict):
            category = _category_name(
                _first(node, ("name", "stageName", "typeName", "classifyName", "categoryName"))
            )
            if category:
                for key in ("corpus", "normal", "ctl", "exerciseList", "list"):
                    items = _maybe_json(node.get(key))
                    if isinstance(items, str):
                        items = _maybe_json(items)
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        if isinstance(item, dict):
                            raw_id = _first(item, _ID_KEYS)
                            if raw_id is not None and not isinstance(raw_id, bool):
                                hints.setdefault(str(raw_id), category)
            nodes.extend(node.values())
        elif isinstance(node, list):
            nodes.extend(node)
    return hints


def extract_challenges(
    payload: Any, *, base_url: str = "", competition_id: str = "1749"
) -> list[Challenge]:
    """递归扫描任意 JSON 响应，选出题目候选并合并。"""
    normalized: dict[str, Challenge] = {}
    order: list[str] = []
    nodes = [payload]
    seen_nodes = 0
    while nodes and seen_nodes < _MAX_WALK_NODES:
        node = nodes.pop()
        seen_nodes += 1
        if isinstance(node, str):
            parsed = _maybe_json(node)
            if isinstance(parsed, (dict, list)):
                nodes.append(parsed)
            elif isinstance(parsed, str) and parsed != node:
                nodes.append(parsed)  # 双重 JSON 编码
            continue
        if isinstance(node, dict):
            challenge = normalize_candidate(node, base_url=base_url, competition_id=competition_id)
            if challenge is not None:
                if challenge.uid not in normalized:
                    normalized[challenge.uid] = challenge
                    order.append(challenge.uid)
                else:
                    normalized[challenge.uid] = merge_challenge(normalized[challenge.uid], challenge)
            nodes.extend(node.values())
        elif isinstance(node, list):
            nodes.extend(node)
    hints = category_hints(payload)
    for uid in order:
        challenge = normalized[uid]
        hint = hints.get(challenge.platform_id)
        if hint and (not challenge.category or challenge.category == "misc"):
            challenge.category = hint
    return [normalized[uid] for uid in order]


def merge_challenge(first: Challenge, second: Challenge) -> Challenge:
    """同一题的多份候选（列表 + 详情）合并，详情优先。"""
    base = first
    other = second
    if _completeness(second) > _completeness(first):
        base, other = second, first
    if len(other.description_md) > len(base.description_md):
        base.description_md = other.description_md
    if base.score is None:
        base.score = other.score
    if not base.category or base.category == "misc":
        base.category = other.category or base.category
    if other.target and not base.target:
        base.target = other.target
    names = {item.name for item in base.attachments}
    for attachment in other.attachments:
        if attachment.name not in names:
            base.attachments.append(attachment)
            names.add(attachment.name)
    base.container_available = base.container_available or other.container_available
    base.solved_on_platform = base.solved_on_platform or other.solved_on_platform
    if not base.raw:
        base.raw = other.raw
    return base


def _completeness(challenge: Challenge) -> int:
    return (
        len(challenge.description_md)
        + len(challenge.attachments) * 200
        + (300 if challenge.score is not None else 0)
        + (200 if challenge.target else 0)
    )


def pick_ctf_stage(stages: list[dict[str, Any]]) -> dict[str, Any] | None:
    """从 open/stage-list 中选出 CTF 赛段；进行中优先，其次未开始。"""
    ctf = [item for item in stages if str(item.get("mode", "")).upper() == "CTF"]
    if not ctf:
        return None
    for status in (_ACTIVE_STAGE_STATUS, "PENDING"):
        for item in ctf:
            if str(item.get("status", "")).upper() == status:
                return item
    return ctf[-1]


def stage_list_body(payload: Any) -> list[dict[str, Any]]:
    """兼容 data.tbody 为数组或二次编码 JSON 字符串。"""
    data = payload.get("data") if isinstance(payload, dict) else payload
    if isinstance(data, dict):
        data = data.get("tbody", data.get("list", data.get("rows")))
    data = _maybe_json(data)
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def parse_detail_snapshot(
    snapshot: dict[str, Any] | None,
    *,
    base_url: str,
    competition_id: str,
    category: str = "misc",
) -> Challenge | None:
    """把页面上的 ``.info_item`` 文本归一化；仅用于 DOM 兜底。"""
    if not snapshot:
        return None
    items = {str(key).strip("：: "): str(value).strip() for key, value in (snapshot.get("items") or {}).items()}
    title = next((items[key] for key in _LABEL_TITLE if items.get(key)), "")
    if not title:
        title = str(snapshot.get("title") or "").strip()
    if not title:
        text = str(snapshot.get("text") or "").strip().splitlines()
        title = text[0].strip() if text else ""
    if not title:
        return None
    description = next((items[key] for key in _LABEL_DESC if items.get(key)), "")
    score = _as_int(next((items[key] for key in _LABEL_SCORE if items.get(key)), None))
    category = next((items[key] for key in _LABEL_CATEGORY if items.get(key)), category) or "misc"
    files = snapshot.get("files") or []
    attachments = [
        Attachment(name=safe_filename(str(name)))
        for name in files
        if str(name).strip()
    ]
    # DOM 不提供稳定的题目 id：只用标题生成稳定指纹（分值可能动态变化，
    # 分类 tab 也可能识别失败，不能进入 key，否则同题会重复建库）。
    key = platform_key(None, title=_title_key(title), fallback="dom")
    return Challenge(
        uid=make_uid("ycb", competition_id, key),
        platform="ycb",
        competition_id=competition_id,
        platform_id=key,
        title=title,
        category=category or "misc",
        score=score,
        description_md=description,
        attachments=attachments,
        raw={"source": "dom", "items": items},
    )


# --------------------------------------------------------------------------- adapter
class YCBAdapter(BrowserAdapterBase):
    name = "ycb"
    capabilities = {"captcha", "attachments", "container", "submit_ui", "dynamic_score"}

    def __init__(self, config):
        super().__init__(config)
        self.base_url = config.platform.base_url.rstrip("/")
        self.competition_id = config.platform.competition_id
        self.detail_url = f"{self.base_url}/compete/{self.competition_id}/detail"
        self.login_url = f"{self.base_url}/{self.competition_id}/login"
        self._session = SessionState(state="unknown", detail="尚未检查登录状态")
        self._answer_url: str | None = None
        self._dom_index: dict[str, int] = {}
        self._detail_cache: dict[str, Challenge] = {}
        self._captcha = CaptchaSolver()
        self._login_retry_at = 0.0
        self._rate_limit = asyncio.Lock()  # actor 已串行，这里只防重入登录

    @property
    def session(self) -> SessionState:
        return self._session

    def _set_session(self, state: str, detail: str, username: str | None = None) -> SessionState:
        self._session = SessionState(state=state, detail=detail, username=username, at=now_iso())
        return self._session

    async def _auth_state(self, page) -> dict[str, Any]:
        try:
            return await page.evaluate(
                """() => {
                    const keys = Object.keys(localStorage);
                    const tokenKey = keys.find(k => k === 'jwtToken' || k.startsWith('jwtToken-'));
                    const token = tokenKey ? localStorage.getItem(tokenKey) : '';
                    return {
                        token: !!token,
                        path: location.pathname + location.search,
                        portal: !!document.querySelector('.portal-user, .user_info_popover_user'),
                        captchaInput: !!document.querySelector("input[placeholder*='验证码']"),
                    };
                }"""
            )
        except Exception:
            return {"token": False, "path": "", "portal": False, "captchaInput": False}

    @staticmethod
    def _looks_logged_in(state: dict[str, Any]) -> bool:
        path = str(state.get("path") or "")
        if "/login" in path:
            return False
        return bool(state.get("token") or state.get("portal"))

    async def _wait_first(self, page, selectors: list[str], timeout_ms: int):
        deadline = asyncio.get_running_loop().time() + timeout_ms / 1000
        while asyncio.get_running_loop().time() < deadline:
            locator = await first_visible(page, selectors, timeout=0.4)
            if locator is not None:
                return locator
            await asyncio.sleep(0.25)
        return None

    # ------------------------------------------------------------------ login
    async def login(self) -> None:
        if not self.config.platform.username or not self.config.platform.password:
            self._set_session("error", "缺少 YCB_USERNAME / YCB_PASSWORD")
            raise LoginFailed("缺少平台凭据：请把账号密码放进 .env 的 YCB_USERNAME / YCB_PASSWORD")
        remaining = self._login_retry_at - asyncio.get_running_loop().time()
        if remaining > 0:
            raise NeedsHuman(
                f"登录连续失败，等待人工处理（约 {remaining:.0f}s 后再试）；"
                f"查看 {self.config.debug_dir}/ 下截图"
            )
        try:
            await self.actor.submit(
                "ycb-login",
                self._login_job,
                priority=Priority.LOGIN,
                timeout=180,
            )
        except NeedsHuman:
            self._login_retry_at = asyncio.get_running_loop().time() + _LOGIN_HUMAN_COOLDOWN
            raise
        except LoginFailed:
            raise
        except Exception as exc:
            self._login_retry_at = asyncio.get_running_loop().time() + _LOGIN_HUMAN_COOLDOWN
            paths: dict[str, str] = {}
            with contextlib.suppress(Exception):
                paths = await self.debug_snapshot("login-error")
            detail = f"登录异常：{type(exc).__name__}: {exc}"
            if paths.get("screenshot"):
                detail += f"；截图={paths['screenshot']}"
            self._set_session("needs_human", detail)
            raise NeedsHuman(detail) from exc

    async def _login_job(self, page) -> None:
        async with self._rate_limit:
            await page.goto(self.detail_url, wait_until="domcontentloaded", timeout=_LOGIN_TIMEOUT_MS)
            await self.settle(page)
            state = await self._auth_state(page)
            if self._looks_logged_in(state):
                self._set_session("logged_in", "持久化 profile 已登录", self.config.platform.username)
                log.info("检测到已登录，复用持久化 profile")
                return

            errors: list[str] = []
            human_reason: str | None = None
            for attempt in range(1, self.config.browser.captcha_retries + 1):
                await page.goto(self.login_url, wait_until="domcontentloaded", timeout=_LOGIN_TIMEOUT_MS)
                await self.settle(page, timeout_ms=3000)
                cap = await self._wait_first(
                    page, self.selectors.get("login", "captcha_image"), timeout_ms=12000
                )
                if cap is None:
                    human_reason = "登录页未找到验证码图片（可能页面结构变化/风控）"
                    break
                src = await cap.get_attribute("src")
                image = decode_data_url(src)
                if not image:
                    with contextlib.suppress(Exception):
                        image = await cap.screenshot()
                try:
                    answer = await self._captcha.solve(image)
                except NeedsHuman as exc:
                    human_reason = str(exc)
                    break

                filled_user = await fill_first(
                    page, self.selectors.get("login", "username"), self.config.platform.username
                )
                filled_pass = await fill_first(
                    page, self.selectors.get("login", "password"), self.config.platform.password
                )
                filled_cap = await fill_first(page, self.selectors.get("login", "captcha"), answer)
                if not (filled_user and filled_pass and filled_cap):
                    human_reason = "登录表单选择器未全部命中"
                    break
                submit = await self._wait_first(
                    page, self.selectors.get("login", "submit"), timeout_ms=5000
                )
                if submit is None:
                    human_reason = "未找到登录按钮"
                    break
                await submit.click()
                with contextlib.suppress(Exception):
                    await page.wait_for_load_state("domcontentloaded", timeout=8000)
                await self._wait_for_token(page, timeout_ms=8000)
                await asyncio.sleep(0.6)
                state = await self._auth_state(page)
                if self._looks_logged_in(state):
                    self._set_session(
                        "logged_in", f"登录成功（第 {attempt} 次验证码）", self.config.platform.username
                    )
                    log.info("ycb 登录成功 attempt=%d", attempt)
                    return
                errors.append(await self._read_login_error(page) or "登录后仍未检测到 token")
                log.info("登录尝试 %d 失败：%s", attempt, errors[-1])

            paths = await self.debug_snapshot("login-needs-human")
            detail = "；".join(errors[-2:]) or human_reason or "验证码识别/登录失败"
            if paths:
                detail += f"；截图={paths.get('screenshot', '')}"
            self._set_session("needs_human", detail)
            raise NeedsHuman(detail)

    async def _wait_for_token(self, page, *, timeout_ms: int = 8000) -> None:
        """登录成功后 SPA 可能还在路由跳转；等 token 落地再判状态。"""
        with contextlib.suppress(Exception):
            await page.wait_for_function(
                """() => Object.keys(localStorage)
                    .some(k => k === 'jwtToken' || k.startsWith('jwtToken-'))""",
                timeout=timeout_ms,
            )

    async def _read_login_error(self, page) -> str:
        texts: list[str] = []
        for selector in self.selectors.get("login", "error"):
            with contextlib.suppress(Exception):
                locator = page.locator(selector)
                for index in range(min(await locator.count(), 3)):
                    value = (await locator.nth(index).inner_text()).strip()
                    if value and value not in texts:
                        texts.append(value)
        return " / ".join(texts)

    async def health(self) -> SessionState:
        if not self.browser.started:
            return self._set_session("logged_out", "浏览器尚未启动")
        try:
            state = await self.actor.submit(
                "ycb-health", self._health_job, priority=Priority.HEALTH, timeout=45
            )
            return state
        except Exception as exc:
            return self._set_session("error", f"健康检查失败：{exc}")

    async def _health_job(self, page) -> SessionState:
        try:
            await page.goto(self.detail_url, wait_until="domcontentloaded", timeout=_LOGIN_TIMEOUT_MS)
            await self.settle(page, timeout_ms=2500)
        except Exception as exc:
            return self._set_session("error", f"打开比赛详情失败：{exc}")
        state = await self._auth_state(page)
        if self._looks_logged_in(state):
            return self._set_session("logged_in", "会话有效", self.config.platform.username)
        return self._set_session("logged_out", "未登录或会话已过期")

    # ------------------------------------------------------------------ discovery
    async def discover(self) -> list[Challenge]:
        challenges = await self.actor.submit(
            "ycb-discover",
            self._discover_job,
            priority=Priority.DISCOVER,
            timeout=240,
        )
        for challenge in challenges:
            self._detail_cache[challenge.uid] = challenge
        if challenges:
            self._set_session("logged_in", f"发现 {len(challenges)} 题", self.config.platform.username)
        return challenges

    async def _discover_job(self, page) -> list[Challenge]:
        if not await self._goto_answer_page(page):
            # 放题前答题页不存在，返回空列表而不是报错
            return []
        state = await self._auth_state(page)
        if not self._looks_logged_in(state):
            raise SessionExpired("发现时跳转到登录页")
        await asyncio.sleep(1.5)

        from_records = self._parse_records()
        active = await self._fetch_active_challenges(page)
        merged: dict[str, Challenge] = {challenge.uid: challenge for challenge in from_records}
        order = [challenge.uid for challenge in from_records]
        for challenge in active:
            if challenge.uid in merged:
                merged[challenge.uid] = merge_challenge(merged[challenge.uid], challenge)
            else:
                merged[challenge.uid] = challenge
                order.append(challenge.uid)
        for challenge in merged.values():
            self._detail_cache[challenge.uid] = challenge
        if merged and all(challenge.description_md for challenge in merged.values()):
            return [merged[uid] for uid in order]

        dom_challenges = await self._discover_dom(page)
        by_title = {_title_key(merged[uid].title): uid for uid in order}
        for challenge in dom_challenges:
            # DOM 没有平台 id，按标题并入网络响应中的同一题，避免重复建库
            target_uid = by_title.get(_title_key(challenge.title))
            if target_uid is None and challenge.uid in merged:
                target_uid = challenge.uid
            if target_uid is not None:
                merged[target_uid] = merge_challenge(merged[target_uid], challenge)
                dom_index = self._dom_index.pop(challenge.uid, None)
                if dom_index is not None:
                    self._dom_index[target_uid] = dom_index
                self._detail_cache[target_uid] = merged[target_uid]
            else:
                merged[challenge.uid] = challenge
                order.append(challenge.uid)
                by_title[_title_key(challenge.title)] = challenge.uid
                self._detail_cache[challenge.uid] = challenge
        return [merged[uid] for uid in order]

    async def _page_token(self, page) -> str:
        try:
            return await page.evaluate(
                """([matchId]) => {
                    let token = localStorage.getItem('jwtToken-' + matchId)
                        || localStorage.getItem('jwtToken') || '';
                    if (!token) {
                        const hit = document.cookie.match(/(?:^|;\\s*)Authorization=([^;]+)/);
                        token = hit ? decodeURIComponent(hit[1]) : '';
                    }
                    return token.replace(/^Bearer\\s+/i, '');
                }""",
                [self.competition_id],
            )
        except Exception as exc:
            log.debug("读取页面 token 失败：%s", exc)
            return ""

    async def _fetch_active_challenges(self, page) -> list[Challenge]:
        """在页面上下文里主动拉取题目列表与详情。

        2026-10-24 实测：答题页的题目列表要等前端轮询才渲染，被动录制/DOM 都
        可能抓空；列表接口只给 id/name，详情接口才含分值、说明、附件和容器。
        这里用页面自身的 localStorage token 发同源请求，避免额外登录态。
        """
        match = re.search(r"/competePage/(\d+)", page.url)
        stage_id = match.group(1) if match else ""
        if not stage_id:
            return []
        token = await self._page_token(page)
        if not token:
            log.debug("页面未提供 token，跳过主动题目发现")
            return []
        try:
            payload = await page.evaluate(
                """async ([matchId, stageId, token, listPath, detailPath]) => {
                    const headers = {
                        Authorization: 'Bearer ' + token,
                        matchId: String(matchId),
                    };
                    const getJson = async (url) => {
                        const controller = new AbortController();
                        const timer = setTimeout(() => controller.abort(), 8000);
                        try {
                            const resp = await fetch(url, {
                                credentials: 'include', headers, signal: controller.signal,
                            });
                            return await resp.json();
                        } catch (err) {
                            return null;
                        } finally {
                            clearTimeout(timer);
                        }
                    };
                    const list = await getJson(
                        `${listPath}?matchId=${matchId}&stageId=${stageId}`
                    );
                    if (!list || list.code !== '00000' || !Array.isArray(list.data)) {
                        return {error: (list && list.code) || 'empty', details: []};
                    }
                    const items = [];
                    for (const group of list.data) {
                        for (const item of (group.corpus || [])) {
                            if (item && item.isOpen !== false && item.id !== undefined) {
                                items.push({group: group.name || '', id: item.id});
                            }
                        }
                    }
                    const details = [];
                    for (const item of items.slice(0, 80)) {
                        const detail = await getJson(
                            `${detailPath}?matchId=${matchId}&exerciseId=${item.id}&stageId=${stageId}`
                        );
                        details.push({group: item.group, id: item.id, payload: detail});
                    }
                    return {error: null, details};
                }""",
                [
                    self.competition_id,
                    stage_id,
                    token,
                    _EXERCISE_LIST_PATH,
                    _EXERCISE_DETAIL_PATH,
                ],
            )
        except Exception as exc:
            log.debug("主动题目发现失败：%s", exc)
            return []
        if not isinstance(payload, dict) or payload.get("error"):
            log.debug("题目列表接口不可用：%s", payload.get("error") if isinstance(payload, dict) else payload)
            return []
        found: dict[str, Challenge] = {}
        order: list[str] = []
        for entry in payload.get("details") or []:
            detail = entry.get("payload") if isinstance(entry, dict) else None
            if not isinstance(detail, dict):
                continue
            for challenge in extract_challenges(
                detail, base_url=self.base_url, competition_id=self.competition_id
            ):
                group = str(entry.get("group") or "").strip()
                if group and (not challenge.category or challenge.category == "misc"):
                    challenge.category = group
                if challenge.uid in found:
                    found[challenge.uid] = merge_challenge(found[challenge.uid], challenge)
                else:
                    found[challenge.uid] = challenge
                    order.append(challenge.uid)
        return [found[uid] for uid in order]

    def _parse_records(self) -> list[Challenge]:
        """合并列表响应与已点击题目的详情响应。

        列表接口在放题后可能只有标题/分数；详情接口（点击题号触发）才有说明和
        附件。两类都作为被动数据源，避免每轮都重复点击。
        """
        records = self.browser.recorder.records()
        if not records:
            return []
        list_records = [r for r in records if "exercise-list" in r["url"]]
        overview_records = [r for r in records if "/player/answer-panel/overview" in r["url"]]
        detail_records = [r for r in records if "/player/ctf/exercise" in r["url"]]
        chosen = list_records or overview_records or detail_records
        # 详情响应按时间顺序追加，用于补全列表项
        chosen = [*chosen, *detail_records]
        found: dict[str, Challenge] = {}
        order: list[str] = []
        for record in chosen:
            for challenge in extract_challenges(
                record.get("payload"),
                base_url=self.base_url,
                competition_id=self.competition_id,
            ):
                if challenge.uid in found:
                    found[challenge.uid] = merge_challenge(found[challenge.uid], challenge)
                else:
                    found[challenge.uid] = challenge
                    order.append(challenge.uid)
        return [found[uid] for uid in order]

    async def _fetch_stages(self, page) -> list[dict[str, Any]]:
        url = f"{self.base_url}{_STAGE_LIST_PATH}"
        params = {"id": self.competition_id, "matchId": self.competition_id}
        headers = await self._auth_headers(page)
        response = await page.context.request.get(
            url, params=params, headers=headers, timeout=_LOGIN_TIMEOUT_MS
        )
        if response.status == 401:
            raise SessionExpired("查询赛段列表时会话过期（HTTP 401）")
        if response.status == 403 and headers:
            # 与附件下载一致：部分网关不接受 authorization，改用 cookie 重试
            response = await page.context.request.get(
                url, params=params, timeout=_LOGIN_TIMEOUT_MS
            )
        if not response.ok:
            raise PlatformError(f"查询赛段列表失败：HTTP {response.status}")
        return stage_list_body(await response.json())

    async def _goto_answer_page(self, page) -> bool:
        """进入 /{competition}/competePage/{stageId}；赛段未开始时返回 False。"""
        if self._answer_url:
            with contextlib.suppress(Exception):
                await page.goto(
                    self._answer_url, wait_until="domcontentloaded", timeout=_LOGIN_TIMEOUT_MS
                )
                await self.settle(page, timeout_ms=3000)
                if "/competePage/" in page.url:
                    return True
            self._answer_url = None

        stages: list[dict[str, Any]] = []
        try:
            stages = await self._fetch_stages(page)
        except SessionExpired:
            raise
        except Exception as exc:
            log.debug("赛段列表不可用，回退详情页入口：%s", exc)
        stage = pick_ctf_stage(stages)
        if stage is not None:
            status = str(stage.get("status", "")).upper()
            stage_id = stage.get("id")
            if status == _ACTIVE_STAGE_STATUS and stage_id not in (None, ""):
                url = f"{self.base_url}/{self.competition_id}/competePage/{stage_id}"
                await page.goto(url, wait_until="domcontentloaded", timeout=_LOGIN_TIMEOUT_MS)
                await self.settle(page, timeout_ms=4000)
                if "/competePage/" in page.url:
                    self._answer_url = page.url
                    return True
                log.warning("赛段进行中但答题页未打开 url=%s -> %s", url, page.url)
            elif status in {"PENDING", "END"}:
                # 详情页只有“查看更多”弹窗，不会进入答题页；未开始/已结束时不必点击
                log.info("CTF 赛段状态为 %s，暂不进入答题页", status)
                return False

        await page.goto(self.detail_url, wait_until="domcontentloaded", timeout=_LOGIN_TIMEOUT_MS)
        await self.settle(page, timeout_ms=3500)
        selectors = [
            "a[href*='competePage']",
            "button:has-text('进入比赛')",
            "button:has-text('进入答题')",
            "button:has-text('开始答题')",
            "button:has-text('立即答题')",
            "button:has-text('去答题')",
        ]
        for selector in selectors:
            with contextlib.suppress(Exception):
                locator = page.locator(selector).first
                if await locator.count() and await locator.is_visible():
                    await locator.click()
                    await self.settle(page, timeout_ms=4000)
                    if "/competePage/" in page.url:
                        self._answer_url = page.url
                        return True
        return False

    async def _discover_dom(self, page) -> list[Challenge]:
        """兜底：切换每个分类 tab，逐个点击题号读取详情文本/被动详情响应。"""
        challenges: list[Challenge] = []
        seen: set[str] = set()
        type_items = page.locator(self.selectors.first("challenge", "type_item", ".type_item"))
        tab_count = 0
        with contextlib.suppress(Exception):
            tab_count = await type_items.count()
        if tab_count <= 0:
            challenges.extend(await self._discover_dom_tab(page, "misc"))
        else:
            for tab_index in range(min(tab_count, 20)):
                tab = type_items.nth(tab_index)
                try:
                    if not await tab.is_visible():
                        continue
                    await tab.click(timeout=4000)
                    await asyncio.sleep(0.7)
                    category = (await tab.inner_text()).strip() or "misc"
                except Exception as exc:
                    log.debug("切换分类 tab 失败 index=%d: %s", tab_index, exc)
                    continue
                challenges.extend(await self._discover_dom_tab(page, category))
        unique: list[Challenge] = []
        for challenge in challenges:
            if challenge.uid in seen:
                continue
            seen.add(challenge.uid)
            unique.append(challenge)
        return unique

    async def _discover_dom_tab(self, page, category: str) -> list[Challenge]:
        locator = page.locator(self.selectors.first("challenge", "number_item", ".number_item"))
        count = 0
        with contextlib.suppress(Exception):
            await page.wait_for_selector(
                self.selectors.first("challenge", "number_item", ".number_item"),
                timeout=4000,
            )
            count = await locator.count()
        if count <= 0:
            challenge = await self._read_current_detail(page, category=category)
            return [challenge] if challenge else []

        challenges: list[Challenge] = []
        for index in range(min(count, _MAX_DETAIL_CLICKS)):
            item = locator.nth(index)
            try:
                if not await item.is_visible():
                    continue
                await item.click(timeout=5000)
                await asyncio.sleep(0.6)
            except Exception as exc:
                log.debug("点击题号失败 tab=%s index=%d: %s", category, index, exc)
                continue
            challenge = await self._read_current_detail(page, category=category)
            if challenge is None:
                continue
            self._dom_index[challenge.uid] = index
            challenges.append(challenge)
        return challenges

    async def _read_current_detail(self, page, *, category: str = "misc") -> Challenge | None:
        snapshot = None
        with contextlib.suppress(Exception):
            snapshot = await page.evaluate(
                """() => {
                    const root = document.querySelector('.topic_content, .topic_detail');
                    if (!root) return null;
                    const items = {};
                    root.querySelectorAll('.info_item').forEach(item => {
                        const label = (item.querySelector('.label')?.innerText || '').trim();
                        const value = (item.querySelector('.value')?.innerText || '').trim();
                        if (label && value) items[label.replace(/[：:]$/, '')] = value;
                    });
                    const files = Array.from(root.querySelectorAll('.file_name'))
                        .map(el => el.innerText.trim()).filter(Boolean);
                    const titleEl = root.querySelector('.topic_title, .title, h1, h2');
                    return {
                        items,
                        files,
                        title: (titleEl?.innerText || '').trim(),
                        text: root.innerText
                    };
                }"""
            )
        dom_challenge = parse_detail_snapshot(
            snapshot,
            base_url=self.base_url,
            competition_id=self.competition_id,
            category=category,
        )
        api_challenge = self._latest_detail_candidate()
        if api_challenge is not None and dom_challenge is not None:
            # 被动响应可能还是上一题的详情；标题不一致时以 DOM 为准
            if not _titles_match(api_challenge.title, dom_challenge.title):
                api_challenge = None
        if dom_challenge is None:
            return api_challenge
        if api_challenge is not None:
            # DOM 只用于标题/附件兜底；详情 JSON 更完整
            if not api_challenge.description_md:
                api_challenge.description_md = dom_challenge.description_md
            if api_challenge.score is None:
                api_challenge.score = dom_challenge.score
            names = {item.name for item in api_challenge.attachments}
            for attachment in dom_challenge.attachments:
                if attachment.name not in names:
                    api_challenge.attachments.append(attachment)
                    names.add(attachment.name)
            return api_challenge
        return dom_challenge

    def _latest_detail_candidate(self) -> Challenge | None:
        record = self.browser.recorder.latest("/player/ctf/exercise")
        if record is None:
            return None
        candidates = extract_challenges(
            record.get("payload"),
            base_url=self.base_url,
            competition_id=self.competition_id,
        )
        return candidates[0] if candidates else None

    async def fetch_detail(self, challenge: Challenge) -> Challenge:
        cached = self._detail_cache.get(challenge.uid)
        if cached is not None and cached.description_md:
            return cached
        return challenge

    # ------------------------------------------------------------------ downloads
    async def download(self, challenge: Challenge, dest: Path) -> list[Path]:
        if not challenge.attachments:
            return []
        # 附件在签名 OSS 上，直连即可；不走浏览器，避免大文件和页面卡死拖住发现循环。
        try:
            return await self._download_direct(challenge, dest)
        except (SessionExpired, PlatformError) as exc:
            log.warning("直连下载失败，改用浏览器会话 uid=%s: %s", challenge.uid, exc)
        return await self.actor.submit(
            f"ycb-download-{challenge.platform_id}",
            lambda page: self._download_job(page, challenge, dest),
            priority=Priority.DOWNLOAD,
            timeout=180,
        )

    async def _download_direct(self, challenge: Challenge, dest: Path) -> list[Path]:
        dest.mkdir(parents=True, exist_ok=True)
        try:
            dest.chmod(0o700)
        except OSError:
            pass
        root = dest.resolve()
        saved: list[Path] = []
        timeout = httpx.Timeout(connect=15.0, read=120.0, write=30.0, pool=15.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            for attachment in challenge.attachments:
                if not attachment.url:
                    log.warning("附件缺少下载 URL，跳过 uid=%s name=%s", challenge.uid, attachment.name)
                    continue
                url = attachment.url
                if not url.startswith(("http://", "https://")):
                    url = urljoin(self.base_url + "/", url.lstrip("/"))
                async with client.stream("GET", url) as response:
                    if response.status_code >= 400:
                        raise PlatformError(
                            f"附件 {attachment.name} 下载失败：HTTP {response.status_code}"
                        )
                    length = _as_int(response.headers.get("content-length"))
                    if length is not None and length > _MAX_ATTACHMENT_BYTES:
                        raise PlatformError(
                            f"附件 {attachment.name} 超过 {_MAX_ATTACHMENT_BYTES} 字节，拒绝下载"
                        )
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > _MAX_ATTACHMENT_BYTES:
                            raise PlatformError(
                                f"附件 {attachment.name} 超过 {_MAX_ATTACHMENT_BYTES} 字节，拒绝下载"
                            )
                path = self._save_attachment(dest, root, attachment, bytes(body))
                if path is not None:
                    saved.append(path)
        return saved

    def _save_attachment(
        self, dest: Path, root: Path, attachment: Any, body: bytes
    ) -> Path | None:
        name = safe_filename(attachment.name)
        target = (dest / name).resolve()
        if root != target.parent and root not in target.parents:
            log.warning("附件路径越界，跳过 name=%s", attachment.name)
            return None
        part = target.with_name(target.name + ".part")
        part.write_bytes(body)
        part.chmod(0o600)
        os.replace(part, target)
        attachment.size = len(body)
        attachment.sha256 = hashlib.sha256(body).hexdigest()
        log.info("附件已下载 name=%s bytes=%d", name, len(body))
        return target

    async def _download_job(self, page, challenge: Challenge, dest: Path) -> list[Path]:
        dest.mkdir(parents=True, exist_ok=True)
        try:
            dest.chmod(0o700)
        except OSError:
            pass
        root = dest.resolve()
        headers = await self._auth_headers(page)
        saved: list[Path] = []
        for attachment in challenge.attachments:
            if not attachment.url:
                log.warning("附件缺少下载 URL，跳过 uid=%s name=%s", challenge.uid, attachment.name)
                continue
            url = attachment.url
            if not url.startswith(("http://", "https://")):
                url = urljoin(self.base_url + "/", url.lstrip("/"))
            try:
                response = await page.context.request.get(
                    url, headers=headers, timeout=120000
                )
                if response.status == 401:
                    raise SessionExpired("下载附件时会话过期（HTTP 401）")
                if response.status == 403 and headers:
                    # 部分 CDN 不接受 authorization；去掉凭据再试一次
                    response = await page.context.request.get(url, timeout=120000)
                if not response.ok:
                    raise PlatformError(f"附件 {attachment.name} 下载失败：HTTP {response.status}")
                headers = getattr(response, "headers", {}) or {}
                length = _as_int(headers.get("content-length"))
                if length is not None and length > _MAX_ATTACHMENT_BYTES:
                    raise PlatformError(
                        f"附件 {attachment.name} 超过 {_MAX_ATTACHMENT_BYTES} 字节，拒绝下载"
                    )
                body = await response.body()
                if len(body) > _MAX_ATTACHMENT_BYTES:
                    raise PlatformError(
                        f"附件 {attachment.name} 超过 {_MAX_ATTACHMENT_BYTES} 字节，拒绝下载"
                    )
            except (SessionExpired, PlatformError):
                raise
            except Exception as exc:
                log.warning("附件下载失败 name=%s: %s", attachment.name, exc)
                continue
            target = self._save_attachment(dest, root, attachment, body)
            if target is not None:
                saved.append(target)
        return saved

    async def _auth_headers(self, page) -> dict[str, str]:
        try:
            token = await page.evaluate(
                """() => {
                    const keys = Object.keys(localStorage);
                    const key = keys.find(k => k === 'jwtToken' || k.startsWith('jwtToken-'));
                    return key ? localStorage.getItem(key) : '';
                }"""
            )
        except Exception:
            token = ""
        headers: dict[str, str] = {"matchId": self.competition_id}
        if token:
            headers["authorization"] = token
        return headers

    # ------------------------------------------------------------------ container
    async def ensure_target(self, challenge: Challenge) -> Target | None:
        if challenge.target is not None:
            return challenge.target
        stage_id, token = await self._container_creds(challenge)
        if stage_id and token:
            return await self._ensure_target_http(challenge, stage_id, token)
        return await self.actor.submit(
            f"ycb-container-{challenge.platform_id}",
            lambda page: self._ensure_target_job(page, challenge),
            priority=Priority.TARGET,
            timeout=300,
        )

    async def expire_target(self, challenge: Challenge) -> bool:
        """销毁平台实例，释放每队 3 台的容器配额。"""
        stage_id, token = await self._container_creds(challenge)
        if not (stage_id and token):
            return False
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                result = await self._http_api(
                    client,
                    "POST",
                    _EXPIRE_ENV_PATH,
                    token,
                    json_body={
                        "exerciseId": int(challenge.platform_id),
                        "stageId": int(stage_id),
                    },
                )
        except Exception as exc:
            log.warning("释放容器失败 challenge=%s: %s", challenge.title, exc)
            return False
        ok = isinstance(result, dict) and result.get("code") == "00000"
        message = result.get("message") if isinstance(result, dict) else ""
        log.info(
            "释放容器 challenge=%s ok=%s message=%s", challenge.title, ok, message
        )
        return ok

    async def _container_creds(self, challenge: Challenge) -> tuple[str, str]:
        """用一次短的浏览器任务取赛段和 token，后续 HTTP 轮询不再占用 actor。"""

        async def job(page):
            if not await self._goto_answer_page(page):
                raise PlatformError("CTF 赛段尚未开始，无法启动容器")
            match = re.search(r"/competePage/(\d+)", page.url)
            stage_id = match.group(1) if match else ""
            token = await self._page_token(page) if stage_id else ""
            return stage_id, token

        try:
            return await self.actor.submit(
                f"ycb-container-creds-{challenge.platform_id}",
                job,
                priority=Priority.TARGET,
                timeout=90,
            )
        except Exception as exc:
            log.warning("获取容器凭据失败 challenge=%s: %s", challenge.title, exc)
            return "", ""

    def _api_headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "matchId": str(self.competition_id),
            "Accept": "application/json",
        }

    async def _http_api(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        token: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        try:
            response = await client.request(
                method,
                f"{self.base_url}{path}",
                params=params,
                json=json_body,
                headers=self._api_headers(token),
            )
            if response.status_code != 200:
                log.debug("平台接口 %s 返回 HTTP %s", path, response.status_code)
                return None
            payload = response.json()
            return payload if isinstance(payload, dict) else None
        except Exception as exc:
            log.debug("平台接口 %s 失败: %s", path, exc)
            return None

    async def _http_detail(
        self,
        client: httpx.AsyncClient,
        stage_id: str,
        token: str,
        platform_id: str,
    ) -> dict[str, Any] | None:
        return await self._http_api(
            client,
            "GET",
            _EXERCISE_DETAIL_PATH,
            token,
            params={
                "matchId": str(self.competition_id),
                "exerciseId": str(platform_id),
                "stageId": str(stage_id),
            },
        )

    async def _ensure_target_http(
        self, challenge: Challenge, stage_id: str, token: str
    ) -> Target | None:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            detail = await self._http_detail(
                client, stage_id, token, challenge.platform_id
            )
            target = self._detail_target(detail)
            if target is not None and await _tcp_alive(target):
                challenge.target = target
                return target
            has_endpoint = bool(self._detail_endpoints(detail))
            if not has_endpoint:
                result = await self._http_api(
                    client,
                    "POST",
                    _BUILD_ENV_PATH,
                    token,
                    json_body={
                        "exerciseId": int(challenge.platform_id),
                        "stageId": int(stage_id),
                    },
                )
                code = result.get("code") if isinstance(result, dict) else None
                message = result.get("message") if isinstance(result, dict) else ""
                if code != "00000":
                    raise PlatformError(
                        f"启动容器失败：{message or '平台未返回成功'}（{code or '无响应'}）"
                    )
                log.info("已请求启动容器 challenge=%s", challenge.title)

            deadline = asyncio.get_running_loop().time() + 240
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(2.0)
                detail = await self._http_detail(
                    client, stage_id, token, challenge.platform_id
                )
                target = self._detail_target(detail)
                if target is not None and await _tcp_alive(target):
                    challenge.target = target
                    log.info(
                        "容器已就绪 challenge=%s target=%s:%s",
                        challenge.title,
                        target.host,
                        target.port,
                    )
                    return target
        raise PlatformError(f"容器启动超时（240s）：{challenge.title}")

    async def refresh_target(self, challenge: Challenge) -> Target | None:
        challenge.target = None
        return await self.ensure_target(challenge)

    async def _api_detail(
        self, page, stage_id: str, token: str, platform_id: str
    ) -> dict[str, Any] | None:
        try:
            return await page.evaluate(
                """async ([matchId, stageId, exerciseId, token, path]) => {
                    const controller = new AbortController();
                    const timer = setTimeout(() => controller.abort(), 8000);
                    try {
                        const resp = await fetch(
                            `${path}?matchId=${matchId}&exerciseId=${exerciseId}&stageId=${stageId}`,
                            {
                                credentials: 'include',
                                headers: {
                                    Authorization: 'Bearer ' + token,
                                    matchId: String(matchId),
                                },
                                signal: controller.signal,
                            },
                        );
                        return await resp.json();
                    } catch (err) {
                        return null;
                    } finally {
                        clearTimeout(timer);
                    }
                }""",
                [self.competition_id, stage_id, platform_id, token, _EXERCISE_DETAIL_PATH],
            )
        except Exception as exc:
            log.debug("题目详情接口失败 id=%s: %s", platform_id, exc)
            return None

    async def _api_build_env(
        self, page, stage_id: str, token: str, platform_id: str
    ) -> bool:
        try:
            result = await page.evaluate(
                """async ([matchId, stageId, exerciseId, token, path]) => {
                    const controller = new AbortController();
                    const timer = setTimeout(() => controller.abort(), 15000);
                    try {
                        const resp = await fetch(path, {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Content-Type': 'application/json',
                                Authorization: 'Bearer ' + token,
                                matchId: String(matchId),
                            },
                            body: JSON.stringify({
                                exerciseId: Number(exerciseId),
                                stageId: Number(stageId),
                            }),
                            signal: controller.signal,
                        });
                        return await resp.json();
                    } catch (err) {
                        return null;
                    } finally {
                        clearTimeout(timer);
                    }
                }""",
                [self.competition_id, stage_id, platform_id, token, _BUILD_ENV_PATH],
            )
        except Exception as exc:
            log.debug("启动容器接口失败 id=%s: %s", platform_id, exc)
            return False
        return isinstance(result, dict) and result.get("code") == "00000"

    @staticmethod
    def _detail_endpoints(detail: Any) -> list[Any]:
        data = detail.get("data") if isinstance(detail, dict) else None
        if not isinstance(data, dict):
            return []
        endpoints = data.get("endpoints") or data.get("endpointList")
        return endpoints if isinstance(endpoints, list) else []

    @classmethod
    def _detail_target(cls, detail: Any) -> Target | None:
        return target_from_payload(cls._detail_endpoints(detail))

    async def _ensure_target_job(self, page, challenge: Challenge) -> Target | None:
        if not await self._goto_answer_page(page):
            raise PlatformError("CTF 赛段尚未开始，无法启动容器")
        match = re.search(r"/competePage/(\d+)", page.url)
        stage_id = match.group(1) if match else ""
        token = await self._page_token(page) if stage_id else ""
        if stage_id and token:
            detail = await self._api_detail(page, stage_id, token, challenge.platform_id)
            target = self._detail_target(detail)
            if target is not None and await _tcp_alive(target):
                challenge.target = target
                return target
            has_endpoint = bool(self._detail_endpoints(detail))
            if not has_endpoint and await self._api_build_env(
                page, stage_id, token, challenge.platform_id
            ):
                log.info("已请求启动容器 challenge=%s", challenge.title)
            deadline = asyncio.get_running_loop().time() + 240
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(2.0)
                detail = await self._api_detail(page, stage_id, token, challenge.platform_id)
                target = self._detail_target(detail)
                if target is not None and await _tcp_alive(target):
                    challenge.target = target
                    log.info(
                        "容器已就绪 challenge=%s target=%s:%s",
                        challenge.title,
                        target.host,
                        target.port,
                    )
                    return target
            raise PlatformError(f"容器启动超时（240s）：{challenge.title}")

        selected = await self._select_challenge(page, challenge)
        if not selected:
            raise PlatformError(f"未找到题目卡片：{challenge.title}")
        button = await self._wait_first(
            page,
            self.selectors.get("challenge", "container_button"),
            timeout_ms=8000,
        )
        if button is None:
            log.info("题目没有容器按钮 uid=%s", challenge.uid)
            return None
        with contextlib.suppress(Exception):
            await button.click()
        deadline = asyncio.get_running_loop().time() + 240
        while asyncio.get_running_loop().time() < deadline:
            target = self._latest_target(challenge)
            if target is None:
                target = await self._target_from_dom(page)
            if target is not None and await _tcp_alive(target):
                challenge.target = target
                log.info(
                    "容器已就绪 challenge=%s target=%s:%s",
                    challenge.title,
                    target.host,
                    target.port,
                )
                return target
            await asyncio.sleep(2.0)
        raise PlatformError(f"容器启动超时（240s）：{challenge.title}")

    async def _select_challenge(self, page, challenge: Challenge) -> bool:
        current = await self._read_current_detail(page)
        if current is not None and _titles_match(current.title, challenge.title):
            return True
        index = self._dom_index.get(challenge.uid)
        if index is not None:
            item = page.locator(
                self.selectors.first("challenge", "number_item", ".number_item")
            ).nth(index)
            if await item.count():
                await item.click(timeout=5000)
                await asyncio.sleep(0.8)
                return True
        item_locator = page.locator(
            self.selectors.first("challenge", "number_item", ".number_item")
        )
        count = await item_locator.count()
        for idx in range(min(count, _MAX_DETAIL_CLICKS)):
            try:
                await item_locator.nth(idx).click(timeout=4000)
                await asyncio.sleep(0.6)
            except Exception:
                continue
            current = await self._read_current_detail(page)
            if current is not None and _titles_match(current.title, challenge.title):
                self._dom_index[challenge.uid] = idx
                return True
        return False

    def _latest_target(self, challenge: Challenge) -> Target | None:
        for needle in ("/player/ctf/exercise", "/player/ctf/build-exercise-env", "/player/ctf/check-exercise-env"):
            record = self.browser.recorder.latest(needle)
            if record is not None:
                target = target_from_payload(record.get("payload"))
                if target is not None:
                    return target
        if challenge.target:
            return challenge.target
        return None

    async def _target_from_dom(self, page) -> Target | None:
        text = ""
        with contextlib.suppress(Exception):
            text = await page.locator("body").inner_text()
        for match in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", text):
            host, port = match.group(1), int(match.group(2))
            if port <= 65535:
                return Target(kind="tcp", host=host, port=port)
        return None

    # ------------------------------------------------------------------ submit / state
    async def submit(self, challenge: Challenge, flag: str) -> SubmitResult:
        # 平台答题框只接受大括号内的内容；本地 flag.txt 仍是完整的 DASCTF{...}。
        answer = _answer_value(flag)
        stage_id, token = await self._container_creds(challenge)
        if stage_id and token:
            try:
                return await self._submit_via_api(challenge, answer, stage_id, token)
            except Exception as exc:
                log.warning("API 提交失败，转浏览器提交 challenge=%s: %s", challenge.title, exc)
        return await self.actor.submit(
            f"ycb-submit-{challenge.platform_id}",
            lambda page: self._submit_job(page, challenge, answer),
            priority=Priority.SUBMIT,
            timeout=90,
        )

    async def _submit_via_api(
        self, challenge: Challenge, flag: str, stage_id: str, token: str
    ) -> SubmitResult:
        """直接调用 answer-panel 接口：比 DOM 提交稳定，且能读到结构化结果。"""
        evidence: dict[str, Any] = {
            "transport": "api",
            "stage_id": stage_id,
            "exercise_id": challenge.platform_id,
        }
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            detail = await self._http_detail(
                client, stage_id, token, challenge.platform_id
            )
            if _detail_solved(detail):
                challenge.solved_on_platform = True
                return SubmitResult("already_solved", "平台显示该题已解出", evidence)

            try:
                response = await client.post(
                    f"{self.base_url}{_ANSWER_PATH}",
                    json={
                        "matchId": int(self.competition_id),
                        "exerciseId": int(challenge.platform_id),
                        "flag": flag,
                    },
                    headers=self._api_headers(token),
                )
            except Exception as exc:
                return SubmitResult(
                    "unknown", f"提交请求失败：{type(exc).__name__}: {exc}", evidence
                )
            status = response.status_code
            evidence["http"] = status
            if status == 401:
                return SubmitResult("session_expired", "提交时会话过期", evidence)
            if status == 429:
                return SubmitResult("rate_limited", "平台限流", evidence)
            try:
                payload = response.json()
            except Exception:
                payload = {"text": response.text[:1000]}
            payload = redact(payload)
            message, code, data = _submit_payload_fields(payload)
            message = redact_text(message).strip()
            evidence.update(
                {
                    "code": code,
                    "message": message[:500],
                    "payload_excerpt": redact_text(
                        json.dumps(payload, ensure_ascii=False, default=str)
                    )[:1000],
                }
            )
            data_dict = data if isinstance(data, dict) else {}

            if (
                code == "40409"
                or "已被解出" in message
                or "无法重新解题" in message
            ):
                challenge.solved_on_platform = True
                return SubmitResult("already_solved", message or "该题已解出", evidence)

            event_id = data_dict.get("eventId")
            if code == "00000" and event_id:
                monitored = await self._monitor_answer(
                    client, token, stage_id, event_id, evidence
                )
                if monitored is not None:
                    return monitored
            elif code == "00000":
                verdict = _boolish(data_dict.get("result"))
                if verdict is True:
                    challenge.solved_on_platform = True
                    return SubmitResult("accepted", message or "Flag 正确", evidence)
                if verdict is False:
                    return SubmitResult("rejected", message or "Flag 错误", evidence)
                solved = _detail_solved(
                    await self._http_detail(
                        client, stage_id, token, challenge.platform_id
                    )
                )
                if solved:
                    challenge.solved_on_platform = True
                    return SubmitResult("accepted", message or "平台显示已解出", evidence)

            combined = message.lower()
            if code in {"40401", "401"} or "token" in combined or "登录" in combined:
                return SubmitResult("session_expired", message or "平台会话过期", evidence)
            if any(word in combined for word in _ALREADY_WORDS):
                challenge.solved_on_platform = True
                return SubmitResult("already_solved", message or "该题已解出", evidence)
            if any(word in combined for word in _RATE_WORDS):
                return SubmitResult("rate_limited", message or "提交过于频繁", evidence)
            if any(word in combined for word in _REJECT_WORDS):
                return SubmitResult("rejected", message or "Flag 错误", evidence)
            if any(word in combined for word in _SUCCESS_WORDS):
                challenge.solved_on_platform = True
                return SubmitResult("accepted", message or "Flag 正确", evidence)

            solved = _detail_solved(
                await self._http_detail(client, stage_id, token, challenge.platform_id)
            )
            if solved:
                challenge.solved_on_platform = True
                return SubmitResult("accepted", message or "平台显示已解出", evidence)
            return SubmitResult("unknown", message or "无法确认提交结果", evidence)

    async def _monitor_answer(
        self,
        client: httpx.AsyncClient,
        token: str,
        stage_id: str,
        event_id: Any,
        evidence: dict[str, Any],
    ) -> SubmitResult | None:
        deadline = asyncio.get_running_loop().time() + 30
        last_message = ""
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(1.0)
            result = await self._http_api(
                client,
                "GET",
                _MONITOR_ANSWER_PATH,
                token,
                params={
                    "matchId": str(self.competition_id),
                    "eventId": str(event_id),
                    "stageId": str(stage_id),
                },
            )
            if not isinstance(result, dict):
                continue
            message = str(result.get("message") or "")
            last_message = message
            data = result.get("data")
            data_dict = data if isinstance(data, dict) else {}
            evidence["monitor"] = redact_text(
                json.dumps(result, ensure_ascii=False, default=str)
            )[:1000]
            combined = message.lower()
            if any(word in combined for word in _ALREADY_WORDS):
                return SubmitResult("already_solved", message or "该题已解出", evidence)
            if any(word in combined for word in _REJECT_WORDS):
                return SubmitResult("rejected", message or "Flag 错误", evidence)
            if any(word in combined for word in _SUCCESS_WORDS):
                return SubmitResult("accepted", message or "Flag 正确", evidence)
            verdict = _boolish(data_dict.get("result") or data_dict.get("correct"))
            if verdict is True:
                return SubmitResult("accepted", message or "Flag 正确", evidence)
            if verdict is False:
                return SubmitResult("rejected", message or "Flag 错误", evidence)
            if "score" in data_dict:
                score = _as_float(data_dict.get("score"))
                if score is not None:
                    if score > 0:
                        return SubmitResult("accepted", message or "Flag 正确", evidence)
                    return SubmitResult("rejected", message or "Flag 错误", evidence)
        if last_message:
            evidence["monitor_timeout_message"] = last_message[:300]
        return None

    async def _submit_job(self, page, challenge: Challenge, flag: str) -> SubmitResult:
        if not await self._goto_answer_page(page):
            return SubmitResult(
                "unknown", "CTF 赛段尚未开始或答题页不可用", {"stage": "not_underway"}
            )
        if not await self._select_challenge(page, challenge):
            paths = await self.debug_snapshot("submit-challenge-missing")
            return SubmitResult(
                "unknown", f"未找到题目卡片：{challenge.title}", {"debug": paths}
            )
        input_locator = await self._wait_first(
            page, self.selectors.get("challenge", "flag_input"), timeout_ms=8000
        )
        if input_locator is None:
            paths = await self.debug_snapshot("submit-no-input")
            return SubmitResult(
                "unknown",
                "未找到 flag 输入框；提交选择器需按真实页面校准",
                {"debug": paths},
            )
        button = await self._wait_first(
            page, self.selectors.get("challenge", "submit_button"), timeout_ms=5000
        )
        if button is None:
            paths = await self.debug_snapshot("submit-no-button")
            return SubmitResult(
                "unknown",
                "未找到提交按钮；提交选择器需按真实页面校准",
                {"debug": paths},
            )

        before_solved = await self._page_solved_state(page)
        holder: dict[str, Any] = {}
        tasks: set[asyncio.Task] = set()

        def on_response(response) -> None:
            if not _is_submit_response(response.url):
                return
            task = asyncio.create_task(self._capture_submit_response(response, holder))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        page.on("response", on_response)
        toast = ""
        try:
            try:
                await input_locator.fill(flag)
                await button.click()
                deadline = asyncio.get_running_loop().time() + 8.0
                while not holder and asyncio.get_running_loop().time() < deadline:
                    await asyncio.sleep(0.2)
                toast = await self._wait_toast(page, timeout_ms=4000)
                await asyncio.sleep(0.5)
                after_solved = await self._page_solved_state(page)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                paths = await self.debug_snapshot("submit-exception")
                return SubmitResult(
                    "unknown",
                    f"提交操作异常：{type(exc).__name__}: {exc}",
                    {"debug": paths},
                )
        finally:
            with contextlib.suppress(Exception):
                page.remove_listener("response", on_response)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        result = classify_submit_signal(
            http_status=holder.get("http"),
            payload=holder.get("payload"),
            toast=toast,
            page_solved_before=before_solved,
            page_solved_after=after_solved,
            retry_after=holder.get("retry_after"),
        )
        result.evidence.setdefault("url", holder.get("url"))
        if result.status == "unknown":
            paths = await self.debug_snapshot("submit-ambiguous")
            result.evidence.setdefault("debug", paths)
        if result.status in {"accepted", "already_solved"}:
            challenge.solved_on_platform = True
            if challenge.uid in self._detail_cache:
                self._detail_cache[challenge.uid].solved_on_platform = True
        return result

    async def _capture_submit_response(self, response, holder: dict[str, Any]) -> None:
        item: dict[str, Any] = {"url": response.url, "http": response.status}
        with contextlib.suppress(Exception):
            retry_after = await response.header_value("retry-after")
            if retry_after:
                with contextlib.suppress(TypeError, ValueError):
                    item["retry_after"] = float(retry_after)
        try:
            content_type = (await response.header_value("content-type")) or ""
            if "json" in content_type.lower():
                payload = await response.json()
            else:
                text = await response.text()
                payload = {"text": text[:1000]}
        except Exception:
            payload = None
        item["payload"] = redact(payload)
        previous = str(holder.get("url") or "").lower()
        if (
            previous
            and "submit" in previous
            and "submit" not in str(response.url).lower()
        ):
            return  # 明确命中 submit 接口后，不被后续 answer-panel 轮询覆盖
        holder.clear()
        holder.update(item)

    async def _wait_toast(self, page, *, timeout_ms: int = 4000) -> str:
        selectors = self.selectors.get("challenge", "toast")
        deadline = asyncio.get_running_loop().time() + timeout_ms / 1000
        while asyncio.get_running_loop().time() < deadline:
            for selector in selectors:
                with contextlib.suppress(Exception):
                    locator = page.locator(selector).first
                    if await locator.count() and await locator.is_visible():
                        text = (await locator.inner_text()).strip()
                        if text:
                            return text
            await asyncio.sleep(0.25)
        return ""

    async def _page_solved_state(self, page) -> bool:
        for selector in self.selectors.get("challenge", "solved_state"):
            with contextlib.suppress(Exception):
                locator = page.locator(selector).first
                if await locator.count() and await locator.is_visible():
                    return True
        return False

    async def is_solved(self, challenge: Challenge) -> bool:
        if challenge.solved_on_platform:
            return True
        cached = self._detail_cache.get(challenge.uid)
        return bool(cached and cached.solved_on_platform)


def _title_key(value: str) -> str:
    return re.sub(r"[\s　·:：\-_]+", "", str(value or "")).lower()


def _titles_match(left: str, right: str) -> bool:
    a, b = _title_key(left), _title_key(right)
    return bool(a and b and (a == b or a in b or b in a))


# --------------------------------------------------------------------------- submit signals
_ALREADY_WORDS = (
    "已经解出",
    "已解出",
    "已经解决",
    "已解决",
    "已答对",
    "已经答对",
    "已通过",
    "已经提交",
    "已提交",
    "重复提交",
    "already solved",
    "already submitted",
)
_SUCCESS_WORDS = ("正确", "成功", "通过", "得分", "恭喜", "correct", "success", "accepted")
_REJECT_WORDS = (
    "错误",
    "不正确",
    "不对",
    "无效",
    "失败",
    "未通过",
    "wrong",
    "incorrect",
    "invalid",
    "not correct",
)
_RATE_WORDS = ("频繁", "太快", "稍后", "次数", "上限", "limit", "rate", "too many")


def _is_submit_response(url: str) -> bool:
    lowered = str(url or "").lower()
    if "slab-match" not in lowered and "/api/" not in lowered:
        return False
    return "submit" in lowered or "answer" in lowered


def _code_is_success(code: Any) -> bool | None:
    if code is None:
        return None
    if isinstance(code, bool):
        return code
    if isinstance(code, int):
        return code in (0, 200)
    text = str(code).strip().upper()
    if text in {"00000", "0", "200", "SUCCESS", "OK", "TRUE"}:
        return True
    if text in {"-1", "1", "500", "ERROR", "FAIL", "FALSE"}:
        return False
    return None


def _submit_payload_fields(payload: Any) -> tuple[str, Any, Any]:
    if not isinstance(payload, dict):
        return "", None, None
    message = ""
    for key in ("message", "msg", "errMsg", "errorMsg", "error", "detail"):
        if payload.get(key):
            message = str(payload[key])
            break
    code = payload.get("code")
    if code is None:
        code = payload.get("success")
    data = payload.get("data")
    if isinstance(data, dict):
        if not message:
            for key in ("message", "msg", "error"):
                if data.get(key):
                    message = str(data[key])
                    break
        if code is None:
            code = data.get("code")
    return message, code, data


def _data_success(data: Any) -> bool | None:
    if not isinstance(data, dict):
        return None
    for key in ("correct", "right", "success", "passed", "accepted", "solved"):
        if key in data:
            return _as_bool(data[key])
    return None


def classify_submit_signal(
    *,
    http_status: int | None,
    payload: Any,
    toast: str = "",
    page_solved_before: bool = False,
    page_solved_after: bool = False,
    retry_after: float | None = None,
) -> SubmitResult:
    """三源判定：提交响应 + toast + 页面已解状态。

    任一源给出明确结论即可；互相矛盾或都读不出时返回 unknown（交给上层复查），
    绝不猜测 accepted/rejected。
    """
    message, code, data = _submit_payload_fields(payload)
    message = redact_text(message).strip()
    toast = redact_text(toast or "").strip()
    combined = f"{message} {toast}".lower()
    evidence: dict[str, Any] = {
        "http": http_status,
        "message": message[:500],
        "toast": toast[:300],
        "page_solved_before": page_solved_before,
        "page_solved_after": page_solved_after,
    }
    if code is not None:
        evidence["code"] = str(code)[:50]
    if payload is not None:
        excerpt = json.dumps(payload, ensure_ascii=False, default=str)[:2000]
        evidence["payload_excerpt"] = redact_text(excerpt)[:1000]

    if http_status == 401:
        return SubmitResult("session_expired", message or "提交时会话过期", evidence)
    if http_status == 429:
        if retry_after is not None:
            evidence["retry_after"] = retry_after
        return SubmitResult("rate_limited", message or toast or "平台限流", evidence)
    if http_status is not None and http_status >= 500:
        return SubmitResult("unknown", message or f"平台 5xx：{http_status}", evidence)

    if any(word in combined for word in _ALREADY_WORDS):
        return SubmitResult("already_solved", message or toast or "该题已解出", evidence)

    if any(word in combined for word in _RATE_WORDS):
        return SubmitResult("rate_limited", message or toast or "提交过于频繁", evidence)

    # 先判拒绝词：“未通过”同时包含成功词“通过”，顺序不能反
    if any(word in combined for word in _REJECT_WORDS):
        return SubmitResult("rejected", message or toast or "Flag 错误", evidence)

    success = _code_is_success(code)
    if success is None:
        success = _data_success(data)
    if success is True or any(word in combined for word in _SUCCESS_WORDS):
        return SubmitResult("accepted", message or toast or "Flag 正确", evidence)

    if page_solved_after and not page_solved_before:
        evidence["page_transition"] = True
        return SubmitResult("accepted", message or "页面显示该题已解出", evidence)

    return SubmitResult("unknown", message or toast or "无法确认提交结果", evidence)


async def _tcp_alive(target: Target, timeout: float = 3.0) -> bool:
    if not target.host or not target.port:
        return False
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port), timeout=timeout
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True
    except Exception:
        return False
