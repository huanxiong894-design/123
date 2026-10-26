"""YCB 适配器纯解析逻辑测试（不启动浏览器）。"""

from __future__ import annotations

import base64
import json

from ycb.adapters.browser_base import load_selectors
from ycb.adapters.ycb import (
    _answer_value,
    category_hints,
    decode_data_url,
    extract_challenges,
    parse_detail_snapshot,
    target_from_payload,
)
from ycb.platform.recorder import NetworkRecorder, redact

BASE = "https://ycb-qy.dasctf.com"


def test_exercise_list_corpus_is_json_string():
    payload = {
        "code": "00000",
        "data": {
            "stageList": [
                {
                    "id": 77,
                    "name": "Web",
                    "corpus": json.dumps(
                        [
                            {
                                "id": 9001,
                                "name": "EzWeb",
                                "score": 500,
                                "hasSolved": False,
                                "isOpen": True,
                                "hasEndpoint": True,
                            }
                        ]
                    ),
                },
                {
                    "id": 78,
                    "name": "Crypto",
                    "corpus": [{"id": 9002, "name": "SignIn", "score": 300}],
                },
            ]
        },
    }
    challenges = extract_challenges(payload, base_url=BASE, competition_id="1749")
    by_id = {item.platform_id: item for item in challenges}
    assert set(by_id) == {"9001", "9002"}
    assert by_id["9001"].category == "Web"
    assert by_id["9002"].category == "Crypto"
    assert by_id["9001"].container_available is True
    assert by_id["9001"].uid == "ycb:1749:9001"


def test_detail_topic_info_fields_and_target():
    payload = {
        "code": "00000",
        "data": {
            "id": 9001,
            "exerciseId": 9001,
            "name": "EzWeb",
            "score": 500,
            "description": "<p>访问 <b>目标</b></p><p>找 flag</p>",
            "classify": {"id": 3, "name": "Web"},
            "hasSolved": True,
            "attachment": [
                {"name": "源码.zip", "url": "/slab-match/api/v1/corpus/ctf/download?fileId=1"},
                {"name": "hint.txt", "url": "https://cdn.example/hint.txt", "size": 12},
            ],
            "endpoints": [
                {
                    "exposeIps": ["10.0.0.8:8080"],
                    "portMappings": [{"type": "http", "port": "8080"}],
                }
            ],
            "isNeedInit": True,
        },
    }
    challenges = extract_challenges(payload, base_url=BASE, competition_id="1749")
    assert len(challenges) == 1
    challenge = challenges[0]
    assert challenge.title == "EzWeb"
    assert challenge.category == "Web"
    assert challenge.score == 500
    assert challenge.solved_on_platform is True
    assert challenge.container_available is True
    assert "目标" in challenge.description_md
    assert "<p>" not in challenge.description_md
    assert challenge.target.host == "10.0.0.8"
    assert challenge.target.port == 8080
    names = [item.name for item in challenge.attachments]
    assert "hint.txt" in names
    assert any(name.endswith(".zip") and name.startswith("attachment-") for name in names)
    source = next(item for item in challenge.attachments if item.name.endswith(".zip"))
    assert source.url.startswith(BASE + "/slab-match/api/v1/corpus/ctf/download")


def test_category_only_nodes_are_rejected():
    payload = {
        "data": {
            "typeList": [
                {"id": 1, "name": "Web"},  # 分类 tab，没有分值/说明/附件
                {"id": 2, "name": "Pwn"},
            ]
        }
    }
    assert extract_challenges(payload, base_url=BASE, competition_id="1749") == []


def test_double_encoded_corpus():
    inner = json.dumps([{"id": 42, "name": "Nested", "score": 100}])
    payload = {"data": {"name": "Misc", "corpus": json.dumps(inner)}}
    challenges = extract_challenges(payload, base_url=BASE, competition_id="1749")
    assert len(challenges) == 1
    assert challenges[0].platform_id == "42"
    assert challenges[0].category == "Misc"


def test_category_hints_from_type_list():
    payload = {
        "data": {
            "typeList": [
                {"name": "Reverse", "corpus": json.dumps([{"id": "r1"}, {"id": "r2"}])}
            ]
        }
    }
    assert category_hints(payload) == {"r1": "Reverse", "r2": "Reverse"}


def test_detail_dom_snapshot_fallback():
    snapshot = {
        "title": "",
        "items": {
            "题目名称": "Classic RSA",
            "题目内容": "n = 12345",
            "题目分值": "500",
            "题目类型": "Crypto",
        },
        "files": ["附件.txt"],
        "text": "",
    }
    challenge = parse_detail_snapshot(
        snapshot, base_url=BASE, competition_id="1749", category="misc"
    )
    assert challenge is not None
    assert challenge.title == "Classic RSA"
    assert challenge.category == "Crypto"
    assert challenge.score == 500
    assert challenge.description_md == "n = 12345"
    assert len(challenge.attachments) == 1
    assert challenge.platform_id  # DOM 兜底使用稳定指纹


def test_target_port_mapping_without_expose_port():
    target = target_from_payload(
        {"endpoints": [{"exposeIps": ["172.16.0.9"], "portMappings": [{"port": "9000"}]}]}
    )
    assert target is not None
    assert target.address() == "172.16.0.9:9000"


def test_decode_captcha_data_url():
    raw = b"\x89PNG\r\n"
    src = "data:image/png;base64," + base64.b64encode(raw).decode()
    assert decode_data_url(src) == raw
    assert decode_data_url("data:image/svg+xml,%3Csvg%3E") == b""
    assert decode_data_url(None) == b""


def test_ycb_selectors_are_loadable():
    book = load_selectors("ycb")
    assert book.get("login", "username")
    assert book.get("login", "captcha_image")
    assert book.get("challenge", "number_item")
    assert book.first("challenge", "number_item").endswith(".number_item")


def test_recorder_redacts_secrets_and_whitelists_urls(tmp_path):
    value = {
        "token": "abc",
        "nested": {"password": "p", "Authorization": "Bearer x", "ok": 1},
        "items": [{"sessionId": "s", "name": "n"}],
    }
    cleaned = redact(value)
    assert cleaned["token"] == "***"
    assert cleaned["nested"]["password"] == "***"
    assert cleaned["nested"]["Authorization"] == "***"
    assert cleaned["nested"]["ok"] == 1
    assert cleaned["items"][0]["sessionId"] == "***"
    assert cleaned["items"][0]["name"] == "n"

    assert NetworkRecorder.interesting(f"{BASE}/slab-match/api/v1/player/ctf/exercise")
    assert not NetworkRecorder.interesting(f"{BASE}/auth-user/api/login")
    recorder = NetworkRecorder(tmp_path)
    assert recorder._file.stat().st_mode & 0o777 == 0o600
    recorder.clear()
    if recorder._fh is not None:
        recorder._fh.close()


def test_answer_value_strips_outer_wrapper():
    # 平台答题框只填大括号内内容；本地 flag.txt 保留完整形式。
    assert _answer_value("DASCTF{abc123}") == "abc123"
    assert _answer_value("flag{y0u_f0und}") == "y0u_f0und"
    assert _answer_value("  DASCTF{a{b}c}  ") == "a{b}c"
    assert _answer_value("plain_value") == "plain_value"
    assert _answer_value("DASCTF{}") == ""
