"""YCB 提交三源判定（响应 / toast / 页面已解）单元测试。"""

from __future__ import annotations

import pytest

from ycb.adapters.ycb import _is_submit_response, classify_submit_signal


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://ycb-qy.dasctf.com/slab-match/api/v1/player/ctf/exercise/submit", True),
        ("https://ycb-qy.dasctf.com/slab-match/api/v1/player/ctf/exercise/answer-panel", True),
        ("https://ycb-qy.dasctf.com/slab-match/api/v1/player/ctf/exercise/1", False),
        ("https://ycb-qy.dasctf.com/static/logo.png", False),
    ],
)
def test_is_submit_response(url, expected):
    assert _is_submit_response(url) is expected


def test_success_code_is_accepted():
    result = classify_submit_signal(
        http_status=200,
        payload={"code": "00000", "message": "提交成功", "data": {"correct": True}},
    )
    assert result.status == "accepted"
    assert "提交成功" in result.message


def test_success_boolean_flag_is_accepted():
    result = classify_submit_signal(http_status=200, payload={"success": True})
    assert result.status == "accepted"


def test_already_solved_message_wins_over_success():
    result = classify_submit_signal(
        http_status=200, payload={"code": "00000", "message": "该题已解出，无需重复提交"}
    )
    assert result.status == "already_solved"


def test_wrong_flag_is_rejected():
    result = classify_submit_signal(
        http_status=200, payload={"code": "10001", "message": "Flag 错误，请重试"}
    )
    assert result.status == "rejected"


def test_not_passed_is_rejected_not_accepted():
    result = classify_submit_signal(
        http_status=200, payload={"code": "200", "message": "未通过校验"}
    )
    assert result.status == "rejected"


def test_toast_rejection_without_payload():
    result = classify_submit_signal(
        http_status=200, payload=None, toast="flag 不正确"
    )
    assert result.status == "rejected"


def test_rate_limit_http_429():
    result = classify_submit_signal(
        http_status=429, payload={"message": "too many requests"}, retry_after=7.5
    )
    assert result.status == "rate_limited"
    assert result.evidence["retry_after"] == 7.5


def test_rate_limit_by_message():
    result = classify_submit_signal(
        http_status=200, payload={"code": "200", "message": "提交过于频繁，请稍后再试"}
    )
    assert result.status == "rate_limited"


def test_session_expired_http_401():
    result = classify_submit_signal(http_status=401, payload={"message": "未登录"})
    assert result.status == "session_expired"


def test_server_error_is_unknown():
    result = classify_submit_signal(http_status=502, payload=None)
    assert result.status == "unknown"


def test_empty_response_is_unknown_and_keeps_evidence():
    result = classify_submit_signal(
        http_status=200, payload={"code": "00000", "data": None}, toast=""
    )
    assert result.status == "accepted"  # 明确成功码
    unknown = classify_submit_signal(http_status=200, payload={}, toast="")
    assert unknown.status == "unknown"
    assert unknown.evidence["http"] == 200


def test_page_solved_transition_counts_as_accepted():
    result = classify_submit_signal(
        http_status=200,
        payload={"data": {"foo": "bar"}},
        page_solved_before=False,
        page_solved_after=True,
    )
    assert result.status == "accepted"
    assert result.evidence["page_transition"] is True


def test_flag_in_message_is_masked_in_evidence():
    result = classify_submit_signal(
        http_status=200,
        payload={"code": "10001", "message": "flag DASCTF{leaked_secret_value} 错误"},
    )
    assert result.status == "rejected"
    assert "leaked_secret_value" not in result.message
    assert "leaked_secret_value" not in result.evidence["payload_excerpt"]
