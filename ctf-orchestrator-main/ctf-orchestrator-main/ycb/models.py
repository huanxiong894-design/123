"""归一化领域模型：解题内核只认识这些结构，不认识任何平台 DOM/API。"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def now_iso() -> str:
    """UTC ISO-8601（秒精度）。前端按浏览器本地时区展示。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Status(str, Enum):
    DISCOVERED = "DISCOVERED"
    PREPARING = "PREPARING"
    READY = "READY"
    SOLVING = "SOLVING"
    SOLVED = "SOLVED"
    SUBMITTING = "SUBMITTING"
    SUBMITTED = "SUBMITTED"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    NEEDS_HUMAN = "NEEDS_HUMAN"

    @classmethod
    def parse(cls, value: str | "Status") -> "Status":
        if isinstance(value, Status):
            return value
        try:
            return cls(str(value).upper())
        except ValueError as exc:
            raise ValueError(f"未知状态：{value!r}") from exc


@dataclass(slots=True)
class Target:
    kind: str  # tcp | http | ssh
    host: str
    port: int | None = None
    url: str | None = None
    creds: dict[str, str] = field(default_factory=dict)
    expires_at: str | None = None

    def address(self) -> str:
        if self.url:
            return self.url
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "creds": dict(self.creds),
            "expires_at": self.expires_at,
            "address": self.address(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Target | None":
        if not data:
            return None
        return cls(
            kind=str(data.get("kind", "tcp")),
            host=str(data.get("host", "")),
            port=data.get("port"),
            url=data.get("url"),
            creds=dict(data.get("creds") or {}),
            expires_at=data.get("expires_at"),
        )


@dataclass(slots=True)
class Attachment:
    name: str
    url: str = ""
    size: int | None = None
    sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "url": self.url, "size": self.size, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Attachment":
        return cls(
            name=str(data.get("name", "attachment")),
            url=str(data.get("url", "")),
            size=data.get("size"),
            sha256=data.get("sha256"),
        )


@dataclass(slots=True)
class Challenge:
    uid: str
    platform: str
    competition_id: str
    platform_id: str
    title: str
    category: str = ""
    score: int | None = None
    description_md: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    target: Target | None = None
    flag_regex: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    container_available: bool = False
    solved_on_platform: bool = False
    seq_no: int | None = None
    status: Status = Status.DISCOVERED
    workspace: str | None = None
    db_id: int | None = None
    discovered_at: str | None = None
    updated_at: str | None = None

    def fingerprint(self) -> str:
        """快照指纹：用于“连续两轮一致才建题”和变更检测。

        不含容器地址与本地状态（容器可能按需启动，不应导致重复建题）。
        """
        material = {
            "title": self.title,
            "category": self.category,
            "score": self.score,
            "description": self.description_md,
            "attachments": [(a.name, a.size, a.sha256) for a in self.attachments],
            "container_available": self.container_available,
            "solved": self.solved_on_platform,
        }
        blob = json.dumps(material, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        status = self.status.value if isinstance(self.status, Status) else str(self.status)
        return {
            "id": self.db_id,
            "uid": self.uid,
            "platform": self.platform,
            "competition_id": self.competition_id,
            "platform_id": self.platform_id,
            "seq_no": self.seq_no,
            "title": self.title,
            "category": self.category,
            "score": self.score,
            "description_md": self.description_md,
            "attachments": [a.to_dict() for a in self.attachments],
            "target": self.target.to_dict() if self.target else None,
            "flag_regex": self.flag_regex,
            "container_available": self.container_available,
            "solved_on_platform": self.solved_on_platform,
            "status": status,
            "workspace": self.workspace,
            "discovered_at": self.discovered_at,
            "updated_at": self.updated_at,
            "raw": self.raw,
        }


@dataclass(slots=True)
class SubmitResult:
    status: str  # accepted | rejected | already_solved | rate_limited | session_expired | unknown
    message: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "message": self.message, "evidence": self.evidence}


@dataclass(slots=True)
class SessionState:
    state: str = "unknown"  # unknown | logged_out | logged_in | needs_human | error
    detail: str = ""
    username: str | None = None
    at: str = field(default_factory=now_iso)

    @property
    def logged_in(self) -> bool:
        return self.state == "logged_in"

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "detail": self.detail,
            "username": self.username,
            "at": self.at,
        }


@dataclass(slots=True)
class Event:
    seq: int
    ts: str
    type: str
    challenge_id: int | None = None
    run_id: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": 1,
            "seq": self.seq,
            "ts": self.ts,
            "type": self.type,
            "challenge_id": self.challenge_id,
            "run_id": self.run_id,
            "payload": self.payload,
        }


def platform_key(
    platform_id: str | None,
    *,
    href: str | None = None,
    category: str = "",
    title: str = "",
    score: int | None = None,
    fallback: str = "",
) -> str:
    """计划中的 platform_key 优先级：平台 id > href 数字 > sha1(type|title|score)。"""
    if platform_id:
        return str(platform_id)
    if href:
        digits = "".join(ch for ch in href if ch.isdigit())
        if digits:
            return digits
    material = f"{category}|{title}|{score}|{fallback}"
    return hashlib.sha1(material.encode("utf-8")).hexdigest()[:16]


def make_uid(platform: str, competition_id: str, key: str) -> str:
    return f"{platform}:{competition_id}:{key}"
