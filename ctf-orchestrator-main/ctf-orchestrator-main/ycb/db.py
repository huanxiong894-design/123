"""SQLite 持久层（单连接、单写者、WAL）。

约定：
- 所有状态变更用 CAS（WHERE status=?）；迁移合法性由 state_machine 校验。
- 题目 upsert 只更新平台侧字段，绝不覆盖本地状态/工作目录。
- 事件 seq 全局单调；token delta 等高频事件不入库（由 EventBus 决定）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import aiosqlite

from ycb.models import (
    Attachment,
    Challenge,
    Event,
    Status,
    Target,
    now_iso,
)
from ycb.scheduling.state_machine import can_transition

log = logging.getLogger(__name__)

_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS challenges (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    uid                TEXT NOT NULL UNIQUE,
    platform           TEXT NOT NULL,
    competition_id     TEXT NOT NULL,
    platform_id        TEXT NOT NULL,
    seq_no             INTEGER NOT NULL,
    title              TEXT NOT NULL,
    category           TEXT NOT NULL DEFAULT '',
    score              INTEGER,
    description_md     TEXT NOT NULL DEFAULT '',
    attachments_json   TEXT NOT NULL DEFAULT '[]',
    target_json        TEXT,
    flag_regex         TEXT,
    container_available INTEGER NOT NULL DEFAULT 0,
    solved_on_platform INTEGER NOT NULL DEFAULT 0,
    fingerprint        TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'DISCOVERED',
    workspace          TEXT,
    raw_json           TEXT NOT NULL DEFAULT '{}',
    discovered_at      TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    solved_at          TEXT,
    UNIQUE(platform, competition_id, platform_id)
);

CREATE TABLE IF NOT EXISTS events (
    seq           INTEGER PRIMARY KEY,
    ts            TEXT NOT NULL,
    type          TEXT NOT NULL,
    challenge_id  INTEGER REFERENCES challenges(id) ON DELETE CASCADE,
    run_id        INTEGER,
    payload_json  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_challenge ON events(challenge_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, seq);

CREATE TABLE IF NOT EXISTS runs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id       INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    backend            TEXT NOT NULL,
    session_id         TEXT,
    pid                INTEGER,
    pgid               INTEGER,
    proc_start_ticks   TEXT,
    status             TEXT NOT NULL DEFAULT 'STARTING',
    resume_of          INTEGER,
    started_at         TEXT NOT NULL,
    ended_at           TEXT,
    raw_path           TEXT,
    meta_json          TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_runs_challenge ON runs(challenge_id, id);

CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id  INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    run_id        INTEGER,
    direction     TEXT NOT NULL,          -- operator | agent | system
    content       TEXT NOT NULL,
    delivered     INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_challenge ON messages(challenge_id, id);

CREATE TABLE IF NOT EXISTS submissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id  INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    run_id        INTEGER,
    flag          TEXT NOT NULL,
    flag_sha256   TEXT NOT NULL,
    status        TEXT NOT NULL,
    message       TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    dry_run       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    UNIQUE(challenge_id, flag_sha256)
);
CREATE INDEX IF NOT EXISTS idx_submissions_challenge ON submissions(challenge_id, id);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._conn: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()

    # ------------------------------------------------------------------ lifecycle
    async def connect(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path, isolation_level=None)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await self._conn.executescript(_SCHEMA)
        await self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(_SCHEMA_VERSION),),
        )
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover
            pass
        log.info("数据库就绪 path=%s", self.path)

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database 未 connect()")
        return self._conn

    # ------------------------------------------------------------------ challenges
    async def insert_challenge(
        self,
        challenge: Challenge,
        *,
        seq_no: int,
        workspace: str,
        flag_regex: str | None,
    ) -> int:
        ts = now_iso()
        async with self._write_lock:
            cur = await self.conn.execute(
                """
                INSERT INTO challenges (
                    uid, platform, competition_id, platform_id, seq_no, title, category, score,
                    description_md, attachments_json, target_json, flag_regex,
                    container_available, solved_on_platform, fingerprint, status, workspace,
                    raw_json, discovered_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    challenge.uid,
                    challenge.platform,
                    challenge.competition_id,
                    challenge.platform_id,
                    seq_no,
                    challenge.title,
                    challenge.category,
                    challenge.score,
                    challenge.description_md,
                    json.dumps([a.to_dict() for a in challenge.attachments], ensure_ascii=False),
                    json.dumps(challenge.target.to_dict(), ensure_ascii=False) if challenge.target else None,
                    flag_regex,
                    int(challenge.container_available),
                    int(challenge.solved_on_platform),
                    challenge.fingerprint(),
                    Status.DISCOVERED.value,
                    workspace,
                    json.dumps(challenge.raw, ensure_ascii=False, sort_keys=True, default=str),
                    ts,
                    ts,
                ),
            )
            await self.conn.commit()
            row_id = cur.lastrowid
        return int(row_id)

    async def get_challenge(self, challenge_id: int) -> Challenge | None:
        cur = await self.conn.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,))
        row = await cur.fetchone()
        return _row_to_challenge(row) if row else None

    async def get_challenge_by_uid(self, uid: str) -> Challenge | None:
        cur = await self.conn.execute("SELECT * FROM challenges WHERE uid=?", (uid,))
        row = await cur.fetchone()
        return _row_to_challenge(row) if row else None

    async def list_challenges(self) -> list[Challenge]:
        cur = await self.conn.execute("SELECT * FROM challenges ORDER BY seq_no, id")
        rows = await cur.fetchall()
        return [_row_to_challenge(row) for row in rows]

    async def update_challenge_from_platform(self, challenge: Challenge) -> bool:
        """用平台快照更新展示字段；不触碰 status/workspace。返回是否发生变化。"""
        fp = challenge.fingerprint()
        async with self._write_lock:
            cur = await self.conn.execute(
                """
                UPDATE challenges SET
                    title=?, category=?, score=?, description_md=?, attachments_json=?,
                    target_json=?, flag_regex=COALESCE(?, flag_regex),
                    container_available=?, solved_on_platform=?, fingerprint=?, raw_json=?, updated_at=?
                WHERE uid=? AND (fingerprint != ? OR raw_json != ?)
                """,
                (
                    challenge.title,
                    challenge.category,
                    challenge.score,
                    challenge.description_md,
                    json.dumps([a.to_dict() for a in challenge.attachments], ensure_ascii=False),
                    json.dumps(challenge.target.to_dict(), ensure_ascii=False) if challenge.target else None,
                    challenge.flag_regex,
                    int(challenge.container_available),
                    int(challenge.solved_on_platform),
                    fp,
                    json.dumps(challenge.raw, ensure_ascii=False, sort_keys=True, default=str),
                    now_iso(),
                    challenge.uid,
                    fp,
                    json.dumps(challenge.raw, ensure_ascii=False, sort_keys=True, default=str),
                ),
            )
            changed = cur.rowcount > 0
            await self.conn.commit()
        return changed

    async def cas_status(
        self,
        challenge_id: int,
        expected: Status | str,
        target: Status | str,
        *,
        force: bool = False,
        solved: bool = False,
    ) -> bool:
        exp = Status.parse(expected)
        dst = Status.parse(target)
        if not can_transition(exp, dst, force=force):
            log.warning("拒绝非法状态迁移 challenge=%s %s -> %s", challenge_id, exp.value, dst.value)
            return False
        ts = now_iso()
        async with self._write_lock:
            cur = await self.conn.execute(
                "UPDATE challenges SET status=?, updated_at=?, solved_at=CASE WHEN ? THEN ? ELSE solved_at END "
                "WHERE id=? AND status=?",
                (dst.value, ts, int(solved), ts, challenge_id, exp.value),
            )
            ok = cur.rowcount > 0
            await self.conn.commit()
        return ok

    async def force_status(self, challenge_id: int, target: Status | str) -> bool:
        dst = Status.parse(target)
        async with self._write_lock:
            cur = await self.conn.execute(
                "UPDATE challenges SET status=?, updated_at=? WHERE id=?",
                (dst.value, now_iso(), challenge_id),
            )
            ok = cur.rowcount > 0
            await self.conn.commit()
        return ok

    async def set_workspace(self, challenge_id: int, workspace: str) -> None:
        async with self._write_lock:
            await self.conn.execute(
                "UPDATE challenges SET workspace=?, updated_at=? WHERE id=?",
                (workspace, now_iso(), challenge_id),
            )
            await self.conn.commit()

    async def set_target(self, challenge_id: int, target: Any) -> None:
        """记录按需启动的容器地址（target=None 表示清除）。"""
        payload = json.dumps(target.to_dict(), ensure_ascii=False) if target is not None else None
        async with self._write_lock:
            await self.conn.execute(
                "UPDATE challenges SET target_json=?, updated_at=? WHERE id=?",
                (payload, now_iso(), challenge_id),
            )
            await self.conn.commit()

    async def allocate_seq_no(self, platform: str, competition_id: str) -> int:
        """按平台/比赛分配人类可读题目序号（1 起）。"""
        key = f"seq:{platform}:{competition_id}"
        async with self._write_lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                cur = await self.conn.execute("SELECT value FROM meta WHERE key=?", (key,))
                row = await cur.fetchone()
                nxt = int(row["value"]) + 1 if row else 1
                await self.conn.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, str(nxt)),
                )
                await self.conn.commit()
            except BaseException:
                await self.conn.rollback()
                raise
        return nxt

    # ------------------------------------------------------------------ events
    async def max_event_seq(self) -> int:
        cur = await self.conn.execute("SELECT COALESCE(MAX(seq), 0) AS m FROM events")
        row = await cur.fetchone()
        return int(row["m"]) if row else 0

    async def insert_event(self, event: Event) -> None:
        async with self._write_lock:
            await self.conn.execute(
                "INSERT INTO events(seq, ts, type, challenge_id, run_id, payload_json) VALUES(?,?,?,?,?,?)",
                (
                    event.seq,
                    event.ts,
                    event.type,
                    event.challenge_id,
                    event.run_id,
                    json.dumps(event.payload, ensure_ascii=False, default=str),
                ),
            )
            await self.conn.commit()

    async def events_after(self, seq: int, limit: int = 1000) -> list[Event]:
        cur = await self.conn.execute(
            "SELECT * FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?", (seq, limit)
        )
        rows = await cur.fetchall()
        return [_row_to_event(row) for row in rows]

    async def events_for_challenge(self, challenge_id: int, limit: int = 300) -> list[Event]:
        cur = await self.conn.execute(
            "SELECT * FROM (SELECT * FROM events WHERE challenge_id=? ORDER BY seq DESC LIMIT ?) ORDER BY seq ASC",
            (challenge_id, limit),
        )
        rows = await cur.fetchall()
        return [_row_to_event(row) for row in rows]

    async def recent_events(self, limit: int = 200, upto_seq: int | None = None) -> list[Event]:
        """最近的持久化事件（按 seq 升序），供 WS resync 时给看板补历史上下文。"""
        if upto_seq is None:
            sql = "SELECT * FROM (SELECT * FROM events ORDER BY seq DESC LIMIT ?) ORDER BY seq ASC"
            params: tuple[Any, ...] = (limit,)
        else:
            sql = (
                "SELECT * FROM (SELECT * FROM events WHERE seq <= ? ORDER BY seq DESC LIMIT ?) "
                "ORDER BY seq ASC"
            )
            params = (upto_seq, limit)
        cur = await self.conn.execute(sql, params)
        rows = await cur.fetchall()
        return [_row_to_event(row) for row in rows]

    # ------------------------------------------------------------------ meta
    async def meta_get(self, key: str) -> str | None:
        cur = await self.conn.execute("SELECT value FROM meta WHERE key=?", (key,))
        row = await cur.fetchone()
        return row["value"] if row else None

    async def meta_set(self, key: str, value: str) -> None:
        async with self._write_lock:
            await self.conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            await self.conn.commit()

    # ------------------------------------------------------------------ messages
    async def add_message(
        self,
        challenge_id: int,
        *,
        direction: str,
        content: str,
        delivered: bool = False,
        run_id: int | None = None,
    ) -> int:
        async with self._write_lock:
            cur = await self.conn.execute(
                "INSERT INTO messages(challenge_id, run_id, direction, content, delivered, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (challenge_id, run_id, direction, content, int(delivered), now_iso()),
            )
            await self.conn.commit()
            msg_id = cur.lastrowid
        return int(msg_id)

    async def mark_message_delivered(self, message_id: int) -> None:
        async with self._write_lock:
            await self.conn.execute("UPDATE messages SET delivered=1 WHERE id=?", (message_id,))
            await self.conn.commit()

    async def list_messages(self, challenge_id: int, limit: int = 200) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM (SELECT * FROM messages WHERE challenge_id=? ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (challenge_id, limit),
        )
        rows = await cur.fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------ runs
    async def create_run(
        self,
        challenge_id: int,
        *,
        backend: str,
        session_id: str | None = None,
        resume_of: int | None = None,
    ) -> int:
        async with self._write_lock:
            cur = await self.conn.execute(
                "INSERT INTO runs(challenge_id, backend, session_id, status, resume_of, started_at) "
                "VALUES(?,?,?,'STARTING',?,?)",
                (challenge_id, backend, session_id, resume_of, now_iso()),
            )
            await self.conn.commit()
            return int(cur.lastrowid)

    async def update_run(self, run_id: int, **fields: Any) -> None:
        allowed = {
            "session_id",
            "pid",
            "pgid",
            "proc_start_ticks",
            "status",
            "ended_at",
            "raw_path",
            "meta_json",
        }
        data = {k: v for k, v in fields.items() if k in allowed}
        if not data:
            return
        sets = ", ".join(f"{k}=?" for k in data)
        async with self._write_lock:
            await self.conn.execute(f"UPDATE runs SET {sets} WHERE id=?", (*data.values(), run_id))
            await self.conn.commit()

    async def get_run(self, run_id: int) -> dict[str, Any] | None:
        cur = await self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

    async def active_runs(self) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM runs WHERE status IN ('STARTING','RUNNING','PAUSED') ORDER BY id"
        )
        return [dict(row) for row in await cur.fetchall()]

    async def runs_for_challenge(self, challenge_id: int, limit: int = 20) -> list[dict[str, Any]]:
        cur = await self.conn.execute(
            "SELECT * FROM (SELECT * FROM runs WHERE challenge_id=? ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (challenge_id, limit),
        )
        return [dict(row) for row in await cur.fetchall()]

    # ------------------------------------------------------------------ submissions
    async def add_submission(
        self,
        challenge_id: int,
        *,
        flag: str,
        flag_sha256: str,
        status: str,
        message: str = "",
        evidence: dict[str, Any] | None = None,
        dry_run: bool = True,
        run_id: int | None = None,
    ) -> int | None:
        """同题同 flag 唯一；重复返回 None。"""
        async with self._write_lock:
            cur = await self.conn.execute(
                "INSERT OR IGNORE INTO submissions("
                "challenge_id, run_id, flag, flag_sha256, status, message, evidence_json, dry_run, created_at"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    challenge_id,
                    run_id,
                    flag,
                    flag_sha256,
                    status,
                    message,
                    json.dumps(evidence or {}, ensure_ascii=False, default=str),
                    int(dry_run),
                    now_iso(),
                ),
            )
            await self.conn.commit()
            if cur.rowcount == 0:
                return None
            return int(cur.lastrowid)

    async def flag_already_tried(self, challenge_id: int, flag_sha256: str) -> bool:
        cur = await self.conn.execute(
            "SELECT 1 FROM submissions WHERE challenge_id=? AND flag_sha256=? LIMIT 1",
            (challenge_id, flag_sha256),
        )
        row = await cur.fetchone()
        return row is not None

    async def get_submission(self, submission_id: int) -> dict[str, Any] | None:
        cur = await self.conn.execute("SELECT * FROM submissions WHERE id=?", (submission_id,))
        row = await cur.fetchone()
        return dict(row) if row is not None else None

    async def find_submission(
        self, challenge_id: int, flag_sha256: str
    ) -> dict[str, Any] | None:
        cur = await self.conn.execute(
            "SELECT * FROM submissions WHERE challenge_id=? AND flag_sha256=? LIMIT 1",
            (challenge_id, flag_sha256),
        )
        row = await cur.fetchone()
        return dict(row) if row is not None else None

    async def update_submission(
        self,
        submission_id: int,
        *,
        status: str | None = None,
        message: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> bool:
        fields: list[str] = []
        params: list[Any] = []
        if status is not None:
            fields.append("status=?")
            params.append(status)
        if message is not None:
            fields.append("message=?")
            params.append(message)
        if evidence is not None:
            fields.append("evidence_json=?")
            params.append(json.dumps(evidence, ensure_ascii=False, default=str))
        if not fields:
            return False
        params.append(submission_id)
        async with self._write_lock:
            cur = await self.conn.execute(
                f"UPDATE submissions SET {', '.join(fields)} WHERE id=?", tuple(params)
            )
            await self.conn.commit()
            return cur.rowcount > 0

    async def reserve_live_submission(
        self,
        challenge_id: int,
        *,
        flag: str,
        flag_sha256: str,
        max_live: int,
        run_id: int | None = None,
    ) -> tuple[int | None, str]:
        """原子地占一次真实提交额度并插入 pending 行。

        返回 ``(submission_id, "ok")``；重复 flag 返回 ``(None, "duplicate")``；
        额度用尽返回 ``(None, "quota")``。所有 dry_run=0 的行（含失败/限流）都计入额度。
        """
        async with self._write_lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                cur = await self.conn.execute(
                    "SELECT 1 FROM submissions WHERE challenge_id=? AND flag_sha256=? LIMIT 1",
                    (challenge_id, flag_sha256),
                )
                if await cur.fetchone() is not None:
                    await self.conn.rollback()
                    return None, "duplicate"
                cur = await self.conn.execute(
                    "SELECT COUNT(*) AS n FROM submissions WHERE dry_run=0"
                )
                row = await cur.fetchone()
                used = int(row["n"] or 0) if row is not None else 0
                if used >= max(0, int(max_live)):
                    await self.conn.rollback()
                    return None, "quota"
                cur = await self.conn.execute(
                    "INSERT INTO submissions("
                    "challenge_id, run_id, flag, flag_sha256, status, message, evidence_json, dry_run, created_at"
                    ") VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        challenge_id,
                        run_id,
                        flag,
                        flag_sha256,
                        "pending",
                        "",
                        "{}",
                        0,
                        now_iso(),
                    ),
                )
                submission_id = int(cur.lastrowid)
                await self.conn.commit()
                return submission_id, "ok"
            except BaseException:
                await self.conn.rollback()
                raise

    async def promote_dry_run_submission(
        self, submission_id: int, *, max_live: int
    ) -> str:
        """dry_run 关闭后把旧记录升级为真实提交（占额度）。

        返回 ``ok | quota | missing | not_dry``。
        """
        async with self._write_lock:
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                cur = await self.conn.execute(
                    "SELECT status, dry_run FROM submissions WHERE id=?", (submission_id,)
                )
                row = await cur.fetchone()
                if row is None:
                    await self.conn.rollback()
                    return "missing"
                if int(row["dry_run"]) != 1 or str(row["status"]) != "dry_run":
                    await self.conn.rollback()
                    return "not_dry"
                cur = await self.conn.execute(
                    "SELECT COUNT(*) AS n FROM submissions WHERE dry_run=0"
                )
                count_row = await cur.fetchone()
                used = int(count_row["n"] or 0) if count_row is not None else 0
                if used >= max(0, int(max_live)):
                    await self.conn.rollback()
                    return "quota"
                await self.conn.execute(
                    "UPDATE submissions SET status='pending', dry_run=0, message='' WHERE id=?",
                    (submission_id,),
                )
                await self.conn.commit()
                return "ok"
            except BaseException:
                await self.conn.rollback()
                raise

    async def count_live_submissions(self) -> int:
        cur = await self.conn.execute("SELECT COUNT(*) AS n FROM submissions WHERE dry_run=0")
        row = await cur.fetchone()
        return int(row["n"] or 0) if row is not None else 0

    async def count_rejections(self, challenge_id: int) -> int:
        cur = await self.conn.execute(
            "SELECT COUNT(*) AS n FROM submissions WHERE challenge_id=? AND status='rejected'",
            (challenge_id,),
        )
        row = await cur.fetchone()
        return int(row["n"] or 0) if row is not None else 0

    async def pending_submissions(self) -> list[dict[str, Any]]:
        """进程重启后仍为 pending（可能已送达也可能未送达）的行。"""
        cur = await self.conn.execute(
            "SELECT * FROM submissions WHERE dry_run=0 AND status IN ('pending','submitting') ORDER BY id"
        )
        return [dict(row) for row in await cur.fetchall()]

    async def list_submissions(
        self, challenge_id: int | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        if challenge_id is None:
            cur = await self.conn.execute(
                "SELECT * FROM (SELECT * FROM submissions ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
                (limit,),
            )
        else:
            cur = await self.conn.execute(
                "SELECT * FROM (SELECT * FROM submissions WHERE challenge_id=? ORDER BY id DESC LIMIT ?) "
                "ORDER BY id ASC",
                (challenge_id, limit),
            )
        return [dict(row) for row in await cur.fetchall()]

    async def submission_stats(self) -> dict[str, int]:
        cur = await self.conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status='accepted' OR status='already_solved' THEN 1 ELSE 0 END) AS accepted, "
            "SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rejected, "
            "SUM(CASE WHEN dry_run=0 THEN 1 ELSE 0 END) AS live "
            "FROM submissions"
        )
        row = await cur.fetchone()
        return {k: int(row[k] or 0) for k in ("total", "accepted", "rejected", "live")}

    # ------------------------------------------------------------------ overview
    async def counts_by_status(self) -> dict[str, int]:
        cur = await self.conn.execute("SELECT status, COUNT(*) AS n FROM challenges GROUP BY status")
        return {row["status"]: int(row["n"]) for row in await cur.fetchall()}

    async def total_challenges(self) -> int:
        cur = await self.conn.execute("SELECT COUNT(*) AS n FROM challenges")
        row = await cur.fetchone()
        return int(row["n"]) if row else 0


# ---------------------------------------------------------------------- row helpers
def _row_to_challenge(row: aiosqlite.Row) -> Challenge:
    attachments = [
        Attachment.from_dict(item) for item in json.loads(row["attachments_json"] or "[]")
    ]
    target = Target.from_dict(json.loads(row["target_json"])) if row["target_json"] else None
    return Challenge(
        uid=row["uid"],
        platform=row["platform"],
        competition_id=row["competition_id"],
        platform_id=row["platform_id"],
        title=row["title"],
        category=row["category"] or "",
        score=row["score"],
        description_md=row["description_md"] or "",
        attachments=attachments,
        target=target,
        flag_regex=row["flag_regex"],
        raw=json.loads(row["raw_json"] or "{}"),
        container_available=bool(row["container_available"]),
        solved_on_platform=bool(row["solved_on_platform"]),
        seq_no=row["seq_no"],
        status=Status.parse(row["status"]),
        workspace=row["workspace"],
        db_id=row["id"],
        discovered_at=row["discovered_at"],
        updated_at=row["updated_at"],
    )


def _row_to_event(row: aiosqlite.Row) -> Event:
    return Event(
        seq=int(row["seq"]),
        ts=row["ts"],
        type=row["type"],
        challenge_id=row["challenge_id"],
        run_id=row["run_id"],
        payload=json.loads(row["payload_json"] or "{}"),
    )


def challenge_counts_summary(counts: dict[str, int], total: int) -> dict[str, int]:
    """补零，方便前端渲染固定状态列。"""
    summary = {status.value: int(counts.get(status.value, 0)) for status in Status}
    summary["_total"] = total
    return summary
