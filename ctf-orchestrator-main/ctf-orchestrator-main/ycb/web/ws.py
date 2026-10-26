"""WebSocket：hello 快照 + 按 seq 补发 + 实时广播 + ping/pong。"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ycb.models import now_iso
from ycb.web.overview import build_overview

log = logging.getLogger(__name__)
router = APIRouter()

REPLAY_LIMIT = 1000
_SUB_QUEUE = 800


def _authorized(websocket: WebSocket) -> bool:
    token = websocket.app.state.ctx.config.server.token
    if not token:
        return True
    supplied = websocket.query_params.get("token") or websocket.cookies.get("ycb_token") or ""
    return bool(supplied) and secrets.compare_digest(supplied, token)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    if not _authorized(websocket):
        await websocket.close(code=4401)
        return
    await websocket.accept()

    ctx = websocket.app.state.ctx
    since_raw = websocket.query_params.get("since_seq")
    since: int | None = None
    if since_raw:
        try:
            since = max(0, int(since_raw))
        except ValueError:
            since = None
    if websocket.query_params.get("reset") in {"1", "true", "yes"}:
        since = None  # 前端主动要求 resync：以 hello 快照为准

    sub = ctx.bus.subscribe(maxsize=_SUB_QUEUE)
    send_lock = asyncio.Lock()
    sender_task: asyncio.Task | None = None

    async def send(payload: dict) -> None:
        async with send_lock:
            await websocket.send_json(payload)

    try:
        max_seq = ctx.bus.last_seq
        resync = False
        replay = []
        if since is None or since > max_seq:
            resync = True
        else:
            replay = await ctx.bus.replay_after(since, limit=REPLAY_LIMIT)
            if len(replay) >= REPLAY_LIMIT and replay and replay[-1].seq < max_seq:
                resync = True
                replay = []

        overview = await build_overview(ctx)
        challenges = [challenge.to_dict() for challenge in await ctx.db.list_challenges()]
        recent = (
            [event.to_dict() for event in await ctx.db.recent_events(limit=200, upto_seq=max_seq)]
            if resync
            else []
        )
        hello = {
            "v": 1,
            "seq": max_seq,
            "ts": now_iso(),
            "type": "hello",
            "challenge_id": None,
            "run_id": None,
            "payload": {
                "overview": overview,
                "challenges": challenges,
                "events": recent,
                "server_time": now_iso(),
                "resync": resync,
                "since_seq": since,
            },
        }
        await send(hello)
        for event in replay:
            await send(event.to_dict())

        threshold = max_seq if resync else (replay[-1].seq if replay else (since or 0))

        async def sender() -> None:
            dropped_seen = 0
            while True:
                event = await sub.get()
                if event.seq <= threshold:
                    continue
                if sub.dropped > dropped_seen:
                    dropped_seen = sub.dropped
                    await send(
                        {
                            "v": 1,
                            "seq": event.seq,
                            "ts": now_iso(),
                            "type": "event.dropped",
                            "challenge_id": None,
                            "run_id": None,
                            "payload": {
                                "count": dropped_seen,
                                "last_seq": event.seq,
                                "resync_recommended": True,
                            },
                        }
                    )
                await send(event.to_dict())

        sender_task = asyncio.create_task(sender(), name="ws-sender")

        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            text = message.get("text")
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if data.get("type") == "ping":
                await send(
                    {
                        "v": 1,
                        "seq": ctx.bus.last_seq,
                        "ts": now_iso(),
                        "type": "pong",
                        "challenge_id": None,
                        "run_id": None,
                        "payload": {"ts": data.get("ts")},
                    }
                )
    except WebSocketDisconnect:
        pass
    except Exception:  # pragma: no cover - 连接异常不拖垮服务
        log.exception("WebSocket 连接异常")
    finally:
        ctx.bus.unsubscribe(sub)
        if sender_task is not None:
            sender_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await sender_task
