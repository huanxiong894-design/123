"""进程内异步事件总线。

- seq 全局单调递增；持久化事件先写 DB 再广播，保证断线按 seq 补发。
- token delta / heartbeat / 发现心跳等高频事件只广播不落库。
- 每个订阅者有界队列；满时优先丢 delta，再丢最旧事件，并累计 dropped 供前端提示重同步。
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any

from ycb.db import Database
from ycb.models import Event, now_iso

log = logging.getLogger(__name__)

EPHEMERAL_TYPES = {
    "heartbeat",
    "discovery.tick",
    "event.dropped",
    "pong",
}
EPHEMERAL_SUFFIXES = (".delta",)


def is_ephemeral(event_type: str) -> bool:
    return event_type in EPHEMERAL_TYPES or event_type.endswith(EPHEMERAL_SUFFIXES)


class SubscriptionClosed(RuntimeError):
    pass


class Subscription:
    def __init__(self, maxsize: int = 500):
        self.maxsize = max(1, int(maxsize))
        self._items: deque[Event] = deque()
        self._wake = asyncio.Event()
        self._closed = False
        self.dropped = 0
        self.last_dropped_seq = 0

    def offer(self, event: Event) -> None:
        if self._closed:
            return
        if len(self._items) >= self.maxsize:
            # 优先丢弃最旧的 delta，保留状态类事件
            for index, item in enumerate(self._items):
                if item.type.endswith(EPHEMERAL_SUFFIXES):
                    del self._items[index]
                    break
            else:
                self._items.popleft()
            self.dropped += 1
            self.last_dropped_seq = event.seq
        self._items.append(event)
        self._wake.set()

    async def get(self) -> Event:
        while True:
            if self._items:
                return self._items.popleft()
            if self._closed:
                raise SubscriptionClosed()
            self._wake.clear()
            if self._items:
                continue
            await self._wake.wait()

    def close(self) -> None:
        self._closed = True
        self._wake.set()

    def __len__(self) -> int:
        return len(self._items)


class EventBus:
    def __init__(self, db: Database):
        self.db = db
        self._seq = 0
        self._subscribers: set[Subscription] = set()
        self._emit_lock = asyncio.Lock()
        self._started = False

    async def start(self) -> None:
        self._seq = await self.db.max_event_seq()
        self._started = True
        log.info("EventBus 就绪 last_seq=%d", self._seq)

    @property
    def last_seq(self) -> int:
        return self._seq

    def subscribe(self, maxsize: int = 500) -> Subscription:
        sub = Subscription(maxsize=maxsize)
        self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        self._subscribers.discard(sub)
        sub.close()

    async def emit(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        challenge_id: int | None = None,
        run_id: int | None = None,
        persist: bool | None = None,
    ) -> Event:
        if not self._started:
            # 允许启动早期（DB 已就绪）发出事件；序列号直接接续 DB。
            self._seq = await self.db.max_event_seq()
            self._started = True

        if persist is None:
            persist = not is_ephemeral(event_type)

        async with self._emit_lock:
            self._seq += 1
            event = Event(
                seq=self._seq,
                ts=now_iso(),
                type=event_type,
                challenge_id=challenge_id,
                run_id=run_id,
                payload=payload or {},
            )
            if persist:
                try:
                    await self.db.insert_event(event)
                except Exception:  # pragma: no cover - DB 故障时看板仍应可用
                    log.exception("事件落库失败 seq=%s type=%s", event.seq, event_type)
            for sub in list(self._subscribers):
                sub.offer(event)
        return event

    async def replay_after(self, seq: int, limit: int = 1000) -> list[Event]:
        return await self.db.events_after(seq, limit=limit)
