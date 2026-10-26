from __future__ import annotations

import asyncio

from ycb.events import EventBus, Subscription, is_ephemeral
from ycb.models import Event


def event(seq: int, event_type: str = "challenge.discovered") -> Event:
    return Event(seq=seq, ts="2026-10-24T02:00:00+00:00", type=event_type, payload={"seq": seq})


async def test_ephemeral_classification():
    assert is_ephemeral("heartbeat")
    assert is_ephemeral("agent.text.delta")
    assert not is_ephemeral("agent.text")
    assert not is_ephemeral("challenge.discovered")


async def test_bus_persists_broadcasts_and_replays(db):
    bus = EventBus(db)
    await bus.start()
    assert bus.last_seq == 0
    sub = bus.subscribe(maxsize=10)

    first = await bus.emit("challenge.discovered", {"x": 1})
    assert first.seq == 1
    received = await asyncio.wait_for(sub.get(), timeout=1)
    assert received == first
    assert (await db.max_event_seq()) == 1

    heartbeat = await bus.emit("heartbeat", {"ok": True})
    assert heartbeat.seq == 2
    assert (await db.max_event_seq()) == 1  # 不落库
    assert (await asyncio.wait_for(sub.get(), timeout=1)).seq == 2

    delta = await bus.emit("agent.text.delta", {"text": "a"})
    assert delta.seq == 3
    assert (await db.max_event_seq()) == 1

    replay = await bus.replay_after(0)
    assert [item.seq for item in replay] == [1]
    assert (await bus.replay_after(1)) == []


async def test_new_bus_resumes_from_db_seq(db):
    bus = EventBus(db)
    await bus.start()
    await bus.emit("system.ready", {"v": "m1"})
    await bus.emit("system.ready", {"v": "m1"})
    assert bus.last_seq == 2

    resumed = EventBus(db)
    await resumed.start()
    assert resumed.last_seq == 2
    event = await resumed.emit("alert", {"message": "x"})
    assert event.seq == 3


async def test_unsubscribe_stops_delivery(db):
    bus = EventBus(db)
    await bus.start()
    sub = bus.subscribe()
    bus.unsubscribe(sub)
    await bus.emit("alert", {"message": "x"})
    assert len(sub) == 0
    try:
        await asyncio.wait_for(sub.get(), timeout=0.2)
    except Exception as exc:
        assert type(exc).__name__ in {"SubscriptionClosed", "TimeoutError"}
    else:  # pragma: no cover
        raise AssertionError("closed subscription should not yield")


def test_subscription_drops_delta_first_then_oldest():
    sub = Subscription(maxsize=3)
    sub.offer(event(1, "agent.text.delta"))
    sub.offer(event(2))
    sub.offer(event(3))
    assert len(sub) == 3

    sub.offer(event(4))
    # 优先丢弃 delta（seq=1），其余保留
    assert [item.seq for item in sub._items] == [2, 3, 4]
    assert sub.dropped == 1
    assert sub.last_dropped_seq == 4

    sub.offer(event(5))
    assert [item.seq for item in sub._items] == [3, 4, 5]
    assert sub.dropped == 2

    sub.offer(event(6, "heartbeat"))
    assert [item.seq for item in sub._items] == [4, 5, 6]
