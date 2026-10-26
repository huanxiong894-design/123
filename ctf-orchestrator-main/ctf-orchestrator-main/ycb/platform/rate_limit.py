"""全局/按题目的异步限速。"""

from __future__ import annotations

import asyncio
import random
import time


class AsyncRateLimiter:
    """串行等待型令牌桶：保证两次动作之间至少间隔 ``min_interval`` 秒。

    所有平台写操作共用同一个实例；发现循环另有自己的低频周期。
    """

    def __init__(self, min_interval: float, *, jitter: float = 0.0):
        self.min_interval = max(0.0, float(min_interval))
        self.jitter = max(0.0, float(jitter))
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._next_at - now
            if delay > 0:
                await asyncio.sleep(delay)
            extra = random.uniform(0, self.jitter) if self.jitter else 0.0
            self._next_at = time.monotonic() + self.min_interval + extra
