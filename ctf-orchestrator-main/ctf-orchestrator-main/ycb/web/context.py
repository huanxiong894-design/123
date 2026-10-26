"""应用运行时上下文（lifespan 中构建，路由通过 app.state.ctx 访问）。"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ycb.adapters.base import PlatformAdapter
from ycb.config import Config
from ycb.db import Database
from ycb.events import EventBus
from ycb.scheduling.discovery_loop import DiscoveryLoop
from ycb.scheduling.manager import ChallengeManager
from ycb.submission.service import SubmissionService
from ycb.submission.watcher import FlagWatcher


@dataclass
class AppContext:
    config: Config
    db: Database
    bus: EventBus
    adapter: PlatformAdapter
    discovery: DiscoveryLoop
    manager: ChallengeManager
    submissions: SubmissionService
    watcher: FlagWatcher
    started_at: str
    heartbeat_task: asyncio.Task | None = None
