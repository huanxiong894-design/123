"""FastAPI 应用工厂（单 worker）。

启动时构建 DB / EventBus / adapter / 发现循环 / 心跳；关闭时按序回收。
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ycb import __version__
from ycb.adapters.registry import create_adapter
from ycb.agents.normalize import set_flag_masking
from ycb.config import Config
from ycb.db import Database
from ycb.events import EventBus
from ycb.models import now_iso
from ycb.scheduling.discovery_loop import DiscoveryLoop
from ycb.scheduling.manager import ChallengeManager
from ycb.submission.service import SubmissionService
from ycb.submission.watcher import FlagWatcher
from ycb.web import api, ws
from ycb.web.context import AppContext
from ycb.web.overview import build_overview

log = logging.getLogger(__name__)

_WEB_DIR = Path(__file__).parent
_STATIC_DIR = _WEB_DIR / "static"
_TEMPLATE_DIR = _WEB_DIR / "templates"

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

HEARTBEAT_INTERVAL = 10.0

AdapterFactory = Callable[[Config], Any]
ManagerFactory = Callable[[Config, Database, EventBus, Any], ChallengeManager]
BackendFactory = Callable[..., Any]


async def _heartbeat(ctx: AppContext) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            overview = await build_overview(ctx)
            await ctx.bus.emit("heartbeat", {"overview": overview}, persist=False)
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover
            log.exception("心跳失败")


def create_app(
    config: Config,
    *,
    adapter_factory: AdapterFactory | None = None,
    manager_factory: ManagerFactory | None = None,
    agent_factory: BackendFactory | None = None,
) -> FastAPI:
    set_flag_masking(not config.server.unmask_flags)
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        config.ensure_dirs()
        db = Database(config.db_path)
        await db.connect()
        bus = EventBus(db)
        await bus.start()
        adapter = adapter_factory(config) if adapter_factory else create_adapter(config)
        manager = (
            manager_factory(config, db, bus, adapter)
            if manager_factory
            else ChallengeManager(config, db, bus, adapter, backend_factory=agent_factory)
        )
        await manager.reconcile_startup()
        submissions = SubmissionService(config, db, bus, adapter, manager=manager)
        await submissions.recover_startup()
        watcher = FlagWatcher(config, db, bus, submissions)
        discovery = DiscoveryLoop(
            config,
            db,
            bus,
            adapter,
            on_new_challenge=manager.auto_start,
            on_solved=manager.on_challenge_solved,
        )
        ctx = AppContext(
            config=config,
            db=db,
            bus=bus,
            adapter=adapter,
            discovery=discovery,
            manager=manager,
            submissions=submissions,
            watcher=watcher,
            started_at=now_iso(),
        )
        app.state.ctx = ctx

        await bus.emit(
            "system.ready",
            {
                "version": __version__,
                "adapter": adapter.name,
                "capabilities": sorted(adapter.capabilities),
                "config": config.safe_dict(),
            },
        )
        await submissions.start()
        await watcher.start()
        await discovery.start()
        ctx.heartbeat_task = asyncio.create_task(_heartbeat(ctx), name="heartbeat")

        try:
            yield
        finally:
            with contextlib.suppress(Exception):
                await bus.emit("system.stopping", {"version": __version__})
            if ctx.heartbeat_task is not None:
                ctx.heartbeat_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await ctx.heartbeat_task
            with contextlib.suppress(Exception):
                await watcher.stop()
            with contextlib.suppress(Exception):
                await submissions.stop()
            await discovery.stop()
            with contextlib.suppress(Exception):
                await manager.close()
            with contextlib.suppress(Exception):
                await adapter.close()
            await db.close()

    app = FastAPI(
        title="CTF 自动化解题编排系统（2026 羊城杯）",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        path = request.url.path
        if config.server.token and path.startswith("/api"):
            supplied = (
                request.headers.get("authorization", "").removeprefix("Bearer ").strip()
                or request.cookies.get("ycb_token")
                or request.query_params.get("token")
                or ""
            )
            if not supplied or not secrets.compare_digest(supplied, config.server.token):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        response = templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "version": __version__,
                "competition_title": "2026 年“羊城杯”网络安全大赛初赛",
            },
        )
        supplied = request.query_params.get("token")
        if config.server.token and supplied and secrets.compare_digest(supplied, config.server.token):
            response.set_cookie(
                "ycb_token", supplied, httponly=True, samesite="strict", max_age=7 * 24 * 3600
            )
        return response

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(status_code=204)

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    app.include_router(api.router)
    app.include_router(ws.router)
    return app
