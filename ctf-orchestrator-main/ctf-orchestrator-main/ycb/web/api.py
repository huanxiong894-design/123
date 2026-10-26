"""REST API。若功能尚未接入，端点明确返回 409 + 说明，不假装成功。"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ycb import __version__
from ycb.agents.base import AgentError
from ycb.submission.service import SubmissionError
from ycb.web.context import AppContext
from ycb.web.overview import build_overview

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


class MessageBody(BaseModel):
    content: str = Field(min_length=1, max_length=4000)


class FlagBody(BaseModel):
    flag: str = Field(min_length=1, max_length=300)


class RestartBody(BaseModel):
    mode: Literal["resume", "fresh"] = "resume"


def ctx(request: Request) -> AppContext:
    return request.app.state.ctx


async def _challenge_or_404(app_ctx: AppContext, challenge_id: int):
    challenge = await app_ctx.db.get_challenge(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="题目不存在")
    return challenge


def _mask_flag(flag: str) -> str:
    if not flag:
        return ""
    if len(flag) <= 14:
        return flag[:4] + "***"
    return f"{flag[:9]}…{flag[-4:]}"


def _mask_submission(row: dict[str, Any], *, unmask: bool = False) -> dict[str, Any]:
    item = dict(row)
    raw = item.pop("flag", "")
    item["flag_masked"] = raw if unmask else _mask_flag(raw)
    if unmask:
        item["flag"] = raw
    item.pop("evidence_json", None)
    return item


# ---------------------------------------------------------------------- read
@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    app_ctx = ctx(request)
    return {
        "ok": True,
        "version": __version__,
        "platform": app_ctx.config.platform.active,
        "dry_run": app_ctx.config.submission.dry_run,
        "discovery_state": app_ctx.discovery.status.state,
        "session_state": app_ctx.adapter.session.state,
    }


@router.get("/overview")
async def overview(request: Request) -> dict[str, Any]:
    return await build_overview(ctx(request))


@router.get("/challenges")
async def challenges(request: Request) -> dict[str, Any]:
    app_ctx = ctx(request)
    items = await app_ctx.db.list_challenges()
    return {"challenges": [challenge.to_dict() for challenge in items]}


@router.get("/challenges/{challenge_id}")
async def challenge_detail(request: Request, challenge_id: int) -> dict[str, Any]:
    app_ctx = ctx(request)
    challenge = await _challenge_or_404(app_ctx, challenge_id)
    messages = await app_ctx.db.list_messages(challenge_id)
    unmask = app_ctx.config.server.unmask_flags
    submissions = [
        _mask_submission(row, unmask=unmask)
        for row in await app_ctx.db.list_submissions(challenge_id)
    ]
    runs = await app_ctx.db.runs_for_challenge(challenge_id)
    events = [event.to_dict() for event in await app_ctx.db.events_for_challenge(challenge_id)]
    return {
        "challenge": challenge.to_dict(),
        "messages": messages,
        "submissions": submissions,
        "runs": runs,
        "events": events,
    }


@router.get("/events")
async def events(
    request: Request,
    after_seq: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=2000),
) -> dict[str, Any]:
    app_ctx = ctx(request)
    items = await app_ctx.bus.replay_after(after_seq, limit=limit)
    return {
        "events": [event.to_dict() for event in items],
        "max_seq": app_ctx.bus.last_seq,
    }


@router.get("/runs/{run_id}/raw")
async def run_raw(request: Request, run_id: int) -> FileResponse:
    app_ctx = ctx(request)
    run = await app_ctx.db.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run 不存在")
    raw_path = run.get("raw_path")
    if not raw_path:
        raise HTTPException(status_code=404, detail="该 run 没有原始日志")
    path = Path(raw_path).resolve()
    runs_root = app_ctx.config.runs_dir.resolve()
    if runs_root != path and runs_root not in path.parents:
        raise HTTPException(status_code=403, detail="日志路径越界")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="原始日志文件不存在")
    return FileResponse(path, media_type="application/x-ndjson", filename=path.name)


# ---------------------------------------------------------------------- operator actions
@router.post("/challenges/{challenge_id}/message")
async def send_message(request: Request, challenge_id: int, body: MessageBody) -> dict[str, Any]:
    app_ctx = ctx(request)
    await _challenge_or_404(app_ctx, challenge_id)
    content = body.content.strip()
    if not content:
        raise HTTPException(status_code=422, detail="消息不能为空")
    try:
        return await app_ctx.manager.send_operator_message(challenge_id, content)
    except AgentError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


async def _agent_action(action, *args, **kwargs) -> dict[str, Any]:
    try:
        return await action(*args, **kwargs)
    except AgentError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/challenges/{challenge_id}/pause")
async def pause_challenge(request: Request, challenge_id: int) -> dict[str, Any]:
    app_ctx = ctx(request)
    await _challenge_or_404(app_ctx, challenge_id)
    return await _agent_action(app_ctx.manager.pause, challenge_id)


@router.post("/challenges/{challenge_id}/resume")
async def resume_challenge(request: Request, challenge_id: int) -> dict[str, Any]:
    app_ctx = ctx(request)
    await _challenge_or_404(app_ctx, challenge_id)
    return await _agent_action(app_ctx.manager.start, challenge_id, resume=True)


@router.post("/challenges/{challenge_id}/stop")
async def stop_challenge(request: Request, challenge_id: int) -> dict[str, Any]:
    app_ctx = ctx(request)
    await _challenge_or_404(app_ctx, challenge_id)
    return await _agent_action(app_ctx.manager.stop, challenge_id)


@router.post("/challenges/{challenge_id}/restart")
async def restart_challenge(
    request: Request, challenge_id: int, body: RestartBody | None = None
) -> dict[str, Any]:
    app_ctx = ctx(request)
    await _challenge_or_404(app_ctx, challenge_id)
    mode = body.mode if body is not None else "resume"
    return await _agent_action(app_ctx.manager.restart, challenge_id, mode)


@router.post("/challenges/{challenge_id}/release-container")
async def release_container(
    request: Request, challenge_id: int, force: bool = False
) -> dict[str, Any]:
    app_ctx = ctx(request)
    await _challenge_or_404(app_ctx, challenge_id)
    await app_ctx.manager.release_container(challenge_id, force=force)
    return {"released": True}


@router.post("/challenges/{challenge_id}/submit")
async def manual_submit(request: Request, challenge_id: int, body: FlagBody) -> dict[str, Any]:
    app_ctx = ctx(request)
    await _challenge_or_404(app_ctx, challenge_id)
    try:
        return await app_ctx.submissions.submit_manual(challenge_id, body.flag)
    except SubmissionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post("/actions/live")
async def enable_live(request: Request) -> dict[str, Any]:
    app_ctx = ctx(request)
    app_ctx.config.submission.dry_run = False
    await app_ctx.bus.emit(
        "alert",
        {"level": "warning", "message": "已关闭 dry_run：后续 flag.txt 将直接提交到平台"},
    )
    return {"dry_run": False, "message": "已关闭 dry_run，后续 flag 直接提交"}


@router.post("/actions/dry-run")
async def enable_dry_run(request: Request) -> dict[str, Any]:
    app_ctx = ctx(request)
    app_ctx.config.submission.dry_run = True
    await app_ctx.bus.emit(
        "alert",
        {"level": "info", "message": "已开启 dry_run：后续 flag 只记录不提交"},
    )
    return {"dry_run": True, "message": "已开启 dry_run"}


@router.post("/actions/stop-all")
async def stop_all(request: Request) -> dict[str, Any]:
    return await _agent_action(ctx(request).manager.stop_all)


@router.post("/actions/pause-all")
async def pause_all(request: Request) -> dict[str, Any]:
    return await _agent_action(ctx(request).manager.pause_all)


@router.post("/actions/resume-all")
async def resume_all(request: Request) -> dict[str, Any]:
    return await _agent_action(ctx(request).manager.resume_all)
