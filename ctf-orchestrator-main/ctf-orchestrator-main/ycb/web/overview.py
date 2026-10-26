"""看板总览快照。"""

from __future__ import annotations

from typing import Any

from ycb import __version__
from ycb.models import Status, now_iso
from ycb.scheduling.state_machine import ACTIVE, ATTENTION


async def build_overview(ctx: Any) -> dict[str, Any]:
    counts = await ctx.db.counts_by_status()
    total = sum(counts.values())
    submissions = await ctx.db.submission_stats()
    session = ctx.discovery.status.session or ctx.adapter.session.to_dict()
    solved = sum(counts.get(s.value, 0) for s in (Status.SOLVED, Status.SUBMITTING, Status.SUBMITTED))
    running = sum(counts.get(s.value, 0) for s in ACTIVE)
    attention = sum(counts.get(s.value, 0) for s in ATTENTION)
    return {
        "version": __version__,
        "platform": ctx.config.platform.active,
        "competition_id": ctx.config.platform.competition_id,
        "dry_run": ctx.config.submission.dry_run,
        "counts": counts,
        "total": total,
        "solved": solved,
        "submitted": counts.get(Status.SUBMITTED.value, 0),
        "running": running,
        "attention": attention,
        "failed": counts.get(Status.FAILED.value, 0),
        "submissions": submissions,
        "max_auto_submits": ctx.config.submission.max_auto_submits,
        "session": session,
        "discovery": ctx.discovery.status_dict(),
        "schedule": {
            "start": ctx.config.schedule.start.isoformat(),
            "end": ctx.config.schedule.end.isoformat(),
        },
        "server_time": now_iso(),
        "started_at": ctx.started_at,
        "workspace_dir": str(ctx.config.workspace_dir),
        "agent_backend": ctx.config.agent.backend,
        "agents_running": ctx.manager.running_count,
        "adapter": ctx.adapter.name,
        "capabilities": sorted(ctx.adapter.capabilities),
        "features": {
            "agent_control": True,
            "auto_submit": True,
            "flag_watch": True,
            "dry_run": ctx.config.submission.dry_run,
            "manual_submit": True,
            "container": "container" in ctx.adapter.capabilities,
        },
    }
