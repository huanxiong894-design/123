"""题目状态机。

所有状态变更必须走 Database.set_status 的 CAS（UPDATE ... WHERE status=?），
这里只负责定义合法迁移。平台显示已解时允许任意非终态直接进入 SUBMITTED。
"""

from __future__ import annotations

from ycb.models import Status

ALLOWED: dict[Status, frozenset[Status]] = {
    Status.DISCOVERED: frozenset({Status.PREPARING, Status.NEEDS_HUMAN, Status.FAILED, Status.STOPPED}),
    Status.PREPARING: frozenset({Status.READY, Status.FAILED, Status.NEEDS_HUMAN, Status.STOPPED}),
    Status.READY: frozenset(
        {
            Status.SOLVING,
            Status.PAUSED,
            Status.STOPPED,
            Status.FAILED,
            Status.NEEDS_HUMAN,
            Status.SOLVED,  # flag.txt 已写入（watcher）
        }
    ),
    Status.SOLVING: frozenset(
        {
            Status.SOLVED,
            Status.FAILED,
            Status.PAUSED,
            Status.STOPPED,
            Status.NEEDS_HUMAN,
            Status.SUBMITTED,  # 平台显示已在别处解出
        }
    ),
    Status.SOLVED: frozenset(
        {
            Status.SUBMITTING,
            Status.SUBMITTED,
            Status.NEEDS_HUMAN,
            Status.STOPPED,
            Status.PREPARING,  # flag 被拒后继续解题
        }
    ),
    Status.SUBMITTING: frozenset(
        {Status.SUBMITTED, Status.SOLVED, Status.SOLVING, Status.NEEDS_HUMAN, Status.FAILED}
    ),
    Status.PAUSED: frozenset(
        {Status.SOLVING, Status.READY, Status.STOPPED, Status.SUBMITTED, Status.SOLVED}
    ),
    Status.STOPPED: frozenset(
        {
            Status.PREPARING,
            Status.READY,
            Status.SOLVING,
            Status.SUBMITTED,
            Status.NEEDS_HUMAN,
            Status.SOLVED,
        }
    ),
    Status.FAILED: frozenset(
        {
            Status.PREPARING,
            Status.READY,
            Status.SOLVING,
            Status.NEEDS_HUMAN,
            Status.STOPPED,
            Status.SOLVED,
        }
    ),
    Status.NEEDS_HUMAN: frozenset(
        {
            Status.PREPARING,
            Status.READY,
            Status.SOLVING,
            Status.STOPPED,
            Status.SUBMITTED,
            Status.SOLVED,
        }
    ),
    Status.SUBMITTED: frozenset(),  # 终态
}

ACTIVE: frozenset[Status] = frozenset(
    {Status.PREPARING, Status.READY, Status.SOLVING, Status.SUBMITTING}
)
RUNNING: frozenset[Status] = frozenset({Status.PREPARING, Status.READY, Status.SOLVING})
ATTENTION: frozenset[Status] = frozenset(
    {Status.NEEDS_HUMAN, Status.PAUSED, Status.FAILED, Status.STOPPED}
)
TERMINAL: frozenset[Status] = frozenset({Status.SUBMITTED})
SOLVED_LIKE: frozenset[Status] = frozenset({Status.SOLVED, Status.SUBMITTING, Status.SUBMITTED})


class InvalidTransition(ValueError):
    pass


def can_transition(current: Status | str, target: Status | str, *, force: bool = False) -> bool:
    cur = Status.parse(current)
    dst = Status.parse(target)
    if force:
        return True
    if cur == dst:
        return True
    return dst in ALLOWED.get(cur, frozenset())


def ensure_transition(current: Status | str, target: Status | str, *, force: bool = False) -> None:
    if not can_transition(current, target, force=force):
        raise InvalidTransition(f"非法状态迁移：{Status.parse(current).value} -> {Status.parse(target).value}")
