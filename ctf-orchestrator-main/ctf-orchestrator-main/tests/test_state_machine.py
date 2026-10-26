from __future__ import annotations

import pytest

from ycb.models import Status
from ycb.scheduling.state_machine import (
    ACTIVE,
    ATTENTION,
    InvalidTransition,
    SOLVED_LIKE,
    TERMINAL,
    can_transition,
    ensure_transition,
)


def test_happy_path_transitions():
    path = [
        Status.DISCOVERED,
        Status.PREPARING,
        Status.READY,
        Status.SOLVING,
        Status.SOLVED,
        Status.SUBMITTING,
        Status.SUBMITTED,
    ]
    for current, target in zip(path, path[1:]):
        assert can_transition(current, target)
        ensure_transition(current, target)


def test_terminal_is_closed_without_force():
    assert TERMINAL == frozenset({Status.SUBMITTED})
    assert can_transition(Status.SUBMITTED, Status.SUBMITTED)  # 同状态 no-op
    for target in Status:
        if target is Status.SUBMITTED:
            continue
        assert not can_transition(Status.SUBMITTED, target)
    assert can_transition(Status.SUBMITTED, Status.SOLVING, force=True)


def test_invalid_transition_raises():
    assert not can_transition(Status.DISCOVERED, Status.SUBMITTING)
    with pytest.raises(InvalidTransition):
        ensure_transition(Status.DISCOVERED, Status.SUBMITTING)


def test_pause_and_recovery():
    assert can_transition(Status.SOLVING, Status.PAUSED)
    assert can_transition(Status.PAUSED, Status.SOLVING)
    assert can_transition(Status.STOPPED, Status.SOLVING)
    assert can_transition(Status.FAILED, Status.PREPARING)
    assert can_transition(Status.NEEDS_HUMAN, Status.SOLVING)
    assert can_transition(Status.SOLVING, Status.SUBMITTED)


def test_rejected_flag_can_return_to_solving():
    assert can_transition(Status.SOLVED, Status.PREPARING)
    assert can_transition(Status.PAUSED, Status.SOLVED)
    assert can_transition(Status.STOPPED, Status.SOLVED)
    assert can_transition(Status.READY, Status.SOLVED)


def test_same_status_is_noop():
    assert can_transition(Status.SOLVING, "solving")
    assert can_transition("SOLVING", Status.SOLVING)


def test_status_groups():
    assert Status.SOLVING in ACTIVE
    assert Status.SUBMITTED not in ACTIVE
    assert Status.NEEDS_HUMAN in ATTENTION
    assert Status.FAILED in ATTENTION
    assert SOLVED_LIKE == frozenset({Status.SOLVED, Status.SUBMITTING, Status.SUBMITTED})
