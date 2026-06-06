"""Tests for core/broker.py — the interactive decision broker (Phase 1)."""

import json
import threading
import time

import pytest

from core.allowlist import Allowlist
from core.broker import (
    Decision,
    DecisionBroker,
    decide,
    start_broker_server,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _broker(tmp_path, timeout=5, seed=None):
    path = tmp_path / "policy.json"
    if seed is not None:
        Allowlist({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": seed, "Resource": "*"}],
        }).save(path)
    return DecisionBroker(allowlist_path=path, timeout=timeout), path


def _answer_async(broker, decision, delay=0.05):
    """Spawn a thread that answers the next pending question after a delay."""
    def run():
        time.sleep(delay)
        pending = broker.next_pending(timeout=2)
        assert pending is not None
        broker.answer(pending.id, decision)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


# --------------------------------------------------------------------------- #
# submit: short-circuit when already allowed
# --------------------------------------------------------------------------- #

def test_empty_actions_allowed_without_prompt(tmp_path):
    broker, _ = _broker(tmp_path)
    assert broker.submit([]) == Decision.ALLOW_ONCE


def test_already_allowed_short_circuits(tmp_path):
    broker, _ = _broker(tmp_path, seed=["s3:GetObject"])
    # No front-end answering; must return immediately, not block/timeout.
    start = time.time()
    assert broker.submit(["s3:GetObject"]) == Decision.ALLOW_ONCE
    assert time.time() - start < 1


# --------------------------------------------------------------------------- #
# block / wake
# --------------------------------------------------------------------------- #

def test_blocks_until_answered_allow_once(tmp_path):
    broker, _ = _broker(tmp_path)
    _answer_async(broker, Decision.ALLOW_ONCE)
    assert broker.submit(["s3:GetObject"]) == Decision.ALLOW_ONCE


def test_deny_answer(tmp_path):
    broker, _ = _broker(tmp_path)
    _answer_async(broker, Decision.DENY)
    assert broker.submit(["s3:GetObject"]) == Decision.DENY


# --------------------------------------------------------------------------- #
# fail-closed timeout
# --------------------------------------------------------------------------- #

def test_timeout_fails_closed(tmp_path):
    broker, _ = _broker(tmp_path, timeout=1)  # nobody answers
    start = time.time()
    assert broker.submit(["s3:GetObject"]) == Decision.DENY
    assert time.time() - start >= 1


# --------------------------------------------------------------------------- #
# idempotent answers
# --------------------------------------------------------------------------- #

def test_first_answer_wins(tmp_path):
    broker, _ = _broker(tmp_path)
    pending_holder = {}

    def submitter():
        pending_holder["decision"] = broker.submit(["s3:GetObject"])

    t = threading.Thread(target=submitter, daemon=True)
    t.start()
    pending = broker.next_pending(timeout=2)
    assert pending is not None
    assert broker.answer(pending.id, Decision.ALLOW_ONCE) is True
    # Second answer is a no-op.
    assert broker.answer(pending.id, Decision.DENY) is False
    t.join(timeout=2)
    assert pending_holder["decision"] == Decision.ALLOW_ONCE


def test_answer_unknown_id_is_noop(tmp_path):
    broker, _ = _broker(tmp_path)
    assert broker.answer("does-not-exist", Decision.ALLOW_ONCE) is False


# --------------------------------------------------------------------------- #
# persistence (always_allow -> IAM policy file)
# --------------------------------------------------------------------------- #

def test_always_allow_persists(tmp_path):
    broker, path = _broker(tmp_path)
    _answer_async(broker, Decision.ALWAYS_ALLOW)
    assert broker.submit(["s3:GetObject"]) == Decision.ALWAYS_ALLOW
    # File written in IAM shape, loadable, permits the action.
    doc = json.loads(path.read_text())
    assert doc["Statement"][0]["Action"] == ["s3:GetObject"]
    assert Allowlist.from_file(path).permits(["s3:GetObject"])


def test_always_allow_suppresses_reprompt(tmp_path):
    broker, _ = _broker(tmp_path)
    _answer_async(broker, Decision.ALWAYS_ALLOW)
    assert broker.submit(["s3:GetObject"]) == Decision.ALWAYS_ALLOW
    # Second time: no front-end answering, but must not block — already allowed.
    start = time.time()
    assert broker.submit(["s3:GetObject"]) == Decision.ALLOW_ONCE
    assert time.time() - start < 1


def test_allow_once_does_not_persist(tmp_path):
    broker, path = _broker(tmp_path)
    _answer_async(broker, Decision.ALLOW_ONCE)
    assert broker.submit(["s3:GetObject"]) == Decision.ALLOW_ONCE
    # Empty/absent policy — nothing persisted.
    if path.exists():
        assert not Allowlist.from_file(path).permits(["s3:GetObject"])


# --------------------------------------------------------------------------- #
# coalescing: one prompt per set, all-or-nothing
# --------------------------------------------------------------------------- #

def test_multi_action_coalesced_into_one_prompt(tmp_path):
    broker, _ = _broker(tmp_path)
    seen = {}

    def submitter():
        seen["decision"] = broker.submit(["s3:GetObject", "s3:PutObject"])

    t = threading.Thread(target=submitter, daemon=True)
    t.start()
    first = broker.next_pending(timeout=2)
    assert first is not None
    assert first.actions == ["s3:GetObject", "s3:PutObject"]
    # Exactly one pending question for the whole set.
    assert broker.next_pending(timeout=0.2) is None
    broker.answer(first.id, Decision.ALWAYS_ALLOW)
    t.join(timeout=2)
    assert seen["decision"] == Decision.ALWAYS_ALLOW


def test_partial_overlap_still_prompts(tmp_path):
    # One action already allowed, one not -> set is not fully permitted ->
    # must still prompt (all-or-nothing on the resolved set).
    broker, _ = _broker(tmp_path, seed=["s3:GetObject"])
    _answer_async(broker, Decision.DENY)
    assert broker.submit(["s3:GetObject", "s3:PutObject"]) == Decision.DENY


# --------------------------------------------------------------------------- #
# end-to-end over the socket (worker decide() <-> parent broker)
# --------------------------------------------------------------------------- #

def test_decide_over_socket_roundtrip(tmp_path):
    broker, _ = _broker(tmp_path)
    sock = tmp_path / "decisions.sock"
    start_broker_server(sock, broker)
    _wait_for_socket(sock)
    _answer_async(broker, Decision.ALLOW_ONCE, delay=0.1)
    assert decide(["s3:GetObject"], sock_path=sock) == Decision.ALLOW_ONCE


def test_decide_fails_closed_when_broker_unreachable(tmp_path):
    # No server bound at this path -> connect fails -> deny.
    assert decide(["s3:GetObject"], sock_path=tmp_path / "nope.sock") == Decision.DENY


def test_decide_empty_actions_allows(tmp_path):
    assert decide([], sock_path=tmp_path / "nope.sock") == Decision.ALLOW_ONCE


def _wait_for_socket(path, timeout=2):
    start = time.time()
    while time.time() - start < timeout:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"socket {path} did not appear")
