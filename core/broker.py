"""Interactive-mode decision broker.

Phase 1 of the interactive enforcement design (see INTERACTIVE.md). When a
request resolves to an action that isn't already allowed, the request is paused
at the proxy and a human is asked **always allow / allow once / deny**.

Process model
-------------
proxy.py runs one **worker process** per CPU (``num_workers`` defaults to 0 ->
``multiprocessing.cpu_count()``) and workers are ``multiprocessing.Process``
instances — they share neither memory nor stdin with the parent. So, exactly
like ``creds.sock``, decisions must funnel through one place: the
``DecisionBroker`` lives in the **proxy parent**, owns stdin/stdout, and workers
reach it over ``decisions.sock``.

Layout
------
* shared:  ``Decision`` enum (the wire + return type), defaults.
* parent:  ``DecisionBroker`` (queue, block/wake, idempotent answers,
           fail-closed timeout, persistence), ``start_broker_server`` (socket),
           ``run_stdin_frontend`` (the ``[a]/[o]/[d]`` loop).
* worker:  ``decide(actions, resource=None)`` — called from the gate; connects
           to the socket, blocks for an answer, fails closed to DENY.
"""

__all__ = [
    "Decision",
    "DecisionBroker",
    "start_broker_server",
    "run_stdin_frontend",
    "decide",
    "INTERACTIVE_TIMEOUT",
    "DECISIONS_SOCK_PATH",
    "ALLOWLIST_PATH",
]

import json
import logging
import os
import queue
import socket
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .allowlist import Allowlist

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Shared: decision model + config
# --------------------------------------------------------------------------- #

class Decision(str, Enum):
    """The three outcomes. Value doubles as the wire encoding."""
    ALWAYS_ALLOW = "always_allow"
    ALLOW_ONCE = "allow_once"
    DENY = "deny"


_CA_DIR = Path.home() / ".iam-agent-proxy"

# Fail-closed window. Kept below common SDK client timeouts (botocore's default
# read timeout is 60s, with retries) so the caller receives our forged
# AccessDenied rather than its own transport error/retry storm.
INTERACTIVE_TIMEOUT = int(os.environ.get("INTERACTIVE_TIMEOUT", "20"))

DECISIONS_SOCK_PATH = Path(
    os.environ.get("DECISIONS_SOCK_PATH", str(_CA_DIR / "decisions.sock"))
)

# The persisted always-allow record IS a standard IAM policy file — the same
# file `enforce` mode consumes and `iam-agent-proxy policy` emits. An
# interactive session is thus a policy-authoring session. Defaults to a
# writable path so interactive mode never requires a pre-existing file.
ALLOWLIST_PATH = Path(
    os.environ.get("ALLOWLIST_PATH") or str(_CA_DIR / "policy.json")
)

# Worker-side socket read timeout. Set above the parent's decision timeout so
# the parent's fail-closed DENY wins the race and reaches the worker, rather
# than the worker timing out the socket first and synthesizing its own DENY.
_WORKER_SOCK_TIMEOUT = INTERACTIVE_TIMEOUT + 10


# --------------------------------------------------------------------------- #
# Parent: the broker
# --------------------------------------------------------------------------- #

class _Pending:
    """A blocked request awaiting a human decision."""

    __slots__ = ("id", "actions", "resource", "ts", "event", "decision")

    def __init__(self, actions: list[str], resource):
        self.id = uuid.uuid4().hex
        self.actions = actions
        self.resource = resource
        self.ts = datetime.now(timezone.utc)
        self.event = threading.Event()
        self.decision: Decision | None = None


class DecisionBroker:
    """Owns the pending queue, the human prompt, and persistence.

    Lives in the parent process. Thread-safe: the socket server calls
    ``submit`` from per-connection threads, the front-end calls ``next_pending``
    / ``answer`` from its own thread, and persistence is parent-only so the
    policy file has a single writer.
    """

    def __init__(
        self,
        allowlist_path: Path = ALLOWLIST_PATH,
        timeout: int = INTERACTIVE_TIMEOUT,
    ) -> None:
        self._timeout = timeout
        self._allowlist_path = allowlist_path
        # Seed the always-allow set from the policy file (hand-authored or from
        # a previous interactive session) so already-allowed actions never
        # re-prompt.
        self._allowlist = Allowlist.load_or_empty(allowlist_path)
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        # FIFO of pending ids for the front-end to consume.
        self._queue: "queue.Queue[str]" = queue.Queue()
        log.info(
            "Decision broker started: allowlist=%s timeout=%ss",
            allowlist_path, timeout,
        )

    # -- request path (called per blocked worker request) ------------------- #

    def submit(self, actions: list[str], resource=None) -> Decision:
        """Resolve a decision for ``actions``, blocking until answered/timeout.

        Coalescing: one prompt for the whole resolved set, all-or-nothing
        (the doc's recommended answer to the coalescing open question). The set
        is treated as a unit — if every action is already allowed it forwards
        immediately without prompting; otherwise the human's single answer
        applies to all of them.
        """
        # Empty action set (e.g. permissionless op) — nothing to gate.
        if not actions:
            return Decision.ALLOW_ONCE

        with self._lock:
            if self._allowlist.permits(actions):
                return Decision.ALLOW_ONCE

        pending = _Pending(actions, resource)
        with self._lock:
            self._pending[pending.id] = pending
        self._queue.put(pending.id)

        answered = pending.event.wait(self._timeout)

        with self._lock:
            self._pending.pop(pending.id, None)
            decision = pending.decision

        if not answered or decision is None:
            # Fail closed: no human answered in time.
            log.warning(
                "Decision timed out after %ss for %s — failing closed (deny)",
                self._timeout, actions,
            )
            return Decision.DENY

        if decision is Decision.ALWAYS_ALLOW:
            self._persist(actions)
        return decision

    # -- front-end path (called by a renderer: stdin, TUI, ...) ------------- #

    def next_pending(self, timeout: float | None = None) -> _Pending | None:
        """Block until a pending question is available; return it (or None).

        Returns None on timeout. Skips ids already answered/expired so a
        front-end never renders a stale question.
        """
        while True:
            try:
                pid = self._queue.get(timeout=timeout)
            except queue.Empty:
                return None
            with self._lock:
                pending = self._pending.get(pid)
            if pending is not None and not pending.event.is_set():
                return pending
            # else: already answered or timed out — drop and keep going.

    def answer(self, pending_id: str, decision: Decision) -> bool:
        """Record a decision for ``pending_id``.

        Idempotent: the first answer for an id wins; later answers (e.g. from a
        second front-end) are no-ops. Returns True if this call set the answer.
        """
        with self._lock:
            pending = self._pending.get(pending_id)
            if pending is None or pending.event.is_set():
                return False
            pending.decision = decision
            pending.event.set()
        return True

    # -- persistence -------------------------------------------------------- #

    def _persist(self, actions: list[str]) -> None:
        """Persist an always-allow into the IAM policy file (parent-only)."""
        with self._lock:
            changed = self._allowlist.add_actions(actions)
            if not changed:
                return
            try:
                self._allowlist.save(self._allowlist_path)
                log.info("Persisted always-allow %s -> %s",
                         actions, self._allowlist_path)
            except OSError as exc:
                log.error("Failed to persist allowlist to %s: %s",
                          self._allowlist_path, exc)


# --------------------------------------------------------------------------- #
# Parent: socket server (mirrors credentials._serve_creds)
# --------------------------------------------------------------------------- #

def _prepare_socket_path(sock_path: Path) -> None:
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if sock_path.exists():
        sock_path.unlink()


def _recv_json(conn: socket.socket) -> dict | None:
    """Read one newline-terminated JSON message from a connection."""
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    if not buf:
        return None
    return json.loads(buf.split(b"\n", 1)[0])


def _serve_decisions(sock_path: Path, broker: DecisionBroker) -> None:
    _prepare_socket_path(sock_path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(str(sock_path))
        sock_path.chmod(0o600)
        srv.listen()
        log.info("Decision socket listening at %s", sock_path)
        while True:
            try:
                conn, _ = srv.accept()
            except OSError as exc:
                log.error("decisions.sock accept error: %s", exc)
                continue
            # One thread per blocked request so many workers can wait at once.
            t = threading.Thread(
                target=_handle_decision_conn,
                args=(conn, broker),
                daemon=True,
            )
            t.start()


def _handle_decision_conn(conn: socket.socket, broker: DecisionBroker) -> None:
    with conn:
        try:
            req = _recv_json(conn)
            if req is None:
                return
            actions = req.get("actions") or []
            resource = req.get("resource")
            decision = broker.submit(actions, resource=resource)
        except Exception as exc:
            # Any broker-side failure fails closed.
            log.error("Decision handling error: %s — denying", exc)
            decision = Decision.DENY
        try:
            conn.sendall((json.dumps({"decision": decision.value}) + "\n").encode())
        except OSError:
            pass


def start_broker_server(sock_path: Path, broker: DecisionBroker) -> None:
    t = threading.Thread(
        target=_serve_decisions, args=(sock_path, broker), daemon=True
    )
    t.start()


# --------------------------------------------------------------------------- #
# Parent: stdin/stdout front-end (transport (A), the v1 default)
# --------------------------------------------------------------------------- #

_KEY_TO_DECISION = {
    "a": Decision.ALWAYS_ALLOW,
    "o": Decision.ALLOW_ONCE,
    "d": Decision.DENY,
}


def _prompt_once(pending: _Pending) -> Decision:
    """Print the question and read one [a]/[o]/[d] answer from stdin."""
    ts = pending.ts.strftime("%H:%M:%S")
    actions = "  ".join(pending.actions)
    while True:
        try:
            ans = input(
                f"[{ts}] PROMPT  {actions}  — allow? [a]lways / [o]nce / [d]eny: "
            ).strip().lower()
        except EOFError:
            # stdin closed (no TTY / piped end) — fail closed.
            return Decision.DENY
        if ans and ans[0] in _KEY_TO_DECISION:
            return _KEY_TO_DECISION[ans[0]]
        print("  Please answer a, o, or d.", flush=True)


def _stdin_loop(broker: DecisionBroker) -> None:
    while True:
        pending = broker.next_pending()
        if pending is None:
            continue
        decision = _prompt_once(pending)
        # First answer wins; if it already timed out this is a quiet no-op.
        if broker.answer(pending.id, decision):
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            label = {
                Decision.ALWAYS_ALLOW: "ALLOWED (always)",
                Decision.ALLOW_ONCE: "ALLOWED (once)",
                Decision.DENY: "DENIED",
            }[decision]
            print(f"[{ts}] {label}  {'  '.join(pending.actions)}", flush=True)


def run_stdin_frontend(broker: DecisionBroker) -> None:
    """Start the stdin/stdout prompt loop in a daemon thread."""
    t = threading.Thread(target=_stdin_loop, args=(broker,), daemon=True)
    t.start()


# --------------------------------------------------------------------------- #
# Worker: the gate's entry point
# --------------------------------------------------------------------------- #

def decide(
    actions: list[str],
    resource=None,
    *,
    sock_path: Path = DECISIONS_SOCK_PATH,
) -> Decision:
    """Ask the parent broker to decide on ``actions``; block for the answer.

    Called from the proxy worker (the gate in ResignPlugin._handle). Fails
    **closed**: any socket error, unreachable broker, or read timeout returns
    ``Decision.DENY`` so a missing/dead broker can never silently allow.

    ``resource`` is accepted but ignored in Phase 1 (action-only); keeping it
    in the signature means the gate call site is unchanged for Phase 2.
    """
    if not actions:
        return Decision.ALLOW_ONCE
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(_WORKER_SOCK_TIMEOUT)
            s.connect(str(sock_path))
            req = {"actions": actions, "resource": resource}
            s.sendall((json.dumps(req) + "\n").encode())
            resp = _recv_json(s)
        if not resp or "decision" not in resp:
            return Decision.DENY
        return Decision(resp["decision"])
    except (OSError, ValueError) as exc:
        log.error("decide() failed (%s) — failing closed to deny", exc)
        return Decision.DENY
