"""IAM policy allowlist for enforcement mode.

Loads a standard IAM policy JSON document and checks whether a set of
resolved IAM action strings is permitted.  Only the Allow/NotAction/Resource
dimensions that matter for per-request enforcement are evaluated — condition
keys and principal checks are not in scope.
"""

__all__ = ["Allowlist"]

import json
import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


class Allowlist:
    """Checks resolved IAM actions against a loaded policy document.

    The policy must be standard IAM JSON:
      {"Version": "2012-10-17", "Statement": [...]}

    Only Allow statements with Effect=Allow are used.  Deny statements are
    ignored — the proxy's job is to enforce a positive allowlist, not to
    replicate full IAM evaluation order.

    Action matching supports the '*' wildcard (e.g. "s3:*", "*").
    """

    def __init__(self, policy: dict) -> None:
        # Flatten all Allow statement actions into a single set of lowercase strings.
        # Wildcards are preserved for matching at check time.
        self._allowed: set[str] = set()
        self._wildcard_prefixes: list[str] = []
        # Preserve the original (un-lowercased) action strings in first-seen
        # order so the allowlist can be written back out as a clean IAM policy
        # that reads the way a human authored it ("s3:GetObject", not
        # "s3:getobject"). Keyed by lowercase form for dedup.
        self._original: dict[str, str] = {}

        for stmt in policy.get("Statement", []):
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                a = action.lower()
                self._original.setdefault(a, action)
                if a == "*":
                    self._wildcard_prefixes.append("")   # matches everything
                elif a.endswith(":*"):
                    self._wildcard_prefixes.append(a[:-1])  # e.g. "s3:"
                else:
                    self._allowed.add(a)

        log.info(
            "Allowlist loaded: %d explicit actions, %d wildcard prefixes",
            len(self._allowed),
            len(self._wildcard_prefixes),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Allowlist":
        with open(path) as f:
            return cls(json.load(f))

    @classmethod
    def empty(cls) -> "Allowlist":
        """An allowlist that permits nothing — the interactive starting point."""
        return cls({"Version": "2012-10-17", "Statement": []})

    @classmethod
    def load_or_empty(cls, path: Path) -> "Allowlist":
        """Load an existing policy, or return an empty allowlist if absent.

        Interactive mode uses this to seed the always-allow set from a policy
        file (hand-authored or from a previous session) without requiring one
        to exist up front.
        """
        if path.exists():
            return cls.from_file(path)
        return cls.empty()

    def add_actions(self, actions: list[str]) -> bool:
        """Add explicit actions to the allow set.

        Returns True if anything was newly added (caller should persist),
        False if every action was already permitted. Original casing of the
        first occurrence is preserved for serialization.
        """
        changed = False
        for action in actions:
            a = action.lower()
            self._original.setdefault(a, action)
            if a == "*" or a.endswith(":*"):
                # Defensive: callers persist resolved concrete actions, not
                # wildcards. Route a wildcard through the same path as load.
                prefix = "" if a == "*" else a[:-1]
                if prefix not in self._wildcard_prefixes:
                    self._wildcard_prefixes.append(prefix)
                    changed = True
            elif a not in self._allowed:
                self._allowed.add(a)
                changed = True
        return changed

    def to_policy(self) -> dict:
        """Serialize back to a standard IAM policy document.

        Emits a single Allow statement with all known actions (explicit +
        wildcard), in sorted original-casing form, Resource "*". This is the
        same shape `iam-agent-proxy policy` emits and `enforce` mode consumes.
        """
        lower_actions = set(self._allowed)
        for prefix in self._wildcard_prefixes:
            lower_actions.add("*" if prefix == "" else prefix + "*")
        actions = sorted(
            self._original.get(a, a) for a in lower_actions
        )
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ProxyInteractiveDecisions",
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "*",
                }
            ],
        }

    def save(self, path: Path) -> None:
        """Atomically write the allowlist to `path` as an IAM policy JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(self.to_policy(), indent=2) + "\n"
        # Atomic replace so a reader (or a crash) never sees a partial file.
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(data)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def permits(self, actions: list[str]) -> bool:
        """Return True if every action in the list is covered by the allowlist.

        An empty action list (e.g. permissionless operation) is always permitted.
        """
        for action in actions:
            if not self._permits_one(action):
                return False
        return True

    def _permits_one(self, action: str) -> bool:
        a = action.lower()
        if a in self._allowed:
            return True
        for prefix in self._wildcard_prefixes:
            if a.startswith(prefix):
                return True
        return False
