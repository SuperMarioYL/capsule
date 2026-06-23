"""Trap layer — record a blocked call and keep an appendable, readable log.

When :mod:`capsule.policy` returns a denial, :mod:`capsule.interpose` refuses
the call and hands the details here. This module owns the *record* of what
happened: an in-memory list of :class:`TrapEvent` for the current run, an
append-only JSONL file on disk for ``capsule report`` to read back later, and a
one-line human-readable rendering of each event (the ``DENIED …`` line a user
sees at the call site).

Allowed calls are recorded too (so a report can show *allowed vs blocked*), but
the headline event is the block — that visible ``DENIED`` line is Capsule's
whole value proposition.

The default log location is ``./.capsule/trap.log`` under the current working
directory. It is JSON-lines so it is both append-cheap and trivially parseable.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from capsule.policy import CallRequest, Decision, Effect

__all__ = [
    "TrapEvent",
    "TrapLog",
    "default_log_path",
    "format_event",
]


def default_log_path(base_dir: str | os.PathLike[str] | None = None) -> Path:
    """The default trap-log path: ``<base_dir or cwd>/.capsule/trap.log``."""
    root = Path(base_dir) if base_dir is not None else Path.cwd()
    return root / ".capsule" / "trap.log"


@dataclass(frozen=True)
class TrapEvent:
    """A single recorded decision about an intercepted call.

    Carries enough to reconstruct *what was attempted*, *what the profile said*,
    and *when* — both for the live trap line and for the after-the-run report.
    """

    ts: str  # ISO-8601 UTC timestamp
    skill: str  # the Skill that issued the call
    tool: str  # the tool verb attempted
    effect: str  # "allow" | "deny"
    rule: str  # the policy rule that decided it
    reason: str  # human-readable explanation
    path: Optional[str] = None
    host: Optional[str] = None
    access: Optional[str] = None
    matched: Optional[str] = None
    raw: Optional[str] = None  # original command line / description, if any

    @property
    def blocked(self) -> bool:
        return self.effect == Effect.DENY.value

    @property
    def allowed(self) -> bool:
        return self.effect == Effect.ALLOW.value

    @classmethod
    def from_decision(
        cls,
        call: CallRequest,
        decision: Decision,
        *,
        skill: str,
        when: Optional[float] = None,
    ) -> "TrapEvent":
        """Build a :class:`TrapEvent` from a call + its :class:`Decision`."""
        moment = when if when is not None else time.time()
        ts = datetime.fromtimestamp(moment, tz=timezone.utc).isoformat()
        return cls(
            ts=ts,
            skill=call.skill or skill,
            tool=call.tool,
            effect=decision.effect.value,
            rule=decision.rule,
            reason=decision.reason,
            path=call.path,
            host=call.host,
            access=call.access if call.path is not None else None,
            matched=decision.matched,
            raw=call.raw,
        )

    def to_json(self) -> str:
        """Serialise to a single JSON line (for the JSONL trap log)."""
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, line: str) -> "TrapEvent":
        """Parse one JSONL record back into a :class:`TrapEvent`."""
        data = json.loads(line)
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


def format_event(event: TrapEvent, *, color: bool = False) -> str:
    """Render a :class:`TrapEvent` as the one-line trap message a user sees.

    Example (denied)::

        DENIED tool=shell cmd="curl https://evil.example" reason=network-not-in-profile

    ``color`` wraps the verdict word in ANSI so the CLI can highlight blocks in
    red without this module importing ``rich`` (it stays dependency-light and
    importable in any environment).
    """
    verdict = "DENIED" if event.blocked else "ALLOWED"
    if color:
        code = "31" if event.blocked else "32"  # red / green
        verdict = f"\033[{code}m{verdict}\033[0m"

    parts = [verdict, f"tool={event.tool}"]
    if event.raw:
        parts.append(f'cmd="{event.raw}"')
    elif event.path:
        parts.append(f"path={event.path}")
    elif event.host:
        parts.append(f"host={event.host}")
    parts.append(f"skill={event.skill}")
    parts.append(f"reason={event.rule}")
    return " ".join(parts)


class TrapLog:
    """An in-memory + appendable record of trap events for a run.

    Holds every :class:`TrapEvent` produced during the process (so the live
    ``report`` can summarise without re-reading disk) and, when given a
    ``path``, appends each event as a JSON line so a later ``capsule report``
    invocation can read a previous run back.

    Parameters
    ----------
    path:
        Where to append events. ``None`` keeps the log purely in memory (handy
        in tests). Defaults to :func:`default_log_path` when constructed via
        :meth:`open`.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path: Optional[Path] = Path(path) if path is not None else None
        self.events: list[TrapEvent] = []

    # -- construction ------------------------------------------------------- #
    @classmethod
    def open(cls, path: str | os.PathLike[str] | None = None) -> "TrapLog":
        """Create a log writing to ``path`` (default ``./.capsule/trap.log``)."""
        return cls(path if path is not None else default_log_path())

    @classmethod
    def in_memory(cls) -> "TrapLog":
        """Create a log that never touches disk (used by tests)."""
        return cls(None)

    # -- recording ---------------------------------------------------------- #
    def record(self, event: TrapEvent) -> TrapEvent:
        """Append ``event`` to memory and (if configured) to the JSONL file."""
        self.events.append(event)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(event.to_json() + "\n")
        return event

    def record_decision(
        self,
        call: CallRequest,
        decision: Decision,
        *,
        skill: str,
        when: Optional[float] = None,
    ) -> TrapEvent:
        """Convenience: build a :class:`TrapEvent` from a decision and record it."""
        return self.record(
            TrapEvent.from_decision(call, decision, skill=skill, when=when)
        )

    # -- reading / summarising --------------------------------------------- #
    @property
    def blocked(self) -> list[TrapEvent]:
        return [e for e in self.events if e.blocked]

    @property
    def allowed(self) -> list[TrapEvent]:
        return [e for e in self.events if e.allowed]

    def summary(self) -> dict[str, int]:
        """``{allowed, blocked, total}`` counts for the run."""
        blocked = len(self.blocked)
        allowed = len(self.allowed)
        return {"allowed": allowed, "blocked": blocked, "total": allowed + blocked}

    def load(self) -> list[TrapEvent]:
        """Read previously appended events from :attr:`path` into memory.

        Used by ``capsule report`` to summarise an earlier run. Replaces the
        in-memory list with what is on disk. Returns the loaded events.
        """
        if self.path is None or not self.path.is_file():
            self.events = []
            return self.events
        loaded: list[TrapEvent] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                loaded.append(TrapEvent.from_json(line))
        self.events = loaded
        return loaded
