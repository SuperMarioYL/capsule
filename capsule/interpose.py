"""Call-site interposition — the shim that sits in front of every tool call.

This is where the deny-by-default model becomes *enforcement* rather than
advice. A host adapter (:mod:`capsule.hosts`) reduces each tool invocation a
Skill makes into a :class:`~capsule.policy.CallRequest` and routes it through a
:class:`Interposer`. The interposer asks :mod:`capsule.policy` for a verdict and:

* **ALLOW** → runs the underlying function and returns its result, recording an
  allowed :class:`~capsule.trap.TrapEvent`.
* **DENY** → records a blocked event, emits the ``DENIED …`` line, and raises
  :class:`CapabilityViolation` *before the underlying function ever runs*.

The critical property — and the thing :mod:`tests.test_interpose` asserts — is
that on a denial the wrapped callable is **never invoked**. A denied ``curl``
does not execute; it is trapped at the call site, not logged after the fact.

Two entry points are provided:

* :meth:`Interposer.check` / :meth:`Interposer.guard` — imperative: ask about a
  call, or run a thunk under the guard.
* :meth:`Interposer.wrap` — a decorator that turns a host's raw tool function
  into a capability-checked one, given a function that maps the call arguments
  to a :class:`CallRequest`.
"""

from __future__ import annotations

import sys
from typing import Callable, Optional, TypeVar

from capsule.policy import CallRequest, Decision, decide
from capsule.profile import Profile
from capsule.trap import TrapEvent, TrapLog, format_event

__all__ = ["CapabilityViolation", "Interposer"]

T = TypeVar("T")


class CapabilityViolation(PermissionError):
    """Raised when a Skill attempts a call outside its capability profile.

    Subclasses :class:`PermissionError` so existing host error-handling that
    already expects an OS-style permission failure treats a Capsule block the
    same way it would a real ``EACCES`` — the call simply does not go through.

    Carries the originating :class:`~capsule.policy.CallRequest`,
    :class:`~capsule.policy.Decision`, and the recorded
    :class:`~capsule.trap.TrapEvent` for callers that want to inspect or report
    the block programmatically.
    """

    def __init__(
        self,
        call: CallRequest,
        decision: Decision,
        event: TrapEvent,
    ) -> None:
        self.call = call
        self.decision = decision
        self.event = event
        super().__init__(
            f"capsule blocked tool={call.tool!r} "
            f"({decision.rule}): {decision.reason}"
        )


class Interposer:
    """Enforces a capability profile at the tool-call site.

    Parameters
    ----------
    profile:
        The active :class:`~capsule.profile.Profile` (deny-by-default).
    trap_log:
        Where decisions are recorded. Defaults to an in-memory log; the CLI
        passes a disk-backed :class:`~capsule.trap.TrapLog` so ``capsule
        report`` can read the run back.
    emit:
        Callable that prints the live trap line (defaults to writing the
        ``DENIED …`` / ``ALLOWED …`` line to stderr). Pass a no-op to silence,
        or a ``rich``-aware printer from the CLI.
    emit_allowed:
        Whether to emit a line for *allowed* calls too. Off by default so the
        terminal only lights up on blocks; the report still counts both.
    """

    def __init__(
        self,
        profile: Profile,
        *,
        trap_log: Optional[TrapLog] = None,
        emit: Optional[Callable[[str], None]] = None,
        emit_allowed: bool = False,
    ) -> None:
        self.profile = profile
        self.trap_log = trap_log if trap_log is not None else TrapLog.in_memory()
        self._emit = emit if emit is not None else self._default_emit
        self.emit_allowed = emit_allowed

    # ------------------------------------------------------------------ #
    @staticmethod
    def _default_emit(line: str) -> None:
        # Trap lines go to stderr so they never pollute a tool's stdout and are
        # visible even when stdout is captured by the host.
        print(line, file=sys.stderr, flush=True)

    def _record_and_emit(self, call: CallRequest, decision: Decision) -> TrapEvent:
        event = self.trap_log.record_decision(
            call, decision, skill=self.profile.skill
        )
        if decision.denied or self.emit_allowed:
            color = getattr(sys.stderr, "isatty", lambda: False)()
            self._emit(format_event(event, color=color))
        return event

    # ------------------------------------------------------------------ #
    def check(self, call: CallRequest) -> Decision:
        """Evaluate ``call``, record it, emit on block, and raise if denied.

        Returns the :class:`Decision` when the call is allowed; raises
        :class:`CapabilityViolation` when it is denied (after recording the
        block). Use this when the host wants to gate a call it will run itself.
        """
        decision = decide(self.profile, call)
        event = self._record_and_emit(call, decision)
        if decision.denied:
            raise CapabilityViolation(call, decision, event)
        return decision

    def guard(self, call: CallRequest, thunk: Callable[[], T]) -> T:
        """Run ``thunk`` only if ``call`` is allowed; otherwise trap + raise.

        This is the core enforcement primitive: ``thunk`` (the actual side
        effect — the real ``curl``, the real file write) is **only** invoked
        after the policy says ALLOW. On DENY it is never called.
        """
        self.check(call)  # raises CapabilityViolation on deny -> thunk skipped
        return thunk()

    def wrap(
        self,
        func: Callable[..., T],
        to_request: Callable[..., CallRequest],
    ) -> Callable[..., T]:
        """Decorate a host tool ``func`` so every call is capability-checked.

        ``to_request`` maps the same ``*args, **kwargs`` the host passes to
        ``func`` into a :class:`CallRequest`. The returned wrapper traps and
        raises before ``func`` runs on a denial.

        Example
        -------
        ::

            checked_read = interposer.wrap(
                os_read_file,
                lambda path, **_: CallRequest(tool="read_file", path=path),
            )
            checked_read("~/.ssh/id_rsa")  # -> CapabilityViolation, file untouched
        """

        def wrapper(*args, **kwargs) -> T:
            call = to_request(*args, **kwargs)
            return self.guard(call, lambda: func(*args, **kwargs))

        wrapper.__name__ = getattr(func, "__name__", "wrapped")
        wrapper.__doc__ = func.__doc__
        wrapper.__wrapped__ = func  # type: ignore[attr-defined]
        return wrapper

    # ------------------------------------------------------------------ #
    @property
    def summary(self) -> dict[str, int]:
        """Allowed/blocked/total counts for everything seen so far."""
        return self.trap_log.summary()
