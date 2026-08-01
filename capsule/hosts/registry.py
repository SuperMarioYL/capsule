"""Pluggable host-adapter registry — the cross-host policy seam.

A *host* is whatever loads and runs installable agent Skills: Claude Code,
Codex CLI, Cursor, Gemini CLI. v0.1 shipped a single adapter (Claude Code) and
hard-wired it into the CLI. v0.2 adds this registry so adding a second host
later is one file under ``capsule.hosts/`` plus a registration line — not an
engine change. Everything downstream of an adapter (the policy engine, the trap
log, the report) is host-agnostic and never learns a host's vocabulary.

The registry maps a ``--host`` flag value to a *factory*: a small callable that
constructs the adapter from an :class:`~capsule.interpose.Interposer` (and an
optional skill name). A factory is used (rather than a class object) so a host
module is only imported when that host is actually selected — registering a
Codex adapter tomorrow won't slow down a Claude-Code-only user's import today.

Design notes
------------
* **Why a registry, not a base class:** the only contract an adapter needs is a
  ``check(tool_name, tool_input)`` method and a ``host`` attribute. A registry of
  factories keeps that contract duck-typed and lets each host module stay
  self-contained. Subclassing would force a shared base that the policy engine
  does not require.
* **Why fail-loud on an unknown host:** silently falling back to Claude Code
  when a user asked for ``codex`` would mean a capability decision is made by the
  *wrong* adapter's translation table — a fail-open smell. Raise so the CLI can
  surface a clear error.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from capsule.interpose import Interposer

__all__ = [
    "HOSTS",
    "DEFAULT_HOST",
    "register_host",
    "get_adapter",
    "known_hosts",
]


def _claude_code_factory(interposer: Interposer, *, skill: Optional[str] = None):
    """Construct the Claude Code adapter (imported lazily to avoid a cycle)."""
    # Local import: claude_code imports from capsule.interpose / capsule.policy;
    # importing it here (at call time) keeps registry importable on its own and
    # means a non-Claude-Code host selection never pays for this import.
    from capsule.hosts.claude_code import ClaudeCodeAdapter

    return ClaudeCodeAdapter(interposer, skill=skill)


#: Registered host-adapter factories, keyed by the ``--host`` flag value. Add a
#: second host by registering its factory here (or via
#: :func:`register_host` at runtime). Keys are matched case-insensitively and
#: ``_``/``-`` interchangeably by :func:`get_adapter`.
HOSTS: dict[str, Callable[..., Any]] = {
    "claude-code": _claude_code_factory,
    "claude_code": _claude_code_factory,
    "claudecode": _claude_code_factory,
}

#: The host used when ``--host`` is omitted. v0.2 ships only this one.
DEFAULT_HOST = "claude-code"


def register_host(name: str, factory: Callable[..., Any]) -> None:
    """Register a host-adapter ``factory`` under ``name`` (idempotent).

    A factory has the signature ``factory(interposer, *, skill=None) -> adapter``
    where ``adapter`` exposes ``check(tool_name, tool_input)`` and a ``host``
    attribute, matching :class:`~capsule.hosts.claude_code.ClaudeCodeAdapter`.
    """
    HOSTS[name] = factory


def get_adapter(
    name: Optional[str],
    interposer: Interposer,
    *,
    skill: Optional[str] = None,
) -> Any:
    """Resolve a host adapter by ``name`` (default :data:`DEFAULT_HOST`).

    Raises
    ------
    ValueError
        If ``name`` is not ``None``/empty and is not a registered host. An
        unknown host is a hard error rather than a silent fall-back, because a
        capability decision made by the wrong adapter's translation table is a
        fail-open smell.
    """
    key = (name or DEFAULT_HOST).strip().lower().replace("_", "-")
    factory = HOSTS.get(key)
    if factory is None:
        # Allow callers that registered under the exact (un-normalised) name.
        factory = HOSTS.get(name or DEFAULT_HOST)
    if factory is None:
        raise ValueError(
            f"unknown host {name!r}; registered hosts: {', '.join(sorted(set(HOSTS)))}"
        )
    return factory(interposer, skill=skill)


def known_hosts() -> list[str]:
    """Return the registered host names (deduplicated, sorted)."""
    return sorted(set(HOSTS))
