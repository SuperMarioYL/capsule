"""Decision engine — given a profile and an attempted call, ALLOW or DENY.

This is the heart of Capsule's enforcement. It takes a :class:`CallRequest`
(the reduced form of a tool call a Skill is attempting) and a validated
:class:`~capsule.profile.Profile`, and returns a :class:`Decision`.

The contract is **deny-by-default**: a call is allowed only if it matches an
explicit allowance, and never if it matches an explicit denial. Concretely, the
engine answers four questions in order, and the first denial wins:

1. Is the *tool verb* in the profile's allow-list? (no → DENY ``tool-not-in-profile``)
2. Does the call touch a path on the profile's ``deny`` list? (yes → DENY ``path-denied``)
3. If it reads/writes a path, is that path inside the matching read/write
   allow-globs? (no → DENY ``path-not-in-profile``)
4. If it opens a network connection, is the host in the egress allow-list?
   (no → DENY ``network-not-in-profile``)

Path matching is lexical (the profile globs were already normalised at load
time by :mod:`capsule.profile`), using a recursive ``**`` matcher so
``./**`` means "anything under the base dir". Host matching supports a leading
``*.`` wildcard for subdomains.

The engine is pure: no I/O, no logging, no side effects. That makes it trivially
testable and means :mod:`capsule.interpose` / :mod:`capsule.trap` own all the
effects (refusing the call, writing the trap record).
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from capsule.profile import Profile

__all__ = [
    "Effect",
    "CallRequest",
    "Decision",
    "decide",
    "match_path",
    "match_host",
]


class Effect(str, Enum):
    """What a decision resolves to."""

    ALLOW = "allow"
    DENY = "deny"


# --------------------------------------------------------------------------- #
# The reduced form of an intercepted tool call
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CallRequest:
    """A tool call reduced to the dimensions the policy engine reasons about.

    A host adapter (:mod:`capsule.hosts`) is responsible for translating a raw
    tool invocation into this shape. Keeping the request minimal keeps the
    engine host-agnostic.

    Attributes
    ----------
    tool:
        The tool verb being invoked (``read_file``, ``edit_file``, ``shell`` …).
    path:
        The filesystem path the call targets, if any.
    host:
        The network host the call would reach, if any (e.g. ``api.github.com``).
    access:
        For a path call, whether it is a ``"read"`` or ``"write"``. Defaults to
        ``"read"`` (the safer assumption — a write must be declared a write).
    raw:
        Optional opaque description of the original call (e.g. a shell command
        line) carried through to the trap record for human readability.
    skill:
        The Skill that issued the call, for trap attribution. May be ``None``
        when unknown; the active profile's ``skill`` is used as a fallback.
    """

    tool: str
    path: Optional[str] = None
    host: Optional[str] = None
    access: str = "read"
    raw: Optional[str] = None
    skill: Optional[str] = None


# --------------------------------------------------------------------------- #
# The verdict
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Decision:
    """The verdict for a single :class:`CallRequest` against a profile.

    Attributes
    ----------
    effect:
        :attr:`Effect.ALLOW` or :attr:`Effect.DENY`.
    rule:
        A short machine-readable tag for *which* rule decided this
        (``tool-not-in-profile``, ``path-denied``, ``path-not-in-profile``,
        ``network-not-in-profile``, or ``allowed``). Stable across versions so
        reports and tests can assert on it.
    reason:
        A human-readable one-liner suitable for the trap log.
    matched:
        The specific glob/host pattern that matched, when relevant — useful in
        a report to show *which* allow/deny rule fired.
    """

    effect: Effect
    rule: str
    reason: str
    matched: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def denied(self) -> bool:
        return self.effect is Effect.DENY


# --------------------------------------------------------------------------- #
# Matching helpers (lexical; profile globs are pre-normalised)
# --------------------------------------------------------------------------- #
def _normalise_call_path(path: str) -> str:
    """Normalise a call's target path the same way profile globs were.

    ``~`` is expanded and relative paths are anchored on the current working
    directory, then collapsed lexically. This mirrors
    :func:`capsule.profile._normalise_glob` so a profile glob and a call path
    are compared in the same coordinate system.
    """
    if path.startswith("~"):
        path = os.path.expanduser(path)
    elif not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    return os.path.normpath(path)


def match_path(path: str, pattern: str) -> bool:
    """Return whether ``path`` matches glob ``pattern``, honouring ``**``.

    ``fnmatch`` treats ``*`` as "anything except the path separator-ish" but is
    actually quite permissive; what it does *not* do is give ``**`` recursive
    semantics distinct from ``*``. We translate ``**`` ourselves:

    * a trailing ``/**`` matches the directory itself *and* everything under it,
    * an interior ``**`` matches across any number of segments.

    Both ``path`` and ``pattern`` are expected to be normalised absolute strings
    (the profile pre-normalises its globs; we normalise the call path above).
    """
    path = _normalise_call_path(path)

    # Exact (non-glob) pattern: direct comparison or prefix-dir containment.
    if "*" not in pattern and "?" not in pattern and "[" not in pattern:
        return path == pattern

    sep = os.sep
    # Trailing "/**" → match the dir and any descendant.
    if pattern.endswith(sep + "**"):
        base = pattern[: -(len(sep) + 2)]
        return path == base or path.startswith(base + sep)

    # Build a regex-equivalent via fnmatch on segment-normalised forms. We
    # special-case "**" by translating it to a marker that crosses separators.
    if "**" in pattern:
        # Translate "**" → match any chars incl. separators; "*" → within a seg.
        import re

        regex_parts: list[str] = []
        i = 0
        while i < len(pattern):
            if pattern[i : i + 2] == "**":
                regex_parts.append(".*")
                i += 2
            elif pattern[i] == "*":
                regex_parts.append(f"[^{re.escape(sep)}]*")
                i += 1
            elif pattern[i] == "?":
                regex_parts.append(".")
                i += 1
            else:
                regex_parts.append(re.escape(pattern[i]))
                i += 1
        return re.fullmatch("".join(regex_parts), path) is not None

    # No "**": plain fnmatch is correct for single-segment wildcards.
    return fnmatch.fnmatch(path, pattern)


def _first_match(path: str, patterns) -> Optional[str]:
    for pat in patterns:
        if match_path(path, pat):
            return pat
    return None


def match_host(host: str, pattern: str) -> bool:
    """Match a network host against an allow pattern.

    Supports an exact host (``api.github.com``) and a leading-wildcard subdomain
    pattern (``*.internal`` matches ``svc.internal`` and ``internal`` itself).
    Matching is case-insensitive.
    """
    host = host.lower().strip()
    pattern = pattern.lower().strip()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".internal"
        return host.endswith(suffix) or host == pattern[2:]
    return fnmatch.fnmatch(host, pattern)


# --------------------------------------------------------------------------- #
# The decision
# --------------------------------------------------------------------------- #
def decide(profile: Profile, call: CallRequest) -> Decision:
    """Decide whether ``call`` is permitted under ``profile``. Deny-by-default.

    The first denial wins; a call is only allowed if it survives every check.
    """
    # 1) Tool verb must be explicitly allowed.
    if not profile.allows_tool(call.tool):
        return Decision(
            effect=Effect.DENY,
            rule="tool-not-in-profile",
            reason=f"tool {call.tool!r} is not in the profile's allowed tools",
        )

    # 2) Explicit path denials trump everything — even an otherwise-allowed read.
    if call.path is not None:
        denied = _first_match(call.path, profile.paths.deny)
        if denied is not None:
            return Decision(
                effect=Effect.DENY,
                rule="path-denied",
                reason=f"path {call.path!r} matches an explicit deny rule",
                matched=denied,
            )

        # 3) Path must fall inside the matching allow-globs for its access mode.
        allow_globs = (
            profile.paths.write if call.access == "write" else profile.paths.read
        )
        matched = _first_match(call.path, allow_globs)
        if matched is None:
            return Decision(
                effect=Effect.DENY,
                rule="path-not-in-profile",
                reason=(
                    f"{call.access} of {call.path!r} is not permitted by any "
                    f"profile path rule"
                ),
            )

    # 4) Network egress must be on the allow-list.
    if call.host is not None:
        matched_host = next(
            (p for p in profile.network.allow if match_host(call.host, p)), None
        )
        if matched_host is None:
            return Decision(
                effect=Effect.DENY,
                rule="network-not-in-profile",
                reason=f"network egress to {call.host!r} is not in the profile",
            )

    return Decision(
        effect=Effect.ALLOW,
        rule="allowed",
        reason="call matches the active capability profile",
    )
