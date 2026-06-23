"""Claude Code host adapter — the call-site chokepoint for the Skill ecosystem.

A *host* is whatever loads and runs installable agent Skills: Claude Code,
Codex CLI, Cursor, Gemini CLI. v0.1 ships a single adapter — Claude Code — and
this module is the integration seam.

The job of a host adapter is narrow and well defined: take a raw tool-call event
in *that host's* shape and reduce it to a host-agnostic
:class:`~capsule.policy.CallRequest`, then route it through an
:class:`~capsule.interpose.Interposer`. Everything downstream (the policy
engine, the trap log, the report) is host-agnostic and never learns Claude
Code's vocabulary. Adding a second host later means writing one more file like
this one — not touching the engine.

What "Claude Code routes tool calls" means concretely
-----------------------------------------------------
Claude Code (and the broader Skill format it shares with Codex CLI) drives a
Skill by emitting **tool-use events**: a tool name plus a JSON ``input`` object.
A handful of built-in tools cover essentially everything a Skill can do to your
machine:

* ``Read`` / ``Edit`` / ``Write`` — filesystem access (``input.file_path``).
* ``Bash`` — an arbitrary shell command (``input.command``); this is the
  high-privilege escape hatch a malicious Skill reaches for (``curl`` exfil,
  ``cat ~/.ssh/id_rsa``).
* ``WebFetch`` / ``WebSearch`` — network egress (``input.url``).
* ``Glob`` / ``Grep`` — read-oriented discovery.

This adapter maps each of those onto Capsule's small set of canonical tool
verbs (``read_file``, ``edit_file``, ``shell``, ``net_fetch`` …) and extracts
the path / host the call would touch. For ``Bash`` it does light, conservative
parsing of the command line: it recognises the common exfil shapes (``curl`` /
``wget`` to a URL, ``cat``/``less`` of a sensitive path) so the *intent* of the
shell command is checked, not just the literal verb ``shell``. The parsing is
intentionally simple and fail-closed: anything it cannot positively classify is
still routed as a ``shell`` call, which a deny-by-default profile blocks unless
``shell`` was explicitly granted.

This is a real, documented seam — not a stub. A host integration calls
:func:`check_tool_use` (or wraps its dispatcher with
:meth:`ClaudeCodeAdapter.guard_tool_use`) at the single point where it is about
to execute a tool, and Capsule decides.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, Callable, Mapping, Optional, TypeVar
from urllib.parse import urlparse

from capsule.interpose import CapabilityViolation, Interposer
from capsule.policy import CallRequest, Decision

__all__ = [
    "ClaudeCodeAdapter",
    "to_call_request",
    "check_tool_use",
    "HOST_NAME",
    "TOOL_MAP",
]

#: Identifier recorded on trap events so a multi-host future can tell hosts
#: apart in a report.
HOST_NAME = "claude-code"

T = TypeVar("T")

#: Maps a Claude Code tool name to Capsule's canonical tool verb. The canonical
#: verbs are what a capability profile's ``tools:`` list is written in, so a
#: profile stays host-agnostic and portable to the next adapter.
TOOL_MAP: dict[str, str] = {
    "Read": "read_file",
    "View": "read_file",
    "Glob": "read_file",
    "Grep": "read_file",
    "LS": "read_file",
    "NotebookRead": "read_file",
    "Edit": "edit_file",
    "Write": "edit_file",
    "MultiEdit": "edit_file",
    "NotebookEdit": "edit_file",
    "WebFetch": "net_fetch",
    "WebSearch": "net_fetch",
    "Bash": "shell",
    "BashOutput": "shell",
}

#: Shell verbs that read a file argument — used to recover the *path* a Bash
#: command targets so a ``cat ~/.ssh/id_rsa`` is checked as a path read, not an
#: opaque shell call.
_FILE_READ_CMDS = {"cat", "less", "more", "head", "tail", "bat", "xxd", "od", "strings"}
#: Shell verbs whose first URL-looking argument is a network egress.
_NET_CMDS = {"curl", "wget", "http", "https", "nc", "ncat", "scp", "sftp", "ssh", "rsync"}

_URL_RE = re.compile(r"""\b((?:https?|ftp)://[^\s'"]+)""", re.IGNORECASE)
_HOSTISH_RE = re.compile(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", re.IGNORECASE)


def _extract_host(token: str) -> Optional[str]:
    """Pull a bare hostname out of a URL or host:port token, if present."""
    token = token.strip().strip("'\"")
    if "://" in token:
        netloc = urlparse(token).netloc or urlparse(token).path
        token = netloc
    # Strip user@ and :port
    token = token.split("@")[-1].split("/")[0].split(":")[0]
    if _HOSTISH_RE.fullmatch(token):
        return token.lower()
    return None


def _parse_bash(command: str) -> CallRequest:
    """Reduce a shell command line to a :class:`CallRequest`, fail-closed.

    Recognises the two exfil shapes that matter for the threat model:

    * network egress (``curl https://evil.example`` → ``shell`` call carrying a
      ``host`` so the network rule applies), and
    * sensitive file read (``cat ~/.ssh/id_rsa`` → ``shell`` call carrying a
      ``path`` so a path deny rule applies).

    Anything it cannot positively classify is returned as a bare ``shell`` call
    with no path/host — which a deny-by-default profile blocks outright unless
    ``shell`` was explicitly granted. We never *upgrade* an unknown command to
    "looks safe"; unknown stays maximally restricted.
    """
    raw = command.strip()

    # First, any explicit URL anywhere in the command is treated as egress.
    url_match = _URL_RE.search(raw)
    if url_match:
        host = _extract_host(url_match.group(1))
        if host:
            return CallRequest(tool="shell", host=host, raw=raw)

    try:
        tokens = shlex.split(raw)
    except ValueError:
        # Unbalanced quotes etc. — cannot parse, stay fully restricted.
        return CallRequest(tool="shell", raw=raw)

    if not tokens:
        return CallRequest(tool="shell", raw=raw)

    verb = tokens[0].rsplit("/", 1)[-1].lower()  # strip any leading path
    args = [t for t in tokens[1:] if not t.startswith("-")]

    if verb in _NET_CMDS:
        for a in args:
            host = _extract_host(a)
            if host:
                return CallRequest(tool="shell", host=host, raw=raw)
        # A network command with no resolvable host is still suspicious.
        return CallRequest(tool="shell", raw=raw)

    if verb in _FILE_READ_CMDS and args:
        return CallRequest(tool="shell", path=args[0], access="read", raw=raw)

    return CallRequest(tool="shell", raw=raw)


def to_call_request(
    tool_name: str,
    tool_input: Optional[Mapping[str, Any]] = None,
) -> CallRequest:
    """Translate one Claude Code tool-use event into a :class:`CallRequest`.

    Parameters
    ----------
    tool_name:
        The host's tool name (``Read``, ``Bash``, ``WebFetch`` …).
    tool_input:
        The host's tool ``input`` object. Recognised keys: ``file_path`` /
        ``path`` / ``notebook_path`` (filesystem), ``command`` (shell),
        ``url`` (network).

    Returns
    -------
    CallRequest
        A host-agnostic request the policy engine can decide on. An unknown
        tool name maps to a ``shell``-class call (the most restricted bucket),
        so a never-seen-before tool is denied by default rather than waved
        through.
    """
    data: Mapping[str, Any] = tool_input or {}
    verb = TOOL_MAP.get(tool_name, "shell")

    # Shell commands get parsed for intent (network / sensitive-path).
    if tool_name in ("Bash", "BashOutput"):
        command = str(data.get("command", "")).strip()
        if command:
            return _parse_bash(command)
        return CallRequest(tool="shell", raw=tool_name)

    # Network tools carry a URL.
    if verb == "net_fetch":
        url = str(data.get("url", "")).strip()
        host = _extract_host(url) if url else None
        return CallRequest(tool=verb, host=host, raw=url or tool_name)

    # Filesystem tools carry a path under one of several keys.
    path = (
        data.get("file_path")
        or data.get("path")
        or data.get("notebook_path")
        or data.get("pattern")  # Glob/Grep target dir lives here sometimes
    )
    access = "write" if verb == "edit_file" else "read"
    return CallRequest(
        tool=verb,
        path=str(path) if path else None,
        access=access,
        raw=f"{tool_name} {path}" if path else tool_name,
    )


class ClaudeCodeAdapter:
    """Binds an :class:`Interposer` to Claude Code's tool-use event shape.

    Construct one per guarded session (the CLI does this), then call
    :meth:`check` at the point the host is about to run a tool, or wrap the
    host's tool dispatcher with :meth:`guard_tool_use`.

    Parameters
    ----------
    interposer:
        The active capability interposer (carries the profile + trap log).
    skill:
        Optional Skill name to attribute calls to when the event itself does
        not name one. Defaults to the profile's bound Skill.
    """

    host = HOST_NAME

    def __init__(self, interposer: Interposer, *, skill: Optional[str] = None) -> None:
        self.interposer = interposer
        self.skill = skill or interposer.profile.skill

    # ------------------------------------------------------------------ #
    def to_request(
        self,
        tool_name: str,
        tool_input: Optional[Mapping[str, Any]] = None,
    ) -> CallRequest:
        """Reduce an event to a :class:`CallRequest`, attributing the Skill."""
        req = to_call_request(tool_name, tool_input)
        if req.skill is None:
            req = CallRequest(
                tool=req.tool,
                path=req.path,
                host=req.host,
                access=req.access,
                raw=req.raw,
                skill=self.skill,
            )
        return req

    def check(
        self,
        tool_name: str,
        tool_input: Optional[Mapping[str, Any]] = None,
    ) -> Decision:
        """Decide a single tool-use event. Raises on a denied call.

        This is the call the host makes *immediately before* executing a tool.
        On ALLOW it returns the :class:`Decision` and the host proceeds; on
        DENY it raises :class:`~capsule.interpose.CapabilityViolation` (after
        the trap line is emitted and recorded) and the host must abort the call.
        """
        return self.interposer.check(self.to_request(tool_name, tool_input))

    def guard_tool_use(
        self,
        run_tool: Callable[[str, Mapping[str, Any]], T],
    ) -> Callable[[str, Mapping[str, Any]], T]:
        """Wrap a host's ``run_tool(name, input)`` dispatcher with enforcement.

        The returned callable performs the capability check first; only on
        ALLOW does the wrapped ``run_tool`` execute. On DENY the underlying tool
        never runs (the core guarantee) and the violation propagates.

        Example
        -------
        ::

            dispatch = adapter.guard_tool_use(host.run_tool)
            dispatch("Bash", {"command": "curl https://evil.example"})  # blocked
        """

        def guarded(tool_name: str, tool_input: Mapping[str, Any]) -> T:
            call = self.to_request(tool_name, tool_input)
            return self.interposer.guard(call, lambda: run_tool(tool_name, tool_input))

        guarded.__name__ = getattr(run_tool, "__name__", "guarded_tool")
        return guarded


def check_tool_use(
    interposer: Interposer,
    tool_name: str,
    tool_input: Optional[Mapping[str, Any]] = None,
    *,
    skill: Optional[str] = None,
) -> Decision:
    """One-shot convenience: decide a single Claude Code tool-use event.

    Equivalent to ``ClaudeCodeAdapter(interposer, skill=skill).check(...)``.
    Raises :class:`~capsule.interpose.CapabilityViolation` on a denied call.
    """
    return ClaudeCodeAdapter(interposer, skill=skill).check(tool_name, tool_input)
