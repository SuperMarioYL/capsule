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

from capsule.interpose import Interposer
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

#: Case-insensitive index of :data:`TOOL_MAP`. A host adapter — or a Skill's
#: ``capsule-calls`` block, which documents no tool-name casing rule — may send
#: a non-canonical verb (``bash`` / ``webfetch`` instead of ``Bash`` /
#: ``WebFetch``). Before v0.4 ``to_call_request`` matched case-sensitively, so
#: a lowercase verb degraded to a bare ``shell`` call with no parsed
#: command/URL and a ``bash: curl https://evil.example`` exfil was waved
#: through under a profile that grants ``shell``. Looking up via this index
#: closes that bypass and hardens future host adapters that send non-canonical
#: casing. ``str.title()`` is NOT enough: it lower-cases the F in ``WebFetch``
#: (and the E in ``MultiEdit``), so a lower-cased index is the correct fix.
_TOOL_MAP_LOWER: dict[str, str] = {k.lower(): v for k, v in TOOL_MAP.items()}

#: Shell verbs that read a file argument — used to recover the *path* a Bash
#: command targets so a ``cat ~/.ssh/id_rsa`` is checked as a path read, not an
#: opaque shell call.
_FILE_READ_CMDS = {"cat", "less", "more", "head", "tail", "bat", "xxd", "od", "strings"}
#: Shell verbs whose first URL-looking argument is a network egress.
_NET_CMDS = {"curl", "wget", "http", "https", "nc", "ncat", "scp", "sftp", "ssh", "rsync"}

_URL_RE = re.compile(r"""\b((?:https?|ftp)://[^\s'"]+)""", re.IGNORECASE)
_HOSTISH_RE = re.compile(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
#: A single-label hostname (no dot) — ``localhost`` or an ssh-config alias
#: like ``nas`` / ``buildbox``. Recognised so a profile can allow-list egress
#: to a local single-label host (a local LLM/Ollama server, a local webhook).
_SINGLE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$", re.IGNORECASE)


def _is_ipv4(token: str) -> bool:
    """True for a dotted-quad IPv4 literal whose every octet is in 0–255."""
    if not _IPV4_RE.match(token):
        return False
    return all(0 <= int(octet) <= 255 for octet in token.split("."))


def _extract_host(token: str) -> Optional[str]:
    """Pull a bare hostname (or IPv4/IPv6 literal) out of a URL or host token.

    Recognises a DNS name (``api.github.com``), a single-label host
    (``localhost``, an ssh-config alias like ``nas``), an IPv4 literal
    (``1.2.3.4``), and a bracketed IPv6 literal (``[::1]`` / ``[fe80::1]``).
    Leading-wildcard subdomain *patterns* (``*.internal``) are NOT hosts and
    are left for the policy engine's :func:`~capsule.policy.match_host` to
    handle.

    Returns the host lower-cased, or ``None`` when the token is not a host.

    Before v0.2 this only matched DNS names (the TLD had to be letters), so an
    IPv4 host returned ``None`` — which let ``curl http://1.2.3.4`` slip past the
    network rule under a profile that grants ``shell``. IPv4 and IPv6 are now
    first-class hosts. Before v0.4 a single-label host (``localhost``) still
    returned ``None``, so a profile that explicitly listed ``localhost`` in
    ``network.allow`` had its explicitly-allowed local egress DENIED — the
    allow-list was silently non-functional for single-label hosts.
    """
    token = token.strip().strip("'\"")
    if "://" in token:
        netloc = urlparse(token).netloc or urlparse(token).path
        token = netloc
    # Strip user@ and /path (NOT :port yet — a bracketed IPv6 may carry one).
    token = token.split("@")[-1].split("/")[0]
    # Bracketed IPv6: netloc like "[::1]:8080" -> the bare "::1".
    if token.startswith("["):
        end = token.find("]")
        if end != -1:
            return token[1:end].lower()
    # Now safe to strip :port (any bracketed IPv6 was handled above).
    token = token.split(":")[0]
    if _is_ipv4(token):
        return token.lower()
    if _HOSTISH_RE.fullmatch(token):
        return token.lower()
    if _SINGLE_LABEL_RE.fullmatch(token):
        return token.lower()
    return None


def _file_url_path(url: str) -> Optional[str]:
    """Local path a ``file:`` URL targets, or ``None`` for a non-file URL.

    ``urlparse('file://~/.ssh/id_rsa')`` splits the leading ``~`` into
    ``netloc`` and ``/.ssh/id_rsa`` into ``path`` (the ``//`` introduces an
    authority). We re-attach a netloc that is not a real host (``~``) so the
    path survives as ``~/.ssh/id_rsa`` and the policy engine's ``~``
    expansion lines up with a profile's ``~/.ssh/**`` deny glob. A standard
    ``file:///etc/passwd`` (empty authority) yields ``/etc/passwd`` unchanged.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() != "file":
        return None
    netloc, path = parsed.netloc, parsed.path
    if netloc and not _extract_host(netloc):
        # The authority is not a host (e.g. '~') — treat it as a path segment.
        return f"{netloc}{path}" if path else netloc
    return path or None


#: POSIX shell interpreters that take a ``-c <command-string>`` payload. When
#: the top-level verb is one of these, ``_parse_bash`` recurses on the ``-c``
#: payload so a hidden ``cat ~/.ssh/id_rsa`` (or a hidden ``curl``) is
#: inspected rather than buried behind an opaque ``bash -c "..."`` wrapper.
#: Non-shell ``-c`` runners (``python -c`` etc.) are deliberately excluded:
#: their payload is arbitrary source code Capsule cannot statically reduce to a
#: path/host, so recursing would only chase syntax it cannot classify.
_SHELL_INTERPRETERS = {"bash", "sh", "zsh", "dash", "ksh", "ash", "rbash"}
#: A short-flag cluster ending in ``c`` — ``-c``, ``-lc``, ``-ic`` — which for a
#: POSIX shell interpreter introduces the command-string argument. The next
#: positional token after it is the inner command line.
_SHELL_C_FLAG_RE = re.compile(r"^-[A-Za-z]*c$")

#: Shell command separators that end one command and start another inside a
#: single Bash call. Every segment of a compound command is an independently
#: executed command, so each one is parsed and the strictest surface (any
#: segment's path or host) is carried into the CallRequest — otherwise only
#: the FIRST segment was inspected and ``true && cat ~/.ssh/id_rsa`` or
#: ``echo 'cat ...' | bash`` reached the interpreter with no path attached.
_SEGMENT_SEPS = {"|", ";", "&&", "||"}

#: Output-redirection tokens — ``>``, ``>>``, and their fd-prefixed forms
#: (``2>``, ``&>``, ``1>>``). The token AFTER one is a file WRITE target and
#: must surface as an ``access="write"`` path so the profile's write scope
#: (e.g. ``./out/**``) applies to shell redirects, not just to edit_file.
_REDIRECT_RE = re.compile(r"^(?:\d+|&)?>>?$")

#: Verbs whose first positional argument is a file write target.
_FILE_WRITE_CMDS = {"tee"}

#: Verbs that COPY a file: their last positional argument is the destination
#: (a write) and every earlier positional is a source (a read). A ``cp
#: ~/.ssh/id_rsa ./out/key`` reads a denied path AND writes an in-scope one, so
#: it needs both surfaces on one request — which is why this verb set could only
#: land once :attr:`~capsule.policy.CallRequest.extra` existed.
_FILE_COPY_CMDS = {"cp", "mv", "install"}

#: Verbs that RUN the rest of the line as a command (``sudo cat x``,
#: ``env FOO=1 cat x``, ``nice cat x``). Unrecognised, the wrapper verb hid the
#: inner command from the verb classifier and the whole call degraded to a bare,
#: surface-less shell call — which a profile that grants ``shell`` allows.
#: ``xargs`` is included: it too takes the command it runs as its arguments.
_COMMAND_WRAPPERS = {
    "env",
    "sudo",
    "doas",
    "command",
    "exec",
    "nohup",
    "nice",
    "ionice",
    "setsid",
    "stdbuf",
    "time",
    "xargs",
}
#: A leading ``KEY=value`` assignment in a wrapper's argument list
#: (``env FOO=1 cat x``) — not the command.
_WRAPPER_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

#: Every verb this adapter classifies. Used to tell a wrapper's flag *value*
#: (the ``root`` in ``sudo -u root cat x``) from the command it wraps.
_KNOWN_VERBS = (
    _NET_CMDS
    | _FILE_READ_CMDS
    | _FILE_WRITE_CMDS
    | _FILE_COPY_CMDS
    | _SHELL_INTERPRETERS
    | _COMMAND_WRAPPERS
)

#: A path-like substring (``~``-rooted, ``/``-rooted, or explicit ``./`` /
#: ``../``) inside raw command text. Used for the pipe-into-interpreter shape
#: (``echo 'cat ~/.ssh/id_rsa' | bash``), where the interpreter's script is the
#: PRECEDING segment's output and the path hides inside a quoted argument that
#: token-level parsing cannot see — the same reason _URL_RE scans raw text.
_PATHLIKE_RE = re.compile(r"(?:~/|\.{1,2}/|/)(?:[\w.-]+/)*[\w.-]+")


def _shell_c_payload(tokens: list[str]) -> Optional[str]:
    """Return the command string a shell-interpreter ``-c`` flag carries.

    Returns ``None`` when there is no ``-c`` flag (e.g. an interactive
    ``bash`` with no script) or when ``-c`` is the last token (no payload) —
    in both cases there is no inner command to recurse into.
    """
    for i, t in enumerate(tokens[1:], start=1):
        if _SHELL_C_FLAG_RE.match(t) and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def _is_command_verb(token: str) -> bool:
    """Whether ``token`` names a command verb this adapter classifies."""
    return token.rsplit("/", 1)[-1].lower() in _KNOWN_VERBS


def _unwrap_command_wrapper(tokens: list[str]) -> Optional[list[str]]:
    """The tokens of the command a wrapper verb actually runs, or ``None``.

    ``sudo -u root cat x`` -> ``["cat", "x"]``; ``env FOO=1 cat x`` ->
    ``["cat", "x"]``; ``nice cat x`` -> ``["cat", "x"]``. The wrapper's own
    flags and ``KEY=value`` assignments are skipped, as is a single bare flag
    *value* when the token after it is a verb we recognise (the ``root`` in
    ``sudo -u root cat x``) — otherwise the wrapper would be classified as an
    unknown verb and the wrapped command would never be inspected at all.

    Returns ``None`` when nothing follows the wrapper's flags, so the caller
    falls back to a bare shell call rather than inventing a surface.
    """
    rest = tokens[1:]
    i = 0
    while i < len(rest) and (
        rest[i].startswith("-") or _WRAPPER_ASSIGNMENT_RE.match(rest[i])
    ):
        i += 1
    if i >= len(rest):
        return None
    if (
        not _is_command_verb(rest[i])
        and i + 1 < len(rest)
        and _is_command_verb(rest[i + 1])
    ):
        i += 1
    return rest[i:]


def _select_read_target(args: list[str]) -> Optional[str]:
    """Pick the filesystem path a file-read verb targets, fail-closed.

    A dash-prefixed flag's *value* is not itself dash-prefixed (the ``5`` in
    ``head -n 5``, the ``256`` in ``tail -c 256``), so a naive ``args[0]`` grab
    selected the flag value as the "path" — letting ``head -n 5 ~/.ssh/id_rsa``
    slip past a ``~/.ssh/**`` deny (the deny never matched ``5``, and ``5``
    matched the ``./**`` read allowance). We instead prefer a token that
    actually looks like a path (carries a ``/`` or a leading ``~``), else the
    first non-numeric token (skipping a flag's numeric value), else the first
    positional — preserving today's behaviour for a bare ``cat notes.txt``.
    """
    for a in args:
        if "/" in a or a.startswith("~"):
            return a
    for a in args:
        if not re.fullmatch(r"\d+", a):
            return a
    return args[0] if args else None


def _surface_rank(req: CallRequest) -> int:
    """Priority of a surface within one command: host, then read, then write."""
    if req.host is not None:
        return 0
    return 1 if req.access == "read" else 2


def _flatten_surfaces(surfaces: list[CallRequest]) -> list[CallRequest]:
    """Every surface in ``surfaces``, one level of ``extra`` unfolded."""
    flat: list[CallRequest] = []
    for surface in surfaces:
        flat.append(surface)
        flat.extend(surface.extra)
    return flat


def _combine_surfaces(surfaces: list[CallRequest], raw: str) -> CallRequest:
    """Fold every surface a command touched into ONE :class:`CallRequest`.

    The request proper carries the strictest surface by the documented priority
    (a host, then a read path, then a write path); the remaining surfaces ride
    along in :attr:`~capsule.policy.CallRequest.extra` so the policy engine
    checks them too. Carrying only the strictest one — what the pre-v0.7 parser
    did — silently dropped the others, so a command that both read a denied file
    and wrote an in-scope redirect was judged on the redirect alone.
    """
    flat: list[CallRequest] = []
    seen: set[tuple[Optional[str], Optional[str], Optional[str], str]] = set()
    for req in _flatten_surfaces(surfaces):
        key = (req.tool, req.path, req.host, req.access)
        if key not in seen:
            seen.add(key)
            flat.append(req)
    if not flat:
        return CallRequest(tool="shell", raw=raw)
    ordered = sorted(flat, key=_surface_rank)  # stable: keeps command order
    primary, *rest = ordered
    if not rest:
        return primary
    return CallRequest(
        tool=primary.tool,
        path=primary.path,
        host=primary.host,
        access=primary.access,
        raw=primary.raw,
        extra=tuple(rest),
    )


def _parse_bash(command: str) -> CallRequest:
    """Reduce a shell command line to a :class:`CallRequest`, fail-closed.

    Recognises the two exfil shapes that matter for the threat model:

    * network egress (``curl https://evil.example`` → ``shell`` call carrying a
      ``host`` so the network rule applies), and
    * sensitive file read (``cat ~/.ssh/id_rsa`` → ``shell`` call carrying a
      ``path`` so a path deny rule applies).

    A command can touch SEVERAL of those surfaces at once, so every surface of
    every segment is collected and the request carries all of them (see
    :func:`_combine_surfaces`); a redirect or a wrapper verb can no longer hide
    the read or the egress the command also performs.

    Anything it cannot positively classify is returned as a bare ``shell`` call
    with no path/host — which a deny-by-default profile blocks outright unless
    ``shell`` was explicitly granted. We never *upgrade* an unknown command to
    "looks safe"; unknown stays maximally restricted.
    """
    raw = command.strip()
    surfaces: list[CallRequest] = []

    # First, any explicit URL anywhere in the command is treated as egress.
    url_match = _URL_RE.search(raw)
    if url_match:
        host = _extract_host(url_match.group(1))
        # Fail-closed: a URL is ALWAYS a network-egress attempt. If we could not
        # resolve a clean host (an obfuscated/unusual URL), still flag the call
        # as network egress by carrying the raw URL token — the policy engine's
        # network rule is then consulted and, against any sane deny-by-default
        # allow-list, the call is DENIED rather than waved through as a bare
        # ``shell`` call (which is what happened pre-v0.2 for IP-host URLs).
        # The scan stays on the raw text because a URL can hide inside a quoted
        # argument (``echo 'curl https://evil.example' | sh``), which token-level
        # parsing cannot see — so it is one surface among the command's others,
        # not a short-circuit.
        surfaces.append(
            CallRequest(tool="shell", host=host or url_match.group(1), raw=raw)
        )

    try:
        tokens = shlex.split(raw)
    except ValueError:
        # Unbalanced quotes etc. — cannot parse, stay fully restricted.
        return _combine_surfaces(surfaces, raw)

    if not tokens:
        return _combine_surfaces(surfaces, raw)

    # A compound command runs EVERY segment (``true && cat x``, ``echo y | bash``,
    # ``a; b``), so every segment is parsed and every surface collected. Pre-v0.6
    # only the first segment's verb was inspected, so a leading ``true &&`` or a
    # pipe into an interpreter hid the rest of the line from the path/network
    # logic.
    segments: list[list[str]] = [[]]
    for t in tokens:
        if t in _SEGMENT_SEPS:
            segments.append([])
        else:
            segments[-1].append(t)

    consumed = 0  # tokens of earlier segments, for the pipe-script shape
    for seg in segments:
        if not seg:
            continue
        surfaces.extend(_parse_segment(seg, raw))

        # ``X | bash`` (no ``-c``): the interpreter's SCRIPT is the preceding
        # segment's output, so a path hiding inside a quoted argument of X
        # (``echo 'cat ~/.ssh/id_rsa' | bash``) is reachable script text.
        # Token-level parsing cannot see inside the quoted arg — scan the
        # preceding raw text for the first path-like substring, mirroring how
        # _URL_RE already scans raw text for hidden URLs.
        verb = seg[0].rsplit("/", 1)[-1].lower()
        found = _flatten_surfaces(surfaces)
        if (
            consumed > 0
            and verb in _SHELL_INTERPRETERS
            and _shell_c_payload(seg) is None
            and not any(s.path is not None and s.access == "read" for s in found)
        ):
            preceding = " ".join(
                t for seg2 in segments for t in seg2 if seg2 is not seg
            )
            if (m := _PATHLIKE_RE.search(preceding)) and not any(
                s.host is not None for s in found
            ):
                surfaces.append(
                    CallRequest(tool="shell", path=m.group(0), access="read", raw=raw)
                )

        consumed += len(seg)

    return _combine_surfaces(surfaces, raw)


def _parse_segment(tokens: list[str], raw: str) -> list[CallRequest]:
    """Every capability surface ONE command segment touches.

    A single segment can touch more than one: a redirect writes a path while the
    verb reads another (``cat ~/.ssh/id_rsa > ./out/x``), and a network verb can
    both egress and redirect (``curl 1.2.3.4/x > ./out/f``). Returning ALL of
    them — rather than the first — is what stops a redirect from hiding the
    verb's own read or egress, and what lets a copy verb surface both ends.
    """
    verb = tokens[0].rsplit("/", 1)[-1].lower()  # strip any leading path

    # A shell-interpreter wrapper (`bash -c "cat ~/.ssh/id_rsa"`) hides a
    # second-level command the top-level verb/args never see. Recurse on the
    # -c payload so a hidden file read is inspected by the path logic below (a
    # hidden URL was already caught by the _URL_RE scan on the full raw above).
    if verb in _SHELL_INTERPRETERS:
        inner = _shell_c_payload(tokens)
        if inner is not None:
            return [_parse_bash(inner)]

    # A command wrapper (`sudo cat x`, `env FOO=1 cat x`, `nice cat x`) runs the
    # rest of the line as the command, so classify THAT command — otherwise the
    # wrapper verb is unrecognised and the whole call degrades to a bare,
    # surface-less shell call, which a profile that grants `shell` allows.
    if verb in _COMMAND_WRAPPERS:
        wrapped = _unwrap_command_wrapper(tokens)
        if wrapped:
            return _parse_segment(wrapped, raw)

    surfaces: list[CallRequest] = []

    # An output redirect (``echo x > ~/.bashrc``) writes the NEXT token's path
    # — surface it as a write so the profile's write scope applies. Collected
    # alongside the verb's own surface rather than instead of it.
    for i, t in enumerate(tokens[:-1]):
        if _REDIRECT_RE.match(t):
            surfaces.append(
                CallRequest(tool="shell", path=tokens[i + 1], access="write", raw=raw)
            )
            break

    args = [t for t in tokens[1:] if not t.startswith("-")]

    if verb in _NET_CMDS:
        for a in args:
            host = _extract_host(a)
            if host:
                surfaces.append(CallRequest(tool="shell", host=host, raw=raw))
                return surfaces
            # A file:// argument targets a local path — surface it so a path
            # deny rule (~/.ssh/**) fires with path-denied instead of the call
            # falling through to a bare, host-less shell allow.
            file_path = _file_url_path(a)
            if file_path is not None:
                surfaces.append(
                    CallRequest(tool="shell", path=file_path, access="read", raw=raw)
                )
                return surfaces
        # A network command whose args yield no resolvable host/path is still
        # network egress — fail-closed: carry the first non-flag arg (or the
        # raw command) as the host so the network rule is consulted.
        fallback_host = args[0] if args else raw
        surfaces.append(CallRequest(tool="shell", host=fallback_host, raw=raw))
        return surfaces

    if verb in _FILE_READ_CMDS and args:
        # Pick the real target, not a flag value (head -n 5 ~/.ssh/id_rsa).
        surfaces.append(
            CallRequest(
                tool="shell",
                path=_select_read_target(args),
                access="read",
                raw=raw,
            )
        )
        return surfaces

    if verb in _FILE_WRITE_CMDS and args:
        surfaces.append(
            CallRequest(
                tool="shell",
                path=_select_read_target(args),
                access="write",
                raw=raw,
            )
        )
        return surfaces

    # A copy verb reads every positional but the last and writes the last one
    # (``cp ~/.ssh/id_rsa ./out/key``), so both ends are surfaced — the shape
    # the v0.6.0 grill deferred until a request could carry two paths. A
    # purely numeric positional is a flag's value, not a path (the ``600`` in
    # ``install -m 600 src dst``), the same convention _select_read_target uses.
    if verb in _FILE_COPY_CMDS and len(args) >= 2:
        surfaces.append(
            CallRequest(tool="shell", path=args[-1], access="write", raw=raw)
        )
        for a in args[:-1]:
            if not re.fullmatch(r"\d+", a):
                surfaces.append(
                    CallRequest(tool="shell", path=a, access="read", raw=raw)
                )
        return surfaces

    return surfaces


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
    verb = _TOOL_MAP_LOWER.get(tool_name.lower(), "shell")

    # Shell commands get parsed for intent (network / sensitive-path).
    if tool_name.lower() in ("bash", "bashoutput"):
        command = str(data.get("command", "")).strip()
        if command:
            return _parse_bash(command)
        return CallRequest(tool="shell", raw=tool_name)

    # Network tools carry a URL.
    if verb == "net_fetch":
        url = str(data.get("url", "")).strip()
        host = _extract_host(url) if url else None
        # A net_fetch-class call is network egress BY DEFINITION, so the network
        # rule must ALWAYS be consulted — even when no host resolves. Before
        # v0.5 this fail-closed only fired for a non-empty URL, so a host-less,
        # path-less net_fetch (notably WebSearch, which carries only a
        # ``query``) consulted no rule and was ALLOWED under a deny-all-network
        # profile. Carry the URL when there is one, else the tool name as the
        # egress sentinel. Mirrors the m4 / file:// fail-closed in _parse_bash.
        if host is None:
            host = url or tool_name
        # A file:// URL targets a local path — surface it so a path deny rule
        # (~/.ssh/**) fires with path-denied, and the call never falls through
        # to a bare net_fetch with no host AND no path.
        path = _file_url_path(url)
        return CallRequest(
            tool=verb,
            host=host,
            path=path,
            access="read",
            raw=url or tool_name,
        )

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
                extra=req.extra,
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
