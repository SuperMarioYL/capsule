"""Capability-profile model — the deny-by-default document a Skill is bound to.

A *capability profile* is the core primitive of Capsule. It is a declarative,
deny-by-default description of what an installable agent Skill is allowed to do
once it is running:

```yaml
skill: curl-exfil-demo          # which skill this profile binds
default: deny                   # deny-by-default
tools:   [read_file, edit_file] # tool verbs allowed
paths:
  read:  ["./**"]               # globs the skill may read
  write: ["./src/**"]           # globs it may write
  deny:  ["~/.ssh/**", "~/.aws/**"]
network:
  allow: []                     # empty = no egress
```

This module turns that document into a typed, validated :class:`Profile` object.
It does **not** make decisions — :mod:`capsule.policy` does that. Keeping the
model and the decision engine separate means the policy engine can be tested in
isolation and a host adapter (:mod:`capsule.hosts`) can hand it any profile.

Design notes
------------
* **Deny-by-default is structural, not cosmetic.** ``default`` may only be
  ``deny``; an empty ``tools`` list means *no tools*, an empty ``network.allow``
  list means *no egress*. The absence of an allowance is a denial.
* Paths are normalised at load time (``~`` expanded, ``./`` resolved against the
  profile's base directory) so glob matching in the policy engine is purely
  lexical and predictable.
* Validation raises :class:`ProfileError` with a precise message rather than
  silently coercing — a malformed profile must fail loudly, never fail open.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "Profile",
    "PathRules",
    "NetworkRules",
    "ProfileError",
    "load_profile",
    "load_profile_file",
]


class ProfileError(ValueError):
    """Raised when a capability profile is missing required fields or malformed.

    A profile that cannot be parsed is treated as a hard error: Capsule never
    falls open on a bad profile, because an unparseable profile is exactly the
    situation in which a Skill could otherwise run unbounded.
    """


# --------------------------------------------------------------------------- #
# Typed sub-models
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PathRules:
    """Filesystem capability rules for a profile.

    Globs are stored exactly as normalised at load time. Matching semantics
    (and the precedence of ``deny`` over ``read``/``write``) live in
    :mod:`capsule.policy`; this class is a passive container.
    """

    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "read": list(self.read),
            "write": list(self.write),
            "deny": list(self.deny),
        }


@dataclass(frozen=True)
class NetworkRules:
    """Network egress capability rules for a profile.

    ``allow`` holds host patterns (e.g. ``api.github.com`` or ``*.internal``).
    An empty tuple means *no egress is permitted* — the deny-by-default stance.
    """

    allow: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, list[str]]:
        return {"allow": list(self.allow)}


@dataclass(frozen=True)
class Profile:
    """A validated, deny-by-default capability profile bound to one Skill.

    Attributes
    ----------
    skill:
        The Skill name this profile governs. The host adapter looks profiles up
        by this name when a Skill issues a tool call.
    default:
        Always ``"deny"`` in v0.1 — deny-by-default is the whole point. Present
        as a field so the YAML stays self-documenting and a future ``allow``
        mode is a single, reviewable change.
    tools:
        The set of tool verbs the Skill may invoke (e.g. ``read_file``,
        ``shell``). Anything not listed is denied.
    paths:
        Filesystem read/write/deny globs (see :class:`PathRules`).
    network:
        Network egress allow-list (see :class:`NetworkRules`).
    base_dir:
        The directory ``./`` relative globs were resolved against (the profile
        file's directory, or the current working directory for in-memory
        profiles). Carried so the policy engine can resolve call paths the same
        way the profile was normalised.
    source:
        Where the profile came from (a file path or ``"<dict>"``), purely for
        diagnostics and trap records.
    """

    skill: str
    default: str = "deny"
    tools: frozenset[str] = field(default_factory=frozenset)
    paths: PathRules = field(default_factory=PathRules)
    network: NetworkRules = field(default_factory=NetworkRules)
    base_dir: Path = field(default_factory=Path.cwd)
    source: str = "<dict>"

    # -- queries used by the policy engine ---------------------------------- #
    def allows_tool(self, tool: str) -> bool:
        """Whether ``tool`` is in the allow-list. Deny-by-default."""
        return tool in self.tools

    def as_dict(self) -> dict[str, Any]:
        """Round-trippable plain-dict view (used by ``capsule report`` etc.)."""
        return {
            "skill": self.skill,
            "default": self.default,
            "tools": sorted(self.tools),
            "paths": self.paths.as_dict(),
            "network": self.network.as_dict(),
            "source": self.source,
        }


# --------------------------------------------------------------------------- #
# Loading + validation
# --------------------------------------------------------------------------- #
def _normalise_glob(pattern: str, base_dir: Path) -> str:
    """Resolve ``~`` and ``./`` in a glob so policy matching is purely lexical.

    We deliberately do **not** call ``.resolve()`` (which would hit the
    filesystem and collapse non-existent paths); we only expand the user home
    and join relative patterns onto ``base_dir`` while preserving any glob
    wildcards. The result is an absolute, normalised pattern string.
    """
    pattern = pattern.strip()
    if not pattern:
        raise ProfileError("empty path glob is not allowed")

    if pattern.startswith("~"):
        expanded = os.path.expanduser(pattern)
    elif os.path.isabs(pattern):
        expanded = pattern
    else:
        # Relative globs (./foo/**, src/**) anchor on the profile's base dir.
        expanded = os.path.join(str(base_dir), pattern)

    # Collapse redundant separators / "." segments without touching wildcards
    # or following symlinks. os.path.normpath is lexical, which is exactly what
    # we want for predictable matching.
    return os.path.normpath(expanded)


def _coerce_str_list(value: Any, *, where: str) -> list[str]:
    """Validate that ``value`` is a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        raise ProfileError(
            f"{where} must be a list, not a bare string (got {value!r})"
        )
    if not isinstance(value, (list, tuple)):
        raise ProfileError(f"{where} must be a list (got {type(value).__name__})")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ProfileError(f"{where} entries must be non-empty strings (got {item!r})")
        out.append(item.strip())
    return out


def load_profile(
    data: Mapping[str, Any],
    *,
    base_dir: str | os.PathLike[str] | None = None,
    source: str = "<dict>",
) -> Profile:
    """Build and validate a :class:`Profile` from an in-memory mapping.

    Parameters
    ----------
    data:
        The parsed profile document (e.g. ``yaml.safe_load(...)``).
    base_dir:
        Directory that relative path globs (``./**``, ``src/**``) resolve
        against. Defaults to the current working directory.
    source:
        Diagnostic label recorded on the profile (a file path or ``"<dict>"``).

    Raises
    ------
    ProfileError
        If a required field is missing or any field is malformed.
    """
    if not isinstance(data, Mapping):
        raise ProfileError(
            f"profile must be a mapping/object (got {type(data).__name__})"
        )

    base = Path(base_dir) if base_dir is not None else Path.cwd()

    skill = data.get("skill")
    if not isinstance(skill, str) or not skill.strip():
        raise ProfileError("profile is missing a non-empty 'skill' name")
    skill = skill.strip()

    default = data.get("default", "deny")
    if default != "deny":
        # v0.1 only supports deny-by-default. Reject anything else loudly so a
        # profile can never silently fail open via 'default: allow'.
        raise ProfileError(
            f"profile.default must be 'deny' in this version (got {default!r}); "
            "deny-by-default is the only supported stance"
        )

    tools = _coerce_str_list(data.get("tools"), where="profile.tools")

    raw_paths = data.get("paths") or {}
    if not isinstance(raw_paths, Mapping):
        raise ProfileError(
            f"profile.paths must be a mapping (got {type(raw_paths).__name__})"
        )
    read = _coerce_str_list(raw_paths.get("read"), where="profile.paths.read")
    write = _coerce_str_list(raw_paths.get("write"), where="profile.paths.write")
    deny = _coerce_str_list(raw_paths.get("deny"), where="profile.paths.deny")

    raw_net = data.get("network") or {}
    if not isinstance(raw_net, Mapping):
        raise ProfileError(
            f"profile.network must be a mapping (got {type(raw_net).__name__})"
        )
    net_allow = _coerce_str_list(raw_net.get("allow"), where="profile.network.allow")

    paths = PathRules(
        read=tuple(_normalise_glob(p, base) for p in read),
        write=tuple(_normalise_glob(p, base) for p in write),
        deny=tuple(_normalise_glob(p, base) for p in deny),
    )
    network = NetworkRules(allow=tuple(h.lower() for h in net_allow))

    return Profile(
        skill=skill,
        default="deny",
        tools=frozenset(tools),
        paths=paths,
        network=network,
        base_dir=base,
        source=source,
    )


def load_profile_file(
    path: str | os.PathLike[str],
    *,
    base_dir: str | os.PathLike[str] | None = None,
) -> Profile:
    """Load and validate a capability profile from a YAML file on disk.

    Parameters
    ----------
    path:
        The profile YAML file.
    base_dir:
        Directory that relative path globs (``./**``, ``src/**``) resolve
        against. Defaults to the **profile file's own directory** — the least
        surprising behaviour for inspecting a checked-in profile in isolation
        (so ``capsule check`` shows globs rooted where the profile lives). A
        runner should pass the *session working directory* instead, because a
        profile that says ``read: ["./**"]`` is meant as "the project the agent
        runs in", not "wherever the shared profile file happens to sit" — this
        is what ``capsule run`` does so a project-relative ``./README.md`` read
        matches the ``./**`` allowance.
    """
    import yaml  # local import keeps the module importable without the dep

    p = Path(path)
    if not p.is_file():
        raise ProfileError(f"profile file not found: {p}")

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - exercised via bad files
        raise ProfileError(f"could not parse YAML in {p}: {exc}") from exc

    if raw is None:
        raise ProfileError(f"profile file is empty: {p}")

    base = Path(base_dir) if base_dir is not None else p.resolve().parent
    return load_profile(raw, base_dir=base, source=str(p))
