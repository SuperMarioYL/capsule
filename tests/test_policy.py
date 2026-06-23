"""Tests for the deny-by-default policy engine and profile model."""

from __future__ import annotations

import os

import pytest

from capsule.policy import (
    CallRequest,
    Effect,
    decide,
    match_host,
    match_path,
)
from capsule.profile import ProfileError, load_profile


def make_profile(tmp_path, **overrides):
    """Build a validated profile rooted at ``tmp_path`` for path-glob tests."""
    data = {
        "skill": "demo",
        "default": "deny",
        "tools": ["read_file", "edit_file"],
        "paths": {
            "read": ["./**"],
            "write": ["./src/**"],
            "deny": ["~/.ssh/**", "~/.aws/**"],
        },
        "network": {"allow": ["api.github.com", "*.internal"]},
    }
    data.update(overrides)
    return load_profile(data, base_dir=str(tmp_path), source="<test>")


# --------------------------------------------------------------------------- #
# Profile loading / validation
# --------------------------------------------------------------------------- #
def test_profile_requires_skill_name():
    with pytest.raises(ProfileError, match="skill"):
        load_profile({"default": "deny", "tools": []})


def test_profile_rejects_default_allow():
    # Deny-by-default is the only supported stance; 'allow' must fail loudly.
    with pytest.raises(ProfileError, match="deny"):
        load_profile({"skill": "x", "default": "allow"})


def test_profile_rejects_bare_string_tool_list():
    with pytest.raises(ProfileError, match="list"):
        load_profile({"skill": "x", "tools": "read_file"})


def test_profile_empty_tools_means_no_tools(tmp_path):
    prof = make_profile(tmp_path, tools=[])
    assert prof.tools == frozenset()
    assert not prof.allows_tool("read_file")


# --------------------------------------------------------------------------- #
# Tool-level deny-by-default
# --------------------------------------------------------------------------- #
def test_allowed_tool_passes(tmp_path):
    prof = make_profile(tmp_path)
    call = CallRequest(tool="read_file", path=str(tmp_path / "a.txt"))
    d = decide(prof, call)
    assert d.effect is Effect.ALLOW
    assert d.rule == "allowed"


def test_unknown_tool_denied_by_default(tmp_path):
    prof = make_profile(tmp_path)
    # 'shell' was never granted -> denied even with no path/host.
    d = decide(prof, CallRequest(tool="shell", raw="curl https://evil.example"))
    assert d.effect is Effect.DENY
    assert d.rule == "tool-not-in-profile"


# --------------------------------------------------------------------------- #
# Path matching
# --------------------------------------------------------------------------- #
def test_read_inside_allowed_glob(tmp_path):
    prof = make_profile(tmp_path)
    call = CallRequest(tool="read_file", path=str(tmp_path / "docs" / "x.md"))
    assert decide(prof, call).allowed


def test_read_outside_base_denied(tmp_path):
    prof = make_profile(tmp_path)
    # A sibling directory is outside "./**" rooted at tmp_path.
    outside = tmp_path.parent / "elsewhere" / "secret.txt"
    d = decide(prof, CallRequest(tool="read_file", path=str(outside)))
    assert d.denied
    assert d.rule == "path-not-in-profile"


def test_explicit_deny_trumps_allow(tmp_path):
    prof = make_profile(tmp_path)
    # ~/.ssh/** is explicitly denied even though read_file is an allowed tool.
    ssh_key = os.path.expanduser("~/.ssh/id_rsa")
    d = decide(prof, CallRequest(tool="read_file", path=ssh_key))
    assert d.denied
    assert d.rule == "path-denied"
    assert d.matched is not None


def test_write_requires_write_glob(tmp_path):
    prof = make_profile(tmp_path)
    # ./README.md is readable (./**) but not writable (only ./src/** is).
    readme = tmp_path / "README.md"
    d = decide(prof, CallRequest(tool="edit_file", path=str(readme), access="write"))
    assert d.denied
    assert d.rule == "path-not-in-profile"


def test_write_inside_write_glob_allowed(tmp_path):
    prof = make_profile(tmp_path)
    target = tmp_path / "src" / "main.py"
    d = decide(prof, CallRequest(tool="edit_file", path=str(target), access="write"))
    assert d.allowed


# --------------------------------------------------------------------------- #
# Network matching
# --------------------------------------------------------------------------- #
def test_network_egress_denied_when_not_listed(tmp_path):
    prof = make_profile(tmp_path)
    d = decide(prof, CallRequest(tool="read_file", host="evil.example"))
    assert d.denied
    assert d.rule == "network-not-in-profile"


def test_network_egress_allowed_when_listed(tmp_path):
    prof = make_profile(tmp_path)
    d = decide(prof, CallRequest(tool="read_file", host="api.github.com"))
    assert d.allowed


def test_empty_network_allow_means_no_egress(tmp_path):
    prof = make_profile(tmp_path, network={"allow": []})
    d = decide(prof, CallRequest(tool="read_file", host="api.github.com"))
    assert d.denied
    assert d.rule == "network-not-in-profile"


# --------------------------------------------------------------------------- #
# Matching helpers (unit level)
# --------------------------------------------------------------------------- #
def test_match_path_recursive_doublestar(tmp_path):
    base = str(tmp_path)
    assert match_path(str(tmp_path / "a" / "b" / "c.txt"), os.path.join(base, "**"))
    assert match_path(base, os.path.join(base, "**"))  # dir itself


def test_match_host_subdomain_wildcard():
    assert match_host("svc.internal", "*.internal")
    assert match_host("internal", "*.internal")
    assert not match_host("svc.external", "*.internal")


def test_match_host_is_case_insensitive():
    assert match_host("API.GitHub.com", "api.github.com")
