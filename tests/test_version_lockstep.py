"""Version-surface lockstep guard.

Capsule's version appears in several places: the ``VERSION`` file, the package
constant, ``pyproject.toml``, the CHANGELOG head, both READMEs, ``web/site.json``
and the recorded demo results. Nothing used to fail when one of them was bumped
and another was not, so drift shipped twice (v0.4.0 left every surface at 0.3.0;
v0.6.0 left the README version lines and ``docs/demo-results.json`` at 0.5.0 and
the CHANGELOG link references stale).

``VERSION`` is the single authoritative source. Every other surface is derived
from it and asserted here, so a partial bump fails the suite instead of shipping
a release whose own README advertises the previous one.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import capsule

REPO_ROOT = Path(__file__).resolve().parent.parent

VERSION_FILE = REPO_ROOT / "VERSION"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"
SITE_JSON = REPO_ROOT / "web" / "site.json"
DEMO_RESULTS = REPO_ROOT / "docs" / "demo-results.json"
READMES = (REPO_ROOT / "README.md", REPO_ROOT / "README.en.md")


def _version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def test_version_file_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", _version()), _version()


def test_package_version_matches_version_file():
    assert capsule.__version__ == _version()


def test_pyproject_version_matches_version_file():
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match is not None, "pyproject.toml has no [project] version"
    assert match.group(1) == _version()


def test_changelog_head_and_link_refs_match_version_file():
    version = _version()
    text = CHANGELOG.read_text(encoding="utf-8")
    headings = re.findall(r"^##\s+\[(\d+\.\d+\.\d+)\]", text, re.MULTILINE)
    assert headings, "CHANGELOG has no versioned section"
    assert headings[0] == version, (
        f"CHANGELOG newest section is {headings[0]}, VERSION is {version}"
    )
    # The newest section needs its own link reference, and [Unreleased] must
    # compare from the version we just released — otherwise the heading is a
    # dead anchor.
    assert re.search(rf"^\[{re.escape(version)}\]:\s*\S+", text, re.MULTILINE), (
        f"CHANGELOG has no [{version}] link reference"
    )
    unreleased = re.search(r"^\[Unreleased\]:\s*(\S+)", text, re.MULTILINE)
    assert unreleased is not None, "CHANGELOG has no [Unreleased] link reference"
    assert f"v{version}...HEAD" in unreleased.group(1), (
        f"[Unreleased] compares from {unreleased.group(1)}, expected v{version}...HEAD"
    )


def test_readme_version_lines_match_version_file():
    for readme in READMES:
        text = readme.read_text(encoding="utf-8")
        match = re.search(r"`v(\d+\.\d+\.\d+)`", text)
        assert match is not None, f"{readme.name} has no `vX.Y.Z` version line"
        assert match.group(1) == _version(), (
            f"{readme.name} advertises v{match.group(1)}, VERSION is {_version()}"
        )


def test_site_json_versions_match_version_file():
    version = _version()
    site = json.loads(SITE_JSON.read_text(encoding="utf-8"))
    assert site["content_version"] == f"v{version}"
    assert site["meta"]["content_version"] == version
    assert site["footer"]["tag"].startswith(version)


def test_demo_results_version_matches_version_file():
    demo = json.loads(DEMO_RESULTS.read_text(encoding="utf-8"))
    assert demo["version"] == _version()
