# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-09-05

### Fixed
- **head/tail/cat -n flag value bypassed the ~/.ssh path deny**: `_parse_bash`
  grabbed `args[0]` as the file-read path, but a flag's bare value (the `5` in
  `head -n 5`) survived flag-stripping, so `head -n 5 ~/.ssh/id_rsa` extracted
  path `5` (matching `./**`, never the `~/.ssh/**` deny) and was ALLOWED under
  `network-deny.yaml`. The path is now selected via a target selector that
  prefers a `/`/`~`-bearing token, else the first non-numeric arg.
- **`bash -c`/`sh -c` wrapper hid a `cat ~/.ssh/id_rsa` read**: `_parse_bash`
  only inspected the top-level verb, so a shell-interpreter `-c` payload
  degraded to a bare host-less `shell` call that was ALLOWED under
  `network-deny.yaml` (shell granted). Capsule now recurses into the `-c`
  payload of POSIX shell interpreters (bash/sh/zsh/dash/ksh/ash) so a hidden
  file read is trapped with `path-denied`. (A URL hidden in `-c` was already
  caught by the raw URL scan.)
- **host-less `net_fetch` (WebSearch) bypassed the network deny**: a
  `net_fetch`-class call with no URL (notably `WebSearch`, keyed on `query`)
  carried no host, so `decide()` consulted no network rule and was ALLOWED
  under a deny-all-network profile. A `net_fetch` is now fail-closed as
  network egress by definition — when no host resolves it carries a sentinel
  so the network rule is always consulted.
- **version surfaces were left at 0.3.0 through the v0.4.0 tag**: the v0.4.0
  release commit bumped the git tag but not `VERSION`, `__init__.py`,
  `pyproject.toml`, `CHANGELOG.md`, or `web/site.json` (`capsule --version`
  reported 0.3.0 at the v0.4.0 tag). All surfaces are now bumped to 0.5.0 and
  this [0.4.0] entry back-fills the changelog.

### Added
- **`capsule report --json`**: emits a machine-readable run summary
  (`{allowed, blocked, total, log, events:[...]}`) to stdout so a CI pipeline
  can consume it programmatically (e.g. `jq .blocked`); complements the
  existing `capsule run` exit-1-on-block convention. An empty/missing log
  yields a zeroed summary and exit 0.

## [0.4.0] - 2026-08-27

### Fixed
- **single-label host network bypass**: `ssh`/`nc`/`rsync`/`scp` to a
  single-label host (`localhost`, an ssh-config alias) reduced to a host-less
  `shell` call, which `network-deny.yaml` (shell granted, `network.allow: []`)
  waved through — a real egress bypassing the deny-all-network stance. The
  `_NET_CMDS` loop now fail-closes (carries the arg as host) so the network
  rule is consulted.
- **single-label host allow-list was non-functional**: `_extract_host` required
  a dotted TLD, so `localhost` returned `None`; the URL-egress fail-closed then
  carried the raw URL as host, which never matched an `allow: [localhost]`
  entry — explicitly-allowed local egress (a local LLM/Ollama server) was
  silently DENIED. Single-label hostnames are now recognised in `_extract_host`.
- **case-insensitive Skill tool-call bypass**: a lowercase tool verb in a
  Skill's `capsule-calls` block (`bash`/`webfetch`) was matched
  case-sensitively and degraded to a bare host-less `shell` call, waving a
  `curl`/`webfetch` exfil through under a profile that grants `shell`. Tool
  names are now mapped via a case-insensitive index.

## [0.3.0] - 2026-08-21

### Fixed
- **file:// URL bypasses the ~/.ssh deny**: a `file://` URL reduced to a
  host-less, path-less call so only the tool-allow check ran — under
  `network-deny.yaml` (which grants `shell` + `net_fetch`) it was ALLOWED,
  defeating the `~/.ssh/**` path deny and the deny-by-default network stance.
  `file://` is now fail-closed like `http`/`https`: its local path is surfaced
  (so a `~/.ssh/**` deny fires with `path-denied`) and any no-host URL still
  consults the network rule.
- **trap log accumulates across runs**: `capsule run` opened the default
  `.capsule/trap.log` without truncating, so `capsule report` read cumulative
  counts across every run ever written, diverging from the run's own summary.
  The default log is now fresh per run; an explicit `--log <path>` keeps the
  append behaviour (audit retention).

### Changed
- README license label corrected from MIT to Apache-2.0 (the LICENSE is
  Apache-2.0); the English badge was also relabelled.

## [0.2.0] - 2026-08-01

### Fixed
- **m4 — IP-egress bypass**: `curl http://<ip>` (IPv4 or bracketed IPv6) is now
  trapped as a network call (fail-closed) instead of being reduced to a bare
  `shell` call that slipped past the network rule under a profile granting
  `shell`. `_extract_host` recognises IPv4/IPv6 literals, and a matched URL is
  always treated as network egress even when no hostname resolves.

### Added
- **m5 — `capsule init`**: scaffolds `capsule.yaml` + an example
  `readonly.yaml` profile into the current directory (refuses to clobber
  existing files unless `--force`). Closes the happy-path step the v0.1.0 plan
  documented but the v0.1.0 product omitted.

### Changed
- **m6 — pluggable host seam**: new `capsule/hosts/registry.py` (`HOSTS` +
  `get_adapter`, default `claude-code`) and a `--host` flag on `capsule run`.
  A future Codex/Cursor adapter is one registered factory, not an engine change.
  Also fixes relative call-path matching: call paths now resolve against the
  profile's `base_dir`, not `os.getcwd()`, so relative paths match relative
  profile globs regardless of the process working directory.

## [0.1.0] - 2026-06-23

### Added
- **m1 — enforce calls**: deny-by-default capability profile traps a disallowed
  tool/path/network call at the call site and blocks + logs it.
- **m2 — profile & report**: YAML capability-profile schema, per-skill profiles
  bound by skill name, and a readable `capsule report` summary (allowed vs
  blocked) over a run.
- **m3 — ship demo**: reproducible `curl-exfil-demo` Skill plus a quickstart so a
  user sees a real block in under five minutes.

[Unreleased]: https://github.com/SuperMarioYL/capsule/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.5.0
[0.4.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.4.0
[0.3.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.1.0
