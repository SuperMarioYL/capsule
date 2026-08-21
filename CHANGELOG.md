# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SuperMarioYL/capsule/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.1.0
