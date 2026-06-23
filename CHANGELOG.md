# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-23

### Added
- **m1 — enforce calls**: deny-by-default capability profile traps a disallowed
  tool/path/network call at the call site and blocks + logs it.
- **m2 — profile & report**: YAML capability-profile schema, per-skill profiles
  bound by skill name, and a readable `capsule report` summary (allowed vs
  blocked) over a run.
- **m3 — ship demo**: reproducible `curl-exfil-demo` Skill plus a quickstart so a
  user sees a real block in under five minutes.

[Unreleased]: https://github.com/SuperMarioYL/capsule/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.1.0
