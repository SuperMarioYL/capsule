**English** | [简体中文](README.md)

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/hero-dark.svg">
  <img src="assets/presentation/hero-light.svg" width="1000" alt="Check capability profiles at an integrated tool dispatcher, refuse disallowed callbacks and record allow/deny reasons.">
</picture>

**Check capability profiles at an integrated tool dispatcher, refuse disallowed callbacks and record allow/deny reasons.**

`v0.5.0` · `Python 3.12+` · [Apache-2.0](LICENSE)

[Website](https://capsule.lei6393.com) · [Demo record](docs/demo-results.json)

## Why use it

A skill’s declared scope needs enforcement in the actual tool path. Capsule supplies a host adapter and Interposer so callers can check tool, path and network rules before entering the underlying callback. Installing the Python package alone does not take over every agent.

## Architecture

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/architecture-dark.svg">
  <img src="assets/presentation/architecture-light.svg" width="1000" alt="The adapter converts tool events into CallRequest. policy.decide checks allowed tools, path denies, read/write scope and network hosts. Interposer records and raises CapabilityViolation on denial, invoking the wrapped function only on allowance. TrapLog supports memory or JSONL, with CLI reporting.">
</picture>

The adapter converts tool events into CallRequest. policy.decide checks allowed tools, path denies, read/write scope and network hosts. Interposer records and raises CapabilityViolation on denial, invoking the wrapped function only on allowance. TrapLog supports memory or JSONL, with CLI reporting.

The execution boundary is [interpose.py](capsule/interpose.py); mapping and shell-intent parsing live in [hosts/claude_code.py](capsule/hosts/claude_code.py). Path rules are lexical, not a kernel sandbox.

## Install

Requires Python 3.12+. The demo invokes simulated host callbacks and performs no file, shell or network actions.

```bash
git clone https://github.com/SuperMarioYL/capsule.git
cd capsule
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Quickstart

The real guard_tool_use checks three requests under network-deny and readonly profiles, allowing only the Read callback. It validates callback-level refusal, not a live agent integration or syscall isolation.

```bash
python examples/presentation_demo.py network-deny
python examples/presentation_demo.py readonly
```

Requests, callbacks and counts are defined in [examples/presentation_demo.py](examples/presentation_demo.py), using the two shipped YAML profiles.

## Usage

check -p FILE validates a profile, init creates initial configuration, and run can replay a skill’s capsule-calls. A real host must route dispatch through adapter.guard_tool_use; calls outside that boundary are not controlled. report reads trap logs, with --json for scripts.

## Recorded demo

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/process-dark.svg">
  <img src="assets/presentation/process-light.svg" width="1000" alt="The real guard_tool_use checks three requests under network-deny and readonly profiles, allowing only the Read callback. It validates callback-level refusal, not a live agent integration or syscall isolation.">
</picture>

### Network-deny profile

One callback is allowed and two denied, with rule names retained.

```text
$ python examples/presentation_demo.py network-deny
{
  "profile": "network-deny",
  "decisions": [
    {
      "tool": "Read",
      "decision": "allow"
    },
    {
      "tool": "Write",
      "decision": "deny",
      "rule": "path-not-in-profile"
    },
    {
      "tool": "WebFetch",
      "decision": "deny",
      "rule": "network-not-in-profile"
    }
  ],
  "callbacks_executed": [
    "Read"
  ],
  "summary": {
    "allowed": 1,
    "blocked": 2,
    "total": 3
  }
}
```

### Readonly profile

Check the same requests under the narrower tool allowlist.

```text
$ python examples/presentation_demo.py readonly
{
  "profile": "readonly",
  "decisions": [
    {
      "tool": "Read",
      "decision": "allow"
    },
    {
      "tool": "Write",
      "decision": "deny",
      "rule": "tool-not-in-profile"
    },
    {
      "tool": "WebFetch",
      "decision": "deny",
      "rule": "tool-not-in-profile"
    }
  ],
  "callbacks_executed": [
    "Read"
  ],
  "summary": {
    "allowed": 1,
    "blocked": 2,
    "total": 3
  }
}
```

## Capabilities and integration

<picture>
  <source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="assets/presentation/integrations-dark.svg">
  <img src="assets/presentation/integrations-light.svg" width="1000" alt="Capsule’s enforcement comes from explicitly wrapping a dispatcher rather than transparently controlling the machine. Trap logs aid review but are not a complete audit of uninstrumented actions.">
</picture>

Capsule’s enforcement comes from explicitly wrapping a dispatcher rather than transparently controlling the machine. Trap logs aid review but are not a complete audit of uninstrumented actions.



## Configuration

Profiles contain skill, default: deny, tools, paths.read/write/deny and network.allow. Explicit deny wins. Relative paths need a clear base_dir; CLI run anchors them to the working directory. Granting shell expands the boundary and requires understanding the limited command-intent parser.

## Roadmap and scope

Tool policies, the host adapter, initialization, replay and reports are implemented. More hosts and a policy control plane remain future work. Kernel seccomp-bpf and a live hosted plan are not implemented.

- Tool policy is not kernel seccomp, a container or a system sandbox.
- Unintegrated calls are uncontrolled, and shell-intent parsing is not complete shell semantics.
- This run validates only the simulated callback boundary.

## License

[Apache-2.0](LICENSE)
