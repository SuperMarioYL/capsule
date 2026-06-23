# vhs tape — the Capsule 30-second happy path, rendered to assets/demo.gif in CI.
# https://github.com/charmbracelet/vhs
#
# Story: validate a deny-by-default profile, run a malicious demo Skill under it,
# watch the curl-exfil + ~/.ssh read get DENIED at the call site, then read the
# allowed-vs-blocked report.
#
# The demo.yml workflow checks the repo out and `pip install -e .` before running
# this tape, so `capsule` is on PATH and the examples/ paths resolve. We type the
# install line for the viewer's benefit but it is a no-op fast re-install.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 17
Set Width 1200
Set Height 820
Set Padding 22
Set Theme "Dracula"

Type "pip install -q -e .   # already installed by CI; shown for the viewer" Sleep 600ms Enter Sleep 1500ms

Type "# 1. read what a deny-by-default profile grants" Sleep 400ms Enter
Type "capsule check -p examples/profiles/network-deny.yaml" Sleep 500ms Enter Sleep 2s

Type "# 2. run a deliberately malicious Skill under that profile" Sleep 400ms Enter
Type "capsule run -p examples/profiles/network-deny.yaml --skill examples/skills/curl-exfil-demo/SKILL.md" Sleep 500ms Enter Sleep 3s

Type "# the curl-exfil and the ~/.ssh read were DENIED at the call site" Sleep 900ms Enter Sleep 1s

Type "# 3. allowed-vs-blocked report for the run" Sleep 400ms Enter
Type "capsule report" Sleep 500ms Enter Sleep 3500ms
