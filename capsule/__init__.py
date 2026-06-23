"""Capsule — a seccomp-style runtime capability sandbox for installable agent Skills.

Each Skill declares which tools, paths, and network destinations it may touch;
Capsule traps every tool call at the call site and blocks (and logs) any call
that falls outside the declared capability profile. Deny-by-default.
"""

__version__ = "0.1.0"
