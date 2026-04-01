#!/usr/bin/env python3
"""
policy_loader.py — Load GuardianPolicy from policy.json
One source of truth for policy configuration. -AoCH

Usage
-----
    from tools.policy_loader import load_policy
    policy = load_policy("policy.json")

    # or CLI:
    python tools/policy_loader.py [path/to/policy.json]

Author: Ivan Putna (Architect of Chaos)
License: MIT
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos_agent_v2_2 import GuardianPolicy

_DEFAULTS = {
    "allowed_commands":    ["ls", "cat", "git", "echo", "python", "python3"],
    "allowed_paths":       ["/workspace", "/tmp"],
    "max_file_size_mb":    10,
    "no_shell":            True,
    "forbid_risky_imports": False,   # intentionally off — see docs -AoCH
    "sandbox_timeout":     10,
    "sandbox_cpu_limit":   5,
    "sandbox_nproc_limit": 32,
    "use_seccomp":         True,
}


def load_policy(path: str = "policy.json") -> GuardianPolicy:
    """
    Load GuardianPolicy from a JSON file.
    Missing keys fall back to safe defaults.
    Unknown keys are ignored (forward-compatible). -AoCH
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"policy_loader: {path} not found — using defaults", file=sys.stderr)
        data = {}
    except json.JSONDecodeError as exc:
        print(f"policy_loader: invalid JSON in {path}: {exc}", file=sys.stderr)
        data = {}

    def get(key: str):
        return data.get(key, _DEFAULTS[key])

    return GuardianPolicy(
        allowed_commands    = get("allowed_commands"),
        allowed_paths       = get("allowed_paths"),
        max_file_size_mb    = int(get("max_file_size_mb")),
        no_shell            = bool(get("no_shell")),
        forbid_risky_imports= bool(get("forbid_risky_imports")),
        sandbox_timeout     = int(get("sandbox_timeout")),
        sandbox_cpu_limit   = int(get("sandbox_cpu_limit")),
        sandbox_nproc_limit = int(get("sandbox_nproc_limit")),
        use_seccomp         = bool(get("use_seccomp")),
    )


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "policy.json"
    policy = load_policy(path)
    import dataclasses
    print(json.dumps(dataclasses.asdict(policy), indent=2))
