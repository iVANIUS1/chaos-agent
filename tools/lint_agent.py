#!/usr/bin/env python3
"""
lint_agent.py — Chaos Agent CLI linter
Runs audit_code() on a Python file and reports findings.

Usage
-----
    python tools/lint_agent.py path/to/file.py [--no-shell] [--forbid-imports]

Exit codes
----------
    0 — allowed
    1 — blocked (hard violation found)
    2 — usage error

Author: Ivan Putna (Architect of Chaos)
License: MIT
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from repo root or from tools/
sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos_agent_v2_2 import audit_code


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit a Python file for dangerous constructs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", help="Python file to audit")
    parser.add_argument(
        "--no-shell",
        action="store_true",
        default=True,
        help="Block shell=True (default: on)",
    )
    parser.add_argument(
        "--forbid-imports",
        action="store_true",
        default=False,
        help="Hard-block risky module imports (default: off — see docs)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    try:
        source = Path(args.file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
        sys.exit(2)

    allowed, findings, meta = audit_code(
        source,
        no_shell=args.no_shell,
        forbid_risky_imports=args.forbid_imports,
    )

    result = {
        "file": args.file,
        "allowed": allowed,
        "reason": meta.get("reason", ""),
        "findings_count": len(findings),
        "findings": findings,
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        status = "✅ ALLOWED" if allowed else f"❌ BLOCKED — {meta.get('reason', '')}"
        print(f"{status}  {args.file}")
        if findings:
            print(f"\n{len(findings)} finding(s):")
            for f in findings:
                print(f"  line {f['lineno']:>4}  [{f['kind']}]  {f['detail']}")

    sys.exit(0 if allowed else 1)


if __name__ == "__main__":
    main()
