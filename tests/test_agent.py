#!/usr/bin/env python3
"""
tests/test_agent.py — Chaos Agent unit tests
Run: python tests/test_agent.py

Author: Ivan Putna (Architect of Chaos)
License: MIT
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test-placeholder")

from chaos_agent_v2_2 import (
    audit_code,
    _within_allowed,
    _check_symlinks,
    _atomic_write,
    TokenBudget,
)


class TestAuditCode(unittest.TestCase):

    # ── Hard blocks ──────────────────────────────────────────
    def test_exec_blocked(self):
        ok, _, _ = audit_code('exec("rm -rf /")')
        self.assertFalse(ok)

    def test_eval_blocked(self):
        ok, _, _ = audit_code('eval("1+1")')
        self.assertFalse(ok)

    def test_compile_blocked(self):
        ok, _, _ = audit_code('compile("x", "f", "exec")')
        self.assertFalse(ok)

    def test_dunder_import_blocked(self):
        ok, _, _ = audit_code('__import__("os")')
        self.assertFalse(ok)

    def test_os_system_blocked(self):
        ok, _, _ = audit_code('import os\nos.system("ls")')
        self.assertFalse(ok)

    def test_os_system_aliased_blocked(self):
        ok, _, _ = audit_code('import os as o\no.system("ls")')
        self.assertFalse(ok)

    def test_ctypes_blocked(self):
        ok, _, _ = audit_code('import ctypes\nctypes.CDLL("libc.so")')
        self.assertFalse(ok)

    def test_obfuscation_blocked(self):
        ok, _, _ = audit_code("x = 'o'+'s'")
        self.assertFalse(ok)

    def test_builtins_dunder_blocked(self):
        ok, _, _ = audit_code('x = obj.__builtins__')
        self.assertFalse(ok)

    def test_shell_true_blocked(self):
        ok, _, _ = audit_code(
            'import subprocess\nsubprocess.run(["ls"], shell=True)',
            no_shell=True,
        )
        self.assertFalse(ok)

    # ── Allowed ──────────────────────────────────────────────
    def test_safe_function_allowed(self):
        ok, _, _ = audit_code(
            'def fib(n: int) -> int:\n    return n if n <= 1 else fib(n-1) + fib(n-2)'
        )
        self.assertTrue(ok)

    def test_import_os_allowed_by_default(self):
        """forbid_risky_imports=False default: import alone is allowed."""
        ok, _, _ = audit_code('import os')
        self.assertTrue(ok)

    def test_benign_getattr_allowed(self):
        ok, _, _ = audit_code('x = getattr(obj, "join")')
        self.assertTrue(ok)

    def test_shell_false_subprocess_still_blocked(self):
        """subprocess.run() is in _DANGEROUS_ATTRS — blocked regardless of shell flag.
        shell=True is an additional block on top of the attr block. -AoCH"""
        ok, _, meta = audit_code(
            'import subprocess\nsubprocess.run(["ls"], shell=False)',
            no_shell=True,
        )
        self.assertFalse(ok)
        self.assertEqual(meta["reason"], "dangerous_attr")


class TestSandboxUtils(unittest.TestCase):

    def test_within_allowed_true(self):
        self.assertTrue(_within_allowed('/tmp/x', ['/tmp']))

    def test_within_allowed_false(self):
        self.assertFalse(_within_allowed('/etc/passwd', ['/tmp']))

    def test_symlink_escape_detected(self):
        d = tempfile.mkdtemp()
        import os
        os.symlink('/etc/passwd', os.path.join(d, 'escape'))
        result = _check_symlinks(d, [d])
        self.assertIsNotNone(result)

    def test_no_symlink_clean(self):
        d = tempfile.mkdtemp()
        result = _check_symlinks(d, [d])
        self.assertIsNone(result)


class TestAtomicWrite(unittest.TestCase):

    def test_writes_correctly(self):
        tf = tempfile.mktemp()
        _atomic_write(tf, b'chaos agent')
        self.assertEqual(open(tf, 'rb').read(), b'chaos agent')

    def test_overwrites_existing(self):
        tf = tempfile.mktemp()
        _atomic_write(tf, b'v1')
        _atomic_write(tf, b'v2')
        self.assertEqual(open(tf, 'rb').read(), b'v2')


class TestTokenBudget(unittest.TestCase):

    def test_burst_streak_triggers(self):
        b = TokenBudget(max_tokens=10_000)
        for _ in range(3):
            b.observe(5000)
        self.assertTrue(b.should_compress())

    def test_no_compress_on_single_spike(self):
        """Single observation should not trigger compression on its own."""
        b = TokenBudget(max_tokens=100_000)  # large budget — single 5000 token call is safe
        b.observe(5000)
        self.assertFalse(b.should_compress())

    def test_total_accumulates(self):
        b = TokenBudget()
        b.observe(100)
        b.observe(200)
        self.assertEqual(b.total, 300)


if __name__ == "__main__":
    unittest.main(verbosity=2)
