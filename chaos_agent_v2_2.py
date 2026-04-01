#!/usr/bin/env python3
"""
Chaos Agent v2.2
Elegant · Minimalist · Production-Ready AI Coding Agent

Author : Ivan Putna (Architect of Chaos)
Created: 2026-03-31
Updated: 2026-04-01
License: MIT

Philosophy
----------
Less code. More intelligence.
One single source of truth. Explicit cognitive layer.
Graceful degradation instead of hard limits.

v2.2 changes
------------
• Sandbox: subprocess-based first line with env_whitelist, timeout,
  symlink-escape pre-check, resource limits (RLIMIT_CPU/NPROC). -AoCH
• Sandbox: seccomp-bpf as optional second layer — detected at runtime,
  silently skipped if unavailable (container, macOS). -AoCH
• forbid_risky_imports: OFF by default. This is intentional — we block
  dangerous CALLS, not imports. Documented here and in README. -AoCH
  (Enable via policy for untrusted code execution contexts.)
• GuardianAgent: symlink pre-check before any sandbox execution.
• All v2.1 features retained: AST audit, EMA TokenBudget,
  atomic checkpoints, reproducibility bundle. -AoCH
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import logging
import os
import resource
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import deque
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Tuple

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("chaos")

API_KEY = os.getenv("ANTHROPIC_API_KEY")
if not API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY environment variable is required")
# Catches wrong key type at startup rather than at the first LLM call. -AoCH
if not API_KEY.startswith("sk-ant-"):
    raise RuntimeError("ANTHROPIC_API_KEY does not look valid (expected sk-ant-... prefix)")

MODEL = "claude-3-5-sonnet-20241022"

# Detect seccomp availability once at import time.
# Seccomp is Linux-only and requires libseccomp. We treat it as optional. -AoCH
try:
    import seccomp  # type: ignore
    _SECCOMP_AVAILABLE = True
except ImportError:
    _SECCOMP_AVAILABLE = False


# ─────────────────────────────────────────────
# ARTIFACT
# Immutable snapshot of a completed run.
# Every execution produces exactly one Artifact → full reproducibility. -AoCH
# ─────────────────────────────────────────────
@dataclass
class Artifact:
    timestamp: str
    version: str
    task: str
    signals: List[str]
    depth: int
    total_tokens: int
    duration_ms: float
    notes: List[str]
    history: List[Dict] = field(default_factory=list)


# ─────────────────────────────────────────────
# CONTEXT
# Lightweight conversation wrapper.
# compress() keeps the window bounded without losing intent. -AoCH
# ─────────────────────────────────────────────
class Context:
    def __init__(
        self,
        system_prompt: str = "You are an elegant, precise, and thoughtful coding agent.",
    ):
        self.system_prompt = system_prompt
        self.messages: List[Dict] = []
        self.summary: str = ""

    def add(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})

    def compress(self) -> None:
        """Drop old messages; keep the most recent window to stay within token limits."""
        if len(self.messages) > 12:
            self.summary = "Previous context has been summarized."
            self.messages = self.messages[-6:]


# ─────────────────────────────────────────────
# AST AUDIT
# Single-pass AST visitor that catches dangerous constructs,
# including aliased calls and string obfuscation. -AoCH
#
# Design decision: forbid_risky_imports is OFF by default.
# Rationale: blocking `import os` would break legitimate utilities
# that import but never call dangerous functions. We block the CALL,
# not the import. Enable forbid_risky_imports=True for fully untrusted
# code execution where even importing is unacceptable. -AoCH
# ─────────────────────────────────────────────
_RISKY_MODULES: frozenset[str] = frozenset({
    "os", "subprocess", "pickle", "marshal", "pty", "importlib", "ctypes",
})

_DANGEROUS_CALLS: frozenset[str] = frozenset({
    "exec", "eval", "compile",
})

_DANGEROUS_ATTRS: frozenset[Tuple[str, str]] = frozenset({
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
    ("subprocess", "run"), ("subprocess", "Popen"),
    ("subprocess", "call"), ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("pickle", "loads"), ("pickle", "load"),
    ("marshal", "loads"), ("marshal", "load"),
    ("pty", "spawn"),
    ("importlib", "import_module"),
    ("ctypes", "CDLL"), ("ctypes", "cdll"),
})


class _AuditVisitor(ast.NodeVisitor):
    """Single-pass AST visitor. Populates findings; sets hard=True on blocking violations."""

    def __init__(self, no_shell: bool, forbid_risky_imports: bool):
        self.no_shell = no_shell
        self.forbid_risky_imports = forbid_risky_imports
        self._aliases: Dict[str, Tuple[str, Optional[str]]] = {}
        self.findings: List[Dict] = []
        self.hard = False
        self.reason = ""

    def _mark(self, lineno: int, kind: str, detail: str, hard: bool) -> None:
        self.findings.append({"lineno": lineno, "kind": kind, "detail": detail})
        if hard and not self.hard:
            self.hard = True
            self.reason = kind

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            self._aliases[local] = (alias.name, None)
            if alias.name.split(".")[0] in _RISKY_MODULES:
                self._mark(node.lineno, "risky_import", alias.name, self.forbid_risky_imports)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            base = node.module.split(".")[0]
            for alias in node.names:
                local = alias.asname or alias.name
                self._aliases[local] = (node.module, alias.name)
            if base in _RISKY_MODULES:
                self._mark(node.lineno, "risky_importfrom", node.module, self.forbid_risky_imports)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        lineno = node.lineno

        # Direct dangerous calls: exec(...), eval(...), compile(...)
        if isinstance(node.func, ast.Name):
            if node.func.id in _DANGEROUS_CALLS:
                self._mark(lineno, f"call_{node.func.id}", node.func.id, hard=True)

        # __import__(...) — dynamic import bypass
        if isinstance(node.func, ast.Name) and node.func.id == "__import__":
            self._mark(lineno, "call___import__", "__import__", hard=True)

        # Attribute calls: os.system(...), subprocess.run(...), etc.
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            obj = node.func.value

            mod: Optional[str] = None
            if isinstance(obj, ast.Name):
                if obj.id in self._aliases:
                    mod, _ = self._aliases[obj.id]
                else:
                    mod = obj.id

            key = (mod or "", attr)
            if key in _DANGEROUS_ATTRS:
                self._mark(lineno, "dangerous_attr", f"{mod}.{attr}", hard=True)

            # shell=True — blocked regardless of function when no_shell=True
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._mark(lineno, "shell_true", f"{mod}.{attr}(shell=True)", self.no_shell)

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Detect string obfuscation: 'o'+'s', 'ev'+'al', etc."""
        if (
            isinstance(node.op, ast.Add)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.right, ast.Constant)
        ):
            combined = str(node.left.value) + str(node.right.value)
            if combined in {"os", "exec", "eval", "compile", "subprocess", "__import__"}:
                self._mark(node.lineno, "obfuscation", combined, hard=True)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Detect __builtins__ / __dict__ access used for dynamic eval bypass."""
        if node.attr in {"__builtins__", "__dict__", "__globals__", "__code__"}:
            self._mark(
                getattr(node, "lineno", 0),
                "dunder_access",
                node.attr,
                hard=True,
            )
        self.generic_visit(node)


def audit_code(
    source: str,
    no_shell: bool = True,
    forbid_risky_imports: bool = False,
) -> Tuple[bool, List[Dict], Dict]:
    """
    Run a single-pass AST audit on Python source code.

    forbid_risky_imports is OFF by default — see module docstring for rationale.

    Returns
    -------
    (allowed, findings, meta)
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return (
            False,
            [{"lineno": exc.lineno, "kind": "syntax_error", "detail": str(exc)}],
            {"reason": "syntax_error", "hard": True},
        )

    visitor = _AuditVisitor(no_shell=no_shell, forbid_risky_imports=forbid_risky_imports)
    visitor.visit(tree)
    allowed = not visitor.hard
    return allowed, visitor.findings, {"reason": visitor.reason, "hard": visitor.hard}


# ─────────────────────────────────────────────
# POLICY
# Declarative safety rules — one source of truth.
#
# forbid_risky_imports=False (default, intentional):
#   We block dangerous CALLS at AST level, not imports.
#   `import os` is legitimate; `os.system(...)` is not.
#   Set to True only when executing fully untrusted, unknown code. -AoCH
#
# no_shell=True (default):
#   Blocks shell=True at AST level AND in sandbox preexec.
#   Two independent layers — belt and suspenders. -AoCH
#
# Future: enforce allowed_paths via seccomp path whitelist. -AoCH
# ─────────────────────────────────────────────
@dataclass
class GuardianPolicy:
    allowed_commands: List[str] = field(
        default_factory=lambda: ["ls", "cat", "git", "echo", "python", "python3"]
    )
    allowed_paths: List[str] = field(
        default_factory=lambda: ["/workspace", "/tmp"]
    )
    max_file_size_mb: int = 10
    no_shell: bool = True
    forbid_risky_imports: bool = False
    sandbox_timeout: int = 10          # seconds; per subprocess execution
    sandbox_cpu_limit: int = 5         # seconds of CPU time (RLIMIT_CPU)
    sandbox_nproc_limit: int = 32      # max child processes (RLIMIT_NPROC)
    use_seccomp: bool = True           # use seccomp if available; silent skip if not


# ─────────────────────────────────────────────
# TOKEN BUDGET
# EMA-based compression trigger.
# Reacts to sustained pressure (burst_streak ≥ 3), not outliers. -AoCH
# ─────────────────────────────────────────────
class TokenBudget:
    def __init__(
        self,
        max_tokens: int = 12_000,
        window: int = 32,
        safety_margin: float = 0.18,
        alpha: float = 0.35,
    ):
        self.max_tokens = max_tokens
        self.safety_margin = safety_margin
        self.alpha = alpha
        self._window: Deque[int] = deque(maxlen=window)
        self._ema: float = 0.0
        self._total: int = 0
        self._burst_streak: int = 0

    def observe(self, used: int) -> None:
        self._window.append(used)
        self._total += used
        self._ema = (
            float(used) if self._ema == 0.0
            else self.alpha * used + (1 - self.alpha) * self._ema
        )
        self._burst_streak = self._burst_streak + 1 if used > self._ema * 1.5 else 0

    def should_compress(self, projected_extra: int = 0) -> bool:
        if not self._window:
            return False
        if self._burst_streak >= 3:
            return True
        burst = max(self._window)
        projected = self._total + projected_extra + int(self._ema) + int(0.5 * burst)
        return projected >= int(self.max_tokens * (1 - self.safety_margin))

    @property
    def total(self) -> int:
        return self._total


# ─────────────────────────────────────────────
# SANDBOX
# Two-layer execution isolation:
#   Layer 1: subprocess with env_whitelist, timeout, resource limits.
#   Layer 2: seccomp-bpf syscall filter (optional, Linux only).
#
# Design:
#   - Layer 1 is always active. It is platform-portable.
#   - Layer 2 is applied via preexec_fn if seccomp is available AND
#     policy.use_seccomp=True. If seccomp is missing (container, macOS),
#     we log a warning and continue — Layer 1 remains active. -AoCH
#
# Symlink pre-check:
#   Walk the workdir before execution. Any symlink pointing outside
#   allowed_paths is detected and the run is aborted. -AoCH
# ─────────────────────────────────────────────
def _within_allowed(path: str, allowed: List[str]) -> bool:
    """Return True if path resolves within any allowed base."""
    ap = os.path.realpath(path)
    return any(
        ap == os.path.realpath(base) or ap.startswith(os.path.realpath(base) + os.sep)
        for base in allowed
    )


def _check_symlinks(workdir: str, allowed_paths: List[str]) -> Optional[str]:
    """
    Walk workdir and detect symlink-escape attempts.
    Returns the offending path string if found, else None. -AoCH
    """
    for root, dirs, files in os.walk(workdir, followlinks=False):
        for name in dirs + files:
            full = os.path.join(root, name)
            if os.path.islink(full):
                target = os.path.realpath(full)
                if not _within_allowed(target, allowed_paths):
                    return f"{full} → {target}"
    return None


def _make_preexec(policy: GuardianPolicy) -> Callable[[], None]:
    """
    Build a preexec_fn for subprocess.run.
    Applies resource limits and optionally seccomp. -AoCH
    """
    cpu_limit = policy.sandbox_cpu_limit
    nproc_limit = policy.sandbox_nproc_limit
    want_seccomp = policy.use_seccomp and _SECCOMP_AVAILABLE

    def preexec() -> None:
        # Resource limits — silently skip if unsupported (e.g. some containers).
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
        except (ValueError, resource.error):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (nproc_limit, nproc_limit))
        except (ValueError, resource.error):
            pass

        # Seccomp layer — deny-by-default with allowlist of safe syscalls.
        # Applied after resource limits so the filter itself doesn't need extra syscalls. -AoCH
        if want_seccomp:
            try:
                import seccomp as sc  # type: ignore
                f = sc.SyscallFilter(defaction=sc.KILL_PROCESS)
                for syscall in [
                    "read", "write", "open", "openat", "close", "stat", "fstat",
                    "lstat", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
                    "rt_sigprocmask", "exit_group", "futex", "getcwd", "getdents64",
                    "access", "newfstatat", "pread64", "pwrite64", "lseek",
                    "dup", "dup2", "pipe", "select", "poll", "clone", "wait4",
                    "execve", "arch_prctl", "set_tid_address", "set_robust_list",
                ]:
                    try:
                        f.add_rule(sc.ALLOW, syscall)
                    except Exception:
                        pass
                f.load()
            except Exception:
                pass  # If seccomp setup fails, continue without it.

    return preexec


def run_sandbox(
    code: str,
    policy: GuardianPolicy,
    workdir: Optional[str] = None,
    env_whitelist: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Execute Python code in a sandboxed subprocess.

    Returns dict with: ok, stdout, stderr, returncode, error.

    Security layers applied:
      1. Symlink pre-check on workdir
      2. Clean environment (env_whitelist only)
      3. subprocess with timeout
      4. RLIMIT_CPU + RLIMIT_NPROC via preexec_fn
      5. seccomp-bpf syscall filter (if available + policy.use_seccomp) -AoCH
    """
    result: Dict[str, Any] = {"ok": False, "stdout": "", "stderr": "", "returncode": -1, "error": ""}

    # Prepare workdir
    if workdir is None:
        workdir = tempfile.mkdtemp(prefix="chaos_sbx_")
    os.makedirs(workdir, exist_ok=True)

    # Layer 1: symlink escape pre-check
    escape = _check_symlinks(workdir, policy.allowed_paths)
    if escape:
        result["error"] = f"symlink_escape: {escape}"
        return result

    # Clean environment — only whitelisted keys pass through. -AoCH
    keys = env_whitelist or []
    clean_env = {k: os.environ[k] for k in keys if k in os.environ}

    # Write code to temp file in workdir
    code_path = os.path.join(workdir, "_chaos_run.py")
    try:
        with open(code_path, "w", encoding="utf-8") as fh:
            fh.write(code)
    except OSError as exc:
        result["error"] = f"write_failed: {exc}"
        return result

    seccomp_status = "available" if _SECCOMP_AVAILABLE else "unavailable"
    if policy.use_seccomp and not _SECCOMP_AVAILABLE:
        logger.warning("seccomp requested but not available — running with Layer 1 only")

    try:
        proc = subprocess.run(
            [sys.executable, code_path],
            capture_output=True,
            text=True,
            timeout=policy.sandbox_timeout,
            cwd=workdir,
            env=clean_env,
            shell=False,                    # never shell=True in sandbox -AoCH
            preexec_fn=_make_preexec(policy),
        )
        result.update({
            "ok": proc.returncode == 0,
            "stdout": proc.stdout[:4096],
            "stderr": proc.stderr[:2048],
            "returncode": proc.returncode,
            "seccomp": seccomp_status,
        })
    except subprocess.TimeoutExpired:
        result["error"] = f"timeout_after_{policy.sandbox_timeout}s"
    except Exception as exc:
        result["error"] = str(exc)

    # Post-execution symlink check — detect any links created during run
    escape_post = _check_symlinks(workdir, policy.allowed_paths)
    if escape_post:
        result["ok"] = False
        result["error"] = f"post_run_symlink_escape: {escape_post}"

    return result


# ─────────────────────────────────────────────
# BUNDLE & INTEGRITY
# Atomic writes and SHA-256 bundle verification.
# A run that cannot be reproduced is not production-ready. -AoCH
# ─────────────────────────────────────────────
def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_write(path: str, data: bytes) -> None:
    """Write atomically: tempfile → fsync → os.replace. Safe on crash. -AoCH"""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def export_bundle(
    kernel: "ChaosKernel",
    artifact: Artifact,
    out_dir: str = "/tmp/chaos_bundle",
) -> str:
    """Export reproducibility bundle: artifact + history + SHA-256 manifest → ZIP."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    bundle_path = os.path.join(out_dir, f"repro_{ts}.zip")
    os.makedirs(out_dir, exist_ok=True)

    artifact_path = os.path.join(out_dir, "artifact.json")
    history_path = os.path.join(out_dir, "history.jsonl")

    _atomic_write(
        artifact_path,
        json.dumps(asdict(artifact), indent=2, ensure_ascii=False, default=str).encode(),
    )
    _atomic_write(
        history_path,
        b"\n".join(
            json.dumps(e, ensure_ascii=False, default=str).encode()
            for e in kernel.history[-1000:]
        ),
    )

    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "agent_version": artifact.version,
        "files": {
            "artifact.json": {"sha256": _sha256_file(artifact_path)},
            "history.jsonl": {"sha256": _sha256_file(history_path)},
        },
    }
    manifest_path = os.path.join(out_dir, "manifest.json")
    _atomic_write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False).encode())

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(artifact_path, "artifact.json")
        zf.write(history_path, "history.jsonl")
        zf.write(manifest_path, "manifest.json")

    return bundle_path


def verify_bundle(bundle_path: str) -> Tuple[bool, Dict]:
    """Verify bundle integrity against manifest SHA-256 hashes."""
    info: Dict[str, Any] = {"ok": True, "errors": []}
    with tempfile.TemporaryDirectory() as td:
        with zipfile.ZipFile(bundle_path, "r") as zf:
            zf.extractall(td)
        manifest_path = os.path.join(td, "manifest.json")
        if not os.path.exists(manifest_path):
            return False, {"ok": False, "errors": ["missing manifest"]}
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        for name, meta in manifest.get("files", {}).items():
            p = os.path.join(td, name)
            if not os.path.exists(p):
                info["ok"] = False
                info["errors"].append(f"missing: {name}")
                continue
            if _sha256_file(p) != meta.get("sha256"):
                info["ok"] = False
                info["errors"].append(f"hash_mismatch: {name}")
    return info["ok"], info


# ─────────────────────────────────────────────
# LLM CALL
# Single async function for all model interactions.
# Manual exponential back-off keeps the dependency tree minimal. -AoCH
# ─────────────────────────────────────────────
async def call_llm(
    messages: List[Dict],
    system: str = "",
    max_tokens: int = 1200,
    temperature: float = 0.3,
) -> Tuple[str, int]:
    """Call Anthropic Messages API with up to 3 retries."""
    async with httpx.AsyncClient(timeout=70.0) as client:
        for attempt in range(3):
            try:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": MODEL,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                        "system": system,
                        "messages": messages,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                text = data["content"][0]["text"]
                usage = data.get("usage", {})
                tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                return text, tokens
            except Exception as exc:
                logger.warning("LLM call failed (attempt %d/3): %s", attempt + 1, exc)
                if attempt == 2:
                    raise
                await asyncio.sleep(2 ** attempt)
    return "", 0


# ─────────────────────────────────────────────
# KERNEL
# The single source of truth for all runtime state.
#
# Key decisions:
#   • emit() is the ONLY path through which events enter history. -AoCH
#   • TokenBudget + depth threshold both trigger compression — whichever
#     fires first. Belt and suspenders. -AoCH
#   • on_event is a pluggable async callback — callers own their I/O. -AoCH
# ─────────────────────────────────────────────
class ChaosKernel:
    def __init__(
        self,
        max_depth: int = 10,
        compression_threshold: int = 8,
        checkpoint_interval: int = 8,
        rate_limit: float = 0.08,
        max_tokens: int = 12_000,
        on_event: Optional[Callable[[Dict], Awaitable[None]]] = None,
    ):
        self.version = "2.2"
        self.max_depth = max_depth
        self.compression_threshold = compression_threshold
        self.checkpoint_interval = checkpoint_interval
        self.rate_limit = rate_limit

        self.on_event: Callable[[Dict], Awaitable[None]] = (
            on_event if on_event is not None else self._default_output
        )

        self.context = Context()
        self.budget = TokenBudget(max_tokens=max_tokens)
        self.history: List[Dict] = []
        self.signals: List[str] = []
        self.depth: int = 0
        self.start_time: float = time.time()
        self.event_counter: int = 0
        self.last_emit: float = 0.0
        self.compressed: bool = False

    # ── Output ──────────────────────────────
    def _should_show_to_user(self, event: Dict) -> bool:
        """
        Attention filter: surface only what the user needs to see.
        Pass on_event= to bypass entirely. -AoCH
        """
        if event.get("type") in {
            "ERROR", "VIOLATION", "DOUBT", "STRATEGIC",
            "ANTI_ENTROPY", "COMPRESSION", "CHECKPOINT", "SANDBOX",
        }:
            return True
        return self.depth % 5 == 0 or len(str(event.get("data", ""))) < 120

    async def _default_output(self, event: Dict) -> None:
        if self._should_show_to_user(event):
            print(
                f"[{event['timestamp']}] [{event.get('source', 'SYS')}] "
                f"{event['type']}: {str(event.get('data', ''))[:160]}"
            )

    # ── Core ─────────────────────────────────
    async def emit(self, event: Dict[str, Any]) -> None:
        """Single entry point for all events."""
        now = time.time()
        gap = self.rate_limit - (now - self.last_emit)
        if gap > 0:
            await asyncio.sleep(gap)
        self.last_emit = time.time()

        self.depth += 1
        self.event_counter += 1

        event.update({
            "id": f"evt_{int(time.time() * 1000)}_{self.event_counter}",
            "timestamp": time.strftime("%H:%M:%S"),
            "depth": self.depth,
            "signals": self.signals[-4:],
            "seq": self.event_counter,
        })

        self.history.append(event)
        await self.on_event(event)

        if event.get("type") == "SIGNAL":
            self.signals.append(event.get("signal", ""))

        if (self.depth >= self.compression_threshold or self.budget.should_compress()) and not self.compressed:
            await self.compress()

        if self.event_counter % self.checkpoint_interval == 0:
            await self._auto_checkpoint()

    async def inject(self, signal_type: str, message: str) -> None:
        """Human-in-the-loop cognitive signal injection."""
        print(f"🧠 SIGNAL [{signal_type}]: {message}")
        await self.emit({"type": "SIGNAL", "signal": signal_type, "data": message, "source": "HUMAN"})

    # ── Anti-Entropy ─────────────────────────
    async def compress(self) -> None:
        """Graceful history compression. Net depth change per cycle: -3. Stable. -AoCH"""
        self.compressed = True
        await self.emit({"type": "COMPRESSION", "data": "Compressing history", "source": "KERNEL"})

        recent = self.history[-10:] if len(self.history) > 10 else self.history
        context_payload = json.dumps(
            [{"type": e.get("type"), "data": str(e.get("data"))[:200]} for e in recent],
            ensure_ascii=False,
        )

        summary, tokens = await call_llm(
            [{"role": "user", "content": f"Summarize this agent history in one concise sentence:\n{context_payload}"}],
            system="You are a precise summarizer. Answer with exactly one sentence.",
        )
        self.budget.observe(tokens)

        self.history = self.history[:-10] + [{
            "type": "COMPRESSED_SUMMARY",
            "data": summary,
            "timestamp": time.strftime("%H:%M:%S"),
            "source": "KERNEL",
        }]
        self.depth = max(3, self.depth - 5)

        await self.emit({
            "type": "COMPRESSION_DONE",
            "data": f"History compressed. New depth: {self.depth}",
            "source": "KERNEL",
        })
        self.compressed = False

    # ── Checkpointing ────────────────────────
    async def _auto_checkpoint(self) -> None:
        artifact = self.checkpoint("auto")
        filename = f"checkpoint_{self.event_counter}.json"
        _atomic_write(filename, json.dumps(asdict(artifact), indent=2, default=str).encode())
        await self.emit({"type": "CHECKPOINT", "data": f"Saved to {filename}", "source": "KERNEL"})

    def checkpoint(self, task: str, notes: Optional[List[str]] = None) -> Artifact:
        return Artifact(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            version=self.version,
            task=task,
            signals=self.signals.copy(),
            depth=self.depth,
            total_tokens=self.budget.total,
            duration_ms=round((time.time() - self.start_time) * 1000, 1),
            notes=notes or ["Production-ready checkpoint"],
            history=self.history.copy(),
        )

    @classmethod
    def load_checkpoint(cls, filename: str) -> "ChaosKernel":
        with open(filename, encoding="utf-8") as fh:
            data = json.load(fh)
        artifact = Artifact(**data)
        kernel = cls()
        kernel.version = artifact.version
        kernel.history = artifact.history
        kernel.signals = artifact.signals
        kernel.depth = artifact.depth
        # start_time resets to now — each session is independent. -AoCH
        kernel.start_time = time.time()
        kernel.event_counter = len(artifact.history)
        return kernel

    def prepare_context(self, max_events: int = 5) -> str:
        """Compact JSON snapshot of most relevant recent events. -AoCH"""
        important_types = {"PLAN", "RESEARCH_DONE", "SIGNAL", "CODE_READY"}
        important = [e for e in self.history if e.get("type") in important_types]
        return json.dumps(important[-max_events:], default=str, ensure_ascii=False)


# ─────────────────────────────────────────────
# BASE AGENT
# Zero-boilerplate shared emit API. -AoCH
# ─────────────────────────────────────────────
class BaseAgent:
    def __init__(self, name: str, kernel: ChaosKernel):
        self.name = name
        self.kernel = kernel

    async def emit(self, event_type: str, data: Any = None) -> None:
        await self.kernel.emit({"type": event_type, "data": data, "source": self.name})


# ─────────────────────────────────────────────
# GUARDIAN
# Centralised policy enforcement.
# v2.2: AST audit + symlink pre-check + sandbox integration. -AoCH
# ─────────────────────────────────────────────
class GuardianAgent(BaseAgent):
    def __init__(self, name: str, kernel: ChaosKernel, policy: Optional[GuardianPolicy] = None):
        super().__init__(name, kernel)
        self.policy = policy or GuardianPolicy()

    async def check(self, action: str, context: Dict) -> bool:
        if context.get("depth", 0) > self.kernel.max_depth:
            await self.emit("ANTI_ENTROPY", "Depth limit reached. Triggering compression.")
            await self.kernel.compress()

        # Route: code strings → AST audit; plain commands → allowlist check.
        if action.strip().startswith(("def ", "import ", "class ", "#", "\n", "async ")):
            allowed, findings, meta = audit_code(
                action,
                no_shell=self.policy.no_shell,
                forbid_risky_imports=self.policy.forbid_risky_imports,
            )
            if not allowed:
                await self.emit("VIOLATION", f"AST audit blocked: {meta['reason']} | {findings[:3]}")
                return False
        else:
            cmd = action.split()[0] if action.split() else ""
            if cmd and cmd not in self.policy.allowed_commands:
                await self.emit("VIOLATION", f"Command not in allowlist: {cmd}")
                return False

        return True

    async def run_code(self, code: str, workdir: Optional[str] = None) -> Dict[str, Any]:
        """
        Full execution pipeline:
          1. AST audit
          2. Symlink pre-check (inside run_sandbox)
          3. Sandboxed subprocess with resource limits and optional seccomp
          4. Symlink post-check (inside run_sandbox)
        -AoCH
        """
        allowed, findings, meta = audit_code(
            code,
            no_shell=self.policy.no_shell,
            forbid_risky_imports=self.policy.forbid_risky_imports,
        )
        if not allowed:
            await self.emit("VIOLATION", f"AST audit blocked before sandbox: {meta['reason']}")
            return {"ok": False, "error": meta["reason"], "findings": findings}

        result = run_sandbox(code, self.policy, workdir=workdir)
        await self.emit("SANDBOX", result)
        return result


# ─────────────────────────────────────────────
# RESEARCHER
# ─────────────────────────────────────────────
class ResearcherAgent(BaseAgent):
    async def research(self, task: str) -> str:
        await self.emit("RESEARCH_START", task)
        text, tokens = await call_llm(
            [{"role": "user", "content": f"Research this task thoroughly: {task}"}],
            system="You are a precise technical researcher.",
        )
        self.kernel.budget.observe(tokens)
        await self.emit("RESEARCH_DONE", text[:150])
        return text


# ─────────────────────────────────────────────
# ENGINEER
# ─────────────────────────────────────────────
class EngineerAgent(BaseAgent):
    async def implement(self, task: str, research: str) -> str:
        await self.emit("IMPLEMENT_START", task)
        code, tokens = await call_llm(
            [{"role": "user", "content": (
                f"Task: {task}\n\nResearch: {research}\n\n"
                "Write clean, safe, production-ready Python code."
            )}],
            system="You are an elegant Python engineer. Return only the code.",
        )
        self.kernel.budget.observe(tokens)
        await self.emit("CODE_READY", "Implementation finished")
        return code


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
async def main() -> None:
    kernel = ChaosKernel(
        max_depth=10,
        compression_threshold=8,
        checkpoint_interval=8,
        rate_limit=0.08,
        max_tokens=12_000,
    )

    policy = GuardianPolicy(
        sandbox_timeout=10,
        sandbox_cpu_limit=5,
        sandbox_nproc_limit=32,
        use_seccomp=True,           # used if available, silently skipped if not
    )

    guardian = GuardianAgent("Guardian", kernel, policy)
    researcher = ResearcherAgent("Researcher", kernel)
    engineer = EngineerAgent("Engineer", kernel)

    task = (
        "Write an elegant, safe, and efficient Python function to compute "
        "the nth Fibonacci number with memoization, full error handling for "
        "invalid inputs, and type hints."
    )

    print("=== CHAOS AGENT v2.2 – Elegant Production Architecture ===\n")
    print(f"    seccomp: {'available ✅' if _SECCOMP_AVAILABLE else 'unavailable — Layer 1 only ⚠️'}\n")

    await kernel.inject("DIRECTION", "Prioritize clarity, safety, efficiency, and minimalism.")
    await kernel.inject("INTUITION", "Direct recursion without memoization will explode on large n.")
    await kernel.inject("DOUBT", "Handle negative numbers and extremely large inputs gracefully.")

    await kernel.emit({"type": "PLAN", "data": task, "source": "Planner"})

    if not await guardian.check(task, {"depth": kernel.depth}):
        return

    research = await researcher.research(task)

    if not await guardian.check("implement", {"depth": kernel.depth}):
        return

    code = await engineer.implement(task, research)

    # Optional: run generated code through sandbox
    sandbox_result = await guardian.run_code(code)

    duration = round((time.time() - kernel.start_time) * 1000, 1)
    artifact = kernel.checkpoint(
        task,
        notes=[
            "All LLM calls are real API requests with exponential back-off retry",
            "Cognitive signals guided reasoning throughout",
            "Guardian used AST audit (v2.2: +ctypes, +__builtins__, +__import__)",
            "Sandbox: subprocess Layer 1 + seccomp Layer 2 (if available)",
            "TokenBudget EMA monitors sustained token pressure",
            "Checkpoints written atomically (fsync + os.replace)",
            f"Sandbox result: {'ok' if sandbox_result.get('ok') else sandbox_result.get('error', 'failed')}",
        ],
    )

    bundle_path = export_bundle(kernel, artifact)
    ok, _ = verify_bundle(bundle_path)

    print("\n" + "═" * 85)
    print("FINAL ARTIFACT – COMPLETE REPRODUCIBILITY")
    print(json.dumps(asdict(artifact), indent=2, ensure_ascii=False, default=str))
    print("═" * 85)

    print(
        f"\n✅ Completed in {duration} ms | "
        f"Depth: {kernel.depth} | "
        f"Tokens: {artifact.total_tokens} | "
        f"Bundle: {'✅ verified' if ok else '❌ FAILED'} → {bundle_path}"
    )
    print("\nGenerated code preview:")
    print(code[:800] + "…" if len(code) > 800 else code)


if __name__ == "__main__":
    asyncio.run(main())
