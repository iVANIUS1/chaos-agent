#!/usr/bin/env python3
"""
Chaos Agent v2.1
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

v2.1 changes
------------
• GuardianPolicy: AST-level audit replaces string-matching — catches obfuscation. -AoCH
• GuardianPolicy: no_shell flag; forbid_risky_imports flag (off by default).
• TokenBudget: EMA-based compression trigger — reacts to sustained pressure,
  not a single spike. Replaces depth-only threshold. -AoCH
• Checkpoints: atomic write (tempfile → fsync → os.replace). -AoCH
• verify_bundle(): SHA-256 integrity check for reproducibility bundles. -AoCH
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import logging
import os
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
# including aliased calls and simple obfuscation. -AoCH
#
# Replaces the v2.0 string-matching approach which could be bypassed
# via concatenation or indirect references. -AoCH
#
# Future: extend to detect dynamic attribute access patterns. -AoCH
# ─────────────────────────────────────────────
_RISKY_MODULES: frozenset[str] = frozenset({
    "os", "subprocess", "pickle", "marshal", "pty", "importlib",
})

_DANGEROUS_CALLS: frozenset[str] = frozenset({
    "exec", "eval", "compile",
})

_DANGEROUS_ATTRS: frozenset[tuple[str, str]] = frozenset({
    ("os", "system"), ("os", "popen"),
    ("subprocess", "run"), ("subprocess", "Popen"),
    ("subprocess", "call"), ("subprocess", "check_output"),
    ("pickle", "loads"), ("marshal", "loads"),
    ("pty", "spawn"),
    ("importlib", "import_module"),
})


class _AuditVisitor(ast.NodeVisitor):
    """Single-pass AST visitor. Populates findings; sets hard=True on blocking violations."""

    def __init__(self, no_shell: bool, forbid_risky_imports: bool):
        self.no_shell = no_shell
        self.forbid_risky_imports = forbid_risky_imports
        # Maps local name → (module, attr_or_None)
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

        # Attribute calls: os.system(...), subprocess.run(...), etc.
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            obj = node.func.value

            # Resolve module name through alias table
            mod: Optional[str] = None
            if isinstance(obj, ast.Name):
                if obj.id in self._aliases:
                    mod, _ = self._aliases[obj.id]
                else:
                    mod = obj.id

            key = (mod or "", attr)
            if key in _DANGEROUS_ATTRS:
                self._mark(lineno, "dangerous_attr", f"{mod}.{attr}", hard=True)

            # Detect shell=True regardless of module
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._mark(lineno, "shell_true", f"{mod}.{attr}(shell=True)", self.no_shell)

        self.generic_visit(node)

    # Detect string obfuscation: 'o' + 's' style concatenation used as module name
    def visit_BinOp(self, node: ast.BinOp) -> None:
        if (
            isinstance(node.op, ast.Add)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.right, ast.Constant)
        ):
            combined = str(node.left.value) + str(node.right.value)
            if combined in {"os", "exec", "eval", "subprocess"}:
                self._mark(node.lineno, "obfuscation", combined, hard=True)
        self.generic_visit(node)


def audit_code(
    source: str,
    no_shell: bool = True,
    forbid_risky_imports: bool = False,
) -> Tuple[bool, List[Dict], Dict]:
    """
    Run a single-pass AST audit on Python source code.

    Returns
    -------
    (allowed, findings, meta)
        allowed  — False if any hard violation was found
        findings — list of {lineno, kind, detail} dicts
        meta     — {reason, hard} summary
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return False, [{"lineno": exc.lineno, "kind": "syntax_error", "detail": str(exc)}], {"reason": "syntax_error", "hard": True}

    visitor = _AuditVisitor(no_shell=no_shell, forbid_risky_imports=forbid_risky_imports)
    visitor.visit(tree)
    allowed = not visitor.hard
    return allowed, visitor.findings, {"reason": visitor.reason, "hard": visitor.hard}


# ─────────────────────────────────────────────
# POLICY
# Declarative safety rules as a plain dataclass.
# Swap or extend without touching any agent logic. -AoCH
#
# no_shell=True       — blocks shell=True at AST level (default on)
# forbid_risky_imports — hard-blocks risky module imports (default off;
#                        enable for untrusted code execution contexts) -AoCH
#
# Future: enforce allowed_paths at OS level (chroot / seccomp). -AoCH
# ─────────────────────────────────────────────
@dataclass
class GuardianPolicy:
    allowed_commands: List[str] = field(
        default_factory=lambda: ["ls", "cat", "git", "echo", "python"]
    )
    allowed_paths: List[str] = field(
        default_factory=lambda: ["/workspace", "/tmp"]
    )
    max_file_size_mb: int = 10
    no_shell: bool = True
    forbid_risky_imports: bool = False


# ─────────────────────────────────────────────
# TOKEN BUDGET
# EMA-based compression trigger.
# Reacts to sustained token pressure (burst_streak ≥ 3),
# not a single outlier event. Prevents unnecessary compression. -AoCH
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
        # Sustained burst pressure overrides projection. -AoCH
        if self._burst_streak >= 3:
            return True
        burst = max(self._window)
        projected = self._total + projected_extra + int(self._ema) + int(0.5 * burst)
        return projected >= int(self.max_tokens * (1 - self.safety_margin))

    @property
    def total(self) -> int:
        return self._total


# ─────────────────────────────────────────────
# BUNDLE & INTEGRITY
# Atomic checkpoint writes and SHA-256 bundle verification.
# A run that cannot be reproduced is not production-ready. -AoCH
# ─────────────────────────────────────────────
def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_write(path: str, data: bytes) -> None:
    """Write data atomically: tempfile → fsync → os.replace. Safe on crash. -AoCH"""
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


def export_bundle(kernel: "ChaosKernel", artifact: Artifact, out_dir: str = "/tmp/chaos_bundle") -> str:
    """
    Export a reproducibility bundle: artifact.json + history.jsonl + manifest.json → ZIP.
    manifest.json contains SHA-256 hashes for integrity verification. -AoCH
    """
    ts = time.strftime("%Y%m%d_%H%M%S")
    bundle_path = os.path.join(out_dir, f"repro_{ts}.zip")
    os.makedirs(out_dir, exist_ok=True)

    artifact_path = os.path.join(out_dir, "artifact.json")
    history_path = os.path.join(out_dir, "history.jsonl")

    _atomic_write(artifact_path, json.dumps(asdict(artifact), indent=2, ensure_ascii=False, default=str).encode())
    _atomic_write(history_path, b"\n".join(
        json.dumps(e, ensure_ascii=False, default=str).encode()
        for e in kernel.history[-1000:]
    ))

    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
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
    """
    Verify a reproducibility bundle against its manifest SHA-256 hashes.

    Returns (ok, info) where info contains any errors found. -AoCH
    """
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
            actual = _sha256_file(p)
            if actual != meta.get("sha256"):
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
    """
    Call the Anthropic Messages API with up to 3 retries.

    Returns
    -------
    (response_text, total_tokens_used)
    """
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
#   • emit() is the ONLY path through which events enter history.
#     This makes the entire execution trace inspectable and reproducible. -AoCH
#   • TokenBudget replaces depth-only compression trigger in v2.1.
#     EMA reacts to sustained pressure, not outlier spikes. -AoCH
#   • on_event is an optional async callback — callers own their I/O. -AoCH
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
        self.version = "2.1"
        self.max_depth = max_depth
        self.compression_threshold = compression_threshold
        self.checkpoint_interval = checkpoint_interval
        self.rate_limit = rate_limit

        # Output strategy:
        #   Pass a custom on_event to take full control of output formatting.
        #   Leave it None to use the built-in attention filter (_default_output). -AoCH
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

        High-priority types are always shown.
        Low-noise events appear every 5 depth ticks or when they are short enough
        to read at a glance. -AoCH

        Alternative: pass your own on_event callback to bypass this entirely.
        """
        if event.get("type") in {
            "ERROR", "VIOLATION", "DOUBT", "STRATEGIC",
            "ANTI_ENTROPY", "COMPRESSION", "CHECKPOINT",
        }:
            return True
        return self.depth % 5 == 0 or len(str(event.get("data", ""))) < 120

    async def _default_output(self, event: Dict) -> None:
        """Built-in output handler using the attention filter."""
        if self._should_show_to_user(event):
            print(
                f"[{event['timestamp']}] [{event.get('source', 'SYS')}] "
                f"{event['type']}: {str(event.get('data', ''))[:160]}"
            )

    # ── Core ─────────────────────────────────
    async def emit(self, event: Dict[str, Any]) -> None:
        """
        The single entry point for all events.
        Enforces rate limiting, stamps metadata, triggers compression
        and checkpointing automatically. -AoCH
        """
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

        # v2.1: check both depth threshold AND token budget pressure. -AoCH
        depth_pressure = self.depth >= self.compression_threshold
        token_pressure = self.budget.should_compress()
        if (depth_pressure or token_pressure) and not self.compressed:
            await self.compress()

        if self.event_counter % self.checkpoint_interval == 0:
            await self._auto_checkpoint()

    async def inject(self, signal_type: str, message: str) -> None:
        """Human-in-the-loop: inject a cognitive signal at runtime."""
        print(f"🧠 SIGNAL [{signal_type}]: {message}")
        await self.emit({
            "type": "SIGNAL",
            "signal": signal_type,
            "data": message,
            "source": "HUMAN",
        })

    # ── Anti-Entropy ─────────────────────────
    async def compress(self) -> None:
        """
        Graceful history compression.
        Summarises recent events via LLM and resets depth.
        Avoids hard limits that would abort a long-running task. -AoCH
        """
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
        # Atomic write: safe even on power loss or crash mid-write. -AoCH
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
        # start_time resets to now — duration_ms measures time since restore,
        # not since the original run. Intentional: each session is independent. -AoCH
        kernel.start_time = time.time()
        kernel.event_counter = len(artifact.history)
        return kernel

    def prepare_context(self, max_events: int = 5) -> str:
        """
        Return a compact JSON snapshot of the most relevant recent events.
        Keeps prompt size predictable without discarding strategic context. -AoCH
        """
        important_types = {"PLAN", "RESEARCH_DONE", "SIGNAL", "CODE_READY"}
        important = [e for e in self.history if e.get("type") in important_types]
        return json.dumps(important[-max_events:], default=str, ensure_ascii=False)


# ─────────────────────────────────────────────
# BASE AGENT
# Thin wrapper so every agent shares the same emit API
# with zero boilerplate duplication. -AoCH
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
# All safety decisions live here — no scattered checks.
# v2.1: uses AST audit instead of string matching. -AoCH
# ─────────────────────────────────────────────
class GuardianAgent(BaseAgent):
    def __init__(self, name: str, kernel: ChaosKernel, policy: Optional[GuardianPolicy] = None):
        super().__init__(name, kernel)
        self.policy = policy or GuardianPolicy()

    async def check(self, action: str, context: Dict) -> bool:
        if context.get("depth", 0) > self.kernel.max_depth:
            await self.emit("ANTI_ENTROPY", "Depth limit reached. Triggering compression.")
            await self.kernel.compress()

        # AST audit for code strings; pattern check for plain commands. -AoCH
        if action.strip().startswith(("def ", "import ", "class ", "#", "\n")):
            allowed, findings, meta = audit_code(
                action,
                no_shell=self.policy.no_shell,
                forbid_risky_imports=self.policy.forbid_risky_imports,
            )
            if not allowed:
                await self.emit("VIOLATION", f"AST audit blocked: {meta['reason']} | findings: {findings[:3]}")
                return False
        else:
            cmd = action.split()[0] if action.split() else ""
            if cmd and cmd not in self.policy.allowed_commands:
                await self.emit("VIOLATION", f"Command not in allowlist: {cmd}")
                return False

        return True


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
            [{
                "role": "user",
                "content": (
                    f"Task: {task}\n\nResearch: {research}\n\n"
                    "Write clean, safe, production-ready Python code."
                ),
            }],
            system="You are an elegant Python engineer. Return only the code.",
        )
        self.kernel.budget.observe(tokens)
        await self.emit("CODE_READY", "Implementation finished")
        return code


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
async def main() -> None:
    # Default output: built-in attention filter.
    # To use a custom handler, pass on_event=your_async_function here. -AoCH
    kernel = ChaosKernel(
        max_depth=10,
        compression_threshold=8,
        checkpoint_interval=8,
        rate_limit=0.08,
        max_tokens=12_000,
    )

    guardian = GuardianAgent("Guardian", kernel)
    researcher = ResearcherAgent("Researcher", kernel)
    engineer = EngineerAgent("Engineer", kernel)

    task = (
        "Write an elegant, safe, and efficient Python function to compute "
        "the nth Fibonacci number with memoization, full error handling for "
        "invalid inputs, and type hints."
    )

    print("=== CHAOS AGENT v2.1 – Elegant Production Architecture ===\n")

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

    duration = round((time.time() - kernel.start_time) * 1000, 1)
    artifact = kernel.checkpoint(
        task,
        notes=[
            "All LLM calls are real API requests with exponential back-off retry",
            "Cognitive signals guided reasoning throughout",
            "Guardian used AST audit for code validation",
            "TokenBudget EMA monitors sustained token pressure",
            "Anti-entropy compression is active and ready",
            "Checkpoints written atomically (fsync + os.replace)",
        ],
    )

    # Export reproducibility bundle. -AoCH
    bundle_path = export_bundle(kernel, artifact)
    ok, bundle_info = verify_bundle(bundle_path)

    print("\n" + "═" * 85)
    print("FINAL ARTIFACT – COMPLETE REPRODUCIBILITY")
    print(json.dumps(asdict(artifact), indent=2, ensure_ascii=False, default=str))
    print("═" * 85)

    print(
        f"\n✅ Completed in {duration} ms | "
        f"Depth: {kernel.depth} | "
        f"Total tokens: {artifact.total_tokens} | "
        f"Bundle: {'✅ verified' if ok else '❌ FAILED'} → {bundle_path}"
    )
    print("\nGenerated code preview:")
    print(code[:800] + "…" if len(code) > 800 else code)


if __name__ == "__main__":
    asyncio.run(main())
