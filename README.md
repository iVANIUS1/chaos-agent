# Chaos Agent

> **Elegant · Minimalist · Production-Ready AI Coding Agent**

**v2.1** — single file, zero unnecessary dependencies, MIT license.

---

## Philosophy

> *Less code. More intelligence.*

One single source of truth. An explicit cognitive layer. Graceful degradation
instead of hard limits.

This project demonstrates a different approach to AI agent architecture — one
that prioritises clarity, debuggability, and systemic thinking. Every design
decision is documented in the code and in [`CHANGELOG.md`](CHANGELOG.md).

---

## What's inside

| File | Purpose |
|---|---|
| `chaos_agent_v2_1.py` | Main agent — single file, production-ready |
| `chaos_agent_v2.py` | v2.0 reference — original architecture |
| `CHANGELOG.md` | Full history with rationale for every decision |
| `chaos_agent_v2_doc.tex` | LaTeX technical documentation (Overleaf / XeLaTeX) |

---

## Key Design Decisions

### 1. Single `emit()` gating point
All events flow through one function. The entire execution trace is inspectable,
reproducible, and serialised into a complete `Artifact` at the end of every run.

### 2. Explicit cognitive signals
`DOUBT`, `INTUITION`, and `DIRECTION` signals are first-class events, injectable
at runtime — by the system or by a human operator.

```python
await kernel.inject("DOUBT", "Direct recursion without memoization will explode on large n.")
await kernel.inject("DIRECTION", "Prioritise clarity, safety, and minimalism.")
```

### 3. Graceful anti-entropy
Instead of hard depth limits that abort running tasks, the kernel detects
cognitive overload and compresses history via a summarisation call. Depth resets
gracefully; execution continues.

### 4. AST-level safety audit (v2.1)
`audit_code()` runs a single-pass AST visitor that catches dangerous constructs —
including aliased calls and string obfuscation — that string-matching cannot detect.

```python
allowed, findings, meta = audit_code(source, no_shell=True)
```

### 5. EMA-based token budget (v2.1)
`TokenBudget` uses an exponential moving average to track token pressure.
Compression fires on sustained pressure (`burst_streak ≥ 3`), not a single spike.

### 6. Atomic checkpoints + reproducibility bundle (v2.1)
Every checkpoint is written atomically (`tempfile → fsync → os.replace`).
`export_bundle()` produces a ZIP with SHA-256 manifest; `verify_bundle()` confirms integrity.

### 7. Pluggable output strategy
Pass a custom `on_event` callback to take full control of output. Leave it empty
to use the built-in attention filter.

```python
# Built-in filter (default)
kernel = ChaosKernel()

# Custom handler — full control
kernel = ChaosKernel(on_event=my_async_handler)
```

---

## Architecture

```
ChaosKernel              ← single source of truth
    │
    ├── emit()            ← sole entry point for every event
    ├── inject()          ← human-in-the-loop cognitive signals
    ├── compress()        ← graceful anti-entropy
    ├── checkpoint()      ← full reproducibility snapshot
    └── TokenBudget       ← EMA-based compression trigger

GuardianAgent            ← centralised policy enforcement (AST audit)
ResearcherAgent          ← technical research phase
EngineerAgent            ← code generation phase
BaseAgent                ← shared zero-boilerplate API

audit_code()             ← standalone AST safety auditor
export_bundle()          ← SHA-256 reproducibility bundle
verify_bundle()          ← integrity verification
```

---

## Quick Start

```bash
git clone https://github.com/iVANIUS1/chaos-agent
cd chaos-agent
pip install httpx
export ANTHROPIC_API_KEY=sk-ant-...
python chaos_agent_v2_1.py
```

---

## Comparison

| Concern | Typical approach | Chaos Agent |
|---|---|---|
| Event routing | Scattered across components | Single `emit()` |
| Safety checks | Duplicated per agent | Central `GuardianPolicy` + AST audit |
| Depth management | Hard limit / exception | Graceful compression |
| Token management | Unmonitored or hard cut | EMA `TokenBudget` |
| Cognitive layer | Purely reactive | Explicit signal injection |
| Output control | Hard-coded logging | Pluggable async callback |
| Reproducibility | Partial | Full `Artifact` + verified bundle |
| Context size | Unfiltered | `prepare_context()` selector |

---

## Known Limitations

- `allowed_paths` is declared in policy but not enforced at OS level.
  Future: `chroot` / `seccomp` integration.
- `forbid_risky_imports` is off by default to avoid blocking legitimate utilities.
- Token budget is reactive. Future: predictive pre-emption.

See [`CHANGELOG.md`](CHANGELOG.md) for full history and roadmap.

---

## License

MIT — free to use, modify, and build upon.

---

## Author

**Ivan Putna** · Architect of Chaos

[LinkedIn](https://www.linkedin.com/in/ivan-putna-3313a3381) · [GitHub](https://github.com/iVANIUS1)
