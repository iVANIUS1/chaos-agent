# CHANGELOG — Chaos Agent

Author: Ivan Putna (Architect of Chaos — AoCH)
License: MIT

All changes are documented with rationale. Finální slovo má vždy Ivan.

---

## v2.2 — 2026-04-01

### Philosophy
Stejná filozofie. v2.2 přidává OS-level sandbox jako druhou linii obrany,
rozšiřuje AST audit o nové vektory a zavádí kompletní CI/CD pipeline.

### Added

**Sandbox — dvouvrstvá izolace (`run_sandbox`)**
- Layer 1 (vždy aktivní): subprocess s `env_whitelist`, `timeout`,
  `RLIMIT_CPU`, `RLIMIT_NPROC` via `preexec_fn`. Přenositelné, bez root.
- Layer 2 (volitelná): seccomp-bpf syscall allowlist. Detekována za běhu;
  pokud není dostupná (kontejner, macOS), tiše přeskočena — Layer 1 zůstává.
- `shell=False` hardcoded v sandbox subprocess — bez výjimky.

**Symlink escape detection (`_check_symlinks`)**
- Pre-check před spuštěním: walk workdir, kontrola realpath vůči `allowed_paths`.
- Post-check po spuštění: detekuje symlinky vytvořené za běhu kódu.
- Obojí integrováno v `run_sandbox()`. -AoCH

**`GuardianAgent.run_code()`**
- Kompletní pipeline: AST audit → symlink pre-check → sandbox → symlink post-check.
- Jeden call, jedna odpověď. -AoCH

**AST audit rozšíření**
- Přidány: `ctypes.CDLL`, `ctypes.cdll`, `os.execv`, `os.execve`,
  `subprocess.check_call`, `pickle.load`, `marshal.load`.
- Přidán `__import__(...)` jako hard-ban (dříve chyběl jako direct call).
- Přidán `visit_Attribute` pro detekci `__builtins__`, `__dict__`,
  `__globals__`, `__code__` — zabraňuje bypass přes dunder přístup.
- Obfuskace rozšířena o `compile` a `__import__` jako cíle concat detekce.

**`forbid_risky_imports` — dokumentovaný záměrný design**
- OFF by default. Rationale: blokujeme nebezpečná VOLÁNÍ, ne importy.
  `import os` je legitimní; `os.system(...)` není.
- Zdokumentováno v module docstringu, policy.json (`_comment` keys),
  README a LaTeX dokumentaci. Je to feature, ne bug. -AoCH

**`tools/lint_agent.py`**
- CLI linter nad `audit_code()`. Exit code 0/1/2.
- `--json` flag pro strojové zpracování (CI integrace).

**`tools/policy_loader.py`**
- Načítá `policy.json` do `GuardianPolicy`. Jeden zdroj pravdy.
- Graceful fallback na defaults při chybějícím nebo nevalidním souboru.

**`policy.json`**
- Deklarativní policy s `_comment` klíči vysvětlujícími každé rozhodnutí.
- Připravena pro verziování v repozitáři.

**`tests/test_agent.py`**
- 21 unit testů pokrývající: AST audit (14 případů), sandbox utils (4),
  atomic write (2), TokenBudget (3).

**`.github/workflows/ci.yml`**
- Tři joby: AST Audit, Unit Tests, Bundle Integrity.
- Bundle verify job závisí na úspěchu předchozích dvou.

### Changed
- `GuardianAgent.__init__`: přijímá `policy` jako parametr (dříve hardcoded).
- `_should_show_to_user`: přidán `SANDBOX` jako high-priority event typ.
- `GuardianAgent.check()`: routing rozšířen o `async ` prefix detekci.
- Verze bumped na `"2.2"`.

### Known limitations (otevřené body)
- seccomp syscall allowlist je konzervativní — může blokovat legitimní
  systémová volání na méně běžných platformách. Laditelné rozšířením listu.
- `RLIMIT_NPROC` může selhat v některých kontejnerech bez user namespaces —
  silently ignorováno, Layer 1 timeout zůstává aktivní.
- MDA repo integrace (pre-commit hook, GPG bundle signing) — Stage 3 roadmap.

---

## v2.1 — 2026-04-01

### Philosophy
Stejná filozofie jako v2.0: méně kódu, více inteligence. v2.1 přidává produkční
odolnost bez přidání závislostí nebo zbytečných vrstev.

### Added

**AST-level audit (`audit_code` + `_AuditVisitor`)**
- Nahrazuje string-matching z v2.0, který šel obejít concatenací nebo aliasem.
- Jediný průchod AST stromem detekuje: `exec`, `eval`, `compile`, `os.system`,
  `os.popen`, `subprocess.*`, `pickle.loads`, `pty.spawn`, `importlib.import_module`,
  `shell=True` v jakémkoliv volání, obfuskaci typu `'o'+'s'`.
- Benigní použití (`getattr(obj, "join")`) projde — žádné false positives.

**`GuardianPolicy` rozšíření**
- `no_shell: bool = True` — blokuje `shell=True` na úrovni AST (default zapnuto).
- `forbid_risky_imports: bool = False` — volitelný tvrdý ban na rizikové importy;
  default vypnuto, aby neblokovalo legitimní utility.

**`TokenBudget` s EMA**
- Nahrazuje depth-only threshold pro spouštění komprese.
- EMA (α=0.35) sleduje průměrný token usage přes klouzavé okno 32 volání.
- Komprese se spustí při `burst_streak ≥ 3` (tři po sobě jdoucí spiky nad 1.5× EMA)
  nebo při projekci přesahu `max_tokens × (1 − safety_margin)`.
- Reaguje na sustained pressure, ne na jednorázový outlier.

**Atomické checkpointy (`_atomic_write`)**
- `tempfile.mkstemp → fh.flush() → os.fsync() → os.replace()`.
- Checkpoint je vždy validní JSON i po pádu uprostřed zápisu.
- Nahrazuje přímý `open(..., "w")` z v2.0.

**Reproducibility bundle (`export_bundle` + `verify_bundle`)**
- `export_bundle()`: zapíše `artifact.json` + `history.jsonl` atomicky,
  vytvoří `manifest.json` se SHA-256 hashi, zabalí do ZIP.
- `verify_bundle()`: ověří integritu bundle vůči manifestu.
- Run, který nelze reprodukovat, není produkční. -AoCH

### Changed

- `GuardianAgent.check()`: pro code strings používá `audit_code()` místo pattern match;
  pro plain commands kontroluje allowlist jako dřív.
- `ChaosKernel.emit()`: compression trigger kombinuje depth threshold AND token budget.
- `ChaosKernel._auto_checkpoint()`: používá `_atomic_write` místo přímého zápisu.
- `ResearcherAgent.research()` a `EngineerAgent.implement()`: volají `budget.observe(tokens)`
  aby TokenBudget měl aktuální data.
- Verze bumped na `"2.1"`.

### Known limitations (otevřené body)

- `allowed_paths` je deklarováno v policy ale není vynuceno na OS úrovni.
  Future: `chroot` / `seccomp` integrace.
- `forbid_risky_imports=False` default znamená, že `import os` projde;
  blokace je na úrovni volání (AST), ne importu.
- `setrlimit` (CPU/NPROC sandbox limity) není implementováno — záměrně;
  přidáme v dalším RC pokud bude potřeba.

---

## v2.0 — 2026-03-31

### Philosophy
Chaos Agent vznikl jako demonstrace alternativního přístupu k AI agent architektuře.
Méně kódu. Více inteligence. Jedna pravda. Explicitní kognitivní vrstva.
Graceful degradation místo hard limitů.

### Core design decisions

**Single `emit()` gating point**
- Všechny eventy tečou jedním místem. Celý execution trace je inspectable
  a reprodukovatelný bez debuggování více call sites.

**Explicitní kognitivní signály**
- `DOUBT`, `INTUITION`, `DIRECTION` jsou first-class eventy.
- Lze injektovat za běhu (`kernel.inject()`), ovlivňují reasoning bez
  pollutování hlavní message history.

**Graceful anti-entropy**
- `ChaosKernel.compress()` sumarizuje historii přes LLM a resetuje depth.
- `self.compressed` flag zabraňuje re-entrantní kompresi.
- Net depth change per cycle: −5 + 2 (dva interní emit) = −3. Matematicky stabilní.

**Deklarativní policy jako dataclass**
- `GuardianPolicy` jako plain dataclass — swap nebo extend bez zásahu do agent logiky.

**Pluggable output strategy**
- `on_event` callback — default `_default_output` s attention filtrem,
  nebo vlastní async handler.
- `_should_show_to_user()` jako metoda na kernelu; `console_output` jako příklad
  custom handleru v `main()`.

**`prepare_context()`**
- Kompaktní JSON snapshot nejrelevantnějších eventů pro LLM prompt.
- Drží prompt size předvídatelný bez ztráty strategického kontextu.

### Bugs fixed during v2.0 development

- Odstraněn nepoužitý `tenacity` import.
- `kernel_signals` parametr odstraněn ze signatur kde se nepoužíval.
- `_should_show_to_user` přidána jako metoda kernelu (v původním draftu chyběla).
- `on_event` defaultuje na `_default_output` místo `None`.
- Přidána validace formátu API klíče při startu (`sk-ant-` prefix).
- `load_checkpoint`: komentář dokumentující záměrný reset `start_time`.

---

## Roadmap (nezávazný)

- [ ] Runtime enforcement `allowed_paths` (chroot / seccomp)
- [ ] AST rozšíření: detekce dynamického attribute access
- [ ] `forbid_risky_imports=True` mode s whitelistou výjimek
- [ ] Predictive token budgeting (pre-empt místo react)
- [ ] Multi-agent orchestration přes shared kernel
- [ ] CLI wrapper pro `audit_code` (standalone linter)
