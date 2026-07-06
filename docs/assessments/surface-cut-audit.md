# Tool/Module Catalog Surface-Cut Audit

**Date:** 2026-07-03 · **Branch:** `design-sync/kuzushi-tui-kit` · **Scope:** every
tool registered by `ModuleRegistry::with_v2_builtins()`.

This is a **kill-list report**. Nothing is deleted here. It classifies each
registered tool **KEEP / FOLD-INTO / CUT** and, for every CUT/FOLD, lists the full
removal footprint (descriptor, executor, options, tests, docs, TUI view/verb) and
whether the cut breaks the public module/manifest contract (→ needs a
`RELEASING.md` migration note per `CLAUDE.md`).

---

## 0. Headline — the "36% hidden/unreachable" number is mostly wrong

Prior audits reported "~36% of tools are hidden or unreachable." Enumerated
against the live registry, that framing does not survive contact with the code:

- **107 tool descriptors** across **58 modules** (54 visible + 4 always-deferred).
- **Strictly invisible on this machine: 7 descriptors** (6.5%), not 36%.
- **Of those 7, four are reachable through the phase-walker journey** and the
  `sast:scan` DAG (`carlini-threat-hunt:run`, `uaf-hunt:hunt`,
  `taint-iris-next:hunt`) — hidden ≠ unreachable.
- A further **14 descriptors are conditionally hidden** (`prompt-armor:*`,
  `shinsa:*`, `tob:*`, `vuln-scout:audit`) — they **self-hide when their backing
  npm plugin is absent** and self-surface when present. That is correct gating,
  not dead surface. (They read as visible in this repo only because all four
  plugins are pnpm-symlinked into `node_modules`.)

So the genuinely **cuttable** surface is small. The genuinely **redundant**
surface (fold to reduce catalog width / duplicated code) is larger but almost
all of it touches the published contract and needs a migration note.

**One clean CUT** (dead diagnostic, no journey, hidden, undocumented):
`smoke:next-step`. Everything else on the kill-list is a **FOLD** (redundant with
a canonical tool) or a **product-decision quarantine** (real capability the
control-room vision no longer centers — see §6, cross-referenced to the
product-vision audit).

The demo/fixture tools some readers expect here (`demo:run`, `demo:legacy`,
`deferred-demo:run`, `test:demo`, `test:empty`, `sdk:sum`, `dyn:echo`,
`dynrt:ask`) are **not shipped surface** — they exist only inside
`modules/*/tests.rs` and never enter `with_v2_builtins()`. They are out of scope
for a catalog cut.

---

## 1. Summary — kill-list ranked by removable LOC

Removable LOC counts the executor/capability code that becomes deletable, not the
descriptor (~15–40 LOC each). "Gate" flags what blocks a clean removal.

| # | Tool(s) | Verdict | Removable LOC | Subsumed by | Gate / risk |
|---|---------|---------|--------------:|-------------|-------------|
| 1 | `deep-audit:run` + `classifier-gate:score` | FOLD-INTO(`triage:run`) — owner decision | ~2,100 | `triage:run` | Real, tested cheap-gate→deep-audit triage subsystem; parallel to `triage:run`, on no journey. Decide: promote as `triage` mode or retire. |
| 2 | `full-mode:hunt` | FOLD-INTO(`agentic-sast:scan`) — owner decision | ~1,400 | `agentic-sast:scan` | Chunked whole-repo LLM scan; overlaps agentic SAST. Real + tested; alternative strategy, not dead. |
| 3 | `taint-iris:hunt` (v1) | FOLD-INTO(`taint-iris-next:hunt`) | ~1,300 | `taint-iris-next:hunt` (v2) | **Public contract** (api-compatibility.md canonical + `dag-ids.ts`). v2 is the phase-walker path; v1 still a `sast:scan` stage → migration note + keep alias. |
| 4 | `threat-leads:build` / `threat-leads:read` | FOLD-INTO(`x-ray:run`/`threat-model:build`) — owner decision | ~920 | `x-ray:run` | Reads x-ray artifacts to synthesize "leads." Undiscoverable-by-verb, 0 literal tests, no per-verb docs. Low adoption. |
| 5 | `verify:exploit` | FOLD-INTO(`verify:finding`) — owner decision | shares 4,497-LOC `verification/` infra | `verify:finding` | Empirical sandboxed verify, **Rust-only** (other langs return `language_unsupported_yet`), 0 literal tests, PORT_PLAN-only docs. Keep as a `verify` mode or quarantine. |
| 6 | `smoke:next-step` | **CUT** | ~313 | — | **Clean cut.** Runtime smoke test ("drive a 2-step tool-loop with an `echo` tool"); hidden, no journey, no docs, no product purpose. |
| 7 | `randori:threat-model` | FOLD-INTO(`threat-model:build`) | ~120 | `threat-model:build` (PASTA) | Overlaps the PASTA methodology already in `threat-model:build`. `randori:pasta` (the attack sim) stays. |
| 8 | `android-apk:{manifest-scan, code-scan, fileprovider-scan, native-libs, network-security-config, hybrid-detect, sast-handoff, prepare, check-env}` (9) | FOLD-INTO(`android-apk:scan`) — surface only | ~0 code (−9 catalog rows) | `android-apk:scan` (umbrella) | `android-apk:scan` already orchestrates every granular stage. Folding is a **discoverability** cut (hide the 9, keep the umbrella); the bug-hunting playbook drives them manually → doc update, code stays. |
| 9 | `shinsa:quick-check`, `shinsa:nist-quick-check` | FOLD-INTO(`shinsa:scan`/`shinsa:nist-scan` via `depth=quick`) | ~small (descriptor) | `shinsa:scan` | One executor already backs all four names by string; collapse quick↔full to a `depth` option. **Public contract** (rust-ddd-target preserves shinsa IDs) + plugin-gated → migration note. |
| 10 | `offense-review:threat-hunt` ⇄ `carlini-threat-hunt:run` | DEDUP (pick one canonical) | ~0 | each other | **Exact alias** — both arms call `run_carlini_threat_hunt` with no name branching. Keep one name, alias the other. Both are on the public contract (api-compatibility.md) → migration note if a name is dropped. |
| 11 | `context-lite:index` ⇄ `context:build` | DEDUP (DAG-internal alias) | ~0 | `context:build` | Exact alias; `context-lite` is a hidden 0-descriptor module. Already effectively folded; no catalog impact. |

**Product-decision quarantine candidates (not surface-dead — see §6):** `pwn:*`
(2,730), `uaf-hunt:hunt` (2,402), `exploit-chain:scan` (1,060),
`vendor-assessment:*` (884), `chrome-rce:*` (592), `offense:chain` (3,048).
These are visible-and-reachable **real** capabilities; whether to keep them is a
product-vision call, not a dead-code call.

---

## 2. Method & ground truth

**Enumeration.** Built the registry via `ModuleRegistry::with_v2_builtins()` and
dumped every `ToolDescriptor` with its `hidden`, `headless`, `runtime_requirement`,
owning module, and module-hidden flag. (Descriptor builders live in
`crates/kuzushi-core/src/modules/descriptor/metadata.rs`: `tool`,
`tool_with_options`, `hidden_tool_with_options`; modules via `builtin_module`
vs `hidden_module`/`.deferred()`.)

**Visibility rule** (`with_v2_builtins/lookup.rs::is_tool_visible`): a tool is
listed in `catalog:tools` / `/use` / the LLM tool list / `module-recommender`
iff `!tool.hidden` **and** its owning module is not hidden. A hidden tool is still
**executable by exact name** — `resolve_tool` = `self.tools.get(name)` is not
visibility-filtered, so `kuzushi run <tool>` and shell `run <tool>` reach hidden
tools if you already know the name; they are just undiscoverable.

**Reachability surfaces checked.** (1) dedicated shell verb in
`crates/kuzushi-tui/src/commands/shell_command_specs/`; (2) dedicated CLI
subcommand in `crates/kuzushi-cli/src/command.rs`; (3) `sast:scan` DAG stage in
`modules/application/sast_scan/`; (4) phase-walker/journey in
`app/onboarding/task_id.rs` + `ui_view_models/journey.rs`. Plus the two generic
paths (`run <tool>` / `use <module>`) that reach any **visible** tool.

**Phase-walker tool set (authoritative, `PlanningTaskId::tool_name`):**
`context:build`, `entry-points:extract`, `x-ray:run`, `threat-model:build`,
`cpg:build`, `codeql:create-db`, `threat-intel:discover`, `pwn:reverse`,
`secret-scan:scan`, `semgrep:scan`, `codeql:scan`, `agentic-sast:scan`,
`taint-iris-next:hunt`, `carlini-threat-hunt:run`, `systems-hunt:systems-hunt`,
`uaf-hunt:hunt`, `triage:run`, `verify:finding`, `patch:finding`, `report:build`.

**`sast:scan` DAG stages:** `agentic-sast:scan`, `offense-review:threat-hunt`,
`taint-iris:hunt`, `taint-iris-next:hunt`, `systems-hunt:systems-hunt`,
`triage:run`, `verify:finding`, `patch:finding`, plus scanner tasks
(semgrep/codeql/secret-scan/dep-hygiene/iac-scan/…) via agentic-sast task
selection.

**Docs coverage** was mapped by a dedicated pass over `docs/`, `schemas/`, and the
TS SDK (`src/modules/`). **Test coverage** counts test files containing each tool's
name literal; "0" means the *tool dispatch* isn't covered even where the
underlying capability function is (noted where relevant).

Legend for the inventory table — **Vis:** `✓`=visible · `H`=tool hidden ·
`M`=module deferred/hidden · `G`=plugin-gated (hidden until plugin installed).
**Reach:** `PW`=phase walker · `DAG`=sast:scan stage · `CLI`=dedicated CLI verb ·
`V`=dedicated shell verb · `run`=generic run/use only · `alias`. **Docs:**
`mod`=modules.md · `pub`=public contract · `doc`=other docs · `—`=none.

---

## 3. Full inventory & verdict (107 tools)

### Core scan / findings pipeline — KEEP
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `sast:scan` | ✓ | CLI(`scan`),V,run | pub | 18 | KEEP — the umbrella; entry point for scan mode. |
| `agentic-sast:scan` | ✓ | PW,DAG,run | pub,mod | 7 | KEEP — canonical LLM detector pass. |
| `semgrep:scan` | ✓ | PW,DAG,run | pub,mod,doc | 15 | KEEP — distinct engine. |
| `codeql:scan` | ✓ | PW,DAG,run | pub,doc | 10 | KEEP — distinct engine. |
| `codeql:create-db` | ✓ | PW,run | — | 0 | KEEP — CodeQL DB build prerequisite (phase-walker `BuildCodeQlDatabase`). Add a test + doc. |
| `secret-scan:scan` | ✓ | PW,DAG,run | pub,doc | 7 | KEEP — distinct engine. |
| `dep-hygiene:check` | ✓ | DAG,run | — | 8 | KEEP — cross-ecosystem dep hygiene. Undocumented → add doc. |
| `cargo-audit:scan` | ✓ | run | — | 6 | KEEP — Rust advisories (distinct ecosystem). |
| `govulncheck:scan` | ✓ | run | — | 3 | KEEP — Go advisories (distinct ecosystem). |
| `sbom-scan:scan` | ✓ | run | — | 4 | KEEP — SBOM emission. Undocumented → add doc. |
| `license-scan:scan` | ✓ | run | — | 4 | KEEP — license posture. Undocumented → add doc. |
| `iac-scan:scan` | ✓ | run | doc | 6 | KEEP — IaC scanning. |
| `exploit-chain:scan` | ✓ | run | doc | 4 | KEEP (surface); see §6 — attack-tree viz page's sole feed, prototype-grade. |
| `triage:run` | ✓ | PW,DAG,run | pub,mod | 14 | KEEP — canonical triage. |
| `verify:finding` | ✓ | PW,DAG,run | pub,mod | 7 | KEEP — canonical verify. |
| `verify:exploit` | ✓ | run | — | 0 | **FOLD/decide → `verify:finding`** — Rust-only empirical verify, untested dispatch, PORT_PLAN-only. |
| `patch:finding` | ✓ | PW,DAG,run | pub | 5 | KEEP — canonical patch. |
| `report:build` | ✓ | PW,run | doc | 5 | KEEP — report builder. |
| `findings:list` | ✓ | CLI(`findings`),V,run | pub | 6 | KEEP. |
| `classifier-gate:score` | ✓ | run | — | 2(catalog) | **FOLD/decide → `triage:run`** — cheap-classifier gate for the deep-audit path; on no journey. |
| `deep-audit:run` | ✓ | run(+TUI worker) | doc | 2 | **FOLD/decide → `triage:run`** — single-finding deep triage parallel to `triage:run`. |
| `full-mode:hunt` | ✓ | run(+TUI worker) | doc | 1 | **FOLD/decide → `agentic-sast:scan`** — chunked whole-repo LLM scan. |

### Context / map / threat-model — KEEP (one fold)
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `context:build` | ✓ | PW,DAG,V,run | pub | 14 | KEEP — everything's `depends_on`. |
| `context-lite:index` | M | alias,DAG | — | — | DEDUP alias of `context:build` (hidden 0-descriptor module). |
| `entry-points:extract` | ✓ | PW,run | — | 0 | KEEP — phase-walker `MapEntryPoints`. Add test/doc. |
| `x-ray:run` | ✓ | PW,run | pub | 4 | KEEP — attack-surface map. |
| `x-ray:read` | ✓ | run | pub | 3 | KEEP — artifact reader (distinct from `:run`). |
| `threat-model:build` | ✓ | PW,V(`threats`),run | pub,mod | 11 | KEEP — STRIDE/PASTA doc. |
| `threat-model:read` | ✓ | V(`threats`),run | pub | 3 | KEEP — artifact reader. |
| `threat-model:methodologies` | ✓ | V(`threats`),run | pub | 2 | KEEP — small metadata lister. |
| `cpg:build` | ✓ | PW,run | doc | 2 | KEEP — CPG build for taint backends. |
| `threat-leads:build` | ✓ | run | — | 0 | **FOLD/decide → `x-ray:run`** — undiscoverable, untested, no per-verb docs. |
| `threat-leads:read` | ✓ | run | — | 0 | **FOLD/decide → `x-ray:run`**. |
| `threat-intel:discover` | ✓ | PW,run | — | 0 | KEEP — phase-walker `ThreatIntelCves`. Untested/undoc → add both. |
| `threat-intel:harvest` | ✓ | run | doc | 1 | KEEP. |
| `threat-intel:apply` | ✓ | run | — | 1 | KEEP. |
| `threat-intel:list` | ✓ | run | — | 1 | KEEP. |
| `randori:pasta` | ✓ | run | doc | 2 | KEEP — attack simulation. |
| `randori:threat-model` | ✓ | run | doc | 1 | **FOLD → `threat-model:build`** (PASTA overlap). |

### Taint family — KEEP v2, fold v1
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `taint-iris-next:hunt` | H | PW,DAG,run(exact) | pub,mod | 6 | KEEP — v2, the A4 oracle path. Hidden but journey-reachable. |
| `taint-iris-next:dataflow-plan` | ✓ | run | pub | 4 | KEEP — agent-facing planning helper. |
| `taint-iris-next:source-sink-trace` | ✓ | run | pub | 3 | KEEP — agent-facing tracer. |
| `taint-iris-next:finding-review` | ✓ | run | pub | 4 | KEEP — agent-facing reviewer. |
| `taint-iris-next:catalog` | H | DAG-internal | pub | 2(catalog) | KEEP — internal CWE-catalog prereq (hidden by design). |
| `taint-iris-next:codeql-db` | H | DAG-internal | pub | 1(catalog) | KEEP — internal DB prereq (hidden by design). |
| `taint-iris:hunt` | ✓ | DAG,run | pub,mod | 4 | **FOLD → `taint-iris-next:hunt`** — v1 superseded by v2 (~1,300 LOC). Public contract → migration note. |

### Offense / hunt (deferred) — KEEP as gated, quarantine is a product call (§6)
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `carlini-threat-hunt:run` | M | PW,DAG(alias),run(exact) | pub,mod | 8 | KEEP — phase-walker `HuntThreatModel`; exact alias of `offense-review:threat-hunt`. |
| `offense-review:threat-hunt` | ✓ | DAG,run | pub | 5 | KEEP — visible canonical name; DEDUP pair with carlini (pick one). |
| `systems-hunt:systems-hunt` | M | PW,DAG | pub(dag-id) | — | KEEP — composed by sast umbrella; DAG executor (not a catalog descriptor). |
| `uaf-hunt:hunt` | M | PW,DAG,run(exact) | doc | 3 | KEEP (gated) — phase-walker `HuntUseAfterFree`; §6 quarantine candidate. |
| `offense:chain` | M | run(exact)+TUI worker | — | 2 | KEEP (gated) — real authorized-attack-chain engine w/ scope guard; §6 quarantine candidate. Undiscoverable + undocumented. |
| `smoke:next-step` | M | run(exact) | — | 1(catalog) | **CUT** — runtime smoke test, no product purpose. |

### PWN suite — KEEP (flag untested sub-tools); §6 quarantine is a product call
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `pwn:reverse` | ✓ | PW,run | doc | 2 | KEEP — phase-walker `ReverseEngineerBinary`. |
| `pwn:auto-solve` | ✓ | run | doc | 1 | KEEP. |
| `pwn:profile-binary` | ✓ | run | doc | 2 | KEEP. |
| `pwn:run-candidates` | ✓ | run | doc | 2 | KEEP. |
| `pwn:calibrate-local` | ✓ | run | doc | 1 | KEEP. |
| `pwn:state` | ✓ | run | doc | 1 | KEEP. |
| `pwn:exploit-run` | ✓ | run | — | 0 | KEEP — but untested + undocumented. |
| `pwn:heap-uaf-scan` | ✓ | run | — | 0 | KEEP — but untested + undocumented. |
| `pwn:menu-probe` | ✓ | run | — | 0 | KEEP — but untested + undocumented. |

### Android APK — KEEP umbrella, fold the 9 granular
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `android-apk:scan` | ✓ | run | doc | 1 | KEEP — umbrella; orchestrates every granular stage + prepare. |
| `android-apk:prepare` | ✓ | run | doc | 0 | **FOLD(surface) → `android-apk:scan`** — decode/prep stage. |
| `android-apk:check-env` | ✓ | run | doc | 0 | **FOLD(surface)** — env preflight. |
| `android-apk:manifest-scan` | ✓ | run | doc | 0 | **FOLD(surface)**. |
| `android-apk:network-security-config` | ✓ | run | doc | 0 | **FOLD(surface)**. |
| `android-apk:fileprovider-scan` | ✓ | run | doc | 0 | **FOLD(surface)**. |
| `android-apk:code-scan` | ✓ | run | — | 0 | **FOLD(surface)** — the only APK tool undocumented anywhere. |
| `android-apk:native-libs` | ✓ | run | doc | 0 | **FOLD(surface)**. |
| `android-apk:hybrid-detect` | ✓ | run | doc | 0 | **FOLD(surface)**. |
| `android-apk:sast-handoff` | ✓ | run | doc | 0 | **FOLD(surface)** — internal handoff to `sast:scan`. |

### Plugin-gated adapters — KEEP (self-hiding when plugin absent)
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `prompt-armor:{scan,analyze,attack,diff,report,config}` | G | run when installed | pub,mod | 1–3 | KEEP — gated on `promptarmor-plugin`. |
| `shinsa:scan` | G | run when installed | pub,mod | 1 | KEEP — gated on `shinsa-plugin`. |
| `shinsa:nist-scan` | G | run when installed | pub | 1 | KEEP. |
| `shinsa:quick-check` | G | run when installed | pub | 2 | **FOLD → `shinsa:scan` (`depth=quick`)**. |
| `shinsa:nist-quick-check` | G | run when installed | pub | 1 | **FOLD → `shinsa:nist-scan` (`depth=quick`)**. |
| `shinsa:frameworks` | G | run when installed | pub | 1 | KEEP — framework lister. |
| `tob:audit` | G | run when installed | pub,mod | 2 | KEEP — gated on `@kuzushi/tob-skills`. |
| `tob:skills` | G | run when installed | pub | 1 | KEEP — skill lister (undocumented per-verb). |
| `vuln-scout:audit` | G | run when installed | pub,mod | 2 | KEEP — gated on `@kuzushi/vuln-scout`. |

### Recon / bounty / vendor / chrome — KEEP (some §6 quarantine)
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `recon:nmap` | ✓ | V(`recon`),run | pub | 7 | KEEP. |
| `recon:subdomain` | ✓ | V,run | pub | 4 | KEEP. |
| `recon:http-fingerprint` | ✓ | V,run | pub | 5 | KEEP. |
| `recon:import` | ✓ | V,run | pub,doc | 2 | KEEP — flagged unreachable in prior audits; verify the verb is wired. |
| `bounty:import-har` | ✓ | run | — | 0 | KEEP — undocumented; importer fn is tested, dispatch isn't. |
| `bounty:import-burp` | ✓ | run | — | 0 | KEEP — undocumented; same. |
| `vendor-assessment:{assess,attach,prompts,scope}` | ✓ | run | pub | 1–2 | KEEP (gated by contract); §6 quarantine candidate (last touched 05-26). |
| `chrome-rce:scan` | ✓ | run | pub | 2 | KEEP; §6 quarantine candidate (last touched 05-20). |
| `chrome-rce:review-trigger` | ✓ | run | pub | 2 | KEEP; §6 quarantine candidate. |

### Variant / ndiff — KEEP
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `variant:hunt` | ✓ | run | pub | 4 | KEEP. |
| `variant:lift-pattern` | ✓ | run | pub | 3 | KEEP. |
| `ndiff:fetch-cve` | ✓ | run | pub | 2 | KEEP. |
| `ndiff:extract-fix-pattern` | ✓ | run | pub | 3 | KEEP. |
| `ndiff:hunt-variants` | ✓ | run | pub | 3 | KEEP. |

### Governance / workspace / catalog — KEEP
| Tool | Vis | Reach | Docs | Tests | Verdict |
|------|-----|-------|------|------:|---------|
| `catalog:modules` | ✓ | CLI(`modules`),V,run | — | 2 | KEEP. |
| `catalog:tools` | ✓ | CLI(`tools`),V,run | — | 2 | KEEP. |
| `module-recommender:recommend` | ✓ | V(`recommend`),run | doc | 6 | KEEP. |
| `config:show` | ✓ | CLI(`config`),V,run | doc | 2 | KEEP. |
| `router:show` | ✓ | run | — | 1(catalog) | KEEP — routing introspection; undocumented. |
| `workspace:status` | ✓ | V(`workspace`),run | — | 4 | KEEP. |
| `workspace:export-findings` | ✓ | CLI(`export`),V,run | doc | 0 | KEEP — export path; dispatch untested by literal (export fns are tested). |
| `engagement:aim` | ✓ | run | — | 1 | KEEP — engagement harness writer (ORPHAN-FINISH per §6). |

---

## 4. CUT footprints (full removal surface)

### 4.1 `smoke:next-step` — CUT (clean)
The only clean cut. A runtime smoke test that "drives a 2-step tool-loop with an
`echo` tool to verify `next_step_blocking` + `run_tool_loop`." Hidden module, no
phase-walker/DAG/verb/CLI path, no docs, zero behavior tests.

Removal footprint:
- **Descriptor + module:** `crates/kuzushi-core/src/modules/router_smoke_module.rs`
  (54 LOC — defines `smoke_module()`; note it also exports `router_module()`, so
  extract `router:show` before deleting the file, or remove only the smoke bits).
- **Executor:** `crates/kuzushi-core/src/modules/run_smoke_next_step_tool.rs`
  (259 LOC) + `run_smoke_next_step_tool` re-export in `modules/registry/mod.rs`.
- **Registration:** the `smoke_module().with_executor(...).deferred()` line in
  `builtins/with_v2_builtins/builtin_registration.rs::register_foundation_modules`.
- **Runtime policy:** `smoke:next-step` arm in `modules/runtime_requirements.rs`
  and any `tool_uses_agent_runtime` entry.
- **Dispatch:** the `smoke:next-step` match arm (routes via
  `execute_runtime_analysis_tool`).
- **Tests:** the catalog/registry snapshot references in
  `modules/registry/tests.rs` (and any golden list of tool names).
- **Docs:** none. **TUI view/verb:** none.
- **Public contract:** **not** on it (no SDK export, no api-compatibility.md
  entry, no `dag-ids.ts`). No migration note required.

### 4.2 Demo/test/SDK fixtures — already out of the shipped catalog
`demo:run`, `demo:legacy`, `deferred-demo:run`, `test:demo`, `test:empty`,
`sdk:sum`, `dyn:echo`, `dynrt:ask` are defined only under
`modules/options/tests.rs`, `modules/registry/tests.rs`,
`modules/descriptor/tests.rs`. They never enter `with_v2_builtins()`; nothing to
cut from the product catalog. (The `kuzushi demo` CLI subcommand is a separate
demo feature, not one of these.)

---

## 5. FOLD-INTO details

- **`taint-iris:hunt` → `taint-iris-next:hunt`.** v2 is the phase-walker taint
  path and a `sast:scan` stage; v1 is a second `sast:scan` stage. Fold: route the
  v1 name to the v2 executor (or drop the v1 stage), keep the descriptor as a
  documented alias. Removable: `capabilities/taint_iris/` (~1,300 LOC) once no
  stage calls it. **Public contract** (api-compatibility.md canonical +
  `dag-ids.ts`) → RELEASING.md note + retain the tool name as an alias.

- **`deep-audit:run` + `classifier-gate:score` → `triage:run`.** A cheap-gate
  (`classifier_gate`, 724 LOC) → deep-auditor (`deep_auditor`, 1,377 LOC)
  incremental-triage subsystem that no journey routes to (`sast:scan` and the
  phase walker both use `triage:run`). Decision: expose as a `triage` mode/option
  or retire. Both are real and tested — treat as a product decision, not a delete.

- **`full-mode:hunt` → `agentic-sast:scan`.** `full_mode_multi` (1,366 LOC) does
  a chunked whole-repo LLM sweep with a `dryRun` cost estimate — a scan
  *strategy* overlapping agentic SAST. Fold as an agentic-SAST mode or keep as a
  distinct budgeted strategy; owner call.

- **`threat-leads:build`/`read` → `x-ray:run`/`threat-model:build`.**
  `capabilities/threat_leads` (896 LOC) reads x-ray artifacts to synthesize leads.
  Undiscoverable-by-verb, no literal tests, no per-verb docs → lowest-adoption
  map-phase tool. Fold its output into x-ray/threat-model or retire.

- **`verify:exploit` → `verify:finding`.** Empirical sandboxed harness, **Rust
  only** today. Keep as a `verify` mode gated on language support, or quarantine.
  The 4,497-LOC `verification/` tree is shared infra — not all removable.

- **`randori:threat-model` → `threat-model:build`.** PASTA overlap (~120 LOC of
  randori-specific threat-model code). Keep `randori:pasta` (the sim).

- **`android-apk:*` 9 granular → `android-apk:scan`.** The umbrella
  (`android_apk_scan.rs`, 394 LOC) already runs prepare + every fixed scan stage.
  Hide the 9 granular descriptors (mark `hidden: true`) to reclaim 9 catalog rows
  and de-noise `/use`; **keep the scanner code** (the umbrella reuses it). The
  bug-hunting playbook (`docs/android-apk-bug-hunting.md`) drives them manually,
  so this is a doc + discoverability change, not a code cut.

- **`shinsa:quick-check`/`nist-quick-check` → `shinsa:scan`/`nist-scan`
  (`depth=quick`).** One executor (`run_shinsa_assessment`) already backs all four
  names by string switch; collapse the quick variants to a `depth` option. Public
  contract + plugin-gated → migration note.

- **`offense-review:threat-hunt` ⇄ `carlini-threat-hunt:run` — DEDUP.** Confirmed
  exact alias (`"carlini-threat-hunt:run" | "offense-review:threat-hunt" =>
  run_carlini_threat_hunt(...)`, no name branching). Pick one canonical
  (`offense-review:threat-hunt` is the visible/preferred name per
  api-compatibility.md; `carlini-threat-hunt:run` is the phase-walker + compat
  name). Keep both names as aliases; do not diverge behavior. Dropping either
  name → migration note.

- **`context:build` ⇄ `context-lite:index` — DEDUP.** Exact alias; `context-lite`
  is a hidden 0-descriptor module. No catalog impact; keep the alias arm.

---

## 6. Not surface-dead — product-decision quarantine (cross-reference)

These are **visible-and-reachable real capabilities** that a *surface-cut* lens
keeps but the *control-room product vision* may retire. That judgment lives in
[`product-vision-alignment-audit.md`](./product-vision-alignment-audit.md); it is
a product call, not a dead-code call. Listed here for completeness with LOC so the
two audits reconcile:

| Subsystem | Tools | LOC (core) | Product-vision verdict |
|-----------|-------|-----------:|------------------------|
| pwn | `pwn:*` (9) | ~2,730 | LEGACY-CUT / at minimum `.deferred()` (the one visible binary-exploit surface). |
| uaf-hunt | `uaf-hunt:hunt` | ~2,402 | LEGACY-CUT (already deferred). |
| offense | `offense:chain` | ~3,048 | LEGACY-CUT (already deferred). |
| exploit-chain | `exploit-chain:scan` | ~1,060 | LEGACY-CUT + retire the attack-tree viz page. |
| vendor-assessment | `vendor-assessment:*` (4) | ~884 | LEGACY-CUT (stale since 05-26). |
| chrome-rce | `chrome-rce:*` (2) | ~592 | LEGACY-CUT (stale since 05-20). |

The prior audit's key correction — which this enumeration independently confirms —
is that `carlini-threat-hunt` and `systems-hunt` are **composed by the `sast:scan`
umbrella** and reached by the phase walker, so they are **KEEP**, not shadow
catalog. The remaining deferred plumbing (`context-lite`, `pipeline`,
`systems-hunt` as DAG-internal executors) is correctly hidden.

---

## 7. Guardrails — cuts that need a `RELEASING.md` migration note

Per `CLAUDE.md` ("Do not break public module/manifest contracts without a
migration plan"), any removal/rename of the following breaks the published
surface and requires a RELEASING.md section + `docs/modules.md` update:

- **SDK-exported module factories** (`src/modules/index.ts`): `sast`, `ndiff`,
  `secret-scan`, `taint-iris-next` (+ exported CWE catalog), `threat-model`,
  `variant`, `vendor-assessment`, `x-ray`. → touches folds #3 (taint) and the
  vendor-assessment quarantine.
- **api-compatibility.md canonical names / registered aliases:** `semgrep:scan`,
  `codeql:scan`, `agentic-sast:scan`, `triage:run`, `verify:finding`,
  `patch:finding`, `findings:list`, `context:build`,
  `offense-review:threat-hunt`, `taint-iris:hunt`, the `sast:<action>` family,
  and the `carlini-threat-hunt:run` alias. → touches folds #3 and #10.
- **`dag-ids.ts` `CANONICAL_DAG_IDS`:** `taint-iris:hunt`, `x-ray:x-ray`,
  `tob:tob-audit`, `vuln-scout:vuln-scout`, threat-model DAG ids, agentic-sast
  sub-detectors, `pipeline:*`/`systems-hunt:*`.
- **rust-ddd-target.md "preserves all `<module>:*` tool IDs" statements:**
  `chrome-rce:*`, `prompt-armor:*`, `vendor-assessment:*`, `shinsa:*` (→ fold #9),
  `tob:*`, `recon:*`. These promise ID/option stability.

**Cuts that need NO migration note** (not on any published surface):
`smoke:next-step` (§4.1), and the descriptor-hide of the 9 granular
`android-apk:*` sub-tools (§5) — provided `android-apk:scan` and the playbook doc
are preserved.

---

## 8. Bottom line

- **Cut now (clean):** `smoke:next-step` (~313 LOC).
- **Fold to shrink the catalog with low risk:** hide the 9 granular `android-apk:*`
  (−9 rows, no code loss); collapse `shinsa` quick↔full to a `depth` option
  (−2 rows); dedup `offense-review:threat-hunt`⇄`carlini-threat-hunt:run` to one
  canonical name; fold `randori:threat-model` into `threat-model:build`.
- **Fold with a migration note + owner sign-off (biggest LOC):** retire
  `taint-iris:hunt` v1 (~1,300), and decide `deep-audit`+`classifier-gate`
  (~2,100), `full-mode:hunt` (~1,400), `threat-leads:*` (~920), `verify:exploit`
  against their canonical peers.
- **Reachable but under-served (fix, don't cut):** add tests/docs for
  `codeql:create-db`, `entry-points:extract`, `threat-intel:discover`,
  `bounty:import-*`, `workspace:export-findings`, `pwn:{exploit-run,heap-uaf-scan,menu-probe}`.
- **Do not treat as dead:** the plugin-gated adapters (self-hiding) and the
  sast-umbrella-composed hunts (`carlini`, `systems-hunt`, `uaf-hunt`,
  `taint-iris-next`). The "36% hidden" figure conflates these with dead surface.
