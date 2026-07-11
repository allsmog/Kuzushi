# Control-Room Build-or-Cut Plan

**Status:** IMPLEMENTATION IN PROGRESS. The interactive cutover now routes Home
to the phase Workbench, projects `modules` as a contextual Capabilities overlay,
folds Burp/HAR intake into `recon:import`, removes binary/UAF tasks from live
Planning, and keeps Expert engines behind an explicit toggle. Historical
inventory below remains decision provenance.

**Date:** 2026-07-09
**Author:** planning pass (Fable 5)
**Scope:** the live Rust module registry
(`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/builtin_registration.rs`
+ `native_scanners/register_modules.rs` + `context/register_context_modules.rs`
+ `plugin_adapters/register_modules.rs`).

---

## 0. Reconciliation with prior memories (verify-first)

The task cited memory counts of "42 modules". **The current registry registers
58 modules.** The prior 57 count predates `wasm-plugin`; the discrepancy with
42 remains definitional rather than a runtime error:

| Source | Count | What it counted |
|---|---|---|
| `product-flow-prd` memory | 42 modules / ~67 tools | research-agent count of *composable parts* grouped by phase bucket |
| `operator-fit-audit` memory | 57 modules / 108 tools | registry before `wasm-plugin` |
| **Current source** | **58 modules registered** | every `registry.register(...)` site in the four register files |

Use **58** as the source inventory. The "42" figure is a phase-bucketed roll-up and
should not be used for cut/finish accounting.

**Prior ORPHAN-FINISH items that have SHIPPED since the 5-day-old memories (do not
re-plan these as orphans):**

- **`kuzushi export`** — now committed. `Command::Export` arm in
  `crates/kuzushi-cli/src/command.rs:131`, dispatch in
  `crates/kuzushi-cli/src/dispatch/reporting.rs:30`, application in
  `crates/kuzushi-cli/src/application/export.rs`. The SARIF-CLI-unreachable gap is
  closed.
- **`recon:import`** — now visible (not hidden). Registered in
  `crates/kuzushi-core/src/modules/recon_module.rs:69`; the registry test at
  `.../registry/tests.rs:1040` asserts "recon:import is visible (not hidden)".
  Reachability BLOCKER is resolved; only *discoverability polish* remains.
- **Patch apply/reject/regen verbs** — now parsed.
  `crates/kuzushi-tui/src/commands/argument_commands/nested.rs:28` →
  `parse_patch_command`, specs at
  `crates/kuzushi-tui/src/commands/shell_command_specs/findings_evidence.rs:111`.
- **False-positive dismissal** — now parsed. `dismiss <reason> <note>` at
  `nested.rs:27` → `parse_dismiss_command`, spec at `findings_evidence.rs:48`.
- **`engagement` domain** — committed. `crates/kuzushi-core/src/engagement/`
  (`mod.rs`, `correction.rs`, `tests.rs`); `engagement:aim` tool wired via
  `.../registry/dispatch_catalog_tool.rs:53`.
- **StrategyQueue** — real `ShellView::StrategyQueue`
  (`crates/kuzushi-tui/src/app/view_state/sast_task_row.rs`), `strategy` verb +
  `approve/reject` sub-verbs
  (`crates/kuzushi-tui/src/commands/shell_command_specs/options_tasks.rs:53`),
  and a `StrategyCommand` correction model
  (`.../commands/shell_command_specs/command_payloads.rs:35`). Routing exists; the
  remaining work is cockpit *depth* (cost estimate, sweep firing), not wiring.

**Still genuinely unfinished (confirmed this pass):**

- **`kuzushi measure`** — the `kuzushi-eval` crate exists (`crates/kuzushi-eval`)
  but there is **no `Command::Measure` arm** in `crates/kuzushi-cli/src/command.rs`.
  Detection-as-a-number stays headless-only.

---

## 1. Historical reconciled module inventory (57-module snapshot)

Disposition legend: **KEEP** (serves control-room vision) · **LEGACY-CUT**
(off-vision, quarantine/remove — operator decision) · **ORPHAN-FINISH** (started,
needs wiring) · **FOLD** (merge into sibling). "hidden/deferred" = registered with
`.deferred()` or `hidden_module()` so it is runnable-by-string but absent from
`/use` and the LLM tool list.

### Foundation / control plane

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `config` | KEEP | operator config surface | `builtin_registration.rs:305` |
| `router` | KEEP | dispatch routing | `builtin_registration.rs:306` |
| `catalog` | FOLD (operator decision) | catalog-era "browse & run"; the reframe retired the catalog product | `builtin_registration.rs:303`, TUI `ShellView::Catalog` |
| `full-mode` | LEGACY-CUT (deferred) | `.deferred()`, `full-mode:hunt` legacy umbrella superseded by `sast:scan` | `builtin_registration.rs:307-310` |
| `classifier-gate` | KEEP | scan gate policy | `builtin_registration.rs:311` |
| `deep-audit` | LEGACY-CUT (deferred) | `.deferred()`, prior-direction umbrella | `builtin_registration.rs:312-316` |
| `context` | KEEP | `context:build` repo snapshot, map-phase input | `context/register_context_modules.rs:9` |
| `context-lite` | KEEP (hidden) | `hidden_module`, MVP scan-compat DAG node | `context/register_context_modules.rs:10` |
| `workspace` | KEEP | workspace state + `workspace:export-findings` | `builtin_registration.rs:297` |
| `engagement` | KEEP + ORPHAN-FINISH (cockpit depth) | `engagement:aim` wired; cockpit surfacing incomplete | `builtin_registration.rs:298`, `engagement_module.rs:10` |
| `module-recommender` | KEEP | deterministic-or-ranked recommender, writes `recommendations.json` | `builtin_registration.rs:299` |

### Detectors / scanners (composable parts — KEEP)

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `sast` (umbrella) | KEEP (anchor) | orchestrates semgrep + agentic + carlini + taint-iris-next + systems-hunt | `builtin_registration.rs:321`, `application/sast_scan/run_sast_scan.rs` |
| `semgrep` | KEEP | native detector | `native_scanners/register_modules.rs:6` |
| `codeql` | KEEP | native detector | `register_modules.rs:7` |
| `iac-scan` | KEEP | native detector | `register_modules.rs:8` |
| `cargo-audit` | KEEP | dependency advisory detector | `register_modules.rs:9` |
| `govulncheck` | KEEP | reachable-vuln detector | `register_modules.rs:10` |
| `license-scan` | KEEP | compliance detector | `register_modules.rs:11` |
| `sbom-scan` | KEEP | SBOM generator | `register_modules.rs:12` |
| `android-apk` | KEEP | mobile detector suite (10 tools, coherent) | `register_modules.rs:14` |
| `dep-hygiene` | KEEP | dependency hygiene detector | `builtin_registration.rs:403` |
| `secret-scan` | KEEP | secret detector | `builtin_registration.rs:404` |
| `exploit-chain` | **LEGACY-CUT (deferred)** | `.deferred()`; sole feed for the fold-weak attack-tree viz page; 869 LOC engine | `register_modules.rs:13`, `scan/engines/exploit_chain/` |

### Agentic / oracles

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `agentic-sast` | KEEP | agentic scanner, composed by sast | `builtin_registration.rs:332` |
| `taint-iris-next` | KEEP (anchor) + ORPHAN-FINISH (stabilize) | A4 neuro-symbolic path oracle; 7 tools; consumes the MCP oracles | `builtin_registration.rs:344`, `capabilities/taint_iris_next/` |
| `taint-iris` (old) | **FOLD → taint-iris-next** (deferred) | `.deferred()`; single tool `taint-iris:hunt` superseded by 7-tool `taint-iris-next:*` | `builtin_registration.rs:339-343` |
| `carlini-threat-hunt` | KEEP (hidden) | `.deferred()` BUT composed by `sast:scan` umbrella (`run_sast_scan.rs:269,292`) — do NOT cut | `builtin_registration.rs:334-338` |
| `offense-review` | FOLD-CANDIDATE (verify) | `offense-review:threat-hunt` ≈ `carlini-threat-hunt:run`; confirm overlap before folding | `builtin_registration.rs:333` |
| `systems-hunt` | KEEP (composed) | composed by `sast:scan` (`run_sast_scan.rs:271`) | `builtin_registration.rs:348` |
| `threat-intel` | KEEP | threat-intel enrichment | `builtin_registration.rs:364` |

### Offense / binary-exploit (LEGACY-CUT cluster)

| Module | Disposition | Evidence | Key files / LOC |
|---|---|---|---|
| `pwn` | **LEGACY-CUT (deferred)** | `.deferred()`; the one VISIBLE-when-run binary-exploit surface; reads `KUZUSHI_REVNG_*`; has a dedicated TUI view | `modules/pwn/` (2639 LOC) + `crates/kuzushi-tui/src/renderer/views/pwn/` |
| `uaf-hunt` | **LEGACY-CUT (deferred)** | `.deferred()`; use-after-free hunter | `capabilities/uaf_hunt/` (2353 LOC) + `modules/uaf_hunt_module.rs` |
| `offense` | **LEGACY-CUT (deferred)** | `.deferred()`; largest off-vision surface | `crates/kuzushi-core/src/offense/` (3050 LOC) + `modules/offense_module.rs` |

### Map phase

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `threat-model` | KEEP | DFD build, feeds Workbench + viz | `builtin_registration.rs:377` |
| `x-ray` | KEEP | repo X-ray map analysis | `builtin_registration.rs:378` |
| `entry-points` | KEEP | attack-surface enumeration | `builtin_registration.rs:379` |
| `cpg` | KEEP | CPG build (oracle input) | `builtin_registration.rs:380` |
| `codeql-db` | KEEP | CodeQL DB build (oracle input) | `builtin_registration.rs:381` |
| `threat-leads` | **LEGACY-CUT (deferred)** | `.deferred()`; prior-direction lead generator | `builtin_registration.rs:382-386` |

### Confirm / fix loop (KEEP — the core loop)

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `triage` | KEEP | triage stage | `builtin_registration.rs:368` |
| `verify` | KEEP | verification stage | `builtin_registration.rs:369` |
| `patch` | KEEP | patch stage (verbs now parsed) | `builtin_registration.rs:370` |
| `findings` | KEEP | findings surface | `builtin_registration.rs:371` |
| `suppress` | KEEP | suppression | `builtin_registration.rs:372` |
| `report` | KEEP | report/export | `builtin_registration.rs:373` |

### Recon / intake

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `recon` | KEEP + ORPHAN-FINISH (discoverability) | `recon:import` reachable but not in `/use`; recon-seed intake serves the harness | `builtin_registration.rs:419`, `recon_module.rs:69` |
| `bounty` | KEEP | HAR/Burp intake | `builtin_registration.rs:420` |
| `vendor-assessment` | **LEGACY-CUT (deferred)** | `.deferred()`; last touched 05-26 per audit | `modules/vendor_assessment/` (339) + `capabilities/vendor_assessment/` (884) |
| `chrome-rce` | **LEGACY-CUT (deferred)** | `.deferred()`; last touched 05-20 per audit | `modules/chrome_rce/` (125) + `capabilities/chrome_rce/` (467) |

### Misc / variant analysis

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `pipeline` | KEEP (hidden) | pipeline DAG plumbing | `builtin_registration.rs:405` |
| `variant` | KEEP-or-FOLD (operator decision) | `variant:hunt`, `variant:lift-pattern`; overlaps `ndiff` | `builtin_registration.rs:406` |
| `ndiff` | KEEP-or-FOLD (operator decision) | `ndiff:hunt-variants`, `ndiff:fetch-cve`, `ndiff:extract-fix-pattern` | `builtin_registration.rs:407` |
| `randori` | KEEP | `randori:pasta`, `randori:threat-model` | `builtin_registration.rs:408` |

### Optional plugin adapters (conditionally visible — KEEP as-is)

| Module | Disposition | Evidence | Key files |
|---|---|---|---|
| `prompt-armor` | KEEP (conditional) | `visible_when(...)` on plugin presence | `builtin_registration.rs:415` |
| `shinsa` | KEEP (conditional) | present only when `@kuzushi/...` installed | `plugin_adapters/register_modules.rs` |
| `tob` | KEEP (conditional) | same gating | `plugin_adapters/register_modules.rs` |
| `vuln-scout` | KEEP (conditional) | same gating | `plugin_adapters/register_modules.rs` |

**Roll-up:** ~40 KEEP · **9 LEGACY-CUT** (`full-mode`, `deep-audit`,
`exploit-chain`, `pwn`, `uaf-hunt`, `offense`, `threat-leads`,
`vendor-assessment`, `chrome-rce`) · **1 FOLD** (`taint-iris` → `-next`) + 2
FOLD-candidates (`offense-review`, `variant`/`ndiff`) · **3 ORPHAN-FINISH**
(`measure` CLI, `recon:import` discoverability, `engagement`/StrategyQueue cockpit
depth) · **1 view FOLD** (`catalog`).

---

## 2. Cut waves (safe-first; each independently shippable)

> **All cuts are OPERATOR DECISIONS** — see §5. These modules already ship
> `.deferred()`, so the safest first step is *quarantine* (keep `.deferred()`, mark
> experimental in docs), and only later *remove*. The PRD non-goal ("don't SHIP
> roadmap modules until first-class evidence") argues for quarantine over deletion
> for anything that could earn its place back.

### Wave C1 — zero-risk quarantine (docs-only, no code removed)

Mechanical. For each LEGACY-CUT module, add an "experimental / not shipped" note
in `docs/modules.md` and confirm `.deferred()` is present (it already is). No
registration change, no test change. Ships immediately, reversible.

- Modules: `full-mode`, `deep-audit`, `exploit-chain`, `pwn`, `uaf-hunt`,
  `offense`, `threat-leads`, `vendor-assessment`, `chrome-rce`.
- Proof: `docs/modules.md` lists each as experimental; registry unchanged; all
  existing tests pass untouched.

### Wave C2 — remove the smallest, most-orphaned surfaces first

Order by LOC and blast radius (smallest/most-isolated first):

1. **`chrome-rce`** (592 LOC total). Remove `modules/chrome_rce/`,
   `capabilities/chrome_rce/`; drop `chrome_rce::module()` registration
   (`builtin_registration.rs:397-399`); remove `dispatch_recon_assessment_tool`
   arms for `chrome-rce:*`; delete/adjust tests referencing `chrome-rce:`.
2. **`vendor-assessment`** (1223 LOC). Remove `modules/vendor_assessment/`,
   `capabilities/vendor_assessment/`; drop registration
   (`builtin_registration.rs:390-394`); clean `dispatch_recon_assessment_tool`
   arms; update tests.
3. **`threat-leads`** (deferred map module). Drop registration
   (`builtin_registration.rs:382-386`); remove `threat_leads_module` fn +
   `dispatch_runtime_analysis_tool` arm; update tests.
4. **`deep-audit`** + **`full-mode`** (foundation umbrellas superseded by
   `sast:scan`). Drop registrations (`builtin_registration.rs:307-316`); remove
   `full-mode:hunt` from `runtime_requirement_for_tool` special-case
   (`builtin_registration.rs:287`); clean `dispatch_runtime_analysis_tool` arms;
   update `runtime_requirement_for_tool` test + any `full-mode:hunt` fixtures.

Each item is one shippable PR. Proof for each: `cargo test -p kuzushi-core` green;
`registry.resolve_tool("<cut>:...")` returns `None`; no dangling `mod`/`use`.

### Wave C3 — remove the large binary-exploit cluster (highest LOC)

Do this last among cuts — biggest blast radius, includes a TUI view.

1. **`exploit-chain`** (869 LOC engine). Remove
   `scan/engines/exploit_chain/`, `native_scanners/exploit_chain_output.rs`, the
   `exploit_chain_module()` registration (`native_scanners/register_modules.rs:13`)
   and its `execute_tool` arm (`register_modules.rs:31`). **Downstream:** the
   attack-tree viz page feeds solely off `app.domain().exploit_chains()`
   (`crates/kuzushi-tui/src/ui_view_models/viz_data.rs:171-195`) — either drop the
   attack-tree `VizPage` variant or leave it drawing its `empty_hint`. Update
   `viz_data` tests + `renderer/views/scene/` tests.
2. **`uaf-hunt`** (2353 LOC). Remove `capabilities/uaf_hunt/`,
   `modules/uaf_hunt_module.rs`; drop registration
   (`builtin_registration.rs:349-353`) + `execute_uaf_hunt_tool_mapping` +
   `dispatch_uaf_hunt_tool`; update tests.
3. **`pwn`** (2639 core + TUI view). Remove `modules/pwn/`; drop registration
   (`builtin_registration.rs:354-358`) + `execute_pwn_tool_mapping` +
   `dispatch_pwn_tool` + the `pwn:auto-solve` special-case in
   `runtime_requirement_for_tool` (`builtin_registration.rs:290`). **TUI:** remove
   `crates/kuzushi-tui/src/renderer/views/pwn/`, the `pwn` references in
   `ui_view_models.rs`, `shellapp.rs`, `effect_runtime.rs`, `view_state/mod.rs`,
   `renderer/views/shell_view_lines.rs`, and any `ShellView::Pwn`-adjacent state.
   Also retire the `KUZUSHI_REVNG_*` env reads (env-doctrine violation noted in
   the audit). Update `app/tests.rs` + `renderer/tests.rs`.
4. **`offense`** (3050 LOC). Remove `crates/kuzushi-core/src/offense/`,
   `modules/offense_module.rs`; drop registration
   (`builtin_registration.rs:359-363`) + `execute_offense_tool_mapping` +
   `dispatch_offense_tool`; update tests.

Proof for the wave: full `cargo test` green across `kuzushi-core` and
`kuzushi-tui`; `scene_view_is_never_a_trap`-style viz tests updated; no
`ShellView::Pwn` render path remains; `.kuzushi/` on-disk formats untouched
(these engines were never in the default scan pipeline, so no artifact schema
changes).

---

## 3. Finish waves (wire the started-but-unwired)

### Wave F1 — `kuzushi measure` (cheapest, highest "close-a-loop" value)

- **Missing:** a `Command::Measure` arm in `crates/kuzushi-cli/src/command.rs`,
  a dispatch arm, and a thin application service that shells into / calls the
  existing `crates/kuzushi-eval` crate.
- **Effort:** S (½–1 day). The eval logic already exists; this is CLI surface +
  one dispatch arm, mirroring the `Export` arm pattern
  (`command.rs:131` / `dispatch/reporting.rs:30`).
- **Proof test:** a CLI integration test in `crates/kuzushi-cli/src/tests.rs`
  asserting `parse_command(["measure", ...])` yields `Command::Measure { .. }` and
  a dispatch smoke test that produces a detection-number JSON on stdout.

### Wave F2 — `recon:import` discoverability (reachable → findable)

- **Missing:** nothing functional (it runs). It is absent from `/use` and the
  operator has no signpost. Decide: surface it in the recon/intake list, or add a
  first-class `kuzushi recon import` shorthand that compiles to the same tool
  input.
- **Effort:** S. Visibility flag / command spec only.
- **Proof test:** extend `.../registry/tests.rs` (already asserts visibility) with
  a `/use`-listing assertion, or a command-spec test that `recon import <file>`
  parses and routes to `recon:import`.

### Wave F3 — engagement / StrategyQueue cockpit depth (highest product value)

- **Present:** `engagement:aim`, `ShellView::StrategyQueue`, `strategy
  approve/reject` verbs, `StrategyCommand` corrections. The *plumbing and routing
  exist.*
- **Missing (per PRD gaps):** signal-driven **priced sweep** firing (only a static
  `PlanningTaskId` walker today), the **cost estimate** in the queue view, and
  per-scan **engine-enablement UI**. This is the "build the room, not just the
  plumbing" work — the largest remaining control-room effort.
- **Effort:** L (multi-PR; this is the real Control-Room build track, out of scope
  for a mechanical finish and better handled by its own PRD). List here so it is
  not mistaken for a small wire-up.
- **Proof test:** a view-model test that a strategy proposal renders with an
  `estimated_cost_usd` and that `strategy approve <id>` transitions a proposal to
  a firing sweep; a dispatch test that the sweep fires `focus × strategy × model ×
  runs` through the shared registry boundary.

### Wave F4 — MCP oracle fan-out (finish the shared oracle surface)

- **Present:** 11–12 `kuzushi-mcp-*` servers, wired today **only** to
  `taint_iris_next` via `with_mcps_for_target`.
- **Missing:** exposing the same oracle set to other agentic tools that would
  benefit (per PRD "MCP oracles ×11 wired to ONLY taint_iris_next today").
- **Effort:** M. Policy plumbing through `AgentToolPolicy::with_mcps`.
- **Proof test:** a dispatch test asserting a second agentic tool receives the MCP
  tool list when `toolPolicy.mcps == true`.

---

## 4. Fold waves (merge into a sibling)

### Wave D1 — `taint-iris` (old) → `taint-iris-next`

- Old module exposes a single `taint-iris:hunt`; `-next` exposes 7 tools
  (`catalog`, `codeql-db`, `dataflow-plan`, `finding-review`, `hunt`,
  `source-sink-trace`). Fold = drop the old registration
  (`builtin_registration.rs:339-343`) + `taint_iris_module` fn; keep a deprecated
  alias `taint-iris:hunt → taint-iris-next:hunt` at the option boundary so any
  saved input keeps working.
- **Proof:** registry test that `taint-iris:hunt` resolves to the `-next` executor
  (or fails with an actionable "renamed to taint-iris-next" error); viz
  `taint_iris:hunt`→AttackPath mapping updated in the auto-open hooks.
- **Effort:** S–M.

### Wave D2 — `offense-review` ≈ `carlini-threat-hunt` (VERIFY then fold)

- `offense-review:threat-hunt` and `carlini-threat-hunt:run` are near-duplicates
  per the audit. **Do not fold blind** — first diff the two executors' prompts and
  outputs. If they converge, fold `offense-review` into carlini and add a
  deprecated alias. If they diverge (e.g. different oracle set), keep both and fix
  the circular descriptions instead.
- **Proof:** a behavior-diff note in the PR; if folded, an alias-resolution test.
- **Effort:** M (investigation-gated).

### Wave D3 — `variant` / `ndiff` overlap (operator decision)

- Both do CVE-diff variant analysis (`variant:hunt`/`variant:lift-pattern` vs
  `ndiff:hunt-variants`/`ndiff:fetch-cve`/`ndiff:extract-fix-pattern`). Decide
  whether they are one capability with two entry points (fold) or two intentional
  stages (keep + document). Needs the operator's product intent.
- **Proof:** if folded, alias tests; if kept, a docs note distinguishing them.
- **Effort:** M.

### Wave D4 — `catalog` view + catalog-era shell views (operator decision)

- The `catalog` module and `ShellView::{Catalog, Module, ModuleRun, Tools, Story}`
  are the retired "browse & run" product. `Home`/`Recommend` are superseded by
  `Workbench`. Folding these is a TUI-surface decision, not a registry cut; it
  touches `renderer/views/shell_view_lines.rs` and the command specs. Sequence
  **after** the module cuts so the view work sees the final tool set.

---

## 5. Operator decisions vs mechanical

**OPERATOR DECISIONS (cutting/folding a shipped-or-shippable feature is the user's
call — do not execute without sign-off):**

- Every LEGACY-CUT module removal in Waves **C2 and C3** (`pwn`, `uaf-hunt`,
  `offense`, `chrome-rce`, `vendor-assessment`, `exploit-chain`, `threat-leads`,
  `full-mode`, `deep-audit`). These are real, compiled capabilities. The PRD
  non-goal favors *quarantine* over deletion; the user must choose quarantine
  (Wave C1) vs. removal (C2/C3), per module.
- **Fold D2** (`offense-review` vs carlini) — needs a product call after the
  behavior diff.
- **Fold D3** (`variant`/`ndiff`) — pure product-intent decision.
- **Fold D4** (catalog-era views) — the user retired the catalog product in the
  reframe, but cutting the views is a visible UX change.

**MECHANICAL (safe to execute once sequenced; no product-meaning judgment):**

- **Wave C1** quarantine notes (docs-only).
- **Wave F1** `kuzushi measure` wire-up (the crate exists; this is plumbing).
- **Wave F2** `recon:import` discoverability.
- **Wave F4** MCP oracle fan-out.
- **Fold D1** `taint-iris` → `-next` (clear supersession, alias preserves compat).

**NOTE — do NOT cut (audit-corrected):** `carlini-threat-hunt` and `systems-hunt`
are `.deferred()`/hidden but are **composed by the `sast:scan` umbrella**
(`application/sast_scan/run_sast_scan.rs:269,271,292`). Removing them breaks the
default scan. They are KEEP-hidden.

---

## 6. Sequencing summary (each wave independently shippable)

1. **C1** quarantine docs — zero risk, ship today.
2. **F1** `measure` + **F2** `recon:import` discoverability — small finishes,
   close advertised loops, no cut risk.
3. **D1** `taint-iris` fold — clean supersession.
4. **C2** small cuts (`chrome-rce`, `vendor-assessment`, `threat-leads`,
   `deep-audit`, `full-mode`) — pending operator sign-off.
5. **C3** large cuts (`exploit-chain`, `uaf-hunt`, `pwn`, `offense`) — pending
   sign-off; biggest blast radius (TUI + viz), do last.
6. **D2/D3** fold investigations — product-intent gated.
7. **F3** control-room cockpit depth + **F4** MCP fan-out + **D4** view fold —
   the real "build the room" track; belongs in its own Control-Room PRD, not a
   mechanical wave.

---

## 7. Risks

- **Mode parity (CLAUDE.md):** every cut must preserve scan/shell/run parity. The
  cut modules are `.deferred()` and not in the default `sast:scan` pipeline, so no
  default-mode behavior changes — but verify no scan/run fixture references a cut
  `<tool>:<verb>` before removal.
- **`.kuzushi` on-disk formats:** none of the cut engines own a persisted artifact
  schema in the default pipeline. Confirm no `runs/<id>/` reader keys off
  `exploit-chain`/`pwn`/etc. output before C3. `exploit-chain` populates
  `app.domain().exploit_chains()` consumed by the attack-tree viz — that is the one
  in-memory downstream to sever.
- **Hidden-but-composed trap:** `carlini`/`systems-hunt` are deferred yet composed
  by the umbrella. Any "remove all `.deferred()` modules" script would break the
  default scan. Cuts must be per-module, not a blanket deferred sweep.
- **Env-doctrine debt rides along:** `pwn` reads `KUZUSHI_REVNG_*`; retiring it
  removes an env-doctrine violation. `KUZUSHI_RIPGREP_BIN`,
  `KUZUSHI_JOERN_TIMEOUT_SECS` remain and are *not* part of this plan (they belong
  to KEEP paths and need the options-migration track).
- **Stale-memory risk:** the prior audits were 5 days old; this pass already found
  `export`/`recon:import`/patch-verbs/dismiss/engagement/StrategyQueue shipped.
  Re-verify current `main` before executing any wave — the tree moves fast.
- **CRAP gate:** cuts reduce surface (good), but the F-wave additions
  (`measure` arm, discoverability, MCP fan-out) must pass the repo CRAP-risk gate
  (`pnpm quality:crap-risk`, risk < 7, functions ≤ 4 complexity / ≤ 40 lines).
