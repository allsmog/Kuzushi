# Cannon → Kuzushi port plan (Direction A)

> **Status:** proposal, awaiting review. No code changed yet.
> **Decision (2026-07-02):** Direction **A** — port cannon *into* Kuzushi as native
> Rust, keeping Kuzushi's broad surface. Write the full phased plan before touching code.
> **Sources:** the three design artifacts (overview / runtime / engagement), five
> file-grounded code maps of cannon (`~/vibe-code/vuln-scan-cannon-harness`) and Kuzushi,
> plus `PERMUTATION.md` / `BENCHMARK.md`. Every claim below carries a `file:line` anchor
> so the plan can be executed against the real tree, not the artifacts' prose.

---

## 0. What "Direction A" means here

Port cannon's four proven subsystems into Kuzushi as first-class Rust, and collapse the
55-module catalog toward cannon's ~8 phase verbs — **without** shelving Kuzushi's unique
surfaces (live `native_scanners`, the tree-sitter/Joern/CodeQL MCP oracle servers,
bounty/recon intake, scan/shell/run mode parity, the Workbench cockpit, `kuzushi-eval`).

The four subsystems to port:

1. **Findings ledger contract** — `sources[]`, sticky human triage, corroboration, repo-scoped merge.
2. **Prompts-as-files** — 3-level resolution (`target override → variant → base`) + sha256 provenance.
3. **Signal-driven permutation planner** — 4 generators → priced, budget-gated queue → `run_salvo`.
4. **Measure/tune** — F1 on a labeled corpus, head-to-head vs an imported SARIF, and a regression gate.

Direction A is the highest-effort path precisely because these land *inside* Kuzushi's
existing seams rather than behind a delegation boundary. The good news the maps surfaced:
**every one of the four already has a partial Kuzushi analog**, so each phase is a
reconciliation/extension, not a greenfield build. That is the spine of this plan.

---

## 1. Ground-truth corrections (the design artifacts are wrong in four load-bearing ways)

Before planning, four premises from the artifacts must be corrected — each changes the work.

| Artifact claim | Reality | Consequence for the port |
|---|---|---|
| "55 registered / **42** shown / **121** tools / **42** ShellViews / 21 planning tasks" | 55 registered ✓, **41** shown, **67** visible tools (121 = total name-space incl. 14 hidden modules), **43** ShellView variants, **22** `PlanningTaskId` entries | Numbers in copy/tests must use 41/67/43/22. 14 modules are *already* hidden — the reframe adds 7, not "cuts to the low teens" from scratch. |
| "5 engine arms (semgrep/codeql/LLM/secrets/dynamic)" | cannon dispatch is **3 arms** — `static_review`/`secrets`/`dynamic` (`cannon:src/detector.rs:17`). Semgrep/CodeQL/SARIF enter cannon only as **ingested SARIF** via `src/seed.rs`; cannon never runs them live. | Kuzushi's `native_scanners` (runs semgrep/codeql live) is a genuine **superset**. The port keeps them as live detector arms *and* adds cannon's seed-ingest path — it does not replace one with the other. |
| "Adopt cannon's ledger schema" (implicitly a new store) | cannon's ledger is **JSON + Markdown round-trip + SARIF export, no SQLite** (`cannon:src/ledger.rs:156`). Kuzushi already has a deduping **SQLite** store (`.kuzushi/v3/index.sqlite3`). | The port is a **schema reconciliation of the existing `FindingStore`**, not a new ledger. Keep SQLite; add the missing columns/child tables. Do **not** import cannon's JSON ledger. |
| "measure/tune is the thing Kuzushi has no answer for" | Kuzushi ships **`crates/kuzushi-eval/`** — precision/recall/F1 vs oracle JSON, OWASP Benchmark + Juice Shop + CVE corpus, `benchmarks/{regression-check,sarif-diff,freeze-baseline}.ts` + `baseline.json` | measure/tune is a **reconciliation**: fold cannon's precision-F1 + `--against SARIF` + train/test `tune` into `kuzushi-eval`, and wire a CLI verb (today `kuzushi-eval` has a standalone `main.rs`, no `kuzushi`-CLI entry). |

There is also a **model-safety constraint** the artifacts ignore: cannon passes `--model`
with backend defaults freely. Kuzushi forbids silent fallback
(`runtime/policy/no_silent_fallback.rs`, `scripts/check-model-safety.mjs`). Every ported
subsystem must resolve models through `resolve_tool_model` / `ctx.config.model`, never a
literal default. This is a hard gate on Phases 3–6.

Baseline caveat (from prior audits): **HEAD already fails some workspace tests** (BDD
onboarding + a snapshot; findings-store parity drift). Phase 0 should establish a clean
baseline-or-known-red list before adding new tests, so regressions are attributable.

---

## 2. The subsystem map — cannon → Kuzushi, per seam

Each row is where a cannon mechanism lands in Kuzushi, and the gap to close.

### 2.1 Findings ledger

| Aspect | cannon (`src/ledger.rs`, `src/artifacts.rs`) | Kuzushi (`crates/kuzushi-core/src/findings/`) | Gap to close |
|---|---|---|---|
| Row type | `LedgerFinding` (`ledger.rs:23`) | `Finding` (`domain/finding_record.rs:62`) | shapes align (id/severity/cwe/file/line/status/evidence) |
| Dedup key | `signature` = `basename:line:cwe` on `Finding` (`artifacts.rs:142`) | `dedup_key` = `file:line/8:cwe` (`finding_record.rs:151`, bucket 8) | reconcile: exact-line vs /8 bucket, basename vs trimmed-path. Pick one canonical key (recommend basename + exact line + normalized-CWE to match cross-engine collisions cleanly) and migrate. |
| Provenance | `sources: Vec<String>` (`ledger.rs:65`) | single comma-merged `tool: String` + `vuln_source: enum` | **add `finding_sources` child table** (or JSON column) accumulating `["semgrep","cannon","sarif:CodeQL"]`. |
| Sticky triage | `triaged_by: "auto"\|"human"\|"imported"`, guarded in `merge`/`apply_verdicts`/`sync_from_md` by `triaged_by != "human"` (`ledger.rs:274`) | `TriageOutcome` has **no** author flag; upsert is last-writer-wins (`persistence/open/triage_and_verification.rs`) → an AI re-run overwrites a human verdict | **add `triaged_by`/`triage_source` column** + gate every write path so human decisions survive re-runs. Port all **three** guard sites, not just merge. |
| Corroboration | `corroboration: usize` + `rounds: Vec<String>` (`ledger.rs:61`) | merge collapses collisions (higher severity wins), count lost (`merge_finding_collision`, `finding_writes.rs:66`) | **derive `corroboration_count` at merge time**; needed for verify `--votes`. |
| Merge scope | repo-wide (one ledger per target) | only within one `scan_id` — each `persist_*` mints its own `run_id`, so semgrep & codeql **don't cross-merge** at persist (`find_collision … where scan_id=?1`, `finding_writes.rs:126`) | **introduce an engagement-scoped merge** (merge on `dedup_key` across `scan_id`, or an engagement-level scan id) so many engines corroborate one row. |
| On disk | `.cannon/ledger.json` ↔ `VULN_FINDINGS.md` ↔ `findings.sarif` | `.kuzushi/v3/index.sqlite3` (+ `workspace:export-findings` already emits SARIF/CSV/MD) | keep SQLite; optionally add a `VULN_FINDINGS.md` round-trip later (nice-to-have, not required). |

**Port note:** the seam is clean — same `open/insert_finding/find_collision` shape and a
near-identical key. All changes are **additive schema** + a merge-scope change. This is the
spine; do it first among the engine phases.

### 2.2 Prompts-as-files

- cannon: `resolve_prompt_path(name, target_dir, variant)` searches `target/prompt_overrides/<name>.md` → `prompts/variants/<variant>/<name>.md` → `prompts/<name>.md` (`src/prompts.rs:31`); `load_prompt` stamps sha256[..16] of the raw template (`prompts.rs:62`).
- Kuzushi: effectively **1-level** — `prompt_file_default_for_tool` is a static 4-arm match (`triage:run`, `verify:finding`, `taint-iris:hunt`, `carlini-threat-hunt:run`) reading one project file (`builtins/with_v2_builtins/execution.rs:119`); SAST has a richer 2-source override (`application/sast_scan/prompt_overrides.rs:3`). Path helper `prompt_override_path(target, module, verb)` already exists (`options/prompt_paths.rs:14`).
- **Gap/port:** generalize the static match into a **data table**, give the loaders an **ordered search path** (`project override → variant → packaged base`), and add the **sha256 provenance** stamp (fold into run-reproducibility metadata, `run_artifacts/run_reproducibility_metadata.rs`). The `<module>/<verb>.md` convention and `prompt_override_path` are reusable as-is. There's an existing `PromptMutation` approval ledger (`prompt_stack/mod.rs`) to integrate with, not fight.

### 2.3 Permutation planner (the big one)

- cannon: generators are **free functions** dispatched by string in `run_generators` (`src/main.rs:668`) — `commits` (incomplete-fix hunts + churn, `generators/commits.rs`), `threatmodel` (reachability flow audits, `generators/threatmodel.rs`), `intel` (dep footguns + optional research, `generators/intel.rs`), `evolve` (prompt-variant breeding, `generators/evolve.rs`). Each returns `Vec<Proposal>` (`queue.rs:59`) with `ProposalSpec{focus×variants×models×runs}` (`queue.rs:36`). The `Queue` prices (`estimate = rounds·cost_per_round·(2 if verify)`), ranks by `yield_score`, gates on `budget_cap`, and EMA-recalibrates `cost_per_round` from actual spend (`queue.rs:255`). Firing = `run_salvo` bounded fan-out with per-round checkpointing (`src/runner.rs:47`).
- Kuzushi: a **static** `PlanningTaskId` enum (22 variants across 4 phases, `app/onboarding/task_id.rs:10`) + topo-sort deps (`onboarding/dependencies.rs`) + a single `VecDeque` walker in the **TUI** (`onboarding/runner.rs:22` `dispatch_next_planning_task`). Phase membership is compiled into `phase()`/`in_phase`.
- **Gap/port:** this is the deepest change. Introduce `Proposal`/`ProposalSpec`/`Queue`/`Generator` into **`kuzushi-core`** (not `kuzushi-tui` — the planner core must be mode-shared per the mode-parity doctrine). The clean seams: the existing `task.tool_name()` indirection and the single `dispatch_next_planning_task` choke point that calls `start_background_tool`. Keep `JourneyProgress` phase *derivation* (it's clean, `ui_view_models/journey.rs:82`); replace phase *execution* (the `PlanningTaskId::ALL` table + single-queue walker) with proposals fired best-yield-first under a budget. cannon dispatches generators by string — porting to a real `trait Generator` is a Kuzushi improvement, not a cannon copy.

### 2.4 Reachability oracle

- cannon: an agent builds a `RepoGraph` into `.cannon/repo_map.json`; `src/repomap.rs` is the pure query layer (multi-source BFS from untrusted entries, `reachable_from_untrusted`, `repomap.rs:141`). The verifier injects `reachability_for_location(...).describe()` as a *hedged* oracle sentence (`stages/verify.rs:114`).
- Kuzushi: **already has stronger oracles** — the tree-sitter/Joern/CodeQL MCP servers (`crates/kuzushi-mcp-*`), wired when `toolPolicy.mcps == true`.
- **Gap/port:** don't rebuild cannon's ad-hoc graph. Wrap the MCP servers as the verifier's oracle input (Joern `taint_paths`/`callers_of`, CodeQL `flows_for_cwe`). Optionally derive a lightweight `RepoGraph` from `entry-points.json` + CPG for the `threatmodel` generator, which needs `reachable_from_untrusted` to propose flow audits.

### 2.5 Verify / Confirm gate

- cannon: `run_verify` multi-vote, 3 perspective-diverse lenses (reachability/exploitability/mitigation), 2-of-3 majority (`stages/verify.rs:160`) + metamorphic perturbation (`stages/metamorphic.rs`, `decide()` at `metamorphic.rs:44`).
- Kuzushi: opt-in but **all-or-nothing** — `SastScanRequests{verify,auto_patch,triage}` with a boolean `needs_verification()` gate (`application/sast_scan/taint_iris_next_hunt_input.rs:39`), then verifies **every** true-positive fingerprint (`true_positive_fingerprints_for_sast_runs`, `sast_run/write_whitebox_diff_scope_json.rs:37`) with no severity floor, cap, or votes.
- **Gap/port:** add `when`/`max`/`votes` to `SastScanRequests` + `from_input`; filter/sort/truncate in `true_positive_fingerprints_for_sast_runs`. `--votes` **depends on the corroboration count from Phase 1** (or on porting cannon's multi-lens verifier). Keep the boolean as the master on/off.

### 2.6 Measure / tune

- cannon: `bench::score(detected, labels, tol) → {tp,fp,fn,precision,recall,f1}` (`src/bench.rs:81`); `--against <sarif>` grades an external tool with the same scorer (`main.rs:1291`); `--gate` fails CI when F1 regresses past a baseline+margin (`tune.rs:56`); `cmd_tune` does a train/test split and picks the best prompt variant on a holdout (`main.rs:1347`).
- Kuzushi: `kuzushi-eval` computes precision + recall-by-tolerance vs oracle JSON (`scoring.rs:24`), has the corpora and `benchmarks/*.ts` regression tooling — but is **recall-centric, standalone `main.rs`, not wired to a `kuzushi` verb**.
- **Gap/port:** add cannon's F1 + `--against SARIF` + baseline `--gate` + train/test `tune` into `kuzushi-eval`, and expose a `kuzushi measure` / `kuzushi tune` verb (or scan-mode `--measure`). Close the loop back to the `evolve` generator (fitness = confirmed findings / F1).

### 2.7 Surface & engagement folder

- Reframe: `Catalog`/`Recommend`/`Module`/`ModuleRun` (`app/view_state/sast_task_row.rs:82-86`) collapse into one advanced catalog; Workbench is **already** the landing (`app/runtime/run_shell.rs:72` `open_start_view`). `findings` and `open <id>` already fold into Workbench.
- Hide 7 plumbing modules by flipping `builtin_module(` → `hidden_module(` in 7 builders (see Phase 0). Every "N modules" surface funnels through `ModuleRegistry::modules()` (`builtins/with_v2_builtins/lookup.rs:4`), so one lever moves them all.
- engagement folder: paths are centralized in `workspace/domain/workspace_target.rs` + `options/prompt_paths.rs`, **but** Map-phase artifact paths are hard-coded a second time in `PlanningTaskId::artifact_relative_path` (`task_id.rs:183`) — a reorg must update both or prior-run reuse detection breaks.

---

## 3. The phased plan

Ordered by dependency. Phase 0 is decision-independent and reversible (the "safe to start"
work). Phases 1–7 are the engine port; each ends green (tests + `pnpm quality:crap-risk`)
and is independently shippable.

### Phase 0 — Surface reframe (decision-independent, reversible)

**Goal:** the home surface tells the truth — a cockpit, not a 41-tile catalog — with zero
engine change. Fully reversible.

**Do:**
- Hide the 7 plumbing modules: `builtin_module(` → `hidden_module(` in
  `resolve_tool_model.rs:16` (catalog), `:30` (config), `:41` (module-recommender);
  `router_smoke_module.rs:20` (router), `:35` (smoke); `full_mode_module.rs:71`
  (classifier-gate); `workspace_module.rs:4` (workspace). They stay executable by name
  (`resolve_tool()` ignores `hidden`, `lookup.rs:27`).
- Collapse browsing views: repoint the `Recommend`/`Module`/`ModuleRun` assignment sites
  (`handle_command.rs:173`, `handle_scan_command.rs:151`, `tool_runner/run_tool/dispatch.rs:59,64`,
  `scan/start_scan/scan_startup.rs:124`) into `ShellView::Catalog` sub-modes; retire the
  three render arms (`renderer/views/shell_view_lines.rs:18-20`).
- Make the `home` verb + fallbacks land on Workbench (`handle_command.rs:111`,
  `construction.rs:98`, `onboarding/runner.rs:373`, `context_workspace_history.rs:49`,
  `navigation_target_story.rs:224`); drop the `Home` special-case in `back_navigation.rs:10`.
- Update chrome/labels/keybindings that name the retired views (`screen_context.rs:52-55`,
  `view_status.rs:13-16`, `keybindings/catalog.rs`, `keybindings/workflow.rs`).

**Watch-outs:** `workspace:export-findings` is a genuinely user-facing action — hiding
`workspace` removes it from the catalog/completions. **Decide:** either keep `workspace`
visible, or surface `export-findings` from the Fix phase / a `findings export` verb before
hiding it. Update the hardcoded `is_hidden_module_id()` list (`activity.rs:886`) and the
test allowlist (`crates/kuzushi-cli/tests/cutover_cli.rs:472`) so the regression guard tracks.

**Tests:** update count assertions (41→34 modules, 67→~58 tools); add a guard that the 7
remain executable-by-name; snapshot the new Workbench-home routing.

### Phase 1 — Ledger contract reconciliation (the spine)

**Goal:** one findings row per real defect, many `sources[]`, sticky human triage,
corroboration count, engagement-scoped merge. Unblocks verify-votes and measure.

**Do (additive schema on `index.sqlite3`):**
- `finding_sources` child table (finding_id, source) + merge helper appends on collision
  (`persistence/store_rows/merge_helpers.rs`, `finding_writes.rs:66`).
- `triaged_by` column on `triage` (`auto|human|imported`); gate every triage write on
  `triaged_by != "human"` (mirror cannon's three guard sites).
- `corroboration_count` derived in `merge_finding_collision`.
- Engagement-scoped merge: add an engagement/repo scan id, or merge on `dedup_key` across
  `scan_id`, so `native_scanners` runs corroborate one row. Reconcile the dedup key
  (line/8 vs exact) — pick one, migrate via the existing `open/init` additive migration path
  (`connection_and_schema.rs:144`).
- Seed-ingest arm: a `findings seed <sarif>` path reusing cannon's `parse_file`
  semantics (SARIF/semgrep/json/csv), tagging `sources[]` + `triaged_by="imported"`.

**Tests:** sticky-across-remerge (port cannon's `human_decisions_are_sticky_across_remerge`),
seed-dedups-and-adds-source, cross-engine corroboration count, migration idempotency.

### Phase 2 — Prompts-as-files (3-level + sha)

**Goal:** every phase's prompt is a file resolved `project override → variant → base`,
stamped with a sha256 in run metadata. Small, independent, high value.

**Do:** turn `prompt_file_default_for_tool` into a data table; give
`read_prompt_file_default` / `read_sast_prompt_override` an ordered search path incl. a
packaged base + a `variant` axis; stamp sha into `run_reproducibility_metadata.rs`; extend
beyond the current 4 verbs to the phase verbs.

**Tests:** resolution order, sha stability, unknown-token passthrough (cannon `interpolate`).

### Phase 3 — Confirm/verify config

**Goal:** "verify only what you ask for, configured" — `--when severity>=high --max N --votes K`.

**Do:** add `when`/`max`/`votes` to `SastScanRequests` + `from_input`
(`taint_iris_next_hunt_input.rs:27`); filter/sort/truncate in
`true_positive_fingerprints_for_sast_runs` (`write_whitebox_diff_scope_json.rs:37`).
`--votes` consumes Phase 1's corroboration count. **Optional stretch:** port cannon's
multi-lens verifier (`stages/verify.rs`) as an alternative verify strategy, using the MCP
oracle (Phase 4) for the reachability lens. Keep `needs_verification()` as master on/off.
**Model safety:** votes/lenses must resolve models via `resolve_tool_model`.

**Tests:** severity filter, cap truncation, votes threshold; bare-scan-verifies-nothing invariant.

### Phase 4 — Reachability oracle wiring

**Goal:** the verifier and the `threatmodel` generator can ask "reachable from an untrusted
entry?" deterministically.

**Do:** wrap the MCP servers (Joern/CodeQL/tree-sitter) as the oracle input to verify;
build a lightweight `RepoGraph`-analog from `entry-points.json` + CPG exposing
`reachable_from_untrusted` for the generator. Reuse cannon's *hedged* `describe()` framing
(oracle, not ground truth).

**Tests:** BFS reachability on a fixture graph; oracle-sentence rendering; MCP-absent fallback is explicit.

### Phase 5 — Permutation planner (core, not TUI)

**Goal:** replace the static 22-task walker with signal-driven, priced, budget-gated proposals.

**Do:**
- New `kuzushi-core` module: `Proposal`/`ProposalSpec`/`Queue` (price = `rounds·cost_per_round·(2 if verify)`, rank by yield, budget gate, EMA recalibrate) + a `trait Generator` with `commits`/`threatmodel`/`intel`/`evolve` impls (ported from `generators/*`).
- A `run_salvo` analog: bounded fan-out + per-round checkpoint (Kuzushi already has background workers + trace; reuse them).
- Rewire the walker: `dispatch_next_planning_task` fires approved proposals best-yield-first instead of popping `PlanningTaskId`. Keep `JourneyProgress` derivation.
- Hunt-phase gate UX in the TUI is the queue's human gate ([k]/[s]/[d]/[a]); headless gets `--approve P-001,P-003` flags (mode parity).

**Watch-outs:** planner **must** live in core (mode-shared); keep the cap-overshoot honesty
(a single in-flight proposal can exceed the cap — cannon's known edge); model selection per
proposal via `resolve_tool_model`.

**Tests:** generator proposals from git/manifest fixtures; queue pricing + budget refusal; EMA
calibration (port `record_result_calibrates_cost_per_round`); rounds == matrix cardinality.

### Phase 6 — Measure / tune (fold into `kuzushi-eval`)

**Goal:** F1 on a labeled corpus, head-to-head vs an imported SARIF, a regression gate, and
prompt self-tuning — as `kuzushi` verbs.

**Do:** add cannon's `score` F1 + `--against SARIF` + baseline `--gate` + train/test `tune`
to `kuzushi-eval`; expose `kuzushi measure` / `kuzushi tune` (or scan `--measure`); feed
`evolve` generator fitness from confirmed-findings/F1. Reconcile `kuzushi-eval`'s
recall-by-tolerance with cannon's precision/F1 into one report.

**Tests:** precision/recall/F1 on a fixture corpus; `--against` apples-to-apples; gate exit-code on regression; holdout split determinism.

### Phase 7 — Engagement folder + strategies + verb collapse (capstone)

**Goal:** one editable `engagement/` folder generated by `aim`; strategies as the variant
axis; 55 modules read as ~8 phase verbs.

**Do:**
- Reorg `.kuzushi/` scattered artifacts into `engagement/{profile.toml, threat-model.md,
  map/, kb/, strategies/, prompts/, context/, authorization.md}`; update **both**
  `workspace_target.rs` path helpers **and** `PlanningTaskId::artifact_relative_path`.
- `aim` as a reorganizer/synthesizer over existing producers (context-snapshot,
  threat-model, entry-points, CPG) that writes the folder; add the genuinely-new
  `shards.yaml` + `kb/` learning loop.
- Strategies (`engagement/strategies/*.toml`) as `{methodology·engines·passes·model·variant}`
  bundles = the planner's variant axis; `deep = pattern + iris-taint + review×2 + invariant`.
- Collapse the catalog: the 13 scanners + 8 hunters become passes/strategies behind Hunt;
  the advanced catalog (Phase 0) keeps the full registry reachable.

**Tests:** engagement round-trips (generate → edit → re-read); strategy expansion into salvo
specs; prior-run reuse still detects artifacts at new paths.

---

## 4. Sequencing & dependencies

```
Phase 0 (surface) ─ independent, reversible ── ship anytime
Phase 1 (ledger) ─┬─→ Phase 3 (verify --votes)
                  ├─→ Phase 6 (measure scores confirmed rows)
                  └─→ Phase 5 (planner outcomes write here)
Phase 2 (prompts) ─ independent ─────────────→ Phase 5 / 7 read prompts
Phase 4 (oracle) ──→ Phase 5 (threatmodel gen) & Phase 3 (reachability lens)
Phase 5 (planner) ─→ Phase 7 (strategies = variant axis)
Phase 6 (measure) ─→ Phase 5 (evolve fitness)   [soft cycle: bootstrap evolve without F1 first]
Phase 7 (engagement) ── capstone, needs 1/2/5
```

**Recommended shippable order:** 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7. Phases 0/1/2/3 deliver
visible value early (honest surface, corroborated findings, tunable prompts, configurable
verify) and de-risk the big Phase 5. The 5↔6 cycle is broken by bootstrapping `evolve`
without a fitness score first (cannon does exactly this — seed genomes at yield 0.7).

---

## 5. Risks & guardrails

- **Model safety (hard gate).** No ported path may inherit cannon's default-model behavior.
  Route everything through `resolve_tool_model` / `ctx.config.model`. `scripts/check-model-safety.mjs` must stay green.
- **Mode parity.** Planner + ledger + prompts live in `kuzushi-core`; TUI gates/editors are
  interactive-only chrome over the same on-disk state. Add each phase to
  `docs/assessments/mode-parity.md`. No TUI-only or CLI-only behavior path.
- **CRAP / clean-code gate.** New functions ≤ complexity 4, < 40 logical lines,
  `pnpm quality:crap-risk` < 7. The planner and merge code are the likeliest offenders — keep
  generators small and side-effect-free (the maps confirm cannon's are pure-core).
- **Dedup-key cutover.** Changing the key touches every row; v3 should rebuild disposable
  projections from source facts/events instead of adding another compatibility migration.
- **Baseline red tests.** Capture the current known-failing set (BDD onboarding + snapshot)
  before Phase 0 so new work is attributable; fix or explicitly quarantine.
- **Cap overshoot honesty.** Preserve cannon's between-proposals gating and surface the
  known single-proposal overshoot in the UI rather than pretending the cap is hard.
- **Backward compatibility is a non-goal** (user's call) — but `.kuzushi/` path moves must be
  migrated, not broken, so existing targets keep working across the reorg.

---

## 6. Open questions for you (blockers on specific phases)

1. **`workspace:export-findings` (Phase 0):** keep `workspace` visible, or relocate the
   export action before hiding it? (It's the one user-facing casualty of the plumbing hide.)
2. **Dedup key (Phase 1):** adopt cannon's exact-line `basename:line:cwe`, or keep Kuzushi's
   `line/8` bucket and just add `sources[]`/sticky on top? Exact-line matches cross-engine
   collisions better; the bucket tolerates off-by-a-few line drift between engines.
3. **Verify strategy (Phase 3):** ship the lightweight `--when/--max/--votes` config on the
   *existing* verifier only, or also port cannon's full multi-lens 2-of-3 verifier as an
   alternative strategy? (The latter is materially more work but is cannon's benchmarked edge.)
4. **measure/tune home (Phase 6):** extend `kuzushi-eval` in place, or build a fresh
   `measure`/`tune` module in `kuzushi-core` that calls into it? (`kuzushi-eval` is recall-shaped
   today; folding in F1 is cleaner but touches its report schema.)
5. **Verb collapse depth (Phase 7):** hard-collapse 55 modules to ~8 verbs (aggressive, matches
   the artifacts), or keep modules as strategy *passes* behind the phase verbs and only reframe
   the surface (safer, reversible)?
