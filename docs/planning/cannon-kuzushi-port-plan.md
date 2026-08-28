# Cannon → Kuzushi port plan (Direction A) — current-tree revision

> **Status:** planning only. No product code changed by this document.
> **Decision (2026-07-02, user):** Direction **A** — port cannon *into* Kuzushi as
> native Rust, keeping Kuzushi's broad surface. Plan-first before any code.
> **Path convention:** Kuzushi's own TypeScript `src/` tree is **retired** (Rust is the
> runtime now); every `src/...` path in this plan — usually written `cannon:src/...` —
> names a file in the external cannon Rust crate above, never Kuzushi's retired `src/`.
> **This doc** re-grounds the port against the **current working tree (2026-07-09)** and
> supersedes the assumptions in `docs/plans/cannon-port-plan.md` (written 2026-07-07).
> The headline change since that plan: **two of its heaviest phases (ledger contract,
> permutation-planner data model) have already substantially landed** as the git-tracked
> `strategy/` + `engagement/` modules and the findings-store fields. This plan re-sequences
> around what is now real.
>
> **Source located:** cannon is at `/workspace/vuln-scan-cannon-harness`
> (crate `cannon` v0.2.0, single binary, ~10k LOC). Fully readable; every cannon claim
> below carries a `cannon:src/...` anchor. Kuzushi claims carry a `crates/...` anchor.

---

## 1. Executive summary

Cannon is a single-binary Rust "AI security harness that reasons": it fires **salvos of
permuted LLM scans** (`focus × variant × model × runs`) at one target, unions and de-dupes
the findings into a **sticky ledger**, runs an **adversarial multi-vote verifier**, and
manages a **signal-driven, budget-gated permutation planner** — all steered through
plain-file prompts and a Ratatui cockpit. It delegates the actual reasoning to the local
`claude` CLI; it owns orchestration, accumulation, triage lifecycle, and cost accounting.

Kuzushi already is the broader product: a live multi-engine scanner (`native_scanners`
runs semgrep/codeql for real), MCP oracle servers (tree-sitter/Joern/CodeQL), a SQLite
findings store with dedup + sticky human triage, `kuzushi-eval` (precision/recall/F1
corpora), a journey/phase spine, an autonomy gate, scan/shell/run mode parity, and the
Workbench cockpit. Direction A folds cannon's four proven subsystems **into** those seams
rather than bolting cannon on as a delegate.

**What is already done (verified in-tree, 2026-07-09):**

- **Ledger contract** — `Finding` now carries `triaged_by: Option<TriageAuthor>`,
  `vuln_source`, `dedup_key`, `corroboration_count: u32`, `sources: Vec<FindingSource>`
  (`crates/kuzushi-core/src/findings/domain/finding_record.rs:70-189`). Sticky human triage
  is enforced (`persistence/open/triage_and_verification.rs:77`; `record_auto_triage` vs
  `append_user_review_decision` split, imported author supported).
- **Planner data model** — `StrategyProposal` (yield_score, expected/approved/actual cost,
  estimated_rounds, findings/confirmed, preflight, resource_risk, status machine) +
  `estimate_strategy_cost` (rounds·cost·2-if-verify — a direct port of cannon's estimator)
  + `calibrated_cost_per_round` (0.7/0.3 EMA — a direct port) + `strategy-queue.jsonl`
  persistence (`crates/kuzushi-core/src/strategy/mod.rs`), plus a **corrections/learning
  layer** that goes beyond cannon (`strategy/correction.rs`). TUI cockpit routing, plain
  parity, and the status-update effect exist (`ShellView::StrategyQueue`,
  `ui_view_models/strategy_queue.rs`, `app/strategy/mod.rs`,
  `app/effects.rs:74`).
- **Engagement harness** — `engagement/harness.toml` with **typed focus intent**
  (`FocusIntent`/`FocusKind`, "focus on sqli" → `CWE-89`) and per-engine enablement + cost
  (`HarnessEngine`) + `budget_usd` (`crates/kuzushi-core/src/engagement/mod.rs`).
- **Prompt provenance** — `prompt_override_path` + `prompt_content_sha256` + a
  `PromptMutation` approval ledger (`crates/kuzushi-core/src/prompt_stack/mod.rs`,
  `options/prompt_paths.rs`).
- **Eval** — `kuzushi-eval` crate with corpora and scoring.

**What cannon still has that Kuzushi does not:**

1. **Signal generators** — cannon mines *evidence* (git history incomplete-fix hunts,
   the repo trust-graph, dependency footguns, bred prompt variants) to **propose** priced
   permutations (`cannon:src/generators/{commits,threatmodel,intel,evolve}.rs`). Kuzushi's
   `StrategyProposal`s are authored by phase-recommendation, not mined from target evidence.
2. **A budget-cap gate at approval** — cannon refuses to approve a proposal that would
   breach the cumulative cap (`cannon:src/queue.rs:219-238` `would_exceed_budget`/`approve`).
   Kuzushi stores per-proposal cost and an EMA helper but has **no cap-enforcing approve**.
3. **Firing approved proposals as a real salvo** — cannon expands a `ProposalSpec` into a
   matrix and runs it, recording actuals back (`cannon:src/main.rs:807` `execute_proposal`).
   Kuzushi's proposals carry a `tool`/`next_input` but there is no approved→fire→record loop.
4. **Engagement-scoped cross-run merge** — cannon's ledger is one-per-target and every
   engine corroborates the same row; Kuzushi merges only within one `scan_id`.
5. **Seed-ingest of external SARIF/semgrep as findings** (cannon `merge_seeds`,
   `cannon:src/ledger.rs:326`) — Kuzushi imports *recon* artifacts but not scanner SARIF
   into the findings table with a `sources[]` tag.
6. **3-level prompt resolution + variant axis** (`cannon:src/prompts.rs:31`).
7. **measure/tune as first-class verbs** — F1, head-to-head `--against <sarif>`, a
   regression `--gate`, and a train/test prompt `tune` (`cannon:src/{bench,tune}.rs`).
   `kuzushi-eval` is recall-shaped and not wired to a `kuzushi` verb.
8. **The verb reframe** — collapse the 55-module catalog toward ~8 phase verbs, and
   generate the editable `engagement/` folder per target.

The remaining work is therefore **smaller and better-seated than the 2026-07-07 plan
assumed**: mostly *connect the already-built planner data model to real evidence and real
firing*, finish the ledger's engagement-scoped merge + seed arm, and add prompts/measure/verb
reframe. The hard invariants are unchanged: **no silent model fallback**, **mode parity**
(core owns policy, TUI owns chrome), and the **CRAP/clean-code gate**.

---

## 2. Source map — cannon (`/workspace/vuln-scan-cannon-harness`)

Single crate, `cannon` v0.2.0. The CLI *is* the phase flow:
`aim → map → permute/queue → fire → triage → manage → prove → chain → fix → measure/tune`
(`cannon:src/main.rs:99-332`).

### 2.1 The phase verbs (CLI)

| Verb | Phase | What it does | Key module |
|---|---|---|---|
| `aim` (alias `threat-model`, `recon`) | AIM | threat-model the target, seed focus areas + Mermaid graph | `stages/threat_model.rs` |
| `map` | AIM | build repo trust-graph → `repo_map.json` (verifier reachability oracle) | `repomap.rs`, `stages/repomap.rs` |
| `permute` | PLAN | run generators → priced/ranked proposals → human gate → fire | `main.rs:884`, `generators/*`, `queue.rs` |
| `queue list/run/clear/budget` | PLAN | inspect / fire-approved / prune / set cap | `main.rs:943` |
| `fire` | FIRE | salvo (`focus×variant×model×runs`) → accumulate → verify → ledger → chain | `main.rs:482`, `runner.rs`, `permute.rs` |
| `triage` (alias `verify`) | TRIAGE | (re)verify ledger findings, N votes | `stages/verify.rs` |
| `manage` (alias `tui`) / `findings` | MANAGE | cockpit / list-set-sync ledger | `tui/mod.rs`, `ledger.rs` |
| `seed` | MANAGE | import SARIF/semgrep/json/csv into ledger (`sources[]`) | `seed.rs`, `sarif.rs` |
| `prove` / `metamorphic` | PROVE | dynamic reproduction / metamorphic perturbation | `dynamic.rs`, `metamorphic.rs` |
| `chain` / `fleet` | CHAIN | compose attack chains from confirmed findings | `stages/chain.rs`, `fleet.rs` |
| `fix` (alias `patch`) | FIX | draft patches + independent review (never applied) | `stages/patch.rs` |
| `measure` (alias `bench`) / `tune` | MEASURE | precision/recall/F1, `--against`, `--gate`, train/test tune | `bench.rs`, `tune.rs` |

### 2.2 The four subsystems that matter for the port

- **Findings ledger** (`cannon:src/ledger.rs`, 673 LOC). `LedgerFinding` keyed by
  `signature = basename:line:cwe` (`artifacts.rs`); `sources: Vec<String>`
  (`ledger.rs:63`); `triaged_by ∈ {auto,human,imported}` guarded in `merge`
  (`ledger.rs:275`), `apply_verdicts` (`:393`), `sync_from_md` (`:513`); `corroboration`
  + `rounds` (`:50-52`); JSON ⇄ `VULN_FINDINGS.md` ⇄ `findings.sarif`; `merge_seeds`
  adds a source to an existing row or inserts as `new/imported` (`:326`);
  `calibration_block` feeds prior false-positives back to the verifier (`:557`).
  Concurrency-safe via re-load-under-lock `Ledger::update` (`:183`).

- **Prompts-as-files** (`cannon:src/prompts.rs`, 81 LOC). `resolve_prompt_path` searches
  `target/prompt_overrides/<name>.md` → `prompts/variants/<variant>/<name>.md` →
  `prompts/<name>.md` (`:31`); `load_prompt` stamps `sha256[..16]` of the raw template
  and interpolates `{tokens}` leaving unknowns intact (`:53-81`).

- **Permutation planner** (`cannon:src/queue.rs` 405, `generators/*`, `permute.rs`,
  `main.rs:648-985`). Generators are string-dispatched free functions that **propose**:
  `commits` (git incomplete-fix hunts + churn), `threatmodel` (trust-graph flow audits),
  `intel` (dep footguns + optional live-CVE research), `evolve` (bred prompt variants,
  fitness = confirmed findings). Each returns `Vec<Proposal>` with a `ProposalSpec`
  (`focus×variants×models×runs`, `queue.rs:36`). `Queue` prices
  (`estimate = rounds·cost_per_round·(2 if verify)`, `:168`), ranks by `yield_score`,
  gates at `budget_cap` (`would_exceed_budget`/`approve`, `:219`), and EMA-recalibrates
  `cost_per_round` from actual spend (`record_result`, `:255`). Firing =
  `execute_proposal` → `build_matrix` → `run_salvo` → accumulate → (verify) →
  `Ledger::update(merge)` → `record_result` (`main.rs:807-881`).

- **Measure/tune** (`cannon:src/{bench,tune}.rs`). `bench::score → {tp,fp,fn,precision,
  recall,f1}`; `--against <sarif>` grades an external tool with the same scorer; `--gate`
  fails (exit 2) on F1 regression past a baseline+margin (`tune::gate`, `:56`);
  `split_corpus` deterministic index-stripe train/test (`tune.rs:17`); `select_best` picks
  the winning prompt variant by F1 then precision then name (`:40`).

- **Detectors** (`cannon:src/detector.rs:24`): **3 arms** — `static_review` (LLM agent),
  `secrets` (deterministic), `dynamic` (build+run+witness). Semgrep/CodeQL/SARIF enter
  **only** as ingested SARIF via `seed.rs` — cannon never runs them live.

### 2.3 On-disk contract cannon owns

`targets/<t>/config.yaml` (source_root/detector/focus_areas/engagement_context, with a
**containment guard** refusing a `source_root` outside the target/cwd unless
`CANNON_ALLOW_EXTERNAL_SOURCE_ROOT=1`, `cannon:src/config.rs:89`) + `context/` +
`prompt_overrides/` + `.cannon/{ledger.json, queue.json, repo_map.json}` +
`VULN_FINDINGS.md` + `findings.sarif` + `CHAINS.md` + `PATCHES/`.

---

## 3. Target map — Kuzushi (what the port lands in)

### 3.1 Dispatch + mode boundary (unchanged, shared)

All three modes converge on `ModuleRegistry::prepare_tool_input(...)` →
`dispatch_prepared_tool_with_runtime(...)`
(`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs`). Descriptor-driven
option validation, stored-option merge, trace scoping, runtime wrap (incl. `TracedRuntime`),
and output normalization live here. **Every ported behavior must land as a descriptor/executor
here or in a shared core module — not a per-mode path.**

### 3.2 The seams cannon maps onto — and their current state

| cannon subsystem | Kuzushi seam (current tree) | State |
|---|---|---|
| Ledger `sources[]` / sticky / corroboration | `findings/domain/finding_record.rs:70-189` (`sources`, `triaged_by`, `corroboration_count`, `dedup_key`, `vuln_source`) + `persistence/open/triage_and_verification.rs:77` sticky guard | **Mostly done.** Remaining: engagement-scoped cross-`scan_id` merge; seed-ingest arm. |
| `Queue`/`Proposal` pricing/EMA/budget | `strategy/mod.rs` (`StrategyProposal`, `estimate_strategy_cost`, `calibrated_cost_per_round`, `strategy-queue.jsonl`) + `strategy/correction.rs` | **Data model done.** Remaining: budget-cap approve gate; generators; approved→fire→record loop. |
| `config.yaml` + typed focus + engine enablement | `engagement/mod.rs` (`EngagementHarness`, `FocusIntent`/`FocusKind`, `HarnessEngine`, `budget_usd`, `harness.toml`) | **Started.** Remaining: full `engagement/` folder (threat-model/map/kb/strategies/prompts/context) + `aim` synthesizer. |
| Prompts 3-level + sha | `options/prompt_paths.rs` + `prompt_stack/mod.rs` (`prompt_content_sha256`) + static 4-arm default match | **1-level + provenance done.** Remaining: variant axis + packaged-base search order; extend beyond 4 verbs. |
| Verifier multi-vote / reachability oracle | `application/sast_scan/taint_iris_next_hunt_input.rs` (`SastScanRequests`, boolean `needs_verification()`) + MCP servers `kuzushi-mcp-{joern,codeql,treesitter}` | **All-or-nothing verify.** Remaining: `when/max/votes` config; wrap MCP as reachability oracle. |
| measure/tune | `crates/kuzushi-eval` (recall-shaped, standalone `main.rs`) | **Corpora + scoring exist.** Remaining: F1 + `--against` + `--gate` + `tune`; wire a `kuzushi` verb. |
| Detectors (static/secrets/dynamic) | `modules/native_scanners/` (runs semgrep/codeql/secrets/iac live) | **Superset already.** No replacement — add cannon's seed-ingest alongside. |
| Journey/phase spine | `ui_view_models/journey.rs` (reality-derived 組/崩/作/掛) + `app/onboarding/task_id.rs` (`PlanningTaskId` static walker) | **Derivation clean, keep.** The static walker is the execution seam the planner replaces. |
| Autonomy gate | `modules::autonomy::gate(name, posture)` in dispatch (recon/hunt/confirm/fix ceiling) | Keep. Planner-fired tools must pass the gate. |
| CLI verbs | `crates/kuzushi-cli/src/command.rs` `Command { Shell, Scan, Findings, Finding, Decision }` | No `aim/permute/measure/tune/seed` yet. |

### 3.3 Invariants the port must not break

- **No silent model fallback** — `runtime/policy/no_silent_fallback.rs` +
  `scripts/check-model-safety.mjs`. Cannon's `resolve_model(...).unwrap_or("opus")`
  (`cannon:src/main.rs:52`) is **forbidden**; every ported path resolves via
  `resolve_tool_model` / `ctx.config.model`.
- **Mode parity** — planner core, ledger, prompts, engagement, measure all live in
  `kuzushi-core`; the TUI queue gate/editor are interactive chrome over shared on-disk
  state; headless reaches the same via CLI verbs/flags. Update
  `docs/assessments/mode-parity.md` per phase.
- **`.kuzushi` formats + paths** — additive migrations only; path moves migrated, not broken.
- **CRAP/clean-code gate** — new fns ≤ complexity 4, < 40 logical lines,
  `pnpm quality:crap-risk` < 7. Generators + merge are the likeliest offenders; keep them
  small and side-effect-free (cannon's are pure — mirror that).

---

## 4. Integration design — port in, map on, or cut

### 4.1 Ports in as-is (new native Rust, no existing analog)

- **Signal generators** as a `trait Generator` in `kuzushi-core` (a Kuzushi improvement
  over cannon's string dispatch). Impls port `generators/{commits,threatmodel,intel,evolve}`
  — pure functions that read git/manifests/threat-graph and emit `StrategyProposal`s. They
  must be side-effect-light and testable off git fixtures.
- **Budget-cap gate** — port `queue.rs::{committed, would_exceed_budget, approve}` onto the
  `StrategyProposal` queue, sourcing the cap from `EngagementHarness.budget_usd`. Preserve
  cannon's honest **between-proposals** enforcement (a single in-flight proposal can overshoot
  — surface it, don't pretend the cap is hard).
- **Approved → fire → record loop** — an `execute_proposal` analog that expands a proposal's
  spec into a salvo of `dispatch_prepared_tool_with_runtime` calls (reusing Kuzushi's
  background workers + trace), then `mark_done` with real cost/findings/confirmed and EMA
  re-calibrates. This is the missing connective tissue between the built data model and reality.
- **Seed-ingest arm** — a `findings seed <sarif|semgrep|json|csv>` path porting
  `merge_seeds` semantics onto the SQLite store: dedup on `dedup_key`, append to
  `sources[]`, insert new rows as `triaged_by = imported`.
- **measure/tune deterministic core** — `bench::score` F1, `tune::{split_corpus, select_best,
  gate, Baseline}` fold into `kuzushi-eval` (they are pure; direct ports).

### 4.2 Maps onto existing abstractions (do NOT duplicate)

- Cannon `Queue`/`Proposal` → **the existing `StrategyProposal`/strategy-queue**. Do not
  introduce a second `Proposal` type; extend the built one with the missing generator source,
  budget gate, and firing loop.
- Cannon `config.yaml` + focus intent → **the existing `EngagementHarness` + `FocusIntent`**.
- Cannon reachability `repo_map.json` oracle → **the existing MCP servers**
  (Joern `taint_paths`/`callers_of`, CodeQL `flows_for_cwe`). Do not rebuild cannon's ad-hoc
  graph; optionally derive a light `RepoGraph` from `entry-points.json` + CPG only for the
  `threatmodel` generator's `reachable_from_untrusted` need.
- Cannon `static/secrets/dynamic` detectors → **`native_scanners`** (a live superset).
- Cannon sticky ledger → **the existing `triaged_by`/`record_auto_triage` split** — already
  enforced; only the merge scope + seed arm are new.
- Cannon prompt provenance sha → **`prompt_content_sha256` + `prompt_stack`** — extend the
  resolver, reuse the provenance.

### 4.3 Cut / quarantine (prior-direction surface, per the alignment audit)

Legacy binary-exploit and catalog-era surfaces do not serve the control-room reframe:
`pwn`, `uaf_hunt`, `exploit-chain` (+ attack-tree viz page), `vendor_assessment`,
`chrome_rce`, `offense`, the `kz` duplicate binary, and the `Catalog/Module/ModuleRun/Tools/
Story` "browse & run" shell views. Per the PRD non-goal, **quarantine** (keep `.deferred()`,
mark experimental) rather than delete unless the user says otherwise — see Open Decisions.

### 4.4 What the ported flow looks like end-to-end

```
aim ──► engagement/harness.toml (+ threat-model, entry-points, CPG)   [engagement/, MCP producers]
  │        typed focus intent ─► CWE tags ─► re-rank
  ▼
permute ─► generators mine evidence ─► StrategyProposals (priced, ranked, budget-gated)
  │        commits · threatmodel · intel · evolve            [strategy/ + new generators]
  ▼
approve (TUI gate k/s/d/a  |  headless --approve P-…)  ─► fire salvo (focus×variant×model×runs)
  │                                                          [dispatch_prepared_tool_with_runtime]
  ▼
findings store (dedup_key, sources[], corroboration_count, sticky triaged_by)   [findings/]
  │        + seed-ingest SARIF/semgrep as sources[]
  ▼
confirm (verify when/max/votes, MCP reachability oracle)   [sast_scan + kuzushi-mcp-*]
  ▼
measure/tune (F1, --against, --gate) ─► evolve fitness      [kuzushi-eval]
```

---

## 5. Phased migration

Each phase ends green (tests + `pnpm quality:crap-risk`) and is independently shippable.
Ordered by dependency; Phase 0 is decision-independent and reversible.

### Phase 0 — Baseline + surface honesty (reversible, start here)

**Goal:** an attributable test baseline and a home surface that reads as a cockpit, not a
41-tile catalog. No engine change.

- Capture the current known-red set (prior audits cite BDD-onboarding + a snapshot; verify
  first) so later regressions are attributable.
- Hide plumbing modules (`builtin_module(` → `hidden_module(`) — they stay executable by name;
  keep every "N modules" count funnelling through `ModuleRegistry::modules()`.
- Confirm Workbench is the landing surface and the retired browsing views route into it.
- Update count assertions + the `is_hidden_module_id()` allowlist + `cutover_cli.rs` guard.

**Watch-out:** `workspace:export-findings` is user-facing — do not hide it without relocating
the export action (Open Decision #1). **Risk:** low. **Rollback:** revert the hidden flags.

### Phase 1 — Finish the ledger (engagement-scoped merge + seed arm)

**Goal:** one row per real defect across *all* engines in an engagement, plus external-scanner
seed ingest. (The `sources[]`/sticky/corroboration fields already exist — this closes the gap.)

- Introduce an **engagement/repo-scoped merge**: merge on `dedup_key` across `scan_id` so
  `native_scanners` runs corroborate one row (today merge is `where scan_id=?1`). Add an
  engagement scan-id or a cross-scan reconcile pass; bump `corroboration_count` on collision.
- Add the **seed-ingest** path (`findings seed`): port `merge_seeds` semantics onto SQLite —
  dedup on `dedup_key`, append `sources[]`, insert new as `triaged_by = imported`.
- Reconcile the dedup key (Open Decision #2: keep the `line/8` bucket vs cannon's exact line).

**Tests:** cross-engine corroboration count; seed-dedups-and-adds-source (port cannon's
`seed_dedups_against_existing_and_adds_new`); sticky-across-remerge already guarded — extend to
the cross-scan merge; migration idempotency. **Risk:** medium (touches the store). **Rollback:**
merge scope behind a flag; seed arm is additive.

### Phase 2 — Prompts-as-files (3-level + variant axis)

**Goal:** every phase prompt resolves `project override → variant → packaged base`, sha-stamped
in run metadata.

- Turn the static default match into a **data table**; give the resolver an ordered search path
  with a **variant** axis and a packaged base; extend past the current 4 verbs to the phase verbs.
- Reuse `prompt_content_sha256` + `prompt_stack`; stamp sha into run-reproducibility metadata.

**Tests:** resolution order; sha stability; unknown-token passthrough (cannon `interpolate`).
**Risk:** low. **Rollback:** revert resolver; table falls back to the static default.

### Phase 3 — Confirm/verify config (`when` / `max` / `votes`)

**Goal:** "verify only what you ask for, configured," instead of all-or-nothing.

- Add `when` (severity floor), `max` (cap), `votes` to `SastScanRequests` + `from_input`
  (`taint_iris_next_hunt_input.rs`); filter/sort/truncate the true-positive fingerprint set.
- `votes` consumes Phase 1's `corroboration_count`. Keep `needs_verification()` as master on/off.
- **Model safety:** vote/lens model selection via `resolve_tool_model` only.

**Tests:** severity filter, cap truncation, votes threshold; **bare-scan-verifies-nothing**
invariant holds. **Risk:** low–medium. **Rollback:** default `when=any, max=0, votes=1` = today.

### Phase 4 — Reachability oracle wiring

**Goal:** the verifier and the `threatmodel` generator can ask "reachable from an untrusted
entry?" deterministically.

- Wrap MCP servers (Joern/CodeQL/tree-sitter) as the verifier's oracle input; keep cannon's
  **hedged** `describe()` framing (oracle, not ground truth).
- Derive a light `RepoGraph`-analog from `entry-points.json` + CPG exposing
  `reachable_from_untrusted` for the generator.

**Tests:** BFS reachability on a fixture; oracle-sentence rendering; **MCP-absent path is an
explicit hedge, not a silent skip**. **Risk:** medium (external tool lifecycles). **Rollback:**
oracle is advisory; absent → hedged sentence.

### Phase 5 — Generators + budget gate + firing loop (the connective phase)

**Goal:** the already-built `StrategyProposal` queue is fed by mined evidence, gated by a
budget cap, and actually fires. This is the heart of the remaining work.

- **Generators** — `trait Generator` in `kuzushi-core` with `commits` / `threatmodel` /
  `intel` / `evolve` impls ported from `cannon:src/generators/*`, each emitting priced
  `StrategyProposal`s (reuse `estimate_strategy_cost`). Bootstrap `evolve` without a fitness
  score first (cannon seeds genomes at ~0.7) to break the 5↔6 cycle.
- **Budget gate** — port `committed`/`would_exceed_budget`/`approve` onto the queue, cap from
  `EngagementHarness.budget_usd`; preserve between-proposals honesty.
- **Firing loop** — approved proposals expand to a salvo via
  `dispatch_prepared_tool_with_runtime` (respecting the autonomy gate), `mark_running` →
  run → `mark_done` with actuals → `calibrated_cost_per_round`. Rewire the
  `dispatch_next_planning_task` choke point to fire approved proposals best-yield-first
  instead of popping `PlanningTaskId`. Keep `JourneyProgress` derivation.
- **Parity:** TUI queue gate (k/s/d/a) is chrome; headless gets `--approve P-001,P-003`.

**Watch-outs:** planner **must** live in core; per-proposal model via `resolve_tool_model`;
cap-overshoot surfaced. **Tests:** generator proposals from git/manifest fixtures; budget refusal;
EMA calibration (port `record_result_calibrates_cost_per_round`); rounds == matrix cardinality
(port `rounds_match_the_matrix_cardinality`). **Risk:** high (the deepest change). **Rollback:**
generators/firing behind an engagement flag; the static walker stays as fallback until parity.

### Phase 6 — Measure / tune (fold into `kuzushi-eval`, wire a verb)

**Goal:** F1 on a labeled corpus, head-to-head vs an imported SARIF, a regression gate, and
prompt self-tuning — as `kuzushi` verbs.

- Fold cannon's `score`/F1 + `--against SARIF` + baseline `--gate` + `split_corpus`/`select_best`
  into `kuzushi-eval`; expose `kuzushi measure` / `kuzushi tune` (or `scan --measure`).
- Feed `evolve` fitness from confirmed-findings / F1 (closes the 5↔6 loop).

**Tests:** precision/recall/F1 on a fixture corpus; `--against` apples-to-apples; gate exit-code
on regression; holdout determinism (port `split_is_deterministic_and_striped`). **Risk:** medium
(touches `kuzushi-eval` report schema). **Rollback:** new verb is additive.

### Phase 7 — Engagement folder + strategies + verb collapse (capstone)

**Goal:** one editable `engagement/` folder generated by `aim`; strategies as the variant axis;
55 modules read as ~8 phase verbs.

- Grow `engagement/` beyond `harness.toml` into `{profile.toml, threat-model.md, map/, kb/,
  strategies/, prompts/, context/, authorization.md}`; update **both** `workspace_target.rs`
  path helpers **and** `PlanningTaskId::artifact_relative_path` (double-encoded today — a reorg
  must touch both or prior-run reuse breaks).
- `aim` as a reorganizer/synthesizer over existing producers (context-snapshot, threat-model,
  entry-points, CPG) that writes the folder + a learning `kb/`.
- Strategies (`engagement/strategies/*.toml`) = `{methodology·engines·passes·model·variant}`
  bundles = the planner's variant axis (`deep = pattern + iris-taint + review×2 + invariant`).
- Verb collapse (Open Decision #5): hard-collapse to ~8 verbs vs modules-as-passes behind phases.

**Tests:** engagement round-trip (generate → edit → re-read); strategy expansion into salvo specs;
prior-run reuse detects artifacts at new paths. **Risk:** high (path moves). **Rollback:** migrate
paths, keep read-compat for old layout for one release.

### Sequencing

```
Phase 0 (baseline+surface) ── independent, reversible ── ship anytime
Phase 1 (ledger merge+seed) ─┬─► Phase 3 (verify votes)  ─┬─► Phase 5 (firing writes here)
                             ├─► Phase 5 (proposal outcomes)
                             └─► Phase 6 (measure scores confirmed rows)
Phase 2 (prompts) ── independent ─────────────► Phase 5 / 7 read prompts
Phase 4 (oracle) ──► Phase 5 (threatmodel gen) & Phase 3 (reachability lens)
Phase 5 (generators+gate+fire) ─► Phase 7 (strategies = variant axis)
Phase 6 (measure) ─► Phase 5 (evolve fitness)   [soft cycle: bootstrap evolve without F1 first]
Phase 7 (engagement) ── capstone, needs 1/2/5
```

**Recommended order:** 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7. Because the planner data model and
ledger fields already exist, Phases 1/3/5 are *finishing* work, not greenfield — the risk on
the historically-scariest phase (5) is materially lower than the 2026-07-07 plan assumed.

---

## 6. Cut / keep matrix

| Item | Verdict | Rationale |
|---|---|---|
| `native_scanners` (live semgrep/codeql/secrets/iac) | **KEEP** | Superset of cannon's 3 detector arms; cannon only ingests SARIF. |
| MCP servers (tree-sitter/Joern/CodeQL) | **KEEP + reuse** | Stronger than cannon's ad-hoc `repo_map.json`; become the reachability oracle (Phase 4). |
| `StrategyProposal` + strategy-queue | **KEEP + extend** | Already the ported planner data model; add generators/gate/firing (Phase 5). |
| `EngagementHarness` + `FocusIntent` | **KEEP + grow** | Already cannon's config + typed focus; grow into the folder (Phase 7). |
| Findings store (`sources[]`/sticky/corroboration) | **KEEP + extend** | Fields landed; add cross-scan merge + seed arm (Phase 1). |
| `kuzushi-eval` | **KEEP + fold** | Corpora exist; fold in F1/gate/tune + a verb (Phase 6). |
| Journey/phase derivation (`journey.rs`) | **KEEP** | Reality-derived, tool-agnostic — the clean spine. |
| `PlanningTaskId` static walker | **REPLACE** | Execution seam the planner supersedes (Phase 5); keep as fallback until parity. |
| Autonomy gate | **KEEP** | Planner-fired tools pass through it. |
| Prompt provenance (`prompt_stack`) | **KEEP + extend** | Add 3-level + variant resolution (Phase 2). |
| Cannon JSON ledger / `VULN_FINDINGS.md` round-trip | **DO NOT IMPORT** | Kuzushi's SQLite store is canonical; MD round-trip is an optional nice-to-have later. |
| Cannon `--model` default fallback | **REJECT** | Violates no-silent-fallback; use `resolve_tool_model`. |
| `pwn`, `uaf_hunt`, `exploit-chain` (+ attack-tree page), `vendor_assessment`, `chrome_rce`, `offense` | **QUARANTINE** (`.deferred()`, experimental) | Prior-direction binary-exploit surface; delete only on user call. |
| `kz` duplicate binary | **CUT** | ROADMAP P0.2 already orders removal. |
| `Catalog/Module/ModuleRun/Tools/Story` browse-&-run views | **FOLD** into Workbench/advanced catalog | Catalog-era product the reframe retires. |
| `src/modules` TS SDK (4.6k LOC) | **DECISION NEEDED** | No live consumer — real external-author audience or cut? (Open Decision #6.) |

---

## 7. Open decisions for the operator

1. **`workspace:export-findings` (Phase 0):** keep `workspace` visible, or relocate the export
   action (e.g. a Fix-phase `findings export` verb) before hiding plumbing? It is the one
   user-facing casualty of the plumbing hide.
2. **Dedup key (Phase 1):** keep Kuzushi's `line/8` bucket (tolerates cross-engine line drift)
   or adopt cannon's exact `basename:line:cwe` (tighter cross-engine collisions)? This changes
   how aggressively multiple engines merge onto one row.
3. **Verify strategy (Phase 3):** ship only lightweight `when/max/votes` on the existing
   verifier, or **also** port cannon's full multi-lens 2-of-3 verifier as an alternative
   strategy? The latter is cannon's benchmarked precision edge but materially more work.
4. **Budget-cap semantics (Phase 5):** hard cap that can refuse an in-flight proposal (needs
   pre-flight cost bounding) vs cannon's honest between-proposals cap that can overshoot once?
   Affects how the cap chip reads and how "spend halt" behaves.
5. **Verb-collapse depth (Phase 7):** hard-collapse the 55 modules to ~8 phase verbs
   (aggressive, matches the artifacts) or keep modules as strategy *passes* behind the phase
   verbs and only reframe the surface (safer, reversible)?
6. **`src/modules` TypeScript SDK:** real external-module-author audience to preserve, or cut
   it with the catalog-era surface?
7. **This vs the prior plan doc:** `docs/plans/cannon-port-plan.md` (2026-07-07) is now partly
   stale (its Phases 1 and 5 have landed). Retire/redirect it to this doc, or keep both?

---

## 8. Risks

- **Model safety (hard gate).** No ported path may inherit cannon's default-model behavior.
  Route everything through `resolve_tool_model` / `ctx.config.model`;
  `scripts/check-model-safety.mjs` stays green. Highest exposure: generator model selection
  and verify votes/lenses (Phases 3, 5).
- **Mode parity.** Planner + ledger + prompts + engagement + measure live in `kuzushi-core`;
  TUI gates/editors are interactive-only chrome over the same on-disk state. Add each phase to
  `docs/assessments/mode-parity.md`. No TUI-only or CLI-only behavior path.
- **CRAP / clean-code.** New fns ≤ complexity 4, < 40 logical lines,
  `pnpm quality:crap-risk` < 7. Generators + cross-scan merge are the likeliest offenders — keep
  generators pure and small (cannon's are).
- **Double-encoded paths (Phase 7).** Map-phase artifact paths live in **both**
  `workspace_target.rs` and `PlanningTaskId::artifact_relative_path`; a reorg must update both or
  prior-run reuse detection silently breaks.
- **Dedup-key cutover (Phase 1).** Changing the key touches every row; prefer rebuilding
  disposable projections from source facts over stacking another compatibility migration.
- **Cap-overshoot honesty (Phase 5).** Preserve cannon's between-proposals gating and surface
  the known single-proposal overshoot rather than pretending the cap is hard.
- **Baseline red tests.** Capture the current known-failing set before Phase 0 so new work is
  attributable; fix or explicitly quarantine.
- **Scope containment.** Cannon's `source_root` containment guard (`config.rs:89`) is a good
  pattern — Kuzushi already refuses cwd fallback (PR #64) and honors `scope.toml`; keep parity
  when `engagement/harness.toml` gains a source-root field so a hostile harness can't redirect
  scan/exec scope.
- **Backward compatibility is a non-goal** (user's call) — but `.kuzushi/` path moves must be
  *migrated*, not broken, so existing targets keep working across the reorg.

---

### Appendix — key file anchors

**cannon:** `src/main.rs` (CLI + fire/permute/queue), `src/ledger.rs` (sticky ledger +
`merge_seeds`), `src/queue.rs` (pricing/budget/EMA), `src/generators/{commits,threatmodel,
intel,evolve}.rs`, `src/permute.rs` (`build_matrix`), `src/detector.rs` (3 arms),
`src/prompts.rs` (3-level+sha), `src/{bench,tune}.rs` (F1/gate/split), `src/config.rs`
(containment guard), `src/stages/{verify,chain,patch,threat_model,repomap}.rs`.

**Kuzushi:** `crates/kuzushi-core/src/findings/domain/finding_record.rs` (Finding fields),
`.../findings/persistence/open/triage_and_verification.rs` (sticky guard),
`.../strategy/mod.rs` + `strategy/correction.rs` (planner data model),
`.../engagement/mod.rs` (harness + focus intent),
`.../modules/builtins/with_v2_builtins/execution.rs` (dispatch boundary),
`.../modules/application/sast_scan/taint_iris_next_hunt_input.rs` (verify gate),
`.../options/prompt_paths.rs` + `.../prompt_stack/mod.rs` (prompt provenance),
`.../runtime/policy/no_silent_fallback.rs` (model safety),
`crates/kuzushi-eval/` (corpora + scoring),
`crates/kuzushi-tui/src/ui_view_models/journey.rs` (phase derivation),
`crates/kuzushi-tui/src/app/onboarding/task_id.rs` (`PlanningTaskId` walker — the replace seam),
`crates/kuzushi-tui/src/{ui_view_models/strategy_queue.rs, app/strategy/mod.rs}` (cockpit),
`crates/kuzushi-cli/src/command.rs` (verb surface — add aim/permute/measure/tune/seed).
