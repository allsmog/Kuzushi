# Tier-3 review — the "do this first" cannon-port increment

> **Status:** review + concrete next-increment spec. No product code changed by this
> document. Read-only pass over the current working tree (2026-07-09) and the external
> cannon crate (`/Users/operator/vibe-code/vuln-scan-cannon-harness`, v0.2.0).
> **Supersedes nothing** — it selects and details the single highest-leverage wedge
> from `cannon-kuzushi-port-plan.md` (Phase 5) and `control-room-build-or-cut-plan.md`
> (Wave F3), after validating both against real code.

---

## 0. TL;DR

- **The plans are ~90% accurate.** Every "already landed" claim I spot-checked is real
  (ledger fields, `StrategyProposal` + cost estimator + EMA, `harness.toml`, no
  `measure`/`aim`/`tune`/`seed` in `command.rs`, `sast:scan` composes carlini/systems-hunt).
- **Three claims are overstated** — the approve→fire loop **already exists** (only the
  *record* half is missing), a fire-time **budget gate already exists** (just not the
  harness cap and not at approve), and `kuzushi-eval` **already computes precision**, not
  just recall. Details in §1.
- **Recommended wedge: close the strategy loop** — price proposals, enforce a real
  cap **at approve** from `harness.toml budget_usd`, and **record actuals back on
  completion** (`mark_done` + EMA recalibrate). This turns ~200 lines of already-shipped
  but **dormant** machinery into a working steer loop and is the hard prerequisite for
  generators, `measure`, and `evolve`. See §2.
- **Next two increments:** (F1) the `kuzushi measure` verb; (F2) the first evidence
  **generator** (`commits`) feeding the now-live priced queue. See §3.

---

## 1. Validation of the two plans against real code

### 1.1 Confirmed-correct "already landed" claims

| Claim | Verified at |
|---|---|
| `Finding` carries `sources: Vec<FindingSource>`, `triaged_by: Option<TriageAuthor>`, `corroboration_count: u32`, `dedup_key: Option<String>`, `vuln_source` | `crates/kuzushi-core/src/findings/domain/finding_record.rs:117,128,136,143,155`; `compute_dedup_key` at `:200` |
| `StrategyProposal` + `estimate_strategy_cost` (rounds·cost·2-if-verify) + `calibrated_cost_per_round` (0.7/0.3 EMA) + `STRATEGY_QUEUE_FILE = "strategy-queue.jsonl"` | `crates/kuzushi-core/src/strategy/mod.rs:8,15,286,291`; status machine `Proposed→Approved→Rejected→Running→Done→Failed` at `:144` |
| Corrections/learning layer beyond cannon | `crates/kuzushi-core/src/strategy/correction.rs` |
| `EngagementHarness` + `harness.toml` + typed `FocusIntent`/`FocusKind` ("focus on sqli" → `CWE-89`) + `HarnessEngine` + `budget_usd` | `crates/kuzushi-core/src/engagement/mod.rs:9,13,24,32,47,134` |
| `engagement:aim` tool wired | `crates/kuzushi-core/src/modules/registry/dispatch_catalog_tool.rs:53`; registration `builtin_registration.rs:298` |
| `ShellView::StrategyQueue` + `strategy approve/reject/fire` verbs | specs `commands/shell_command_specs/options_tasks.rs:59,74`; reducer `crates/kuzushi-tui/src/app/strategy/mod.rs` |
| **No** `Command::Measure/Aim/Tune/Seed` arm | `crates/kuzushi-cli/src/command.rs` has only `Shell, Scan, Findings, Finding, Runs, Export, Run, Decision, …` |
| `sast:scan` umbrella composes carlini + systems-hunt | `crates/kuzushi-core/src/modules/application/sast_scan/run_sast_scan.rs:269,271,292,329,331` — **guardrail is real**; both are `.deferred()`/hidden but load-bearing for the default scan. Do not cut. |
| `kuzushi-eval` crate exists with corpora + scoring | `crates/kuzushi-eval/src/{scoring,report,runner,oracle_matching}.rs` |

### 1.2 Overstated / needs correction (load-bearing for the wedge)

1. **"There is no approved→fire→record loop" (cannon-port §1 bullet 3) is HALF-wrong.**
   The approve→**fire** half is fully built: `StrategyCommand::Fire` →
   `strategy_fire_effects` → `ShellEffect::FireNextApprovedStrategy` →
   `fire_next_approved_strategy_effect` picks the next `Approved` runnable proposal,
   marks it `Running`, and dispatches its `tool` + `next_input` through the shared
   `reduce_run_tool` path (`crates/kuzushi-tui/src/app/strategy/mod.rs:59-110,168-178`).
   **What is genuinely missing is only the RECORD half:** `mark_done` (`strategy/mod.rs:263`)
   has **zero non-test callers** — nothing calls it on tool completion, so a fired
   proposal is stuck in `Running` forever, actuals (`actual_cost_usd`, `findings_count`,
   `confirmed_count`) are never recorded, and `calibrated_cost_per_round` is **never fed**.
   The EMA is dead code with no input.

2. **"No cap-enforcing approve" (cannon-port §1 bullet 2) is overstated.** A budget gate
   *does* exist — `strategy_exceeds_budget` at *fire* time
   (`app/strategy/mod.rs:180-201`) — but it (a) fires against the **session cost-cap**
   (`session().session_budget_usd()`), not `harness.toml budget_usd`; (b) runs at **fire**,
   not **approve**; and (c) is effectively inert today because proposals arrive **unpriced**
   (see #3), so `approved_cost_usd`/`expected_cost_usd` are both `None` → `0.0` → never
   blocks. The correct statement is "the cap is neither the harness cumulative cap nor
   enforced at approve, and is dead because proposals are unpriced."

3. **Proposals are created UNPRICED.** The one and only producer,
   `persist_strategy_proposals` in
   `crates/kuzushi-core/src/capabilities/module_recommender/adapters.rs:87-176`, builds every
   `StrategyProposal` with `expected_cost_usd: None`, `estimated_rounds: None`,
   `yield_score: None` (`:157-160`). So `estimate_strategy_cost` and
   `calibrated_cost_per_round` — both shipped and tested — have **no live caller in the
   product path**. This is the crux: the pricing machinery exists but is disconnected at
   both ends (creation and completion).

4. **`kuzushi-eval` is not "recall-only".** `report.rs`/`scoring.rs` already compute
   **precision** (`precision_for_hits`) *and* recall (`recall_by_tolerance`)
   (`scoring.rs:24-25,39-40` in `crates/kuzushi-eval`). The crate *description* says "Recall
   scorer" but the code is precision+recall. What is genuinely missing for `measure` is
   **F1**, `--against <sarif>` head-to-head, and the `--gate` regression exit-code — not
   the base scorer. Scope F1 accordingly (it's `2·p·r/(p+r)` over existing numbers).

**Net:** the plans point at the right work; the wedge is smaller and better-seated than
even the re-grounded cannon-port plan states — the strategy loop is one hook (record-back)
and one pricing call away from being real.

---

## 2. Recommended wedge — **close the strategy loop**

> Price proposals at creation → enforce a real budget cap **at approve** from
> `harness.toml` → **record actuals back** on completion (`mark_done` + EMA recalibrate).
> One core-owned data path; a single TUI completion hook. Everything else is already built.

### 2.1 Why this wedge (leverage × risk × unblocks-later)

- **Leverage — highest of the three candidates.** It activates ~200 lines of shipped-but-
  dormant code (the whole `StrategyProposal` cost model, `estimate_strategy_cost`,
  `calibrated_cost_per_round`, the fire loop, the queue view). Candidate (a) `measure` is a
  leaf that unblocks only `tune`; candidate (b) surface-reframe produces **no new
  capability** and mostly churns count-assertions. This wedge is the connective tissue the
  entire Direction-A vision hangs on: "signal-driven, budget-gated, self-calibrating
  salvos."
- **Unblocks later phases directly.** Generators (Phase 5) need a **priced, cap-gated
  queue to fire into** and **calibration data to price against** — both delivered here.
  `evolve` fitness (Phase 6) needs `confirmed_count` recorded back — delivered here.
  `measure`/`tune` consume the same actuals. Nothing downstream works until the loop closes.
- **Risk — medium, contained.** All *policy* (pricing, cap check, record-back) lands as
  **pure core functions** in `strategy/mod.rs`; the TUI adds one completion hook that calls
  them. No model selection is touched → **trivially no-silent-fallback-safe**. The one real
  design question (correlating a finished run back to its proposal) is answered cleanly by
  Kuzushi's **single-slot `JobHub`**: at most one proposal is `Running` at a time, exactly
  like cannon's one-in-flight target, so record-back is a stateless "find the lone `Running`
  proposal, guard by `result_run_id`, `mark_done`."
- **Preserves mode parity.** Pricing + cap + record-back live in `kuzushi-core`, so the
  future headless `kuzushi strategy approve/fire` verb calls the identical helpers; the TUI
  keeps only chrome (the k/s/d/a gate + completion hook). Shared on-disk truth stays
  `strategy-queue.jsonl` (additive — existing fields already serialize).

### 2.2 The three slices (each independently testable)

#### Slice A — price proposals at creation (core, pure)

- **Modify** `crates/kuzushi-core/src/capabilities/module_recommender/adapters.rs`
  `strategy_proposal_from_recommendation` (`:143`): set `estimated_rounds` from the
  recommendation (default 1 for a single-tool review pass), and set
  `expected_cost_usd = Some(estimate_strategy_cost(rounds, cost_per_round, verify))`.
- **Source `cost_per_round`** from a persisted, calibrated value (Slice C writes it):
  add `load_calibrated_cost_per_round(workspace) -> f64` to `strategy/mod.rs` reading a new
  `strategy-calibration.json` (`{ "cost_per_round_usd": f64 }`) in `workspace.state_dir()`;
  seed default (cannon uses ~0.7/round; pick a conservative documented constant). Keep it a
  small pure fn + one IO adapter (CRAP: the read is the only side effect).
- **`verify` flag** from the recommendation phase (Confirm-phase proposals price ×2).
- **Guardrail:** no model string, no env read; cost-per-round is data, defaulted honestly.

#### Slice B — real cap **at approve**, from `harness.toml`

- **Add to `strategy/mod.rs`** (pure, ports `cannon:src/queue.rs:219-238`):
  - `committed_cost(proposals: &[StrategyProposal]) -> f64` — sum `approved_cost_usd`
    (fallback `expected_cost_usd`) over `Approved | Running | Done`.
  - `would_exceed_budget(proposals, candidate, cap: f64) -> bool` — cannon's
    **between-proposals** honesty: `committed + candidate.expected > cap`. A single in-flight
    proposal may overshoot — **surface it, do not pretend the cap is hard** (matches cannon
    and no-silent-fallback candor).
- **Wire into approve.** `update_strategy_proposal_status_effect`
  (`app/strategy/mod.rs:203`), for `status == Approved`, loads the cap from
  `EngagementHarness::load(workspace).budget_usd` and, if `would_exceed_budget`, **refuses**
  with an actionable log (`"approving P-… ($X) would exceed engagement budget $Y
  (committed $Z)"`) and leaves status `Proposed`. This is the cap-enforcing approve the
  plan wanted, sourced from the *engagement* budget (not the session cost-cap, which stays
  as the independent fire-time safety net).
- **Keep** the existing fire-time `strategy_exceeds_budget` session check as a second,
  orthogonal guard (defense in depth; now non-inert because Slice A prices proposals).

#### Slice C — close the loop: record actuals + recalibrate

- **Add core fn** `record_strategy_result(workspace, run_id, actual_cost_usd, findings,
  confirmed) -> Result<bool>` to `strategy/mod.rs`: load queue, find the lone proposal in
  `Running` status (guard: its `result_run_id`/`source_run_id` is unset or matches
  `run_id`), call `mark_done(...)`, persist queue, then **recalibrate**:
  `new_cpr = calibrated_cost_per_round(prev, actual_cost / rounds)` and write
  `strategy-calibration.json` (feeds Slice A's next pricing). On tool failure, an analogous
  `record_strategy_failure` → `mark_failed`. Pure logic + two IO adapters; keep each fn
  ≤ 4 complexity.
- **TUI completion hook.** In `apply_finished_tool_event`
  (`crates/kuzushi-tui/src/app/tool_runner/run_tool/events_and_results.rs:18`) and the scan
  finisher `apply_scan_finished`, when the finished run corresponds to a fired proposal,
  emit a `ShellEffect::RecordStrategyResult { target, run_id, cost, findings, confirmed }`
  that calls the core fn and invalidates the strategy-queue workbench cache. Actuals:
  `actual_cost_usd` from the run's `summary.json` spend, `findings_count` from the run's
  findings delta (already surfaced to `apply_scan_finished(run_id, findings_count)`),
  `confirmed_count` from verified findings in that run.
- **Correlation is stateless** (single-slot `JobHub` ⇒ ≤1 `Running` proposal), so **no new
  `ShellApp` field** is required; the `result_run_id` guard prevents a stray non-strategy
  run from closing a proposal.

### 2.3 Touchpoints summary

| Layer | File | Change |
|---|---|---|
| Core data/policy | `crates/kuzushi-core/src/strategy/mod.rs` | `committed_cost`, `would_exceed_budget`, `record_strategy_result`, `record_strategy_failure`, `load/save_calibrated_cost_per_round` (+ `strategy-calibration.json`) |
| Core producer | `.../capabilities/module_recommender/adapters.rs` | price proposals in `strategy_proposal_from_recommendation` |
| Core exports | `.../public_exports/agent_workspace.rs` | re-export the new helpers |
| TUI approve gate | `crates/kuzushi-tui/src/app/strategy/mod.rs` | cap check in `update_strategy_proposal_status_effect` |
| TUI completion hook | `.../app/tool_runner/run_tool/events_and_results.rs` + scan finisher | emit `RecordStrategyResult` effect |
| TUI effect | `.../app/effects.rs` | handle `RecordStrategyResult` → core fn |
| Descriptor/CLI | **none** for the wedge | headless `strategy` verb is a fast-follow (§3), not the wedge |

### 2.4 Tests (test-backed, close to behavior)

- **Core (`strategy/tests.rs`):** proposal prices via `estimate_strategy_cost`;
  `would_exceed_budget` true/false around the cap (port cannon's
  `approve_respects_budget`); `record_strategy_result` transitions the lone `Running`
  proposal → `Done` with actuals; recalibration writes an EMA-updated cost-per-round (port
  `record_result_calibrates_cost_per_round`); failure path → `Failed`; `result_run_id`
  guard ignores a non-matching run.
- **TUI (`app/tests.rs`):** `strategy approve` on an over-cap proposal is refused and logs;
  a fired proposal is marked `Done` after `apply_finished_tool_event`; strategy-queue cache
  is invalidated on record.
- **Parity:** a plain-render test that a `Done`/`Failed` proposal shows actual cost +
  findings in the queue view.
- **Gate:** `pnpm quality:crap-risk` < 7; every new fn ≤ 4 complexity / ≤ 40 lines.

### 2.5 Invariants preserved

- **No silent fallback:** pricing/cap/record-back touch no model/runtime/provider. The
  fired tool still routes through `dispatch_prepared_tool_with_runtime` → `resolve_tool_model`.
- **`.kuzushi` formats:** additive only — the `StrategyProposal` fields being populated
  already serialize; `strategy-calibration.json` is a new additive artifact in
  `state_dir()`. No path moves.
- **Mode parity:** all decision logic in `kuzushi-core`; TUI holds only chrome + one hook.
- **Autonomy gate:** fired proposals already pass through the shared dispatch autonomy gate
  (unchanged).

---

## 3. The next two increments (each independently shippable)

### Increment F1 — `kuzushi measure` verb (finish the genuine orphan)

- **Why second:** small, closes an advertised loop, and gives Slice C's `confirmed_count`
  actuals a scoreboard — but it does not itself unblock the planner, so it follows the loop.
- **What:** add `Command::Measure { target, against: Option<PathBuf>, gate: Option<f64> }`
  to `crates/kuzushi-cli/src/command.rs`, a dispatch arm mirroring the `Export` pattern
  (`command.rs:131` / `dispatch/reporting.rs:30`), and a thin application service calling
  `kuzushi-eval`. Add **F1** (`2·p·r/(p+r)`) over the existing precision+recall in
  the `scoring.rs` module in `crates/kuzushi-eval`; add `--against <sarif>` (score an external tool with
  the same matcher) and `--gate <baseline+margin>` (exit 2 on F1 regression, port
  `cannon:src/tune.rs:56`).
- **Parity:** `run --measure` optional; `measure` stays headless-friendly JSON on stdout.
- **Tests:** `parse_command(["measure", …]) → Command::Measure`; F1 on a fixture corpus;
  gate exit-code on regression.
- **Open operator decisions:** (1) is `measure` its own verb or `scan --measure`? (2) what
  is the default F1 baseline/margin for `--gate`? (3) does `--against` accept SARIF only, or
  also semgrep-json (ties into the seed-ingest arm)?

### Increment F2 — first evidence generator (`commits`) feeding the live queue

- **Why third:** with the loop closed and priced (wedge) and a scoreboard (F1), the queue
  can now be fed by **mined evidence** instead of only phase-recommendation — the first real
  taste of cannon's permutation planner, and the point where the priced/cap/record machinery
  pays off end-to-end.
- **What:** a `trait Generator` in `kuzushi-core` (improves on cannon's string dispatch) with
  a `commits` impl ported from `cannon:src/generators/commits.rs` — mine git history for
  incomplete-fix hunts + churn hotspots, emit **priced** `StrategyProposal`s (reuse
  `estimate_strategy_cost` from the wedge). Pure over a git fixture; side-effect-light.
- **Parity/CRAP:** generator core is pure and testable off a fixture repo; keep each emit
  fn small.
- **Tests:** proposals generated from a git fixture; priced; ranked by `yield_score`;
  respect the wedge's `would_exceed_budget` at approve.
- **Open operator decisions:** (1) which generators ship first and in what order
  (`commits` → `threatmodel` → `intel` → `evolve`)? (2) does `evolve` bootstrap without a
  fitness score (cannon seeds genomes ~0.7) to break the generate↔measure cycle? (3) is
  generation a new `permute`/`strategy generate` verb or folded into
  `module-recommender:recommend`?

---

## 4. Sequencing

1. **Wedge — close the strategy loop** (§2). Price + cap-at-approve + record-back. Turns
   dormant machinery live; no cut risk; medium/contained.
2. **F1 — `kuzushi measure`** (§3). Small orphan-finish; scoreboard for actuals.
3. **F2 — `commits` generator** (§3). First mined-evidence proposals into the now-live
   priced queue.

Everything downstream in `cannon-kuzushi-port-plan.md` (more generators, seed-ingest,
3-level prompts, verify config, engagement-folder capstone, verb collapse, and the
`control-room` cut waves) stays gated behind operator decisions and is **not** blocked by
starting the wedge — the wedge is decision-independent and reversible (pricing defaults are
data; the cap reads an optional `budget_usd`; record-back is additive).
