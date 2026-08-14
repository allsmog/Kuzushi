# Review Yield — End-to-End Testing Plan

Validates the full 8-PR chain (#130 → #131 → #133 → #134 → #138 → #139 → #140 → PR 8)
as one system, on real targets, from event substrate to Learn-mode ordering. Every phase
has explicit pass criteria and an abort rule. Run phases in order — each depends on the
previous one's artifacts.

## Phase 0 — Preconditions (operator, one-time)

1. **Require green CI**: oxidized-joern is public, so every Rust lane runs against the
   real pinned engine without a cross-repository secret. All required lanes must be
   green on the chain before merging anything.
2. **Merge order**: the chain is stacked; merge bottom-up: #130 → #131 → #133 → #134 →
   #138 → #139 → #140 → PR 8. After each merge, retarget the next PR's base to main
   (GitHub does this automatically for stacked PRs on merge).
3. Build once: `cargo build --workspace --locked` and note the binary path.
4. Pick two real targets: **T1** = a repo with an existing `.kuzushi` store containing
   historical review decisions (e.g. the mariadb/redis eval targets); **T2** = a fresh
   repo with no `.kuzushi` state.

## Phase A — Provenance substrate (PR 1)

| # | Step | Pass criteria |
|---|------|---------------|
| A1 | Open T1's store (any read command, e.g. `kuzushi findings --target T1`) | Backfill migration runs; no error; store still readable |
| A2 | `sqlite3 .kuzushi/v3/index.sqlite3 "select count(*), count(decision_event_seq) from review_decisions"` | Backfilled count matches `finding_events` decision events; unmatched rows are NULL (not fabricated) |
| A3 | Record one decision via TUI (workbench review) and one via CLI on the same target | Both rows carry `decision_event_seq`/`decision_event_hash`; TUI row's `decision_read_watermark < decision_event_seq - 0`; CLI row's watermark == seq-1 (barrier) |
| A4 | Rebuild projection (`RebuildProjection`) | Provenance identical after replay (determinism) |

**Abort rule**: any misattributed provenance (hash not matching `finding_events`) stops the run — file a bug before Phase B.

## Phase B — Census + export (PR 2)

| # | Step | Pass criteria |
|---|------|---------------|
| B1 | `kuzushi review-yield census --target T1` | Counts plausible vs. `sqlite3` ground truth; exact-vs-barrier cutoff split reported; author + dismiss-reason breakdowns present |
| B2 | `kuzushi review-yield census --target T2` | All-zeros census, no error, no state created |
| B3 | `kuzushi review-yield export --target T1 --out ds.jsonl` twice | Identical `datasetDigest` both runs (byte-reproducible) |
| B4 | Leakage grep on ds.jsonl: `grep -Ei 'rationale|triaged_by|"file_path"|snippet|/Users/|src/' ds.jsonl` | Zero hits; only `pathBucket` vocabulary appears |
| B5 | Every row: `anchorObservation.seq <= featureCutoffSeq < labelEvent.seq` (jq assertion) | Holds for 100% of rows |
| B6 | **Census decision gate**: record eligible-identity count and class balance | ≥200 identities & ≥50/class → production-model track is open; below → everything from Phase D onward validates *mechanism only*, and the PR 7/8 modes stay experimental |

## Phase C — Training (PR 3)

| # | Step | Pass criteria |
|---|------|---------------|
| C1 | `cd experiments/review-yield && scripts/self-test.sh` | Full pipeline green without venv (stdlib), and with venv if present |
| C2 | Train on the REAL T1 export: `scripts/train.sh ds.jsonl` | Frozen split manifest emitted before fitting; run completes; honest gate report (expect `bootstrap_improvement` and diversity gates to fail on a small corpus — that is correct behavior, not a bug) |
| C3 | IG audit: `python3 -m kuzushi_review_yield.ig_audit ds.jsonl` (adjust to real entrypoint) | Report ranks features by root information gain — **read it**: if toolFamily or pathBucket dominates severity/staticProofState, that's the actionable product finding |
| C4 | Export artifact `review-tree.json` | `modelId` verifies via `scripts/verify-artifact.sh` |

## Phase D — Artifact + cross-language parity (PR 4)

| # | Step | Pass criteria |
|---|------|---------------|
| D1 | `kuzushi review-yield validate-model --model review-tree.json` | Exit 0; prints modelId/depth/nodes matching Python's report |
| D2 | Tamper 1 byte in a copied artifact → validate-model | Nonzero exit, explicit hash error (fail closed) |
| D3 | `kuzushi review-yield score --target T1 --model review-tree.json --json` | Every finding gets a signal OR an explicit eligibility reason; rerun → identical output (determinism) |
| D4 | Cross-check 3 findings by hand against Python `artifact_eval.py` on the same features | Identical leaf, rate, path |

## Phase E — Shadow + sessions (PR 5, config surface from PR 7)

Configure operator (home) config — NOT the target's:
```toml
[review_yield]
mode = "shadow"
model_path = "/abs/path/review-tree.json"
```

| # | Step | Pass criteria |
|---|------|---------------|
| E1 | Put `[review_yield]` in `<T1>/.kuzushi/v3/config.toml` instead | Shell refuses loudly (project-local rejection) — then remove it |
| E2 | Launch shell on T1, browse the queue WITHOUT opening findings (cursor movement only) | Zero `review-session-started` events appended |
| E3 | Open 3 findings (Enter), one twice | Exactly 3 session events (once per finding per visit); payload has hashes/ranks/bands only — no feature values, paths, or rationale |
| E4 | Decide one opened finding | Decision row carries `review_session_id` joining to the session event |
| E5 | Capture full queue order (aliases) with shadow on vs. mode="off" | Byte-identical, including backlog toggle |
| E6 | Point `model_path` at a corrupted file, relaunch | One explicit startup error; state disarmed; shell still usable; no silent downgrade |

## Phase F — Visible (PR 6)

Set `mode = "visible"`.

| # | Step | Pass criteria |
|---|------|---------------|
| F1 | Open a scored finding's detail | Signal section: rate %, leaf support, 95% interval, entropy bits, model label, decision path + the advisory copy "Advisory historical reviewer-outcome signal." / "Not vulnerability proof and not a human decision." |
| F2 | Open an ineligible finding (e.g. unknown category) | Honest explicit message, no fake numbers |
| F3 | Queue order vs. off | Byte-identical (visible never reorders) |
| F4 | Plain mode (non-TTY) run | Same section content, no ANSI/box-drawing artifacts |
| F5 | Grep rendered copy for "vulnerability probability", "confirmed by model", "watermark" | Zero hits |

## Phase G — Within-band (PR 7)

Set `mode = "within-band"`.

| # | Step | Pass criteria |
|---|------|---------------|
| G1 | Queue order vs. off: diff per (proof band, severity) group | Rows move ONLY inside equal-band groups; group boundaries and per-group multisets identical |
| G2 | A band containing ≥1 ineligible finding | That entire band in baseline order (frozen) |
| G3 | Flip back `mode = "off"`, relaunch | Byte-identical to original baseline (rollback) |
| G4 | Export findings (markdown bundle + JSON) after a session | Provenance block records mode + modelId; headless CLI export has no block |
| G5 | Backlog toggle active | Model ordering NOT applied (documented exclusion) |

## Phase H — Learn mode (PR 8)

Set `mode = "learn"`.

| # | Step | Pass criteria |
|---|------|---------------|
| H1 | Queue order within bands | Highest leaf-entropy first, support ascending tie-break; same band-safety rules as G1–G3 |
| H2 | Queue chrome while Learn actively reorders | Truthful "model knowledge-gap review" indicator visible; indicator ABSENT when unscored/frozen or in other modes |
| H3 | Detail section under Learn | Entropy/support emphasized; copy never implies vulnerability uncertainty |
| H4 | Plain-mode parity for the indicator | Present and truthful |

## Phase I — TUI DevEx journeys (regression)

Run the tmux-driven journeys most likely to regress from queue/detail changes (use the
`tui-devex-audit` skill): the review/workbench journeys plus one fresh-target journey on
T2 with `[review_yield]` unset — confirming zero Review-Yield chrome appears for
unconfigured operators. Judge captures against the signifier↔state↔intent invariant.

## Phase J — Full regression + close-out

1. `cargo test --workspace --locked 2>&1 | tail -5` — expected knowns: 1 core failure
   (`builtin_dispatch_policy_inventory…`, pre-existing, fails on main), 12 TUI
   pre-existing failures, occasional `run_codeql_flows…` 1s-timeout flake under load
   (passes solo). Anything else is new — bisect the chain.
2. `pnpm verify:quick:summary`; rerun only failures for diagnostics.
3. After CI is green and the chain merges: re-run Phases B–H once on merged main
   (catches stacked-merge integration drift).
4. Retire this plan into `docs/assessments/` with observed results filled in.

## First execution — observed results (2026-08-04, pre-PR-8 build at #140 tip)

Run against the Kuzushi repository's own dev store (391 finding observations) with a
model trained on the committed synthetic corpus. Phases H (Learn) and the interactive
TUI journeys were not yet runnable (PR 8 in flight, scripted-plain shell only).

| Phase | Result |
|---|---|
| C1 self-test | PASS — 156 tests, byte-identical corpus regen, digest verify, tamper fails closed |
| C2 train | PASS — depth-2 tree: `sourceSinkLinked` → `evidenceCount` |
| D1 validate-model | PASS — Rust verifies a freshly Python-trained artifact's digest |
| D2 tamper | PASS — 1 flipped byte → explicit `invalidModelHash`, exit 1 |
| D3 score | PASS — 391 findings scored, advisory wording inline, deterministic |
| B1 census | PASS — honest zero-census; after 4 CLI adjudications: 2 confirmed / 1 rejected / 1 policy-excluded, all cutoffs `head-barrier` (CLI path, as designed) |
| B2 fresh target | PASS — explicit error, exit 1, no state created |
| B3 reproducibility | PASS — identical digests across runs; workspace-rooted `--out` enforced; 0600 files |
| B4 leakage grep | PASS — zero hits incl. planted distinctive rationale strings |
| B5 causality | PASS — `anchor ≤ cutoff < label` on every exported row |
| C2-real honesty | PASS — exporter refused all-zero metrics (illustrative-values guard) on the 3-row corpus |
| E1 project-local config | PASS — shell and scan reject loudly; NOTE: `findings` CLI ignores rather than rejects (it never loads config) — acceptable, add a pinning test |
| E2/E3 shadow sessions | PASS — once-per-finding (double open → 1 event); payload carries hashes/ranks/bands only |
| E4 session→decision join | FAIL at the time of this run — scripted plain-shell `decision` did not persist (detail view advertises `decision <true-positive|false-positive> <reason>`). Diagnosed and fixed as a staleness-guard bug; see the follow-up status below |
| F1 visible section | PASS — full signal + exact advisory copy in plain output |
| G1 within-band | PASS — reorder observed only after lazy scoring, movers stay in the (high, unverified) band |
| G3 rollback | PASS — mode=off restores byte-identical order |

### Phase H addendum (2026-08-04, PR 8 build at #141 tip)

| Phase | Result |
|---|---|
| H1 learn ordering | PASS — reorders vs. baseline after lazy scoring; identical to within-band on this corpus because every scored finding shares one tree leaf (objectives tie) — a multi-leaf corpus is needed to observe entropy-first divergence |
| H2 indicator honesty | PASS — `[learn mode - model knowledge-gap review]` present in Learn after scoring, absent in off mode |
| H4 plain parity | PASS — indicator renders in plain output |

Open follow-ups from this run: (1) plain-scripted decision recording (E4), (2)
`findings`-CLI config-rejection pinning test, (3) proactive queue scoring at launch
(lazy-scoring caveat below), (4) Phase H + I once PR 8 merges.

### Follow-up status (2026-08-04)

Items 1–4 are addressed on `fix/review-yield-e2e-followups`. Items 5–6 (the
regression and merged-main re-run in Phase J) remain open.

1. **E4 plain-scripted decision — FIXED.** Root cause was not plain-mode
   routing: the `ReviewSessionStarted` event an open records lands in
   `finding_events` under the opened finding's `stable_fp`, so the decision
   staleness guard read the operator's own session as "the finding changed
   after read watermark" and refused the verdict. That rejected every armed-mode
   verdict, interactive included. Observation-only event kinds are now excluded
   from the staleness and rekey scans. Re-verified end to end: `open F-0051` then
   `decision false-positive …` through scripted stdin persists the row with
   `review_session_id` set and prints `decision saved`.
2. **`findings`-CLI pinning — DONE.** `findings_cli_ignores_a_project_local_review_yield_section`
   asserts the config-loading surfaces reject a project-local `[review_yield]`
   while `findings` proceeds over the same target. Documented in
   `docs/operator-control-surfaces.md`.
3. **Proactive scoring — DONE.** Arming an ordering or display mode scores the
   hydrated queue, and every findings reload re-requests scoring for the
   generation it loaded. Re-scoring an unchanged generation is a no-op; `off`
   and `shadow` request nothing. The armed-mode log lines no longer say "once
   the queue is scored".
4. **Rank objective — DONE.** `review_sessions` gained an additive
   `shadow_rank_objective` column (`yield` | `learn`, null for legacy rows) with
   the matching `shadowRankObjective` payload key, projector, and migration. A
   session records the active objective's rank beside its label; a session with
   no rank names no objective.

## Known limitations to carry into evaluation

- **Selective labels**: retrospective metrics on T1 measure historical reviewer
  behavior, not counterfactual yield — only the Phase E session telemetry accumulating
  over time supports a prospective claim.
- ~~**Lazy scoring**: the queue reorders after the first finding-open, not at
  launch (shipped PR 5/6 effect design; documented follow-up).~~ Resolved: the
  queue is scored when the mode is armed and again on every findings reload.
- **Small-corpus honesty**: with a census below the §17.1 gates, Phases G/H validate the
  *mechanism*; do not read their orderings as product-quality signal.
