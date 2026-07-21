# Coverage, Fidelity, and Fleet — architecture for multi-target scanning

Status: PROPOSED (2026-07-20). Distilled from a full read of
`~/orchestrate-harness-repo` (laptop-side fleet orchestrator) and its vendored
`internal-scanning-harness` (calibrated six-stage scan lifecycle). This document
maps those systems' proven mechanics onto kuzushi's existing seams to enable:

1. Submodule scan recommendations
2. Phase scans (stage-scoped, resumable, plan-first)
3. Session scans (session as a budgeted, checkpointed unit)
4. Threat-model management under the existing DFD visualization
5. Multi-target scanning and aggregation
6. Remote scanning and aggregation (à la orchestrate-harness)
7. Scanning fidelity (à la internal-scanning-harness)
8. Branch / SHA awareness end to end

Design rule inherited from both source systems: **judgment lives in prompts,
but every quality claim is enforced by code at a write-time chokepoint.**
Severity caps, dedup, coverage accounting, and schema drift are never left to
an LLM's discretion or a reader's heuristics.

---

## 0. Existing seams this builds on (no parallel systems)

| Capability | Existing kuzushi seam |
|---|---|
| Per-target state | `<target>/.kuzushi/v3/` (untrusted-config gate already in `config/load_config_for_target.rs`) |
| Global operator state | `~/.kuzushi/v3/` (config, sessions, runs, objects, `target-history.json`) |
| Run truth | `run_lifecycle` `RunPresentationV1` + workflow-v2 hash-linked phase receipts (`PhaseReceiptProjection`) |
| Findings | `findings::FindingStore` (sqlite index, watermark) |
| Scope tree | `workspace/domain/nested_scope.rs` `NestedProjectScopeTree` |
| Diff scoping | `workspace/diff_scope` (`git_diff_files`, `WhiteboxDiffScopeReport`, `ChangedLineRange`) |
| Ranking | `capabilities/module_recommender` (attack surface × threat-model signals × findings) |
| Threat model | `threat_model.rs` (`persistent_threat_model_path`), `kuzushi-mcp-threat-model`, TUI DFD model (nodes/flows/zones/crossings) |
| Surfaces | TUI phase rail (map/scan/review/prove/fix), guided scan, plain renderer, devex journey harness |
| Cheap engine reuse | `kz bridge --bare`, `--shard` manifests (kz-engine adoption work) |

Everything below is expressed as extensions of these, in dependency order.

---

## 1. Coverage Ledger — the keystone (enables #1, #2, #8)

**What:** a per-target, append-derived record of *what has been scanned, at
which revision, by which phase/strategy*. This is the single missing fact that
blocks every other capability: today `target-history.json` is a bare MRU list
and no run records the SHA it scanned.

**Storage:** new tables in the per-target `.kuzushi/v3/index.sqlite3`
(same store the findings watermark lives in):

```sql
scan_baselines(
  scope_id      TEXT,   -- NestedProjectScopeTree node id (or "" = whole target)
  phase         TEXT,   -- map|scan|review|prove|fix
  mode          TEXT,   -- default|entry|strategy:<id>|sweep-skip
  run_id        TEXT,   -- links to the workflow-v2 receipt (hash-linked truth)
  revision_sha  TEXT,
  branch        TEXT,
  dirty         INTEGER,-- scanned a dirty tree (warn-grade provenance)
  ts            TEXT,
  PRIMARY KEY (scope_id, phase, mode, ts)
)
```

**Write chokepoint:** the run-lifecycle terminal event. When a phase attempt
completes with a valid typed receipt, the ledger row is written *from the
receipt* (never from TUI caches — same authority rule as
`TypedReceiptResolution`). A run with no receipt writes no baseline; coverage
can never claim more than the receipts prove.

**RevisionRef everywhere:** a small value type
`RevisionRef { sha, branch, dirty }` captured once at run start (already
cheap: `target_git_metadata` exists) and carried on: the receipt, every
finding row (`findings` gains `revision_sha`/`branch` columns), and the
ledger. This is the harness's `meta.json scanned_sha` generalized.

**Sweep (deterministic, no LLM):** `kz sweep [--json]` — for each scope with a
baseline, one *whole-repo* `git diff --name-only <baseline>..HEAD` (cached per
baseline SHA), filtered by scope paths via `diff_scope::contains_path`.
Verdicts per scope × phase: `CHANGED (n files)` / `current` /
`no-baseline`. `--write-skips` records a `mode=sweep-skip` baseline row for
no-diff scopes so the SHA advances — but, per the sweep.py scar, only from a
whole-repo diff, never a pathspec-limited one (a pathspec miss silently
advances baselines past unscanned changes).

Lesson imported: the harness's `--since auto` exit-code contract — "no diff →
skip and record", "no baseline → do a full scan, which seeds the baseline".

---

## 2. Scan Recommender — submodule scan recommendations (enables #1)

**What:** extend `capabilities/module_recommender` into a `ScanRecommender`
that folds four deterministic signals per scope node and emits ranked,
*reasoned* recommendations:

| Signal | Source | Reason tag |
|---|---|---|
| Coverage gap | ledger: never-scanned scope, or phase never run | `never-scanned`, `phase-gap` |
| Staleness | sweep: CHANGED since baseline (weight by changed-file count) | `changed` |
| Surface density | `attack_surface` map + repository inventory: sink-dense files with **zero findings citing them** (the sink-gap join: inventory × `FindingStore` file references) | `sink-gap` |
| Yield priors | findings-per-scope-per-mode history (derived from the store; the harness's `rsh learn` live-priors idea) | `yield`, `saturated` |

Output type:

```rust
ScanRecommendation {
    scope_id, phase, reason: ReasonTag, score: f32,
    evidence: String,       // "14 files changed since a1b2c3", "37 sinks, 0 findings"
    suggested_mode: Option<String>,
}
```

**Surfaces:**
- Map phase gains a `NEXT SCANS` pane (sibling of HOT MODULES) listing the top
  recommendations with reason + evidence, `enter` = pre-filled scan command.
- `kz recommend [--json]` for scripting and remote queues.
- The guided-scan modal seeds its default target scope from the top row.

Saturation is honest, not fabricated: a scope is `saturated` only when the
ledger shows ≥N passes at the current SHA with zero new findings — and the
recommendation then flips to sink-gap files only (the harness's "1 gap-fill
researcher" rule).

---

## 3. Threat-Model Registry & Refine — management under the DFD (enables #4)

Kuzushi already renders the visualization (DFD nodes/flows/zones/trust
crossings). What's missing is the management layer the harness proved out.

**Registry:** a `threat_models` table in the per-target store, built by an
indexer (runs with hydration, not on the UI thread):

```sql
threat_models(
  source_path   TEXT,   -- repo-relative THREAT_MODEL*.md or kuzushi persistent model
  scope_prefix  TEXT,   -- longest scope this model governs
  content_hash  TEXT,
  indexed_at    TEXT
)
```

**Resolution order** (the harness's 5-step, adapted), implemented as one pure
function `resolve_threat_model(scope) -> (path, ResolvedVia)`:
1. explicit per-scope override (target `.kuzushi/v3/config.toml` — untrusted,
   already gated)
2. longest `scope_prefix` match in the registry
3. nearest-ancestor `THREAT_MODEL*.md` walk from the scope root
4. kuzushi's persistent target-level threat model
   (`persistent_threat_model_path`)
5. none → map phase shows "build threat model" (existing empty state)

**Provenance:** every scan run's receipt carries
`threat_model: { source_path, resolved_via, content_hash }`. Review/prove
phases can then answer "which model seeded this finding", and refine knows
which upstream file to update. (Extends the receipt payload; the semantic-key
accounting contract keeps it visible-or-disclosed on the result card.)

**Refine (a map-phase operation, not a new phase):** the harness's delta swarm
translated to kuzushi ops:
- *surface delta:* `git log --since <last refine> --name-only` → candidate new
  entry points / moved boundaries
- *evidence miner:* map recent findings onto threat IDs; raise likelihood when
  evidence count crosses thresholds
- *question closer:* resolve open questions against source
Contract: **threat IDs are never renumbered**; every refine appends a
provenance entry (`mode, date, delta_from, inputs`). New entry points emit
*proposed* scope recommendations (flagged `proposed-by-refine`) that the
operator accepts/rejects in the TUI — the human-review gate the harness put on
shard proposals.

---

## 4. Phase & Session model (enables #2, #3)

Mostly formalizing what exists:

- **Stage independence is the default.** A phase completes → STOP with its
  result card. Auto-advance is a property of *unattended queue mode* only
  (see §6), never of interactive sessions. (Matches the harness's
  scar-earned rule and our no-gate-creep constraint.)
- **Plan-first pipelines.** `kz pipeline plan <target> --until <phase>
  [--scope s]` is deterministic and LLM-free: resolves scopes, threat model,
  baselines, and prints/persists `plan.json` (inputs, expected outputs,
  missing prerequisites). The run step consumes the plan. A `--from` stage
  whose input artifact is missing fails at plan time, not mid-run.
- **Session as a budgeted unit.** A *session scan* is a session launched with
  a manifest: `{ campaign_id, phase_scope, budget (tokens/wall-clock),
  handoff_path }`. On budget exhaustion or phase completion it writes a
  handoff artifact (`.kuzushi/v3/handoff/<campaign>.md`: what's done, what's
  next, open blockers) and stops. The next session reads it. This is the
  orchestrate nightly A/B/C pattern generalized, and it exists because long
  sessions without prompt caching re-bill their context every turn.
- **Session mining.** Session transcripts (`~/.kuzushi/v3/sessions/**.jsonl`)
  already exist; a deterministic linter (repeated-message spam, stall gaps,
  budget burn per phase) feeds the fidelity scorecard (§7) — we've already
  used this by hand to find the watcher-storm bug.

---

## 5. Fleet layer — multi-target aggregation (enables #5)

New global namespace `~/.kuzushi/v3/fleet/`; per-target stores remain the
immutable truth (the corpus.py rule: **runs are truth, corpus is derived and
rebuildable**).

**Target registry** (replaces the bare `target-history.json` list, which is
kept for MRU):

```toml
# ~/.kuzushi/v3/fleet/targets.toml
[[target]]
id      = "monorepo"
path    = "/home/ubuntu/monorepo"
remote  = "github.com/acme/monorepo"
default_branch = "master"
label   = "Appliance"
```

**Fleet corpus:** `~/.kuzushi/v3/fleet/corpus.sqlite3`, rebuilt by
`kz fleet ingest [--rebuild]`:
- reads each registered target's store (findings + receipts + ledger)
- normalizes rows to `(target_id, scope, file, class, revision)` with the
  dedup contract from §7
- rows failing the contract get `quality_flags` and are **counted, never
  dropped or silently fixed** (`kz fleet status` shows the drift count)

**Fleet status** (`kz fleet status`, and a TUI fleet dashboard grown out of
the target picker): per target — coverage % (scopes with fresh baselines),
stale-scope count, P0/P1 open backlog, last-scanned SHA vs `origin/<default>`,
quality-flag count. One screen, the `rsh status` scorecard shape.

**Cross-target queries:** `kz fleet findings --class oob-write --severity P0`
etc. — pure queries over the derived corpus.

Trust note: pulled/ingested artifacts are *data*, never config; the existing
untrusted-target-config gate pattern applies to anything read out of a target
tree.

---

## 6. Remote execution plane (enables #6)

A new crate **`kuzushi-fleet`** (CLI-only; the TUI only ever reads its
artifacts). Strict transport/judgment split, per orchestrate:

- **Config:** `~/.kuzushi/v3/fleet/remotes.toml` — box name, ssh spec,
  per-box path overrides. Config is the only thing a user edits.
- **Verbs** (each one encodes an orchestrate scar):
  - `kz remote doctor` — paths resolve, engine version, model env, disk;
    refuse launch on FAIL.
  - `kz remote stage` — ship the *pinned* engine (the `kz` binary + bare
    scripts) and the queue file. Refuse if the local checkout is behind its
    upstream (`git rev-list HEAD..@{u}`); refuse to re-stage over live remote
    sessions without `--force`; every transfer is loud-fail (a silent scp
    failure once re-ran a stale queue).
  - `kz remote launch` — start a rolling queue in tmux on the box: slots per
    box, stagger, optional start-at/window; retries transient failures with
    capped backoff, re-issuing full prompts (checkpoints provide resume).
  - `kz remote status` — tmux sessions, live (zombie-aware) engine processes,
    queue-log tail, per-run state (running/ended/done+artifact size). Built to
    answer "can I step away".
  - `kz remote pull --out <dir>` — artifacts + `MANIFEST.json`, with a
    recency cutoff by default (stale runs must not be re-ingested under
    today's date).
- **Aggregation path:** `pull` fills a local inbox
  (`~/.kuzushi/v3/fleet/inbox/<box>/<run>/`); `kz fleet ingest` consumes it.
  Remote boxes never write the fleet corpus directly.
- **Unattended queues** are the one place phase auto-chaining is allowed, and
  it is declared in the queue file, not inferred. Credentialed side effects
  (publishing, ticket filing) never run remotely/unattended — they stay in an
  interactive session, exactly like orchestrate's compute-only cron with
  MCP-in-session Drive I/O.

---

## 7. Fidelity harness (enables #7)

Two halves, mirroring the harness.

**7a. Result-fidelity contracts (code, at write time):**
- **Derived severity.** Findings carry a `precondition` from a closed enum;
  ingest computes the severity ceiling mechanically from a per-target tier
  table and records `tier_capped` when it lowers a claim. Claims above the
  ceiling are capped, counted, and visible — never re-litigated in prompts.
  (475/514 of the pilot's P0 downgrades were precondition mis-tiering; the
  ceiling became code.)
- **Dedup contract.** Cluster key = file + line-window (±15, span-extended).
  The human-readable identity string is *never* a dedup key (free-text slugs
  churn run-to-run). Chains are dedup-exempt by category.
- **Class enum.** `class` constrained to a fixed enum at ingest; free text
  stays in title/category. Pre-enum rows get `class-inferred` quality flags,
  never silent rewrites.
- All three live in one module (`findings/ingest_contract.rs`), the write-time
  chokepoint. Consumers never grow schema heuristics.

**7b. Scanner-fidelity canary:**
- `fixtures/canary-target/` — a small planted-findings repo with an
  `expected-findings.json` manifest: for each plant, file:line window, class,
  expected tier, and *why* (including at least one calibration trap that must
  be **capped**, not found-and-inflated — the harness's "if all three come
  back P0, calibration isn't applied" check).
- Tier 1 (always, cargo test): ledger/sweep/recommender/ingest-contract
  behavior over fixture stores — deterministic, no LLM.
- Tier 2 (opt-in, spends LLM): scripted-mode scan of the canary target,
  asserting recall ≥ threshold, zero misses on P0 plants, and correct
  tier-capping. Runs like a devex journey (bounded, artifacts kept).
- Results append to a fidelity scorecard (per engine version) in the fleet
  store; regressions are visible before a real campaign trusts a new build.

**7c. Negative knowledge (optional, high-leverage):** a per-target guards
ledger — verifier-examined protections recorded as
`{file, line, guard, protects, bypass_result, revision_sha}` with SHA-based
expiry (a guard row dies when its file changes past the recorded SHA). Next
scans attack recorded guards instead of re-deriving flows; an unprimed pass
re-finding a "refuted" flow raises a `guard-conflict` quality flag rather than
being trusted either way.

---

## 8. Branch / SHA model (enables #8)

- `RevisionRef` (§1) on every run, receipt, finding, baseline, and guard row.
- **Dirty-tree honesty:** scanning a dirty tree is allowed but the ledger row
  records `dirty=1` and the result card says so; recommendations prefer clean
  baselines. `kz` can create ephemeral pinned worktrees (under a configurable
  cache root — bind-mount-safe on dev boxes) for master-baseline scans; shared
  working trees are never mutated.
- **Cross-revision comparison:** `kz diff-findings --base <revA> --head <revB>`
  joins the corpus across two revisions by the dedup cluster key and labels
  each finding's `lead`: `branch-delta` (only on head), `backport-gap` (only
  on base), `both`. This is how the harness's branch triage classified
  trident-branch findings, generalized.
- **Expiry semantics:** anything cached against code content (guards,
  saturation, sink-gap) is keyed by SHA and expires on change — staleness is
  computed, never assumed.

---

## 9. Build order and placement

| Milestone | Delivers | Where |
|---|---|---|
| **M1 — Coverage** | RevisionRef; `scan_baselines`; receipt-driven ledger writes; `kz sweep`; findings gain revision columns | `kuzushi-core::workspace::{revision, coverage_ledger}`, `run_lifecycle` terminal hook, `kuzushi-cli` |
| **M2 — Recommend + TM mgmt** | ScanRecommender; map-phase NEXT SCANS pane; threat-model registry + resolution + receipt provenance; refine op | `capabilities/scan_recommender` (extends module_recommender), `threat_model/registry.rs`, `kuzushi-tui` map page |
| **M3 — Fidelity + Fleet (local)** | ingest contracts; canary fixture + tier-1 tests; fleet registry/corpus/status; fleet TUI view | `findings/ingest_contract.rs`, `fixtures/canary-target/`, `kuzushi-core::fleet` (read side), `kuzushi-cli fleet` |
| **M4 — Remote** | `kuzushi-fleet` crate: doctor/stage/launch/status/pull; inbox ingest; unattended queue mode | new crate `kuzushi-fleet` |
| **M5 — Deep fidelity** | canary tier-2 e2e; guards ledger; session-transcript linter; cross-revision diff-findings | spread across the above |

Dependency spine: **M1 is load-bearing for everything** (recommendations,
staleness, fleet coverage, branch labels all read the ledger). M2/M3 are
independent of each other; M4 depends on M3's inbox/corpus; M5 hardens.

Invariants throughout:
- Per-target store is truth; every aggregate is derived and rebuildable.
- Every quality rule is enforced at exactly one write-time chokepoint.
- Drift is counted and shown, never absorbed.
- Deterministic before LLM: plan/sweep/recommend/gate steps never spend
  tokens; LLM phases consume their outputs.
- Interactive sessions stop at phase boundaries; only declared unattended
  queues chain.
- Anything read from a target tree or a remote box is untrusted data.
