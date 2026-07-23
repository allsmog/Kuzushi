# Kuzushi Local Monorepo Acceptance — Gap Ledger (Phase A)

Engagement: local monorepo acceptance vs `/home/ci/monorepo` (alias `monorepo`,
the monorepo codebase — remote `git@github.com:acme/monorepo.git`).
Baseline artifact roots:

- Provenance + J17: `/home/ci/kz-local-monorepo/phaseA-20260722-161613/`
- Gate baseline run: `/home/ci/kz-local-monorepo/gate-20260722-163233-baseline/`

Target at baseline: branch `snejad-wycheofproof-chunkedgcm` (sic — see
provenance JSON for exact value), HEAD `b460acefd05c901969ca99cc2eefae7711040fea`,
tracked tree clean, 442,579 tracked files, 18 GiB, 1 uninitialized submodule
(`src/go/src/acme/vendor`), pre-existing `.kuzushi/` engagement state
present and protected (never deleted during this engagement).

Classifications per contract: UNSUPPORTED DOMAIN STATE · HONESTY FAILURE ·
SCALE/RESOURCE FAILURE · TARGET DRIFT · HARNESS DRIFT (baseline
infrastructure) · DESIGN DRIFT (visible composition vs required story).

Status values: OPEN (Phase B work), EVIDENCE-PENDING (awaiting capture
inspection), RECORDED (baseline fact, no repair required).

---

## G1 — No root-first holistic state machine exists — UNSUPPORTED DOMAIN STATE — OPEN

The contract's central rule (no current accepted root holistic baseline →
zero authoritative child-scope recommendations; dominant NEXT = "Run holistic
repository scan") has no implementation anywhere. `grep -ri holistic crates/
docs/` returns nothing. The §7 states (INVENTORY MISSING/PARTIAL → SECURITY
MODEL MISSING/STALE → HOLISTIC NOT RUN/RUNNING/PARTIAL/CANCELED/COMPLETE/
STALE) do not exist as domain concepts.

- Evidence: code map (Explore agent 2026-07-22); J25 `map-initial` capture —
  expected-FAIL row `expect: Run holistic repository scan`.
- Closest existing concepts: map-evidence adequacy hint
  (`workflow_attempts/map_evidence.rs`) and the recommender's `NeverScanned`
  row — neither gates anything.

## G2 — Recommender emits child-scope recommendations with no root baseline — UNSUPPORTED DOMAIN STATE / HONESTY FAILURE — OPEN

`capabilities/scan_recommender/fold.rs` scores every scope independently
(NeverScanned 0.9, PhaseGap 0.85, Changed, SinkGap, Saturated). Nothing
orders root before children; a fresh monorepo target immediately gets
authoritative-looking per-scope rows. Contract requires recommendations to
exist ONLY against an accepted root holistic baseline, each carrying score
components, reason tags, and evidence rows bound to that baseline.

- Evidence: `fold.rs:23-35`; J26 `map-after-build` NEXT SCANS ask row.

## G3 — Repository inventory is a capped fs walk, not git-index enumeration — SCALE/RESOURCE FAILURE — OPEN

`workspace/inventory/build_repository_inventory.rs`: recursive
`fs::read_dir`, `MAX_REPOSITORY_ENTRIES = 100_000`. Monorepo has 442,579
tracked files → the walk is structurally guaranteed truncated (~23% seen).
No use of `git ls-files`/index despite the target being a git worktree; no
shard/checkpoint/resume; single-pass with byte budgets (512 MiB inspect,
256 KiB/file).

- Contract §9 requires efficient enumeration for ~500k files, bounded shards,
  resumability, honest bounds (checkpoint + partial instead of raised caps).
- Evidence: build_repository_inventory.rs:3-5,19-33,100-144; J26 receipt
  capture (duration + disclosure).

## G4 — Inventory is not persisted as a reusable revision-bound artifact — UNSUPPORTED DOMAIN STATE — OPEN

Contract: ONE RepositoryInventory per baseline revision, persisted, reused by
every downstream stage, refreshed incrementally via one whole-repo diff.
Actual: the inventory exists only as a section inside
`.kuzushi/context-snapshot.json` (no revision key, overwritten in place), and
is **rebuilt live** by at least four other consumers (module_recommender
adapters, attack_surface/add, project_model inventory_section, threat_model
variant_scan) — repeated full walks of a 442k-file tree.

- Evidence: code map §1; `context.rs:22-24`; consumers listed above.

## G5 — ScopeGraph is flat: every scope parents to root — UNSUPPORTED DOMAIN STATE — OPEN

`workspace/application/nested_scope.rs` `insert_scope` hard-codes
`parent: Some(ROOT_SCOPE_ID)`. Contract requires nearest-parent containment
(no flat root attachment) so child scopes nest under their true parents
(e.g. `src/go/src/acme/...` under `src/go`). Discovery caps
(`PACKAGE_ROOT_SCAN_BUDGET = 50_000` entries, 512 entrypoint clusters) are
silent — no truncation record on the persisted tree.

- Evidence: nested_scope.rs:120-145 (flat parent), :15-16 (silent budgets);
  J25/J26 scope-tree captures.

## G6 — Coverage baselines land only on the root scope id — UNSUPPORTED DOMAIN STATE — OPEN

`coverage_ledger/summary_intake.rs:31-33` records every run-derived baseline
against `ROOT_SCOPE_ID` with mode `"default"`. Child scopes can never earn
receipt-backed coverage; to the recommender they are permanently
"never-scanned". Contract requires scope-resolved baselines (root holistic +
per-scope scan receipts).

## G7 — Partial/canceled runs record zero coverage and are unresumable — HONESTY FAILURE / SCALE — OPEN

`summary_intake.rs:25-27` writes nothing unless `status == "completed"`. The
contract requires a canceled/partial holistic pass to persist an honest
HOLISTIC PARTIAL/CANCELED receipt with a durable checkpoint that a re-run
resumes from. Today cancellation leaves no ledger trace at all (the run
summary exists, but coverage state cannot distinguish "never attempted" from
"attempted and canceled at 40%").

- Evidence: J27 cancel-receipt capture; summary_intake.rs.

## G8 — Recommender/hydration re-walks the repo per Map visit — SCALE/RESOURCE FAILURE — OPEN

`ViewHydrationKey::ScanRecommendations` re-runs `recommend_scans_for_target`
(git diffs + walk-derived inputs) every time the Map page activates
(`requests.rs:128-135`). No memo keyed by (revision, ledger tick); no
operation counters anywhere to prove non-quadratic behavior (§17 machine
assertions require counters).

## G9 — Context snapshot / project-model staleness is advisory, not enforced — HONESTY FAILURE — OPEN

Snapshot has no revision key (G4); `built_at_revision` exists on
project-model sections but nothing marks the holistic/OUTPUT surfaces STALE
when target HEAD moves. Contract §7 requires HOLISTIC COMPLETE → STALE
transitions from revision drift, with re-run offered while stale results
remain visible-but-labeled.

## G10 — J17 canonical journey stale against head TUI — HARNESS DRIFT — OPEN (fix in Phase B)

J17 presses `d` on the target picker and waits for "PDF phase reference
fixture loaded"; head moved the demo entry to the `:demo` command
(`picker_keys.rs` has no `d` demo binding; picker hint says "type `:demo`
for the offline fixture"). Verified manually: `d` is inert; `:demo` loads
the fixture and completes a Run Focus MAP run. All 32 J17 FAIL rows cascade
from this. Pre-existing upstream drift (same era as the bdd-tui V-series
drift), not caused by this engagement.

- Evidence: `journeys-J17/**/report.txt` (both phaseA and gate runs);
  manual repro 2026-07-22 16:2x UTC.

## G11 — Launch-time auto-import runs an attempt AND records a map coverage baseline — HONESTY FAILURE — OPEN

On first launch against monorepo, an attempt auto-ran
`workspace:import-findings` from `/home/ci/monorepo/.audittest/kuzushi-ledger.jsonl`
(1 finding imported), leaving a partial RESULT card the operator must
resolve. Worse: the pre-existing coverage ledger
(`.kuzushi/v3/coverage.sqlite3`) now contains exactly one row —
`scope_id=root, phase=map, mode=default, sha=b460acef, dirty=1` — written by
that unsolicited attempt. A ledger-import side effect earned a root MAP
baseline with no mapping work performed, so the recommender's
"never-scanned" signal for the root map phase is already forged before the
operator does anything. Violates both "page visits never advance reality"
and the contract's requirement that coverage rows be receipt-backed by real
work at a recorded revision.

- Evidence: read-only sqlite dump 2026-07-22 (row ts=1784688607 = recon
  launch); recon capture "RESULT partial · Import findings · completed";
  J25 `map-initial` capture.

## G12 — Scope discovery persists nothing on a 58-root-dir monorepo — SCALE/RESOURCE + HONESTY FAILURE — OPEN

Recon showed `○ scope tree · no persisted nested scopes yet; run 'next' to
map project boundaries` on monorepo, and after a multi-minute TUI session
`/home/ci/monorepo/.kuzushi/v3/project-model/` does not exist at all —
the background `discover_and_save_nested_project_scopes` thread produced no
persisted tree and no error surfaced to the operator. Monorepo has real
members the discovery should find (.gitmodules submodule, go.work/Cargo
manifests, `src/go/src/acme/...`), so either the 50k-entry
`PACKAGE_ROOT_SCAN_BUDGET` walk never completed within the session, or it
failed silently. Either way the operator sees a permanently empty scope
tree on exactly the class of target where scopes matter most, with no
progress, partial, or failure disclosure.

- Evidence: absence of `.kuzushi/v3/project-model/` (checked read-only
  2026-07-22); recon capture; J25/J26 captures.

## G13 — Pre-existing engagement state coexistence — RECORDED

`/home/ci/monorepo/.kuzushi/` predates this engagement (audit-gauntlet
campaign: findings.json 44 KiB, crypto-review.json, v3/ stores incl.
coverage.sqlite3 and index.sqlite3+WAL). A second live kuzushi-head TUI
(tmux session `kz`, pid 1390294 — not ours) holds the same v3 sqlite store
open in WAL mode. Never deleted, never reset; recorded as an environmental
caveat for sqlite-locking flakes during journeys.

## G14 — Target is live and unpinned — RECORDED (drift watch)

Monorepo is a shared live checkout (untracked `.ccsec-*-state/` dirs churn).
Drift checkpoints wrap every journey batch
(`local-monorepo-gate.sh drift_checkpoint_begin/end`); any HEAD/dirty change
is classified TARGET DRIFT and never "fixed" by resetting the target.

## G15 — Whole-repo context build cannot finish in operator time — SCALE/RESOURCE FAILURE — OPEN

J26: `run context:build {}` against monorepo did not complete within the 900 s
journey bound. At timeout the Run Focus showed `stage 3/5 · building
repository inventory · 6959 entries walked` after 15m03s — roughly 7.7
entries/second. At that rate the 100k-entry cap alone is ~3.6 hours, and the
repository has 442,579 tracked files. The walk inspects up to 256 KiB of
content per file inline during enumeration, in a debug binary, on a loaded
shared box — but the contract's §9 bar (efficient git-index enumeration,
bounded shards, checkpoint/resume, minutes not hours) is missed by two
orders of magnitude. Liveness signaling itself was honest (heartbeat
"last progress 7s ago", live entry counter).

- Evidence: `journeys-baseline/20260722-163723/J26/01-context-build-receipt.txt`.

## G16 — Cancellation acknowledged but never honored; TUI wedged — SCALE/RESOURCE + UNSUPPORTED DOMAIN STATE — OPEN

J27: Ctrl+C during the inventory stage flips tasks to `× canceling` and
shows the honest banner "abort requested for tool — waiting for cleanup;
Ctrl+C will not exit while work is live" — but the build never observes the
abort: 180 s later (and still at 4m00s) the run remains `canceling` with
`NO PROGRESS SIGNAL for 4m00s`, no canceled receipt is ever produced, no
checkpoint is persisted, and the operator cannot navigate anywhere
(Navigate mode unreachable, page keys dead). The contract requires
cancellation to land promptly as a durable HOLISTIC PARTIAL/CANCELED
receipt with a resumable checkpoint. Honesty positive: nothing fake was
shown — the product truthfully reports being stuck.

- Evidence: `journeys-baseline/20260722-165445/J27/04-cancel-requested.txt`,
  `05-cancel-receipt.txt`, `06-map-after-cancel.timeout.txt`.

## G17 — Pre-baseline Map composition collapses; prompt unavailable at launch — DESIGN DRIFT — OPEN

Required §10 pre-baseline Map: repository identity/revision, INVENTORY and
SECURITY MODEL status rows, HOLISTIC SCAN "NOT RUN", and one dominant
root-scan action. Actual (J25 `01-map-initial`): the unresolved auto-import
RESULT card owns the top half; the body renders only the PROJECT CONTEXT
pane (no ATTACK SURFACE / HOT MODULES / NEXT SCANS / THREAT MODEL panes at
120x36); NEXT recommends `context build`; no security-model row, no
holistic row. Additionally the prompt cannot accept typed commands
immediately after launch while the unsolicited import run is live — the
harness `setg` submit failed identically in J25 and J26 ("draft never
rendered intact"), and the idle footer still reads "Ctrl+C request abort".

- Related positives recorded for Phase B preservation: guided Map route
  card already implements a Map-level current-revision gate ("No accepted
  current-revision Map exists. What should Kuzushi map first?"); Review/
  Prove disclose imported-finding provenance honestly; Scan page refuses to
  invent a plan ("scanner plan not recorded yet"); target revision loads
  async as "rev:checking…" without fabrication.

---

## Baseline journey verdicts (gate-20260722-163233-baseline, all RECORDED)

| Journey | Result | Headline evidence |
|---|---|---|
| J17 | 3 pass / 32 fail | G10 — `d` demo hook stale vs head (`:demo` now); all fails cascade |
| J25 | 9 pass / 2 fail | G1 (no holistic NEXT), G11 (prompt owned by unsolicited run), G17 |
| J26 | 1 pass / 6 fail | G15 — build incomplete at 900 s (6,959 entries / 15 min) |
| J27 | 4 pass / 3 fail | G16 — cancel never honored, UI wedged; route/modules cards honest |

Target drift: none across the whole gate (`head` stable at `b460acef`,
tracked tree clean at every checkpoint). `.kuzushi` state inventory
51 → 53 entries — only Kuzushi's own v3 store (run records, sqlite
WAL/shm, `latest` pointer); nothing pre-existing deleted.

Journey-capture verdict rows (PASS/FAIL/ask answers per capture) live under
the corresponding `gate-*/journeys-*` directories; this ledger records the
durable classification and repair status.
