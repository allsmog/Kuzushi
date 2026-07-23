# Kuzushi Local Monorepo Acceptance — Phase A Baseline (SEALED)

Date: 2026-07-22 · Engagement: local monorepo acceptance (MONOREPO)
Author: repository maintainer
acceptance contract. This report is immutable baseline evidence: it records
what production Kuzushi does against the operator's real checkout **before
any repair**. The companion gap ledger is
[KUZUSHI_LOCAL_MONOREPO_GAP_LEDGER.md](./KUZUSHI_LOCAL_MONOREPO_GAP_LEDGER.md).

## 1. Target resolution and provenance

`KUZUSHI_DEVEX_TARGET` was unset in the operator environment. Resolution,
recorded with reasoning in
`/home/ci/kz-local-monorepo/phaseA-20260722-161613/provenance-baseline.json`:

- **Target: `/home/ci/monorepo`** (alias `monorepo`). Real git worktree,
  remote `git@github.com:acme/monorepo.git` — monorepo *is* the monorepo
  codebase. 442,579 tracked files, 18 GiB, 58 root directories,
  `bazel-bin`/`bazel-out` symlinked outside the repo, one uninitialized
  submodule (`src/go/src/acme/vendor`, left uninitialized).
- `/home/ci/monorepo-canonical` is an empty non-git directory → **no parity pass
  is possible** (`--parity` reports this honestly).
- Baseline TargetRevisionSet: HEAD `b460acefd05c901969ca99cc2eefae7711040fea`,
  branch `snejad-wycheproof-chunkedgcm`, tracked tree clean, live untracked
  churn (`.ccsec-*-state/` dirs). The target is a **live shared checkout**,
  never pinned/reset/cleaned by this engagement.
- Kuzushi under audit: `1165f02c064f46140cf621b6646a472908596b37` (+ known
  intentional local dirt), binary sha256
  `108db41a…985737`, `kuzushi 0.24.0-alpha.8 (1165f02c0+dirty · debug)`.
- Pre-existing engagement state under `/home/ci/monorepo/.kuzushi/`
  (audit-gauntlet campaign) inventoried and **protected** — never deleted.
  Environmental caveat: a second live kuzushi TUI (tmux `kz`, not ours)
  holds the same v3 sqlite store open (WAL).

## 2. How the baseline was captured

Gate: `scripts/devex/local-monorepo-gate.sh --baseline`
(`KUZUSHI_DEVEX_TARGET=/home/ci/monorepo KUZUSHI_MONOREPO_ALIAS=monorepo`).
Artifacts: `/home/ci/kz-local-monorepo/gate-20260722-163233-baseline/`
— target provenance JSON at every checkpoint, `.kuzushi` state inventory
before/after (never deletes), one production build, then journeys
**J17** (canonical fixture reference) and the new real-target journeys
**J25/J26/J27** (authored for this engagement; they never delete target
state — the old J22/J23 `rm -rf @TARGET/.kuzushi` pattern is forbidden
here). Every capture has `.txt` + `.ansi` + `.provenance.json` (binary
sha256, kuzushi head, dirty flag, alternate-screen state, dimensions).
Baseline mode records journey failures as evidence (`RECORDED`), failing
only on infrastructure errors. Verdict: `CLEAN` (infrastructure), zero
target drift across all checkpoints.

## 3. What the product does today (observed, with evidence)

1. **Launch against monorepo** lands in the Workbench Map page with an
   **unsolicited attempt already run**: `workspace:import-findings`
   auto-imported 1 finding from `monorepo/.audittest/kuzushi-ledger.jsonl`,
   left an unresolved `RESULT partial` card, **and wrote a
   `root/map/default` coverage baseline row** into
   `.kuzushi/v3/coverage.sqlite3` (the only row in the ledger) — mapping
   coverage earned by an import side effect (ledger G11, HONESTY FAILURE).
   While that run is live the prompt rejects typed commands (J25/J26 setg
   failures) (G17).
2. **Pre-baseline Map page** (J25 `01-map-initial`): PROJECT CONTEXT pane
   only — `context:missing · Next: context build`, empty scope tree, no
   ATTACK SURFACE / HOT MODULES / NEXT SCANS / THREAT MODEL panes at
   120x36 under the unresolved result. NEXT recommends `context build`.
   **No holistic concept exists anywhere in the codebase** (no state
   machine, no gate, no "Run holistic repository scan" action) — the
   contract's central requirement is entirely absent (G1, G2).
3. **Whole-repo context build** (J26): honest live progress (heartbeats,
   entry counter) but **~7.7 entries/second** — 6,959 entries after 15
   minutes at `stage 3/5 · building repository inventory`; did not finish
   within 900 s. The walk is recursive `fs::read_dir` (never the git
   index), hard-capped at 100k entries (~23% of this repo), with inline
   256 KiB/file content inspection and no checkpoint/shard/resume
   (G3, G15). The inventory persists only inside
   `context-snapshot.json` (no revision key) and is **rebuilt live by at
   least four other consumers** (G4).
4. **Cancellation** (J27): Ctrl+C is acknowledged honestly (`× canceling`,
   "abort requested — waiting for cleanup") but **never honored** — 4+
   minutes later still canceling, `NO PROGRESS SIGNAL`, no canceled
   receipt, no checkpoint, and the operator is trapped in Run Focus
   (navigation dead, "Ctrl+C will not exit while work is live") (G16).
5. **Scope tree**: background discovery persisted **nothing** on this
   58-root-dir monorepo (`.kuzushi/v3/project-model/` does not exist after
   multi-minute sessions), silently (G12). The persisted-tree design is
   flat anyway — every scope parents to root, no nearest-parent nesting
   (G5).
6. **Coverage/recommendations**: run baselines only ever land on the root
   scope id (G6); partial/canceled/interrupted runs write nothing (no
   resumable partial receipts, G7); the recommender has no root-first
   gate and re-runs its fold (git diffs + walks) on every Map-page
   activation with no memo or operation counters (G2, G8); snapshot
   staleness on revision drift is advisory only (G9).
7. **Honesty positives to preserve in Phase B**: guided Map route card
   already gates on "No accepted current-revision Map exists"; Review and
   Prove disclose the imported finding's provenance and unverified proof
   ladder truthfully; Scan page refuses to invent a plan; revision loads
   as "rev:checking…" instead of a fabricated value; Run Focus liveness
   and cancel banners never claim false completion.
8. **Harness reality**: J17, the canonical five-phase reference journey,
   fails 32 checks on head because the target-picker demo hook moved from
   the `d` key to the `:demo` command — pre-existing upstream drift, to be
   repaired in Phase B alongside the product slices (G10).

## 4. Baseline verdict

The required root-first monorepo product story does not exist in today's
Kuzushi: no holistic domain state (G1), ungated child recommendations (G2),
an inventory that can neither finish (G15) nor persist/rebind (G3, G4),
a flat scope graph (G5), root-only coverage (G6), non-resumable partials
(G7), unhonored cancellation (G16), silent scope-discovery failure (G12),
and a coverage row forged by a launch-time import side effect (G11). The
honest-disclosure machinery that does exist (receipts, provenance, liveness
banners) is a solid foundation: the product generally refuses to lie — it
simply lacks the root-first domain model and the scale engineering this
target class demands.

Phase B repairs proceed against gap ledger entries G1–G12, G15–G17, with
G13/G14 as standing constraints (protected pre-existing state, live-target
drift watch). Definition of done: two consecutive clean FULL gates
(`local-monorepo-gate.sh --full`) on a stable target revision.
