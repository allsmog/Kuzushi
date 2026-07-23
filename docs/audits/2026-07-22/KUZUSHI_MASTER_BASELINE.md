# Kuzushi Master Acceptance — Baseline (Phase A, SEALED BY REFERENCE)

Date: 2026-07-22 · Campaign: KUZUSHI MASTER AUDIT → REPAIR → CONVERGENCE

This master campaign incorporates and supersedes the earlier local-monorepo
acceptance contract. Its Phase A was executed and **sealed** under that
contract before the master contract arrived; per master-contract §2 the
sealed evidence is authoritative and is adopted here by reference rather
than re-captured (re-running Phase A would produce a *post-repair* state —
Cycle-2 inventory repairs were already in flight when the master contract
landed, and are disclosed below).

## 1. Sealed Phase A evidence (adopted by reference)

- Baseline report: [KUZUSHI_LOCAL_MONOREPO_BASELINE.md](./KUZUSHI_LOCAL_MONOREPO_BASELINE.md)
- Human gap ledger: [KUZUSHI_LOCAL_MONOREPO_GAP_LEDGER.md](./KUZUSHI_LOCAL_MONOREPO_GAP_LEDGER.md)
  (G1–G17; machine form now in
  [kuzushi-master-gap-ledger.jsonl](./kuzushi-master-gap-ledger.jsonl))
- Artifact roots (immutable, never overwritten):
  - `/home/ci/kz-local-monorepo/phaseA-20260722-161613/`
  - `/home/ci/kz-local-monorepo/gate-20260722-163233-baseline/`
- Target: `/home/ci/monorepo` (alias `monorepo`; **is** monorepo — remote
  `git@github.com:acme/monorepo.git`). HEAD
  `b460acefd05c901969ca99cc2eefae7711040fea`, branch
  `snejad-wycheproof-chunkedgcm`, tracked tree clean, 442,579 tracked files,
  18 GiB, one uninitialized submodule. `KUZUSHI_DEVEX_TARGET` was unset;
  resolution reasoning recorded in `provenance-baseline.json`.
  `/home/ci/monorepo-canonical` is empty/non-git → no parity target exists.
- Kuzushi under audit: `1165f02c064f46140cf621b6646a472908596b37` (+ known
  local dirt), `kuzushi 0.24.0-alpha.8 (1165f02c0+dirty · debug)`.
- Toolchain at baseline: rustc per repo toolchain, Node 26 (`~/.local`),
  tmux (system), pnpm available; provider capability: Vertex ADC path
  available on this box (per prior STOCK bridge work) — no credential values
  recorded anywhere.
- Journeys run: J17 (canonical fixture reference — 3/32, G10 drift),
  J25/J26/J27 (authored for this engagement, real-target, non-destructive).
  J22/J23 were **statically inspected and NOT executed** — each contains
  `rm -rf "@TARGET/.kuzushi"` (master ledger M1, HARNESS SAFETY FAILURE),
  which the master contract §12.3 hard-fails.
- Target preservation: zero drift across all checkpoints; `.kuzushi` state
  51 → 53 entries, only Kuzushi's own v3 run records; nothing pre-existing
  deleted.

## 2. Master-contract hypothesis verification (H1–H10)

Verified 2026-07-22 against the local working tree (checks re-run today
where the sealed ledger did not already cover them):

| # | Hypothesis | Verdict | Evidence |
|---|---|---|---|
| H1 | Screen-composition redesign substantially present | **CLOSED-AT-BASELINE** (composition layer exists) | `PhaseSurfaceId` live in `crates/kuzushi-tui/src/app/shellapp.rs` et al.; `WorkbenchPane` absent from the tree; J21 exists and drives recommendation/investigation/trace/chains/Scan-setup |
| H2 | evidence-loop gate: J21–J24, hidden module-path default, stale provider prose | **CONFIRMED** | `evidence-loop-gate.sh:30` `WORKLOAD_TARGET=${KUZUSHI_DEVEX_TARGET:-/home/ubuntu/monorepo/src/py/cloud}`; `:118` loops J21–J24; `:139-140` hard-coded "no ANTHROPIC_API_KEY; no Vertex provider" (ledger M2) |
| H3 | J22/J23 delete `@TARGET/.kuzushi` | **CONFIRMED** | `J22:18`, `J23:23` `shell: rm -rf "@TARGET/.kuzushi"` (ledger M1) |
| H4 | Scope discovery: flat root attachment, no nearest-parent, redundant work | **CONFIRMED** | Ledger G5 (`insert_scope` parent=ROOT always), G12 (persists nothing on monorepo, silently), G4/G8 (redundant walks) |
| H5 | Recommendations lack a root-baseline gate | **CONFIRMED** | Ledger G1/G2 (`fold.rs` independent per-scope scoring; no holistic concept in the codebase) |
| H6 | Inventory: capped, truthful truncation, heartbeats, not persisted/resumable | **CONFIRMED** | Ledger G3/G4/G15 (100k cap ≈23% of monorepo, honest heartbeats, no checkpoint/resume, snapshot-embedded only) |
| H7 | Attack chains advisory, not first-class validation subjects | **CONFIRMED** | `chains.rs:7` "Candidates are advisory leads for operator review"; no scenario lifecycle |
| H8 | Prove is finding-oriented; no durable AttackScenario subject | **CONFIRMED** | `grep ValidationSubject\|AttackScenario` over kuzushi-core: zero hits (ledger M3) |
| H9 | J24 proves refusals/deferral only, not draft→stage→apply→reverify | **CONFIRMED** | J24 header/body: refusal + defer coverage only (ledger M4) |
| H10 | J17 stale vs current composition | **CONFIRMED** | Ledger G10 (`d` → `:demo` drift; 32-check cascade) |

No hypothesis other than H1 is fixed in the working tree; nothing is
recreated that already exists.

## 3. Repairs already in flight at master-contract adoption (disclosure)

The local-monorepo contract's Phase B had begun before the master contract
arrived. Production changes already made (all Kuzushi-side, none touching
the target), belonging to master Cycle 2 (inventory):

- `build_repository_inventory`: git-index enumeration
  (`git ls-files -z --cached` with fs-walk fallback), budget-charged-before-
  read byte accounting, per-entry cancellation with honest partial-prefix
  truncation disclosure, `_with_observer` API; 69 inventory unit tests green
  incl. a real-worktree git-vs-fs parity test and a cancellation test.
- `context:build` wired to `ScanCancellation` (G16 root fix, e2e proof
  pending).
- A `SourceTextScan` memoization refactor of the per-line route inspectors
  (G15 measured root cause: O(lines×bytes), 140 ms/entry) is in progress.
- Harness: `local-monorepo-gate.sh` (baseline/fast/full/live/parity) and
  journeys J25–J27 (non-destructive, real-target) exist and produced the
  sealed baseline.

These do not alter the sealed baseline evidence; they are recorded in the
ledger as `IN-REPAIR` and must pass the master gate like everything else.

## 4. Baseline verdict

Identical to the sealed report §4: the root-first monorepo product story
does not exist (G1/G2), the inventory can neither finish (G15) nor persist
(G4), the scope graph is flat (G5), coverage is root-only and success-only
(G6/G7), cancellation is unhonored (G16), launch forges a coverage row
(G11) — while the existing honesty machinery (receipts, provenance,
liveness banners) is a solid foundation. The master contract adds: harness
safety failures (M1/M2), the missing AttackScenario/ValidationSubject
domain (M3), and the missing patch-lifecycle journey coverage (M4).

Campaign state and cycle progress live in
[KUZUSHI_MASTER_LOOP_STATE.md](./KUZUSHI_MASTER_LOOP_STATE.md).
