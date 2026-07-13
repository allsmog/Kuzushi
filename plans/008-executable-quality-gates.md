# Plan 008: Make benchmark, CI, setup, and documentation claims executable

> Executor: make current claims truthful and mechanically checked. Do not run a
> paid real-model benchmark or fabricate metrics. Preserve unrelated dirty edits.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Category**: tests/dx/docs/direction
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

The detection regression workflow compares its only mock result with an empty
baseline and treats missing entries as a pass. Aggregate typecheck omits the
codegen project, contributor setup can succeed without Rust, cargo-deny claims
duplicate bans it does not run, and several live-tree docs point to deleted or
already-fixed behavior.

## Current state

- `benchmarks/baseline.json` has no datasets;
  `benchmarks/regression-check.ts::compareDataset` passes a missing baseline.
- `scripts/typecheck-all.mjs` lists root, benchmarks, and perf but omits
  `scripts/codegen/tsconfig.json`.
- `scripts/bootstrap.sh` and `.devcontainer/devcontainer.json` do not establish
  the pinned Rust toolchain; `CONTRIBUTING.md` calls JS-only `pnpm test`
  "everything."
- CI's cargo-deny command omits `bans`; `deny.toml` has no `[bans]` policy.
- Stale claims exist in `README.md` near the retired TS runtime tree,
  `docs/plans/product-flow-prd.md`, `ROADMAP.md`, and the `--ignored` command in
  `crates/kuzushi-tui/tests/parity.rs`.

## Steps

1. Make missing benchmark baselines fail closed unless an explicit bootstrap or
   update flag is present. Add unit fixtures for missing, regression, equality,
   update, and malformed baselines.
2. Generate and commit the deterministic mock-backed baseline used by CI,
   including provenance (dataset revision, harness/config, mock identity, and
   timestamp semantics). Expand workflow path filters to all detection-affecting
   crates/bridge inputs. Add an opt-in manual real-model workflow that records
   the same provenance and requires explicit credentials/approval; do not run it.
3. Add codegen tsconfig to `typecheck:all` and a contract test ensuring every
   declared TS project is represented.
4. Make bootstrap check `cargo`, `rustc`, rustfmt, and Clippy; provision the
   pinned Rust feature in the devcontainer; make contributor commands clearly
   run both native and TypeScript verification.
5. Add an explicit `[bans]` policy and run `cargo deny check advisories licenses
   bans sources` identically in docs and CI. Add only narrow, explained duplicate
   exceptions proven necessary by the current resolved graph.
6. Reconcile the four stale documentation areas against the live tree. Extend
   `check-doc-command-drift.mjs` with path and test-selector guards where a
   stable mechanical assertion is possible.

## Verification

```text
pnpm typecheck:all
pnpm test
pnpm check:docs
pnpm benchmark:regression -- --help
cargo deny check advisories licenses bans sources
bash -n scripts/bootstrap.sh
```

Also execute the deterministic benchmark workflow commands locally; the first
comparison against the committed mock baseline must pass, while a fixture with
an unknown dataset must exit nonzero.

## Done criteria

- Missing benchmark baselines cannot silently pass CI.
- The committed deterministic gate has provenance and a real non-empty baseline.
- Real-model numbers remain explicitly unmeasured until an operator runs the
  credentialed manual workflow.
- All TS projects, Rust prerequisites, dependency bans, and cited docs are
  truthfully checked.

## STOP conditions

Stop before spending provider credits, weakening existing dependency policy to
make bans green, or rewriting historical documents whose historical status is
explicit. Report any external credential requirement instead.
