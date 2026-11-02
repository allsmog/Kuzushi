# Full CI could never resolve its first quality baseline (2026-11-02)

## The defect

`.github/workflows/ci-full.yml` is the only workflow that runs `rust-core`,
`windows-compile`, `cargo-deny`, `coverage`, `mutation`, `e2e`, `real-semgrep`,
`verify-pack`, and `node22-compat`. Every one of those jobs declares
`needs: quality-gauntlet`, and `quality-gauntlet`'s ninth step resolves the
changed-code quality interval:

```yaml
- name: Resolve the complete quality interval
  id: interval
  env:
    QUALITY_BASE_REF: ${{ inputs.quality_base_ref }}
  run: node scripts/quality-interval.mjs
```

`scripts/quality-interval.mjs` accepted exactly two baselines: an explicit
`quality_base_ref` input, or the newest **successful** ancestral Full CI run on
the branch. Neither is reachable from the monthly `schedule` trigger — a
scheduled event carries no inputs, and no Full CI run on `main` has ever
concluded `success`. So the step threw:

```text
Error: No successful ancestral Full CI baseline; supply quality_base_ref
explicitly for the initial run
```

The advice in that message was unreachable from the trigger that hit it. The
run died 40 seconds in and skipped all eleven downstream jobs. Observed on
run 41328219289 (2026-11-01, `main` at `efb5de8`) and run 36896353990
(2026-10-01); run 41361400731's monthly predecessors show the same shape. The
release path was never affected: `release-candidate.yml` declares
`quality_base_ref` as `required: true` and passes it through.

Net effect: the repository's only license/advisory audit, Windows compile
check, end-to-end suite, packaging contract, coverage and mutation sweeps had
no successful run to point at, while `main` kept merging. Pull-request CI
(`ci.yml`) still covered `verify:quick:summary`, `rust-tests`, and
`platform-runtime`, which is why the gap stayed quiet.

## Why this ranked first

Highest blast radius of anything found this pass: one deterministic error
disabled nine CI jobs that nothing else in the repository runs, and it will
recur every month until the bootstrap is reachable. It is also the cheapest to
fix correctly — the policy was already written down, only its initial case was
missing — and it is independently reviewable without touching product code.

## What changed

`scripts/quality-interval.mjs` gained a third and last rung below the existing
two: a baseline declared in `.github/quality-baseline`.

- Precedence is unchanged where it already worked: explicit input, then the
  newest successful ancestral run. The declared baseline is consulted only when
  neither exists, and goes inert the moment a Full CI run succeeds on the
  branch.
- The baseline is committed, so it is reviewed like any other change, and it is
  a single full lowercase 40-character SHA — `HEAD^`, a tag pattern, or a short
  SHA is
  rejected rather than guessed at.
- Ancestry is still verified for every rung by `main()`, so a stale declared
  SHA fails as a non-ancestor instead of silently measuring a bogus interval.
- The resolved rung is disclosed as `source` in the step's JSON receipt
  (`input`, `run`, or `bootstrap`), so a reader can tell which baseline a
  quality interval actually used.

Absent, malformed, and non-ancestral declared baselines remain hard failures.
`RELEASING.md`'s full-quality-run contract records the third rung.

## What this does not claim

The nine downstream jobs have not had a successful run in this repository, so
this change unblocks them rather than attesting that they pass. The first
monthly sweep after it lands is the first real signal from `cargo-deny`,
`windows-compile`, `e2e`, `coverage`, `mutation`, `verify-pack`,
`node22-compat`, `real-semgrep`, and `rust-core`, and it may surface genuine
failures in any of them. That is the gate working, not a regression from this
change.

One related latent failure was measured and deliberately left alone:
`crates/kuzushi-tui/src/renderer/context_generation/controls.rs` is 305 logical
lines, over the gate's 300-line limit for files **added** in the interval. It
entered on `95ed006d7` (2026-10-25), so an interval that begins before that
commit fails the CRAP-risk gate on it. The declared baseline is `f49b882`
(2026-11-01), after the add, so the first sweep is not blocked by it; a release
candidate passing an older `quality_base_ref` would be, and splitting that file
is its own change.
