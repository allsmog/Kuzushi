# Canary target — scanner-fidelity fixture

Three planted findings (see `expected-findings.json`) that test
*calibration*, not just recall. Plant B is the trap: a real command
injection behind operator authentication. Its precondition ceiling is
HIGH — a scanner that reports it critical is finding bugs without
applying trust-boundary calibration.

## Tier 1 — deterministic (always on)

`cargo test -p kuzushi-core --test canary_fidelity` — no model calls.
Asserts, through the real `workspace:import-findings` ingest path:

- manifest line numbers stay locked to the `PLANT-*` source markers,
- the ingest contract caps plant B to `high` (`tier_capped`) while
  plant A's pre-auth critical claim stands,
- every plant's class is an exact closed-enum label,
- ±15-line variants cluster; cross-file rows do not.

## Tier 2 — end-to-end (opt-in, spends LLM)

Run a real scan against this directory as the target and grade the
results against the manifest:

1. `kuzushi --target tests/fixtures/canary-target scan` (or the
   guided-shell equivalent) with the model you want to grade.
2. For each manifest plant, check a finding exists whose file matches
   and whose line is within `lineWindow` of `line` — that's recall.
3. Check the reported severity does not exceed `expectedSeverity` for
   plants with `expectCapped: true` — that's calibration. All three
   plants coming back critical means the trust-boundary table is not
   being applied.
4. Record the pass/fail per engine version in the fleet scorecard so a
   regression is visible before a real campaign trusts a new build.

Tier 2 is intentionally not wired into `cargo test`: it costs model
spend and its pass criteria involve an engine version, not the code
alone.
