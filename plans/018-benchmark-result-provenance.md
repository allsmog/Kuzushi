# Plan 018: Bind benchmark comparisons and scoreboards to result provenance

> Executor: preserve fail-closed spend validation. Do not run a paid model or
> label any deterministic fixture as a real-model result.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Category**: product truth/benchmarking
- **Depends on**: Plan 017
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

Current metrics contain counts and a spend receipt but no dataset, harness,
configuration, model, or execution-mode identity. Regression comparison keys
only by dataset name, baseline updates retain unrelated global provenance, and
the scoreboard treats omission of `--mock` as proof of a real LLM run. Results
from different detector configurations can therefore be compared or published
as if they were equivalent.

## Steps

1. Define a versioned per-result provenance object containing at least
   execution mode (`deterministic-fixture` or `real-model`), dataset content
   digest/revision, harness contract version/digest, normalized scan-config
   digest, model identity, Kuzushi/code revision, and the existing spend
   receipt identity. Separate comparability fields from observational fields
   such as code revision, timestamp, duration, and run ID: revisions are
   expected to differ in a regression comparison but must remain visible.
2. Have the harness derive provenance from inspected inputs and canonical scan
   metadata. Never infer `real-model` from a missing flag. Deterministic fixtures
   must carry an explicit committed provenance document; real scans must carry
   a canonical model/config identity or fail closed.
3. Move baseline provenance to each dataset result (with a schema migration),
   validate all loaded metrics structurally, and require exact compatibility
   across dataset, harness/scoring contract, normalized config, model, and mode
   before compare, update, or bootstrap. A mismatch must explain the differing
   fields and require an intentional new baseline; differing code revisions are
   reported as the before/after subjects, not rejected.
4. Make the scoreboard use the same validator and derive its displayed mode,
   model/config, dataset revision, and commit from result artifacts. Remove or
   reject caller flags that contradict artifact provenance. Reject mixed,
   duplicate, malformed, or incomparable result sets.
5. Regenerate only the deterministic fixture metrics and baseline provenance.
   Keep the manual paid workflow approval-gated and untouched.

## Verification

- A mock artifact cannot be printed as a real-model run, even without a CLI
  flag; a contradictory flag fails.
- Dataset, model, config, harness, and mode mismatches fail before comparison or
  update with field-specific diagnostics; code-revision changes remain
  comparable and are displayed explicitly.
- Malformed metrics and mixed-provenance scoreboards fail closed.
- Deterministic benchmark, regression, scoreboard, typecheck, docs, and fixture
  regeneration checks pass without a provider request.

## Done criteria

Every compared, baselined, or published metric is self-describing and is
accepted only against explicitly compatible provenance.
