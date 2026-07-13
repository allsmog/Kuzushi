# Plan 036: Bind benchmark provenance to the executed scan and validated corpus

> Executor: all tests and baseline regeneration in this plan use committed
> deterministic fixtures. Do not invoke a provider-backed model.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: HIGH
- **Category**: benchmark integrity/provenance
- **Depends on**: Plans 018 and 019
- **Planned at**: commit `775a4134f2cb`, Cycle 9

## Why this matters

The harness accepts `--run` without `--config`, hardcodes a Semgrep task, and
then hashes the unrelated `scanConfig` declaration as if it described the
execution. Unknown config keys are silently ignored. The committed merge gate
uses exactly that path. Ground-truth JSON is loaded through an unchecked type
cast, and execution mode is not reconciled with the SARIF receipt, so a
deterministic fixture can be labeled as a real-model result. These gaps make a
provenance-bound scoreboard look stronger than its actual evidence.

## Steps

1. Define and validate the small harness-owned scan-config surface. Live
   `--run` requires an exact config matching the provenance declaration; reject
   unknown keys and construct the command only from that normalized value.
2. Validate ground-truth documents before scoring: bounded regular file,
   exact schema, unique IDs, safe relative paths, positive bounded lines,
   canonical CWEs, booleans, pinned repository revision, and finite entry
   count.
3. Extend canonical benchmark SARIF receipts with complete observed model-call
   evidence derived from terminal run summaries. A real-model declaration must
   use canonical run-summary spend, a complete audit, at least one observed
   call, and exactly the declared model. Deterministic-fixture mode must prove
   zero calls and no observed models; a live deterministic scan may retain its
   canonical run-summary receipt while a committed synthetic SARIF uses the
   fixture source.
4. Route deterministic CI and baseline freezing through the same explicit
   harness config, regenerate fixture metrics/baseline from the mock SARIF, and
   document the evidence boundary.
5. Before a live run, prove the dataset repository is the declared remote at
   the declared commit/tag, is the worktree root, and is clean. Reject a
   symlinked, dirty, wrong-remote, or wrong-revision checkout before scanning.
6. Reject `real-model` provenance on the existing `--sarif` path. A canonical
   spend receipt does not bind imported findings to the declared checkout, so
   real-model publication must use `--run` and execute the checkout proof.

## Verification

- `--run` without config, unknown config keys, and declaration/config
  contradictions fail before a scan starts; no hidden task is appended.
- Duplicate IDs, traversal/absolute paths, invalid lines/CWEs/booleans,
  unknown fields, oversized corpora, and unpinned datasets fail closed.
- Real-model mode rejects deterministic receipts, zero observed calls,
  incomplete audit, or a different/multiple model; deterministic mode rejects
  canonical paid receipts or claimed calls.
- Live mode rejects a dirty corpus, a mismatched origin, a symlinked/nested
  checkout, or a HEAD that does not resolve to the declared dataset revision.
- Real-model `--sarif` fails before dataset/SARIF reads; deterministic fixture
  imports remain supported and real-model receipt validation stays covered as
  a pure contract test.
- Rust SARIF export tests prove model-call evidence comes from the included
  canonical run summaries and malformed trace evidence is not called complete.
- Benchmark tests, typecheck, Rust workspace checks, workflow contract tests,
  and deterministic baseline comparison pass without provider spend.

## Done criteria

Every published benchmark result binds its declared command surface, validated
corpus, spend source, and model mode to evidence produced by the execution it
claims to represent.

## Cycle 9 recheck

- A read-only recheck found that an existing canonical receipt could be reused
  with `executionMode=real-model` and a different declared dataset because the
  imported SARIF schema has no checkout/revision binding.
- The safe finite policy now rejects that combination before reading benchmark
  inputs and requires `--run`, which performs the pre/post checkout proof. The
  deterministic fixture import path is unchanged.
- A second Cycle 9 pass closed three deeper integrity gaps. Non-fixture corpus
  declarations now require immutable full commit digests; checkout proof rejects
  sparse and non-default index state and tracked submodules, hashes tracked
  worktree bytes against a temporary HEAD-only index, and treats ignored
  untracked content as non-corpus input except for Kuzushi-owned state created
  after the scan.
- SARIF import is now a no-follow bounded regular-file read with explicit byte,
  run, rule, result, location, and string budgets. Candidate generation indexes
  findings by normalized file, CWE, and line window, while global candidate and
  residual-flow budgets fail dense adversarial inputs deterministically.
- Benchmark model evidence excludes audit rows explicitly marked as pre-call
  failures (`callAttempted=false`); legacy rows without the field remain calls.
- A final TOCTOU recheck found that proof still bracketed a scan executed in the
  mutable source checkout. Live scans now run only in a private materialization
  of the declared commit: bounded tree/blob protocols, portable path and entry
  limits, whole-chain symlink containment, read-only source modes, and a
  no-follow post-run manifest bind the execution bytes. Only new `.kuzushi`
  state is permitted, and tracked `.kuzushi` entries remain immutable.
- Provider-free verification: all 120 deterministic benchmark tests passed,
  including moved-tag, hidden-index, sparse-checkout, ignored-content, oversized
  SARIF/blob inputs, disjoint-index, dense-residual-budget, order-invariance,
  checkout-mutation, tracked-state, and chained-symlink regressions; benchmark
  TypeScript typecheck and targeted formatting/lint checks passed.
- The root closure gate passed all 183 Vitest tests, 122 Node tests, all four
  TypeScript projects, codegen drift, documentation, dependency policy, and
  packed-runtime verification without executing a provider-backed benchmark.
