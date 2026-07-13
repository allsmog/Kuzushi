# Kuzushi benchmark scoring

The TypeScript harness evaluates a ground-truth dataset against a complete
scan-produced SARIF document. It is intentionally stricter than a generic
SARIF viewer because benchmark mistakes can turn into false product claims.

## Finding scope and identity

- Every `runs[]` entry is scored. Rule tags are resolved within the run that
  emitted the result.
- A result is in scope when its first location is a local file URI with a
  positive `startLine`. Explicit non-file URIs are out of scope. A local result
  with a missing rule, file, or line is malformed and fails the run.
- Exact duplicates are counted once. Identity preference is SARIF
  `fingerprints["kuzushi/v1"]`, then `properties.kuzushiIdentityId`, then the
  normalized `(file, startLine, endLine, ruleId)` tuple. Reusing a stable
  fingerprint or identity for different sites or rules is an error.
- Matching is one-to-one, maximum-cardinality, then minimum-total-line-distance.
  Ground-truth keys and finding identities provide the deterministic tie-break.
  A finding with no compatible ground-truth site is a false positive, including
  findings in local files not named by the ground-truth corpus.
- A true-positive match requires an explicit equivalent CWE from the result,
  its rule tags, or Kuzushi's `kuzushiCwe` property. Unknown and wrong CWEs do
  not wildcard-match a nearby truth; they remain false positives and leave the
  expected vulnerability as a false negative.
- A clean scan is one SARIF driver run with `rules: []` and `results: []`, not
  `runs: []`. It therefore scores truthfully as zero detections while retaining
  the canonical outer-run spend receipt.
- `--line-tolerance` accepts only decimal integers from 0 through 100.

## Result provenance

The harness requires `--provenance <path>`. That explicit declaration chooses
`deterministic-fixture` or `real-model` mode and records the model, normalized
scan configuration, code revision, and observation time. The harness hashes
the inspected ground truth, scoring-contract sources, and normalized config
into every metrics file. Dataset, harness, config, model, scoring-mode, and
execution-mode identities must match before baseline comparison or publication;
code revisions stay visible as the before/after subjects and do not block a
comparison. The scoreboard has no caller-controlled mock/real switch.

For `--run`, `--config` is mandatory and must match the declaration exactly.
Only `mode`, `tasks`, `failOn`, and `budget` are accepted because those are the
only command fields the harness owns; unknown fields fail instead of being
hashed and ignored. The scan command is built solely from that value, with no
hidden default task. Target-local Kuzushi configuration remains visible through
the outer run's observed `configHash` rather than being misrepresented as a
harness command-line setting.

Before a live scan starts, the harness also verifies that `dataset/repo` is a
non-symlink Git worktree root, that `origin` matches the ground-truth
`repoUrl`, that `HEAD` resolves to the declared full commit ID, and that the
checkout is clean. The scan does not run in that mutable checkout. The harness
loads the declared tree through bounded `git ls-tree` and one bounded
`git cat-file --batch`, rejects unsafe entries and escaping symlink chains, and
materializes those exact object bytes into a private read-only root. Only its
`.kuzushi` state directory is writable. A no-follow byte/type manifest must
still match after the scan, apart from newly generated `.kuzushi` state, before
the result can be published.

Real-model provenance therefore requires `--run`. The `--sarif` import path is
reserved for `deterministic-fixture` evidence: an existing provider SARIF
receipt does not itself prove which dataset checkout or revision produced its
findings. This policy is enforced before the harness reads the dataset or SARIF,
so an imported receipt cannot be relabeled with a different corpus identity.

## Spend truth

Benchmark SARIF has exactly one authoritative receipt at
`properties.kuzushiBenchmark.aggregateSpend`:

```json
{
  "schemaVersion": 2,
  "aggregateSpend": {
    "runId": "scan-...",
    "totalCostUsd": 0.125,
    "source": "canonical-run-summary",
    "models": ["anthropic:claude-sonnet-4-6"],
    "llmCallCount": 3,
    "llmAuditComplete": true,
    "configHash": "sha256:..."
  }
}
```

The Rust scan export copies this value from the terminal outer scan
`run.json.costUsd`. That outer value already aggregates child-tool spend, so
child summaries are never summed again. Missing metadata, per-run legacy totals,
run-level duplicates, negative values, and non-finite values fail closed. A
measured zero is valid and carries a receipt in the metrics JSON.

The committed synthetic fixture uses `source: "deterministic-fixture"` and
makes no provider request. Its receipt must contain zero calls and no observed
models. A live provider-free deterministic scan keeps its canonical run-summary
source and must additionally carry the outer-run config hash.
Real-model mode requires canonical run-summary spend, a complete trace audit,
at least one observed call, an outer-run config hash, and exactly the model in
the provenance declaration. It also requires the live `--run` path so commit
materialization and the manifest proof bracket the scan. The real-model
workflow remains manual and approval-gated; do not use its output as a baseline
until an authorized run
completes with that evidence and reviewed provenance.

## Deterministic verification

```sh
node --test benchmarks/regression-check.test.mjs
pnpm benchmark --dataset benchmarks/govwa \
  --sarif benchmarks/fixtures/mock-govwa.sarif.json \
  --provenance benchmarks/baseline-provenance.json \
  --output benchmarks/fixtures/mock-govwa-metrics.json
pnpm benchmark:regression -- \
  --results benchmarks/fixtures/mock-govwa-metrics.json
pnpm typecheck:benchmarks
```
