# review-yield HISTORY

One row per experiment run. Run directories are reproducible from the dataset
digest and the configuration digest — there is no wall clock anywhere in the run
id, the results, or the artifact — so they are not committed; this file is.

## What a row is allowed to claim

Every number below is **measured** on the named dataset digest. Nothing in this
file is illustrative. A row generated from real Kuzushi review data would name a
real dataset digest; every row here names the synthetic corpus, and a synthetic
corpus proves the pipeline runs, not that the idea works.

## Runs

| run id | dataset | rows (train/val/test) | selected | test P@20% | test PR-AUC | Brier | ECE |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| `dc4a56c0-20550306` | synthetic seed 6601 | 185 / 39 / 41 | depth 2, leaf 10, weight none, α 0.0 | 0.875000 | 0.760943 | 0.205708 | 0.023675 |

Baselines on the same single test evaluation:

| scorer | P@20% | PR-AUC |
| --- | ---: | ---: |
| decision tree | 0.875000 | 0.760943 |
| logistic regression (from scratch) | 0.750000 | 0.715149 |
| restricted static impact | 0.625000 | 0.692229 |
| static proof + severity (reconstructed baseline order) | 0.500000 | 0.633899 |
| severity only | 0.500000 | 0.572706 |
| majority class | 0.375000 | 0.558168 |

Overfitting demonstration (Week 11), same folds: the permissive tree
(`max_depth=12`, `min_samples_leaf=1`) reaches **1.000** training accuracy at 33
leaves and **0.538** validation accuracy; the selected tree reaches **0.708**
training and **0.692** validation at 3 leaves.

## Gates on run `dc4a56c0-20550306`

Ten of eleven gates pass. The one that fails, fails honestly:

- `bootstrap_improvement`: **fail** — ΔPrecision@20% between the within-band
  tree policy and the baseline queue is `0.000` with a 95% paired-bootstrap
  interval of `[-0.125, +0.250]` over 41 test identities. The within-band policy
  had room to act (11 of 17 bands held more than one row, covering 35 of 41
  rows), so this is a sample-size result, not a policy-blocked one. On a corpus
  this size the interval cannot clear zero, which is exactly what the gate is
  for.

`feature_completeness_reported` records that 55 of 320 synthetic rows carry an
absent whitelisted feature and are excluded from fitting. Version one reports
that count rather than imputing a value.

## Information-gain audit

`scripts/ig-audit.sh` ships regardless of model quality. On the synthetic corpus
(parent entropy 0.996289 bits over 265 complete rows, 123 positive):

| feature | best root split | gain (bits) |
| --- | --- | ---: |
| `sourceSinkLinked` | `== "false"` | 0.094024 |
| `evidenceCount` | `<= 2.5` | 0.069193 |
| `staticProofState` | `== "source_sink_linked"` | 0.035009 |
| `severityRank` | `<= 4.5` | 0.034641 |
| `toolFamily` | `== "iac-scan"` | 0.009410 |
| `pathBucket` | `== "generated"` | 0.008936 |

Read on real data, the shape of this table is the deliverable: evidence linkage
above severity would support evidence-first review; a high `toolFamily` gain
would indicate tool memorization or sharply uneven tool quality; a high
`pathBucket` gain would point at corpus quality rather than a general feature.
On synthetic data it says only that the planted signal is recoverable.

## Self-test (no LLM cost, no installs)

`scripts/self-test.sh` runs the whole chain: 155 stdlib unit tests, byte-exact
regeneration of the committed synthetic corpus, train, evaluate, export,
artifact digest verification, the committed parity fixtures (including a
tampered one that must fail closed), and the information-gain audit. Three tests
skip without the optional extras venv; `USE_VENV=1 scripts/self-test.sh` runs
them.
