# review-yield — offline Weeks 9-11 experiment

From-scratch entropy, information gain, ID3, pruning, calibration, temporal
evaluation, and a versioned model artifact, over the corpus that
`kuzushi review-yield export` writes.

This is the repository's first Python. It is **offline only** (ADR-1) and is
**deliberately excluded from CI**: nothing in Kuzushi's Rust runtime imports it,
and it never opens Kuzushi's SQLite store. `scripts/self-test.sh` is the gate.

## Run it

```sh
cd experiments/review-yield

# The gate: unit tests, corpus reproduction, train, export, digest verification.
scripts/self-test.sh

# The tests on their own — zero installs, stdlib only.
PYTHONPATH=src python3 -m unittest discover -s tests

scripts/train.sh                      # fit + evaluate + export + model card
scripts/evaluate.sh reports/<run-id>  # measured metrics and the gate table
scripts/ig-audit.sh                   # the standalone information-gain report
scripts/verify-artifact.sh reports/<run-id>/model.json
```

### Dependency policy

The learner, the exporter, and **every test** are stdlib-only. That includes
BLAKE3: `src/kuzushi_review_yield/blake3_pure.py` is a transcription of the
reference implementation, checked against the published vectors always and
against the official `blake3` binding — the same Rust crate the workspace links
— whenever that binding happens to be installed.

`scripts/setup-venv.sh` installs two extras and nothing else: `scikit-learn`
for the library comparison tree, and `blake3` for that cross-check. Their
absence skips exactly two tests. Run `USE_VENV=1 scripts/self-test.sh` to
include them.

## Measured versus illustrative

Every number this experiment produces is one of two things, and it is always
labelled:

- **measured** — computed from a dataset named by its digest, on a stated fold.
  `reports/*/results.json`, the model card, and the IG audit are measured.
- **illustrative** — a worked example from the design document or a hand-built
  fixture used to check the mathematics. The numbers in `fixtures/` and in the
  design document's §13.3/§18.1 samples are illustrative.

The exporter enforces the boundary rather than trusting a convention: an
artifact whose `evaluation` block carries no dataset digest, or whose metrics
are the design document's all-zero sample, is refused.

Everything here is trained on **synthetic** data. No real Kuzushi review data is
committed to this repository (design §11.4). The synthetic corpus has planted
signal; its metrics say the pipeline works, not that the idea works.

## Course mapping (design §26)

| week | topic | where it lives | what to look at |
| --- | --- | --- | --- |
| 9 | supervised learning, leakage, baselines | `dataset.py`, `splits.py`, `baselines.py` | the whitelist loader that refuses a row carrying its own outcome; the temporal split frozen before selection; five baselines including a from-scratch logistic regression |
| 10 | entropy and information gain | `entropy.py`, `id3.py`, `ig_audit.py` | the three hand-computed root splits below; deterministic tie-breaks; the standalone IG audit |
| 11 | overfitting, pruning, calibration, ranking | `id3.py`, `calibration.py`, `bootstrap.py`, `evaluate.py`, `model_card.py` | the permissive-versus-pruned gap; Jeffreys smoothing and beta intervals; paired bootstrap by identity; the within-band queue policy |

### The hand-computed root splits (Week 10)

`fixtures/tiny-hand-verified.jsonl` holds ten rows, four positive. Parent
entropy is **0.970951** bits. These values are asserted as literals in
`tests/test_information_gain.py` and `tests/test_id3_fixture.py`, so the code
cannot drift away from the arithmetic:

| candidate split | information gain (bits) |
| --- | ---: |
| `evidenceCount <= 2.5` | **0.556780** |
| `evidenceCount <= 1.5` | **0.419973** |
| `pathBucket == "vendor"` | **0.321928** |
| `pathBucket == "test"` | **0.281291** |
| `sourceSinkLinked == true` | **0.256426** |
| `pathBucket == "application"` | **0.000000** |

The fitted tree roots at `evidenceCount <= 2.5`; its right child is a pure
`3+ / 0-` leaf whose smoothed rate is `3.5 / 4 = 0.875`, **not** 100%. That is
the point of Jeffreys smoothing (§14.7): three examples are not certainty.

`hasSinkEvidence` duplicates `sourceSinkLinked` in the fixture precisely so a
gain tie exists; the tie-break rule (feature name, then split kind, then
threshold or category) resolves it to `hasSinkEvidence`, deterministically.

## What the corpus contract actually is

The loader mirrors the merged Rust exporter on this branch, not an assumption:

- 29 whitelisted features (`hasRemediation` included), unknown or absent keys fail;
- `quality.cutoffQuality ∈ {tui_read_watermark, barrier_at_head}` — `missing` is
  a real classification that is never exported, and a row carrying it is refused;
- `identityMatchTier ∈ {stable_fp, dedup_collision, dedup_key_cross_run,
  model_dedupe, unknown}`;
- `maxEvidenceConfidence` and `meanEvidenceConfidenceMillis` may be null. Version
  one excludes those rows from fitting and **reports the count**; it never imputes
  zero, and every internal node records `missingDirection: "ineligible"`;
- every row must satisfy `anchor <= cutoff < label`.

## The model artifact contract

`fixtures/parity/` is a two-language contract with PR 4's Rust loader. The
canonical rule and the digest framing are documented in
`fixtures/parity/README.md`; both sides pin the same digests over the same bytes.

In short: canonical JSON (ASCII-only, keys sorted by byte value, compact
separators, `modelId` excluded from the hashed form, floats quantized to at most
six fractional digits), digested with the repository's existing length-framed
BLAKE3 `hash_parts` under the domain `kuzushi-review-yield-model-v1`.

## Limits worth stating up front

- The task is `review_yield_predecision_v1`: it predicts a decision that already
  happened. A product model needs the prospective pre-review task.
- Selective labels are not solved by a retrospective replay — only adjudicated
  findings appear at all.
- The "baseline order" is a reconstruction. Three rival orderings exist in the
  codebase and the review queue's backlog toggle bypasses the documented one, so
  the baseline here is proof band, then severity, then identity.
- Promotion gates report `pass`, `fail`, or `not_applicable_course_exercise`. A
  corpus too small for a production claim says so.
