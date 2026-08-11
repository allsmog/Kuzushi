# Model artifact parity fixtures

These files are a two-language contract. Python asserts them in
`tests/test_parity_fixtures.py`; PR 4's Rust loader and evaluator assert the
same bytes and the same tables. Do not edit them by hand — regenerate with
`PYTHONPATH=src python3 scripts/build-parity-fixtures.py` and change both sides
in the same pull request.

## Canonical form

UTF-8, ASCII-only strings, object keys sorted by byte value at every depth,
compact separators (`,` and `:`), no trailing newline, top-level `modelId`
excluded from the hashed form. Every float is quantized to at most 6 fractional
digits, and a nonzero magnitude below `1e-4` is written as `0.0`, so Python's
`repr` and Rust's `ryu` cannot render the same number differently.

## Digest

`hash_parts("kuzushi-review-yield-model-v1", [canonical_bytes])`, the repository's
existing length-framed BLAKE3 from `crates/kuzushi-core/src/identity/hash.rs`:

```text
blake3( u64_be(10) || "kuzushi:v3"
     || u64_be(len(domain))    || "kuzushi-review-yield-model-v1"
     || u64_be(len(canonical)) || canonical_bytes )
```

`modelId` is `blake3:` plus the lowercase 64-hex digest.

## Files

| file | role |
| --- | --- |
| `model-numeric-small.json` | design §18.1's three-node numeric tree; 3 nodes, depth 1 |
| `model-mixed-depth3.json` | categorical root, numeric inner nodes, one `missingDirection: "left"`, one leaf under `minimumLeafSupport` |
| `model-tampered-hash.json` | byte-identical to the numeric model except one flipped digest hex character; must fail closed |
| `expected-scores.json` | feature vector → leaf id, smoothed rate, decision path, eligibility |
| `pinned-digests.json` | the exact model ids and canonical byte lengths both languages must reproduce |

Routing contract, pinned by `expected-scores.json`: `value <= threshold` goes
left; an absent feature follows `missingDirection` (`ineligible` fails closed);
a category outside `branches` is `unknownCategory`; a leaf below
`minimumLeafSupport` is `insufficientLeafSupport` and still reports its stats.
