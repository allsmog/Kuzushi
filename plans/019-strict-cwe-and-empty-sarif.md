# Plan 019: Score strict CWE matches and represent empty SARIF scans

> Executor: baseline changes must follow from deterministic scoring behavior,
> not hand-edited numbers. Preserve generic SARIF compatibility.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: metric correctness/SARIF
- **Depends on**: Plan 017
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

The matcher currently treats a finding with no extracted CWE as compatible
with every expected CWE. Rust SARIF does not emit canonical CWE tags, so a
nearby finding of an unknown or wrong vulnerability class can become a true
positive. Separately, an allowed zero-finding scan serializes `runs: []`; the
scorer rejects it instead of reporting zero recall and the expected false
negatives.

## Steps

1. Add canonical optional CWE data to the workspace export projection, derived
   once with the shared Rust finding-domain extractor. Emit standard SARIF rule
   tags/properties (and a stable Kuzushi result property if useful) without
   changing finding fingerprints or generic consumers.
2. Make benchmark matching require an explicit compatible CWE by default.
   Unknown or wrong-CWE findings remain unmatched false positives and leave the
   ground-truth entry false negative. If location-only scoring is retained for
   legacy experiments, expose it as a conspicuous non-default mode in
   provenance; never silently wildcard.
3. For an allowed empty export, emit one stable Kuzushi SARIF driver run with
   `rules: []` and `results: []`. Scan-specific export should identify the outer
   scan when canonical metadata makes that possible; generic export may use a
   stable Kuzushi driver. Keep the scorer's nonempty-run validation.
4. Add Rust-shaped integration fixtures rather than only hand-authored tagged
   SARIF. Regenerate deterministic metrics/baseline through the harness.

## Verification

- Same-file/same-line unknown and wrong CWEs do not match a known ground-truth
  CWE; equivalent CWE spellings do.
- Rust SARIF includes canonical CWE tags when extractable and omits them
  honestly when not.
- A zero-finding scan round-trip preserves the canonical spend receipt and
  scores TP=0, FP=0, FN=all vulnerable entries, precision/recall/F1=0.
- SARIF schema/consumer tests, benchmark tests, fixture regression, Clippy,
  typecheck, and CRAP gates pass without a paid run.

## Done criteria

Benchmark true positives require the right vulnerability class, and a clean or
catastrophically empty scan remains a valid, truthfully scoreable artifact.
