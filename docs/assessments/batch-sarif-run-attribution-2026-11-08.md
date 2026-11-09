# Batch SARIF folding republished one engine's finding under another's name (2026-11-08)

## The defect

`workspace:export-findings` emits SARIF 2.1.0 with **one `runs[]` entry per
`Finding.tool`** (`export_sarif.rs`: `group_findings_by_tool` →
`build_sarif_run`). Each run declares its own `tool.driver.name`, its own
`tool.driver.rules[]`, and its own `originalUriBaseIds`. SARIF resolves all
three against the run that contains a result: a result's detector is the
`tool.driver` of its own run, and `result.ruleId` names a reporting descriptor
in that run's `tool.driver.rules[]`.

`kuzushi scan --sarif` on a batch then annotates the exported document with the
batch occurrence fold (`scan_gate.rs::annotate_batch_sarif`). That annotation
pooled the results:

```rust
let folded = fold_sarif_results(take_sarif_results(runs), report)?;
let count = folded.len();
runs[0]["results"] = serde_json::Value::Array(folded);
```

`take_sarif_results` drained every run's `results` into one list, and the whole
folded list was assigned to `runs[0]`. `group_findings_by_tool` is a `BTreeMap`,
so `runs[0]` is whichever tool sorts first by name.

For a batch whose findings came from more than one engine — the ordinary case
for a `sast:scan` umbrella run, and for any batch mixing a native scanner with
an agentic engine — this means:

1. **Every result was attributed to the wrong detector.** A `systems-hunt`
   finding was published inside the run whose `tool.driver.name` is `semgrep`.
   GitHub code scanning and every other SARIF consumer name the tool from the
   containing run, so the alert credited an engine that never reported it.
2. **`result.ruleId` stopped resolving.** `runs[0].tool.driver.rules[]` only
   holds rules built from that tool's own records, so a moved result referenced
   a rule id the run does not declare. A consumer that cannot resolve the
   reporting descriptor loses what the rule carries: `defaultConfiguration.level`,
   the `security-severity` score code scanning reads to set alert severity, and
   the `tags` that carry the finding's CWE.
3. **The other engines' runs declared they found nothing.** `Vec::append` left
   runs `1..n` with an empty `results` array while keeping their driver and
   rules, so the document asserted each remaining engine ran clean.

None of this needs unusual input. The existing test
`batch_sarif_emits_one_annotated_result_per_safe_occurrence_group` already built
a two-engine document (`semgrep` + `systems-hunt`) and asserted the folded
result at `/runs/0/results` — it was asserting the misattribution.

## Why this ranked first

It is a shipped evidence-honesty defect in the document Kuzushi hands to a CI
gate, reachable on a normal multi-engine batch scan rather than from a
constructed edge case, and it misnames the detector — the one field a reader
uses to decide which engine to trust and where to look. The fix is local to the
one function that moved the results, changes no artifact format, schema, option,
or gate semantics, and the correct placement is already recorded in the data the
annotation walks.

## The fix

`take_sarif_results` tags each drained result with the index of the run it came
from (`FoldedResult`), the fold carries that index through, and
`restore_folded_results` pushes each surviving result back into its own run.
`drain(..)` leaves every visited run with an empty `results` array, so a run
whose only observation was superseded by the fold's representative publishes no
result rather than a stale one — which is the honest reading: the representative
carries `properties.kuzushiBatchOccurrence.runIds` and `.seen` for the group.

The fold itself is untouched: one result per occurrence group, preferring the
row's `representative_fingerprint`. The count printed as "wrote N
identity-folded batch finding(s)" and returned to the gate is the same number as
before; only its placement changes.

A missing `results` array on a run the fold drained is an explicit error rather
than a dropped result, since every run the export emits (including
`empty_sarif_run`) carries one.

## What this does not claim

- No change to `--fail-on` semantics, the blocking count, or the gate receipt's
  `blockingFindingsSha256`. Those are computed from the findings store, not from
  the SARIF document. `sarifSha256` is a digest of the bytes written, so it
  changes with the bytes, as it does for any export change.
- No change to the SARIF projection itself: `export_sarif.rs`, the location
  policy in `findings/presentation/sarif_location.rs`, and the single-run
  `report:sarif` emitter are untouched.
- No claim that a cross-engine duplicate is now published twice. The export
  folds cross-engine duplicates into one record before SARIF is written, so a
  folded group reaches the annotation as one result in one run.
- The occurrence-group fold still keeps one result per group document-wide. This
  change decides *where* that result lives, not how many there are.

## Verification

- `each_engines_result_stays_in_its_own_run` fails against the prior code with
  `left: [("semgrep", "java.injection.tainted-system-call"), ("semgrep", "systems/cwe-78")]`
  and passes after.
- `batch_sarif_emits_one_annotated_result_per_safe_occurrence_group` now asserts
  the driver and `ruleId` of the surviving representative rather than its index.
- `cargo test -p kuzushi-cli --lib -- scan_gate`, `pnpm verify:quick:summary`.
