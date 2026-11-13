# One severity-label parser — 2026-11-13

## Defect

Kuzushi resolved a scanner-native or model-emitted severity string to a
`Severity` band through **three** parsers with different vocabularies:

| Parser | Callers |
| --- | --- |
| `Severity::from_label` | `systems-hunt`, `chains`, `full-mode-multi`, ledger import, `Severity::try_from` |
| `Severity::from_scanner_label` | `agentic-sast` (and through it `taint-iris-next`), `carlini-threat-hunt`, `variant-ndiff` |
| `uaf_hunt::severity_from_label` (private copy) | `uaf-hunt` |

The vocabularies were not the same set. `from_label` normalizes the label
(trims, strips surrounding quotes, folds `_`/`-`/runs of whitespace, lowercases)
and bands `crit`, `warn`, `note` and `error`. `from_scanner_label` did none of
that normalization and knew neither `crit`, `warn` nor `note`. The `uaf-hunt`
copy additionally knew neither `ERROR` nor `WARNING` — Semgrep's own vocabulary
and among the likeliest things a model emits — and knew `INFORMATION`, which
the canonical parser did not.

So the same label produced different bands depending on which engine reported
the finding:

| Label | `systems-hunt` | `agentic-sast` | `uaf-hunt` |
| --- | --- | --- | --- |
| `ERROR` | High | High | **Unknown** |
| `WARNING` | Medium | Medium | **Unknown** |
| `warn` | Medium | **Unknown** | **Unknown** |
| `note` | Info | **Unknown** | **Unknown** |
| `crit` | Critical | **Unknown** | **Unknown** |
| `"high"` (quoted) | High | **Unknown** | **Unknown** |
| `INFORMATION` | **Unknown** | Info | Info |

`Severity::Unknown` is not a cosmetic outcome. Both severity gates rank it as
`None` and never block on it — `kuzushi-cli/src/application/ci.rs::severity_blocks`
and `findings/application/batch_occurrence/gate_binding.rs::blocking_finding_keys`
— so a finding whose label failed to parse can never trip `scan --fail-on` or
`kuzushi ci`, and sorts last in Review. A use-after-free that `uaf-hunt`
labelled `ERROR` passed a `--fail-on high` gate that the identical finding from
`agentic-sast` would have failed. `agentic-sast`'s normalizer records no warning
when a label fails to parse, so nothing in its output disclosed the drop.

`from_scanner_label`'s own doc comment claimed it canonicalized scanner and
model labels "in one place". It did not; it was the narrower of two copies.

## Change

`Severity::from_label` is now the single parser. It gains `information` — the
one spelling only the retired copy covered — and an honest doc comment stating
what the band decides. `from_scanner_label` is deleted and its three adapters
(`agentic_severity`, `carlini_severity`, `severity_from_agent`) call
`from_label`. `uaf_hunt::severity_from_label` is deleted and `read_severity`
calls `from_label`. `Severity::from_semgrep` is unchanged — it was already a
pure delegation with no vocabulary of its own.

## What this changes for operators

Findings from `agentic-sast`, `taint-iris-next`, `carlini-threat-hunt`,
`variant-ndiff` and `uaf-hunt` whose severity label is in the table above now
reach a real band instead of `Unknown`. Those findings become gateable, so a
`--fail-on` or `kuzushi ci` run over a workspace that holds them can newly
fail where it previously passed. That is the defect being corrected, not a
side effect of it. No label that failed to parse before is now guessed at:
`very_high` and `MEDIUM-HIGH` still fail closed to `Unknown`.

## What this does not claim

- Severity *rank* is still spelled out in six places (`ci.rs`,
  `gate_binding.rs`, `ingest_contract.rs`, `threat_impact.rs`, `scan`,
  `review_yield`). They agree with each other and with the derived `Ord`, so
  this is duplication without a behavior difference, and it is out of scope here.
- `agentic-sast`'s normalizer still records no warning when a label fails to
  parse, where `taint-iris-next` does. Narrowing that gap is separate work.
- Nothing here re-bands findings already written to a store. The parser runs at
  ingest; existing `Unknown` rows stay `Unknown` until the finding is observed
  again.
