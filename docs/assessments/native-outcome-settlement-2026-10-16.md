# Source-bound outcomes and direct scanner settlement

Controlled regressions reproduced three inconsistencies. The shared source guard
overwrote failed/skipped status and headlines after a source change. Canonical
`ok:false` still classified as failed, but the raw status and headline disagreed.
Direct Cargo and IaC could return partial after their finding commits had already
recorded completed ledger runs. The exact-context reader also inferred source
currency from outcome rather than an independent check.

## Changes

Failed and skipped work retain their outcome, headline, errors and unresolved
spend metadata. Source verification adds a separate warning. Usable completed or
partial work still becomes partial when its source cannot be verified. The
optional `data.sourceCheckCurrent` marker records the final content check;
missing means unrecorded. Source currency is independent of successful analysis.
It is a point-in-time check against the operation's captured content, not a
coverage, finding-validity or standalone Git revision guarantee. Exact context
checks keep their additional recorded-revision requirements.

Cargo and IaC now commit observations and final status after source settlement.
Positive and empty changed-source runs stay partial. Settlement errors retain
the original captured source identity. Existing limits, inspection receipts,
normalized fields, selected-directory path rebasing and prepared dispatch remain.
IaC's private IO adapter allows a deterministic post-analysis edit in tests; the
production entry always supplies the actual scanner and exposes no new option.

Scan and Report no longer infer discovery scope from a workspace target when
typed coverage is unavailable. They say `not recorded`; typed receipts retain
their real paths. This does not add typed coverage to every direct adapter.
Release notes describe the additive marker and changed settlement order.

## Verification

Evidence root: `/tmp/kuzushi-native-outcome-settlement-20261016`.
`source-outcome-before.log` records failed and skipped results becoming raw
partial results. `cargo-status-before.log` records a positive prepared Cargo
result that was partial while its ledger run was completed. Both positive and
empty cases pass after correction. `iac-status-before.log` records that mismatch
for positive and empty actual IaC analysis through the controlled IO adapter;
`iac-status-after.log` passes both. No target source is executed.

Final focused validation has 204 distinct Rust passes: 143 Core and 61 TUI. It
covers source outcome/spend retention, original error classes, failed/canceled
artifact authentication, context currency, direct scanner persistence, source
drift, partial/stopped native work, scope/path contracts, evidence indexing,
comparison, Scan and Report readers. The scope correction has separate passing
reruns of all 22 Scan and 19 Report checks. A zero-test selector was corrected
and its original output retained under `before-selector-fix`; it counts as no
evidence. The workspace build passes. The risk proxy passes for 149 changed code
files and its 15 support checks.

All ten repository summary checks pass. The receipt is dirty, reports
`driftedDuringRun: true` and is unsigned. It is development evidence, not
clean-commit or release verification. Final documentation is checked separately
after this update.

Final J298 uses installed cargo-audit 0.22.2 and a copied local advisory database,
with fetching and yanked checks disabled. Owned hypothetical dependency metadata
produces a declared-package signal, not runtime reachability evidence. Three
installed audit actions surround one controlled adapter failure, plus an initial
local dependency probe. The result, ledger and Report distinguish completed,
partial and failed work. Original failure text is readable at 40 columns through
the visible filter and page-up controls. Restart retains three observations,
one scripted deferral and all four outcomes. J298 has 19 machine passes, zero
failures, 21 capture pairs and six pending human judgments.

Final J299 inspects only `selected/` with explicit entry, file and aggregate byte
limits. It excludes a symlink cycle and parent configuration, retains one signal
when an oversized file is omitted, then explicitly repeats after removing that
inert fixture. Two observations and one deferral survive restart; the later
source remains subject to reassessment rather than inheriting a fresh verdict.
Source-check success stays distinct from incomplete inspection. Report discloses
partial coverage and unrecorded typed scope. J299 has 19 machine passes, zero
failures, 15 capture pairs and four pending human judgments. This native case
does not claim a controlled in-flight IaC edit; that is separate Rust evidence.

Final native SHA-256:
`63968ea9e49b120fc1b998a996f0bc04e794c6ee7d292223c256b4098a16e092`.
The manifests freeze 13 programs, 4,277 source inputs and 728 runtime inputs.
Final cases are `native/J298/20261016-025456/J298` and
`native/J299/20261016-025718/J299`. `native-evidence-final.json` checks every
requested/actual size, text/ANSI/provenance hash, native identity, no-color
recovery and the complete narrow failure cause. The installed scanner digest
also matches after the case. Source/runtime inputs stayed unchanged during each
final journey. Selected ANSI cell replays were visually inspected; they are not
OS screenshots and do not close operator judgments.

The first J299 recipe expected SAST-style completion copy. Its timeout frame
and completed durable result are retained under the original timestamp and
`before-recipe-corrections`. The corrected recipe waits for IaC's actual run
receipt. Earlier Cargo transcript captures had not paged far enough to show
the cause at 40 columns. The final recipe filters and captures every needed
page; earlier rounds remain separate under `before-first-page-capture` and
their original timestamps. Production programs did not change between rounds.

## Limits

These are owned inert fixtures and scripted review controls. They execute no
target source, generate no vulnerability patch or reproducer, create no Git
commit and make zero live model requests. Fourteen earlier experiment requests
remain spent, with no new allowance approved. Advanced direct actions here do
not qualify finite campaign approval or general model usefulness.

Direct CodeQL/Govulncheck behavior, atomic source/persistence transactions,
every race and storage-failure timing, default scanner quality, complete typed
coverage for direct adapters and broader investigation acceptance remain open.
No maturity promotion, retirement, reference-level UX claim or broad delivery
checkbox follows from this increment.
