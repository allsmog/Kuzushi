# Review source provenance, October 6, 2026

Review now distinguishes the source behind a recorded verdict from later
observations. The operator can read both recorded revisions, retain the earlier
decision, and deliberately record a new verdict. Missing a finding on a later
pass does not establish a fix. This checkpoint remains on `main` at
`799bfa287091e35525fc74e988e57d3363583161`, with pending changes preserved.

## Defects and behavior

Two real findings-store regressions failed before the change. Export selected
the newest decision's source while the effective verdict retained an earlier
human decision. Run-scoped snapshot ids also falsely implied changed code when
the captured cited file was identical. The basis now follows the exported
verdict's recorded watermark and compares exact captured file path/content.
Uncaptured source remains unknown. The additive `sourceComparison` field
distinguishes not reobserved, same cited source, different cited source and
unknown. Cited-file equality does not establish whole-repository stability.

The TUI reads the same Core application service in a background worker. Its
cache key includes target, immutable observation identity, decision watermark
and displayed ledger watermark. Historical run metadata uses the existing
reader without its metadata-repair behavior. Rendering opens no
store, changes no verdict and starts no provider work. Recorded commit, branch
and dirty state differences prompt reassessment even when the cited file is
unchanged. Unknown history and reader failures remain visible.

Native inspection found a separate navigation defect: Enter selected finding
detail at 60 columns but left that pane hidden. A focused layout regression
failed before the fix. Explicit Enter and typed `open` now reveal the selected
detail in the shared zoom surface when the viewport hides it. Default compact
layout and background focus ownership are unchanged.

## Evidence

Evidence root: `/tmp/kuzushi-experiment-main-20261006/`.

- `decision-source-before.log`: five passes and two failing source-basis
  regressions before the Core change.
- `decision-source-export-tests.log`: 72 export/application passes and one
  existing ignored test, including real JSON/Markdown and receipt consumers.
- `review-source-hydration-tests.log`: 63 hydration passes.
- `review-source-final-tests.log`: ten behavioral passes plus one conditional
  native-fixture preparation test that performs no preparation without its
  explicit test environment. Checks include real store-to-detail hydration,
  bounded observation reads, draft preservation, stale metadata remaining
  unchanged, revision warnings and narrow detail opening.
- `review-source-layout.log`: 18 layout checks, including the 120-case
  phase/size/profile matrix, exhaustive plain output and 30 phase goldens.
- `review-source-navigation-build.log`: workspace build passes after the
  navigation fix. `review-source-risk-final.log`: 41 changed production files
  pass the shipped CRAP-risk gate.

Final native J98: `tui/20261006-144339/J98/`. The harness records 26 machine
passes, zero failures and four review items. Its raw result remains
`REVIEW_REQUIRED`. Separate `manual-review.json` records four passing judgments
with actual text/ANSI hashes and capture provenance. All six viewport sizes,
contiguous 40x12 paging, explicit new decision and no-color restart were read.
The native binary SHA is
`38870e171bbd6674d387242a592c850cc6b2ec677552b528c87af1bc7306fe38`.

Failed predecessors remain at `20261006-142927`, `20261006-143319`,
`20261006-143942` and `20261006-144216`. Their raw failures are retained. The
first two expose hidden narrow detail. The third captured a typed reason before
submission completed and did not page far enough into the warning. The fourth
retained a later scroll position that hid the expected new notice. The final
journey pages contiguously, restores the reader position before decision and
waits for the persisted source-B state.

The fixture receipt verifies three retained decisions, an explicit deferred
decision against source B, unchanged source and original metadata, zero provider
requests and no source execution. Findings and commit metadata are labeled
synthetic; captured benign source files use the real store and hash path.

Final repository verification is recorded in
`/tmp/kuzushi-experiment-main-20261006/final-review-source-gates.json`.
Independent before/after pending-change fingerprints and native binary hashes
are recorded beside it. Read those receipts for the final gate outcome. The
verifier conservatively flags a dirty checkout as drift; retain that raw flag
and assess actual changes using the independent fingerprints.

## Limits and remaining acceptance

This is product provenance and navigation evidence. It does not establish real
scanner precision, a real Git SHA transition, a fix, full terminal accessibility
or visual parity with the reference products. Report readiness still describes
recorded decisions; it does not certify their applicability to newer source.
Complete source-aware verdict applicability remains open.

No new model call, allowance approval, commit or push occurred. The separate
live experiment remains at seven settled requests out of ten approved, with
two protected for Review and unknown dollars. Its proposed three-pass follow-up
and total ceiling of 21 remain unapproved and unstarted. All nine delivery
milestones remain unchecked.
