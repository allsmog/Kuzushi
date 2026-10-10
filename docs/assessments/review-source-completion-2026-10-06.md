# Review completion follows recorded source, October 6, 2026

A terminal verdict on an earlier source observation no longer completes Review
for a later, changed or unverified source. The verdict remains in history and
on the finding detail. The current queue names reassessment, and the journey
counts only source-qualified decisions. Work remains on `main` at
`0912eecdc97a4762aa22c99fde69d5e95947dd01`, with inherited pending changes
preserved and no new commit or push.

## Changes and evidence

Three resolver regressions failed before the change. Display timestamps could
hide a newer recorded decision after clock regression, projection identifiers
could disagree with event order, and an embedded triage cache could appear newer
than its immutable decision record. The shared resolver now uses recorded event
sequence, with a legacy record-id fallback. Human authority remains unchanged.
The exact governing record supplies source provenance to exports and the TUI.

The shared application reader compares captured cited-file changes and recorded
Git commit, branch and dirty state. A different cited file or recorded revision
requires reassessment. Matching clean, valid recorded commits can retain a
decision. Missing later identity, identical dirty metadata and unrecorded
decision sources require reassessment. Metadata is cached for at most 128
distinct runs; further comparisons remain unverified. Reads never repair run
metadata, execute source or create a model runtime.

Source-qualified completion is shared by investigation reporting and the TUI's
unfiltered journey counts. Open Review and decision-backlog projections include
historically terminal decisions needing reassessment. The finding still displays
its recorded verdict, alongside the source warning. JSON exports add
`sourceApplicability`, and Markdown names the same qualification. The projection
watermark is checked before and after completion reads; concurrent ledger changes
produce an explicit refresh error.

A final failure-state check found that comparison failure reset reviewed counts
but retained confirmed counts and hid terminal decisions from the open queue.
Two regressions first failed. The shell now clears both current counts and
retains governing terminal decisions as unverified source work. A subsequent
successful comparison replaces that status without changing recorded verdicts.

Evidence root: `/tmp/kuzushi-experiment-main-20261006/`.

- `review-applicability-order-before.log` retains the three failing regressions;
  `review-applicability-order-after.log` records six passing resolver checks.
- `review-applicability-core-closeout.log` records 124 workspace application
  passes after the final Markdown change. The source classifier covers matching
  clean commits, branch changes, dirty state, missing metadata and invalid SHAs.
- `review-applicability-tui-first.log` records eleven source-reader and
  presentation passes. `review-applicability-journey-first.log` exercises a real
  findings store: older-source confirmation stays in the open queue, and an
  explicit new decision completes Review on source B.
- `review-applicability-tui-final.log` records 285 Review-related passes.
  `review-applicability-layout.log` records three phase-presentation checks.
- `review-applicability-unavailable-before.log` retains the two failing
  comparison-error regressions; `review-applicability-unavailable-after.log`
  records all 15 refresh checks passing after the repair. The tests exercise
  the common error handler through a missing target and inspect the open queue.
  They do not establish all concurrent-store failure scenarios.
- `review-applicability-final-build.log` records a workspace build. The first
  CRAP-risk failure is retained in `review-applicability-risk.log`; extraction of
  source attachment keeps the export function within the required size.
  `review-applicability-risk-final.log` records 57 changed production files
  passing before the final presentation adjustment. Final composition and quick
  gate receipts are recorded separately at this evidence root.
  `review-applicability-unavailable-build.log` records the latest workspace
  build after the error-handler repair.

Before the final error-handler repair,
`review-applicability-composition-closeout.log` records all 18 composition checks
passing, including 120 phase/size/color buffers, 30 plain projections, 30 checked
snapshots and failure-state rendering. These compatibility renderers execute no
verification or patching work. `final-review-applicability-gates.json` is the
summary verification receipt. Independent before/after pending-change and native
fingerprints accompany it; raw dirty/drift flags remain unchanged.

J100 at `tui/20261006-164751/J100/` has 24 machine passes, zero failures and four
separate passing screen judgments. Its raw result remains `REVIEW_REQUIRED`.
`manual-review.json` records actual text/ANSI hashes and capture provenance.
All six viewport sizes were read. At 40x12, five contiguous Page Down captures
expose the old verdict, rationale and complete source warning while NEXT stays
in Review. No-color restart agrees with export on the newer decision. The
fixture verifies three retained decisions, unchanged source bytes and unchanged
earlier event provenance.

The preceding `162915` run passes the same four screen judgments before the
error-handler repair. Run `162338` has 23 machine passes but fails its separate screen
review: the compact row called the retained human verdict `open`. The corrected
row says `reassess` and names its next action. Both raw reports remain unchanged.

The fixture uses labeled synthetic findings and commit metadata, real captured
benign file versions and a deliberately shifted projection display date of
2099. It does not change the system clock or prove an actual Git SHA transition.
No scanner, provider request, source execution or vulnerability patch occurs.

## Remaining acceptance

Dirty or unversioned repository content hashes are not authenticated for later
decision reuse here. Those observations conservatively require a new review.
Historical CLI/export completeness filters retain their recorded-verdict
compatibility semantics; their records disclose source qualification. The TUI's
current-source queue and journey use the qualified completion service. A full
cross-interface filter migration remains separate work.

Completion reads currently run at the existing synchronous findings-refresh
edge. Large-ledger responsiveness remains unmeasured. Real Git transitions,
scanner precision, revision-specific fix adjudication and complete terminal
reference parity remain unvalidated. No module is promoted or retired, and all
nine delivery milestones remain unchecked. The live three-pass follow-up and
its proposed ceiling of 21 requests remain unapproved and unstarted.

The owned live fixture was reread against the preceding checkpoint. Source,
accepted context and global active-context state match. Seven requests of ten
are settled, five attempts are recorded, two Review requests remain protected
and no request reservation is unresolved. Dollar usage remains unavailable.
The follow-up has only its plan artifact and no queue.
