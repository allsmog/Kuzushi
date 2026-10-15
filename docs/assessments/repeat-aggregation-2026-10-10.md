# Repeat discovery and dependable Review approval

Three observed workflow defects are repaired. Global source aggregation now
orders its JSON inputs by authoritative ledger sequence rather than database
traversal order. Broad Review selection freezes the exact raw generations that
approval rereads, so consolidated source history cannot make the same selection
fail revalidation. Distinct-source counting uses producer plus source signature;
repeat runs retain provenance and run membership without being counted as
independent corroboration.

Finding detail adds bounded first/latest observation rows with associated run
references and recorded dates. Source history remains separate from confidence,
verdicts and absence evidence. Raw observations and human decisions are retained.
The ordered merge is a pure finding-domain helper; SQLite readers and UI source
counting consume shared concepts. No schema or tool-input migration is required.
Older unapproved Review drafts containing consolidated rows may need explicit
regeneration; their saved plans are retained rather than rewritten.

## Failure evidence

The chronology and multiple-generation approval regressions both fail before
repair and pass afterward. The real existing three-pass fixture showed
firstScanId from pass three and lastScanId from pass one, while every immutable
raw row correctly described its own run. This was a projection defect.

An initial history-collapse change lost middle-run membership. Three existing
findings tests caught it. All per-run source records are now retained; only the
distinct-source count is consolidated. The final 482-test findings filter passes,
including middle-run selection. The first native journey also expected a lower
PROVENANCE heading before scrolling to it. Its captured detail was correct; the
journey now asserts the actual selected-finding surface and reads source history
in authenticated wide captures.

## Native and interface evidence

Final J188 is
`/tmp/kuzushi-repeat-aggregation-20261010/read-history/20261010-235103/J188`.
It has 17 machine passes, zero failures and 24 authenticated native text/ANSI
captures across six sizes with no-color restart. Native SHA-256 is
`2c5f48707e99d4360f29a41f6f7654d48c6560012db146ab1f952cb7050c869d`.
All three observed run ids appear in visible source history. The list and detail
report one source, with an unverified signal. Approval succeeds after broad
selection over three observations and freezes one raw generation, one Review job
and one attempt. Its separate two-total/two-protected allowance survives restart.
The job remains unlaunched with zero provider reservations, work attempts or
human decisions. The owned public-example source is unchanged and never executed.
The fixture is unversioned; this increment does not establish new SHA-comparison
evidence. One scoped assistant judgment is separate from REVIEW_REQUIRED and
operator approval false. Compact metadata remains dense.

There are 636 distinct passing focused tests across findings, Review, triage,
TUI source history, findings projections and detail rendering; overlapping test
names are counted once. Workspace build and the 149-file production risk proxy
pass. All ten repository summary gates pass. The unsigned receipt is
`/tmp/kuzushi-repeat-aggregation-20261010/precommit-verify-receipt.json`;
it records dirty/drifted state and cannot attest to a clean commit. Focused
documentation checks cover the final evidence-only updates.

The live test proposal is regenerated locally as
`live-owned-review-raw-20261010`, retaining its same generation, source, accepted
context, model, strategy and two-additional-request bound. The old unapproved
draft remains saved. No allowance approval or live model launch occurs. Its
proposal at `/private/tmp/kuzushi-live-review-20261010/proposal.md` remains pending
the operator's decision.

## Remaining acceptance

Real Review adapters, calibrated verdict usefulness, cancellation and exhausted
allowance, complete module readiness, operator acceptance and reference parity
remain open. No module is promoted, retired or deleted. All nine broad delivery
milestones remain unchecked.
