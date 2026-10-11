# Reversible finding relationships

The Review path now keeps grouping decisions separate from finding identities,
raw observations and finding verdicts. This is a bounded increment on main.
The complete investigation plan and all nine milestones remain open.

## Behavior

Default `triage:dedupe` records model proposals with exact finding identities,
fingerprints and recorded runs. The existing shared allowance still governs
model calls. `dryRun` writes nothing; explicit advanced `legacyRekey=true`
retains historical compatibility behavior. Existing rekeys are unchanged.
Default prepasses therefore no longer prune a subsequent review queue through
identity rekeys. Remaining per-finding work can cost more and must fit its
approved allowance. Candidate collection still reads the whole ledger before
its model-input cap; large-ledger resource readiness remains unproven.

Versioned relationship metadata appends to existing audit events through the
single storage writer. Model proposals must still match the latest recorded
observation at commit. Human acceptance, rejection or removal requires a reason
and exact revision. Stale editors fail rather than overwriting a later decision.
These decisions remain bound to their recorded endpoints when source changes;
they do not assert current-source applicability or establish a vulnerability.

The shared `findings:relationships` tool reads bounded pages and
`findings:relationship` applies decisions through prepared dispatch. Neither
produces a phase-completion receipt. TUI reads use background hydration and
writes settle outside the terminal loop. `relationships` and Review `L` open a
contextual reader. Its note field owns keyboard input and multiline paste;
cancel and failed saves preserve the shell draft. JSON, JSONL, SARIF properties
and Markdown manifests carry relationships separately from verdicts. CSV keeps
its columns and declares the omission.

## Verification

Evidence root: `/tmp/kuzushi-review-relationships-20261008`.
Nine focused core relationship tests pass, including source-change refusal and
shared prepared dispatch. Six TUI tests pass, including editor ownership,
target-switch refusal, failed-save draft preservation, visible narrow actions
and six viewport sizes.
The registered-surface render test passes. The code quality proxy passes over
266 changed files, including inherited work.

The broader export run passes 96 tests with one ignored fixture and one CSV
metadata-order failure. Appending the new omission preserves the original
prefix; the isolated failed test now passes. Native build succeeds and all ten
repository gates pass in `verify-final-summary.json`.

Final J114:
`/tmp/kuzushi-review-relationships-20261008/tui/20261007-205449/J114`.
Raw REVIEW_REQUIRED and exit 4 remain unchanged: fourteen machine passes,
zero failures and six review questions. `manual-review.json` records six
separate scoped passing judgments. `ansi-review.json` records all fourteen
live frames, including 40x12 paging and no-color restart. The binary SHA-256 is
`79a10d9a47cd40bb7b19343b018d1924bfdb5cc2d44c003c3d53d639152c54aa`.

The fixture and history receipts establish two unchanged observations and
identities, zero rekeys and zero finding verdicts. Proposal, acceptance and
removal persist as revisions 1, 2 and 3 with unchanged endpoint bindings.
Exactly one intercepted request is reserved in the approved four-call account;
human decisions, exports and restart add no calls. JSON, JSONL, SARIF and
Markdown carry the removed relationship with each original finding still
`needs_review`; CSV declares the omission without changing its columns.
Owned source bytes stay unchanged. The driver is unchanged.

## Retained failures and limits

The first native run had thirteen machine passes but exposed inaccurate note
editor chrome and cramped narrow reading. A later run failed because the
generic navigation helper assumed `Esc prompt`; this contextual reader's
advertised Escape returns to its origin. J114 now follows its visible control,
with no driver changes. A report-fixture failure assumed SARIF held one run;
actual exports correctly retain the two origin runs. The fixture now reads
all results. Source-change testing also found and fixed an old-id-only check
that missed a newer observation for the same identity.

Every model request in this increment is intercepted on owned greeting data.
The observations are labeled synthetic; no live inference or target-source
execution occurs. This establishes transport, accounting and operator-control
behavior, not model quality. Accepted duplicate groups are not yet collapsed
into one Review row. Reviewed reusable lessons, full module usefulness,
monorepo editing and complete reference-quality TUI acceptance remain open.

The captured global route/posture chip and historical composer notice still
need a separate clarity pass. Narrow details also page as a document without a
sticky selected-relationship heading. The current reader clears the scoped
metadata workflow checks; these observations prevent a full reference-quality
or complete layout acceptance claim.
