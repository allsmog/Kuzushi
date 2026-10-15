# Guided Review planning

Selecting triage in `plan review` opens the bounded Review form before the
credential gate. Preparing the draft makes no model request. The picker explains
that Enter prepares Review and leaves other selected work paused. Unselected
worker count defaults to one; explicit stored or picker choices are preserved
for validation rather than silently reduced. Active work prevents replacement of
its queue.

A runtime-free draft returns from Run Focus to its Review form even when other
choices are paused. Runnable continuations still hold Run Focus. Background
completion preserves the operator's newer view, draft and cursor.

## Failures preserved

The first J186 run had no selected task, so it did not prove a credential defect.
The second run explicitly selected triage and opened authentication before work
review. The new gate resolves that order. A later draft stayed in Run Focus
because paused choices counted as live continuation; that predicate is corrected.
The exit confirmation for unsaved planning choices was legitimate and is retained.

An initial final run had 12 machine passes but did not assert Back's destination.
Inspection found that its supposed Escape toggled context instead. A stronger
destination assertion failed. A disposable tmux byte reader confirms that token
`Esc` sends literal bytes `45 73 63`; token `Escape` sends `1b`. J186 now uses
`Escape` and waits for the returned picker. The protected journey runner is
unchanged. Earlier journeys using `keys: Esc` do not establish actual Escape
navigation, even when their other checks pass. Their broader machine receipts
are not erased or promoted into that missing evidence.

Preserved failures and the byte probe are under
`/tmp/kuzushi-guided-review-20261010`. A wrapper preflight refusal under
`verified-back` performed no journey; the subsequent `asserted-back` run used
the proper wrapper and exposed the token problem.

## Verification

Final J186 is
`/tmp/kuzushi-guided-review-20261010/escape-verified/20261010-222342/J186`.
It records 16 machine passes, zero failures and 15 authenticated native text/ANSI
captures at all six required sizes, plus no-color restart. Native SHA-256 is
`acfb67a6a98a0cb9b1c9051a505eb1bf205659c68f6cee5d0ca420270bdf7a6f`.
Actual Escape restores the selected picker after preparation and restart. At
40×12 all advertised controls remain visible, though draft reading is dense.
No-color captures contain no ANSI color escapes. One scoped assistant judgment
is separate from raw REVIEW_REQUIRED and operator approval false.

There are 193 distinct passing tests across the Review, planning and completion
filters, including the new active-work guard; overlapping names are counted once.
The workspace build passes. Two old Map rendering fixtures now expect the actual
11 rows and select their intended task by identity instead of a stale index.
All ten repository summary gates pass, including format, workspace checking,
architecture, model safety and the changed-code risk proxy. The unsigned receipt
is `/tmp/kuzushi-guided-review-20261010/precommit-verify-receipt.json`.
It truthfully records dirty/drifted state and does not attest to a clean commit.
Only evidence documentation changes after that run; focused documentation checks
cover those final edits.

The owned fixture has one labeled pending observation. Its source is never executed. Preparing one
deep Review job records no provider reservation, work attempt or human decision.
The fixture deliberately has no credentials, so this evidence cannot qualify a
live adapter or model judgment. Exact source identity is a content tree hash;
the unversioned fixture supplies no commit comparison evidence.

The dedicated operator-approved receipt identity is already enrolled. Its
private key remains outside the repository with mode 0600; public trust is
restricted to the `kuzushi-verify` namespace. Dirty-tree verification cannot be
signed as a clean-commit receipt.

## Remaining acceptance

Live Review adapters and retries, accepted-context and cross-SHA inheritance,
cancellation, report integration, complete allowance coverage, operator screen
acceptance and reference parity remain open. No module is promoted or retired,
and none of the nine broad delivery milestones closes from this fixture.
