# Proposal regeneration and history, October 9, 2026

Recommendation refresh previously kept a proposal's status and creation time
while replacing its approval amount, correction and outcome fields. This mixed
old review authority with a newly generated suggestion. The repaired private
history boundary preserves prior records and adds unapproved drafts instead.

The first proposal retains its legacy id. A collision receives a unique
`-draft-<uuid>` suffix. Same-run replay can reuse an unchanged unreviewed draft;
reviewed rows and unnamed runs create separate drafts. Generated artifacts list
only the current generation's proposals. Workspace corrections targeting the
legacy family are applied before identity assignment. Corrections targeting a
version-specific id do not silently apply to a different version.

Existing JSON fields, ledger paths and the 4 MiB atomic write limit remain
unchanged. There is no automatic history deletion or retention expansion. A
write-limit failure retains prior persisted history. This does not introduce a
new executor, change proposal firing behavior, or approve finite study work.

The TUI reads external changes on explicit reopen and distinguishes pending
hydration from an empty queue. Newest drafts appear first within their status
group. `strategy inspect <id>` opens one recorded proposal without approval or
execution and is bound to the selected target. Missing ids are explicit. The
composer draft survives inspection. The command catalog and visible footer use
the same routed command. `recommendations` replaces stale refresh guidance.

Wrapped cards retain complete ids, phase, strategy, yield/rounds, expected and
approved amounts, recorded actual cost, outcome, result/source run, preflight,
lineage and rationale. Invalid or absent costs render unknown. Inspection puts
the selected record before long queue paths. Paging uses the actual viewport
and clamps to the rendered document. A visible allowance note separates
proposal approval from an investigation allowance or approved study.

Evidence root: /tmp/kuzushi-proposal-history-20261009.
Final J152: /tmp/kuzushi-proposal-history-20261009/verified-tui/20261009-190910/J152.
Native SHA-256:
3e5ac5aefe3c6c23dd496c75cf3d5d45cabb3a7e23f058b758bfb873d55dc730.

The journey records 34 machine passes, zero failures and 18 populated live
text/ANSI pairs across six viewport sizes and no-color restart. Every native
hash, dimension and ANSI-stripped text matches. All final captures were
reviewed. Three scoped assistant screen judgments stay separate from raw
REVIEW_REQUIRED and operator approval false. Actual 40x12 paging reaches the
recorded approved/actual amounts and result reference without entering the
composer. Explicit inspection reads retained approval, completion and failure.

The fixture first generates real deterministic recommendations through native
prepared dispatch. Actual keep/skip commands record decisions on their original
ids. Outcome receipts and the operator preference are labeled owned synthetic
metadata, not scanner evidence. Regeneration compares every original record in
full and verifies that new proposals and current artifacts contain no copied
approval, cost or result authority. Restart preserves the same values. Source
and isolated configuration stay unchanged. No provider/scanner calls, target
execution, finding observations, campaign work or allowance reservations occur.

There are 123 distinct focused tests: core recommender (35), prepared dispatch
and artifacts (8), shared strategy persistence/corrections (12), TUI queue (10),
strategy application behavior (18), public routing (18) and keybindings (32),
with overlap removed. Tests cover every reviewed status, missing run identity,
same-run replay, changed input, workspace corrections, current-generation
artifacts, target isolation, missing ids and viewport text preservation.
Workspace build and the CRAP-risk proxy for 563 changed code files pass.
All ten repository summary steps pass. The receipt records dirty source and
`driftedDuringRun: true`; that flag also includes an initially dirty checkout,
so it does not prove a concurrent edit. Final documentation checks follow the
checkpoint update.

Retained intermediate evidence includes a whitespace reconstruction assertion
and a native capture before queue hydration. The stronger journey waits for
the actual summary and requires exact recorded costs and result references in
narrow captures. The driver stays unchanged.

The legacy queue remains a Compatibility reader. Its recorded preflight,
approval and result references do not certify current source applicability,
engine availability, actual live spend or finding resolution. Large-queue
responsiveness and an explicit retention/export policy need separate evidence.
Live provider usefulness/accounting, remaining module qualification, complete
investigation and reference-quality TUI acceptance remain open. Visible tool
qualification stays 55 of 109, with 54 unassigned. All nine delivery milestones
remain unchecked. Work is uncommitted on main; no product commit, push, OAuth
renewal or inference occurs.
