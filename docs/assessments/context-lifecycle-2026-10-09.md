# Immutable context lifecycle, October 9, 2026

This increment audits the runtime-free `threat-model:models`, `:revisions`,
`:diff`, `:activate`, `:restore` and `:adopt` tools through shared prepared
dispatch and owned native TUI experiments. Registration and phase metadata do
not establish usefulness. Fixtures contain labeled context and comment-only
source; no provider request, scanner or target-source execution runs.

## Defects reproduced and fixed

1. **Text edits disappeared from revision comparison.** A shared-dispatch
   regression saved an inactive overview edit, then received “no differences”
   from `threat-model:diff`. Comparison now includes full editable before/after
   values. Unique component/question ids and exact question text match reordered
   rows; ambiguous or unkeyed rows compare by position. Removed text is retained.
   Other changed top-level document sections, including metadata, are disclosed.
   An unchanged compared subset cannot establish identical documents. Existing
   structural output remains compatible. Text comparison is computed once for
   headline, structured output and bounded terminal preview.
2. **Context management published a false partial Map result.** Native
   activation succeeded, but its descriptor claimed ownership of a Map attempt
   whose complete mapping artifacts it did not produce. A TUI boundary test
   reproduced `Some(Map)` for activation. Activate, restore, adopt, manual revise
   and selective regenerate now declare `phase_result: false`. They remain
   ordinary prepared tools, preserve their options/effects/authorization and
   cannot replace Map. This does not add DAG execution ordering.
3. **Mirror adoption carried stale verification into new content.** A real
   shared-dispatch test adopted changed text and retained the old verification.
   Adoption now clears verification and marks the new object user-edited. The
   original verified object remains unchanged. The transaction authenticates
   the observed mirror digest before withdrawal and keeps the existing pending
   mirror recovery record. Later edits refuse the commit. No public manifest,
   activation or pending-record schema changes were introduced.

## Per-tool evidence

| Tool | Distinct contribution | Qualified outcome |
|---|---|---|
| models | Choose among saved context lineages | Real manifest, active pointer and inactive copy are readable |
| revisions | Inspect immutable history | Newest-first metadata retains source revision and restore/adopt origin |
| diff | Compare contexts without activating them | Exact text, changed sections and both content hashes are preserved |
| activate | Explicitly change the active pointer | Existing revision is selected without new content or lost exact reads |
| restore | Recover historical context | New revision links to historical content; original remains readable |
| adopt | Preserve reviewed mirror edits | New active revision preserves edited content and invalidates old checks |

All six consume the shared descriptor input and dispatch boundary. The tests
exercise missing/malformed selectors, unknown input, foreign inline target,
divergent mirror, no-op adoption and immutable object preservation. Exact copy
reads stay independent of the active pointer. Resource evidence is limited to
runtime-free operation, existing bounded store reads and bounded previews;
all options and large-store cancellation remain unverified. Missing workspace
and source integrity continue to use shared store/dispatch errors.

## Verification

Evidence root: `/tmp/kuzushi-context-lifecycle-20261009`.

Seventy focused checks pass: eight diff, nine text-edit/comparison, six lifecycle,
thirty-five store/recovery, nine TUI comparison and three phase-ownership checks.
The store suite includes mirror drift before withdrawal and the existing
crash-recovery cases. Locked workspace builds pass. Summary verification and
exact build/capture hashes are retained with the experiments.

Final J140 is
`/tmp/kuzushi-context-lifecycle-20261009/tui/20261009-053817/J140`:
twelve machine passes, no failures, five human questions and fourteen
authenticated live capture pairs. Comparison is captured at all six sizes;
two no-color restart captures contain no color SGR. Operation-specific result
checks identify fresh activation, restore and adoption feedback. Every capture
matches the current workspace-built native SHA-256:
`a06a3bf69ad51e8a39025c0ef5fd80adcd0c5cbc9f27a8ac7cd13919758fcc22`.

The fixture retains three initial objects, checks unchanged comment-only source,
and reads the exact inactive copy after each active-context change and restart.
Adopted Alpha is visibly unverified; Beta and the original objects retain their
own history. No findings, campaign plan, work attempt or provider reservation is
created. Three scoped judgments pass and two remain partial: model actions still
require typed revision ids, the cycle label obscures activation, and tiny Logs
pages offer limited reading space. Raw REVIEW_REQUIRED and operator approval
false remain explicit. These captures do not establish full interaction parity.

The sequential J105 regression at
`/tmp/kuzushi-context-lifecycle-20261009/edit-tui/20261009-052156/J105`
records thirty-one machine passes, no failures and twenty-six live captures.
Its seven scoped questions cover multiline Unicode paste, preserved draft,
actual before/after edits, inactive saving, explicit study selection and restart.
The three-pass plan stays unapproved with no jobs or provider requests; the
original active context and source remain unchanged. It used the preceding
phase-repair binary, so its exact receipt is separate from final J140.

## Retained failures and remaining work

Retained failures include the real text-diff omission, false Map ownership and
stale adoption verification. A lifecycle test initially assumed oldest-first
history; it now checks the actual newest-first contract. The first J140 expected
a TargetWrite approval popup for WorkspaceWrite actions. Existing explicit
commands authorize these reversible context operations without that popup;
authorization was not changed. Generic receipt waits could match an older
notice, so final captures require operation-specific feedback. The first
verification invalidation fix correctly hit the mirror-change guard, which was
preserved while the observed digest was carried through the transaction.

Pending: every option combination, large-store cancellation/latency, richer
DFD field comparison, full semantic equivalence, first-class revision-history
controls, full TUI parity and complete live-model investigation acceptance.
No scanner quality, current-repository-SHA applicability, full phase milestone
or module maturity is established here. Work remains uncommitted on main.
