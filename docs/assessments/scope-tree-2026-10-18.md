# Selectable scope membership and context, October 18, 2026

Scope review now has expandable boundary and coverage branches with selectable
file rows. The earlier flat-list implementation gap is repaired. This increment
also repairs the live-source cache lookup exposed by the literal-path experiment.
It does not close the full investigation plan or claim reference-product UX parity.

## Operator behavior

Up/Down chooses rows. Right expands a branch; Left returns to its parent or
collapses it. Each expanded branch displays at most 32 members and explicit
previous/next page actions. Paging uses the existing prepared `pack:scopes`
membership reader, including files beyond the 128-file coverage preview. There
is no recursive filesystem navigation or model request in tree expansion.

Enter on a file opens a focused menu with that exact identity. Exclusion starts
with its literal path. An excluded member offers restoration of its covering
exclusion rule; a directory rule can restore several files. Add pre-fills the
selected file without accepting overlap or creating work. Boundary-only actions
remain in boundary menus. Canonical action ids survive filtering and search;
clearing a no-match search restores an available selection. Space marks whole
discovery boundaries only, including after acceptance. File selection cannot
mark its parent. The existing full file reader remains available with `f`.

Selection and expansion survive reopening and resizing. Same-membership refresh
keeps loaded pages. Membership/source changes clear stale pages and return a
removed member to its surviving parent. A new proposal clears prior tree state.
These view positions are retained in the process, not promised across restart.

Details show inheritance, exact local overrides or explicit omission from a
matching target and scope revision. Saved associations come from the current
authenticated selected report. Report receipts now retain `scopeProposalRef`,
`inheritedThreatModelRef` and `contextSelections` from the frozen plan. These are
additive fields; migration guidance is in `RELEASING.md`. Earlier saved studies
can be re-exported without new scans. No globally active context is changed.

## Defects found during qualification

The Review source view trimmed the finding path before querying its cache,
while hydration used the literal path. It therefore labeled an unchanged
spaced file missing or changed. The lookup now preserves the path; focused
cache tests and the actual scanner journey verify the correction.

Native v1 completed discovery and reporting but failed three recovered-context
checks. The first implementation read only an editable planner, which is absent
when browsing a completed campaign. Native v2 retained the new provenance but
still failed the same three checks: scope-tool completion restored the underlying
Module view, leaving report hydration inactive. The scope overlay now retains
the selected read key independently of that view. Loading and failed reads are
visible; a previous report cannot supply current associations. The final journey
waits for the association itself, then checks the same exact frozen-context
requirements. Both earlier failures remain retained.

## Verification and limits

There are 163 distinct focused Rust passes. Core scope-study and report checks,
TUI scope/context/finding checks, delayed report-read and overlay hydration
regressions, the locked workspace build, Core/TUI Clippy and the complexity-risk
proxy pass. The proxy covers 21 changed production files. No target source is
executed by these checks.

Final sequential native J336 uses an owned 131-file fixture and installed
Semgrep with a local harmless marker rule. It records 90 machine passes, zero
failures, 79 text/ANSI capture pairs and eight pending human judgments. Exit 4
means review required. The six fixed jobs each execute once, retaining nine
observations under three distinct identities. Recurrence stays three per finding;
severity remains informational and proof signal-only. Three scripted human
deferrals, literal paths and selected-plan completion survive export and restart.
The global context pointer remains unset. Source hashes remain unchanged.

The final native binary SHA-256 is
`f05c9481ab62f6d482796c95a835c084aa9781d3e6214faa07433cb5ebecd6d4`.
Hashes for 4,651 source inputs, 817 runtime inputs and 14 frozen programs remain
unchanged through the journey. The independent check authenticates the plan and
all approved input digests, one-attempt limits, source membership, observations,
decisions, context selections and recovered association text. The scanner entry
point is hashed; its complete installed Python dependency tree is not authenticated.

Twenty final ANSI cell replays were inspected. Selected members and controls
were exercised at 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12; the tmux status
row leaves one fewer application row. Saved context and no-color recovery have
native 120x36 evidence. Narrow context reading still relies on the shared paged
detail layout and focused viewport checks. These are terminal-cell replays, not
OS screenshots. Eight human judgments remain pending. Finding locations outside
the scope browser still lack explicit quotation of edge spaces.

There are zero provider reservations or requests. The one-call allowance is
entirely protected for Review; Scan has zero provider calls available. This adds
no live validation and leaves the cumulative real-model count at 14. No new
allowance, follow-up job, runtime execution, reproducer or patch is implied.

Evidence root: `/tmp/kuzushi-scope-tree-20261018`.
Final journey: `native-v3/native/J336/20261018-065841/J336`.
Focused Core results are in `verification-v4`; final TUI/build/risk results are
in `verification-v7`. Earlier versions and native failures remain intact.
The independent receipt is `native-v3/independent-artifact-check.json`.
All ten repository summary checks pass. The development receipt is dirty and
unsigned at `draft-receipt.json`; the signed receipt for published `b3b63ad43e`
remains separate. This increment is a reviewable draft on `main`.
