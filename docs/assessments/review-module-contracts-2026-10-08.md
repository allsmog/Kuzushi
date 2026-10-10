# Review module contracts, October 8, 2026

The module outcome audit found defects in suppression descriptors, headless
finding paging and auxiliary report selection. This increment repairs these
contracts and checks their consumers. It does not establish usefulness for all
registered tools or complete the full investigation acceptance.

## Corrected contracts

All three suppression actions require the findings store their executors use.
`suppress:list` declares its existing workspace write: evaluating expired or
removed rules can append lifecycle events. The shared Review ceiling now applies
to that reconciliation. `suppress:remove` declares a required `id` and both
executor-supported aliases, `ruleId` and `rule_id`.

Suppression actions and individual human dismissals are auxiliary results. They
retain Review authorization but cannot create a replacement phase result.
Implicit reporting now respects the existing descriptor `phase_result` flag
through the dispatch registry, including relationships and lessons that already
declare auxiliary ownership. Explicit reports can still select those runs.

A native two-page listing exposed that the first listing invalidated its own
cursor by advancing run events. Cursors now bind materialized matching findings,
decisions, ledger aliases and relevant source-run facts. Ordinary unrelated
bookkeeping can advance the disclosed watermark without invalidating a later
page. The concurrent before/after projection check remains conservative.
Changed query, target, findings, decisions, suppression or relevant run facts
still invalidate the cursor. Old cursors require a first-page reload.

The screen audit found that rule suppression was labeled `dismissed`. Review
now labels it `suppressed` and retains the separate human decision and author.
The native JSON listing also omitted lifecycle suppression. Its additive
`suppressed` boolean now makes that state readable independently of the retained
confidence field and human decision.

## Evidence and limits

Evidence is retained under `/tmp/kuzushi-review-module-audit-20261008`.
Eight core suppression tests exercise shared preparation and execution, missing
store refusal, canonical aliases, malformed rules, idempotent expiry, the Review
ceiling, reopening and preservation of an independent human dismissal.
Fourteen page tests include native-style run bookkeeping between pages, changed
decisions and suppression, relevant source-run binding, query and target changes,
complete matching and alias stability. Three report tests preserve analysis
sources after operational and auxiliary runs while allowing explicit reports.
Twenty-three TUI phase-result regressions include auxiliary Review ownership.
Two label tests exercise the actual Review view model and compact/wide rendering
without converting suppression into a human verdict.
Fourteen detail-pane regressions also pass, including a wrapped suppression
claim that preserves evidence and does not call the observation refuted.

J135 uses two explicitly labeled observations imported over owned comment-only
files. It records one human dismissal, manages a rule for the other observation,
and checks real shell result artifacts, JSON listings, exports and implicit
report consumption. It exercises six sizes, expiry and no-color restart. No
scanner, model request, source execution or exploit work is involved.
The final J135 evidence is at
`/tmp/kuzushi-review-module-audit-20261008/tui/20261008-234539/J135`:
fourteen machine passes, no failures and fifteen authenticated text/ANSI pairs
across all six sizes. Three no-color captures contain no color SGR sequences.
Native SHA-256:
`4d5549b5a27c1b5d6529aa97ced0d56ed20cebbcd7644b92a4f040ac5cb61900`.
`checkpoint.json` records each lifecycle stage, unchanged source hashes, two
observations, one human decision and no model reservations. Three scoped screen
judgments pass. The size review remains partial: at 40x12, selected identity,
claim and suppression are visible, but the Enter-detail hint is omitted and
the phase destination is clipped. No broad usability acceptance is inferred.
Raw exit 4 remains `REVIEW_REQUIRED`, with four human questions pending.
All ten gates in `verify-shipping.json` pass, including the workspace check
and the CRAP-risk proxy. Machine checks and scoped screen judgments remain
separate from human acceptance.

Retained failures include the unusable cross-invocation cursor, an uninitialized
accounting table in the no-model fixture, long-command harness convergence,
transient result text, an omitted JSON suppression field and a label assertion
that accidentally included the general legend. Capture review also found the
detail pane calling a suppressed claim refuted; that wording was corrected.
The harness driver stays
unchanged. Fixture corrections are distinguished from production repairs.

The registry-derived matrix now replaces outdated exact-scope claims with the
J126/J127 evidence and its standard-strategy limitations. Pending scanner
strategies, external dependencies, measured quality, interface parity and live
model usefulness remain pending. No module is promoted or retired here.
The matrix retains 109 tools, with 37 having qualified execution evidence and
72 still unassigned. These counts do not measure product completion.
Full reference parity and the complete operator journey remain open. The prior
OAuth authentication failure grants no additional request, allowance or model
selection.
