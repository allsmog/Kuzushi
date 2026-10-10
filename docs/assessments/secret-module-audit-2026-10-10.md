# Bounded native secret inspection

October 10, 2026. Work remains uncommitted on main. Exploit development,
reproducer generation/execution and vulnerability patching remain excluded.

## Defects and resulting behavior

The scanner's recursive directory collection had no explicit entry budget and
did not check cancellation during collection. Standalone output always used a
completed envelope, even when unread paths existed. A whole-directory finding
cap stopped without recording potentially unsearched matches or files. These
states could be mistaken for complete inspection.

Traversal now uses an iterative stack and at most 100,000 directory entries.
It checks cancellation during collection, excludes symlinks and retains lexical
depth-first order within enumerated candidates. At a cap it records unknown
remaining coverage. This does not assert deterministic prefix selection from
an oversized directory or complete repository coverage.

`maxEntries` and `maxTotalBytes` are canonical descriptor options with aliases,
positive bounds and hard ceilings of 100,000 entries and 512 MiB. Opened-file
reads reserve their metadata length plus one growth-detection byte before IO.
The same contained descriptor supplies the bounded read. Failed reads keep
their reservations; insufficient allowance starts no further content read.
Per-file caps remain explicit omissions. The output shows conservative
reservations, limits, exclusions and coverage gaps.

All coverage gaps produce partial standalone receipts. Whole-directory and
accepted exact-file Scan adapters use the shared implementation and forward
gaps. Findings already observed remain available, including after mid-scan
cancellation. Cancellation before/during collection fails before discovery.
Matches stay signal-only with redacted evidence. No credential-validity request
or model call occurs. The module description no longer implies verified
high-confidence credentials.

Direct inspection scans its resolved contained directory. Accepted exact file
membership remains a Scan umbrella surface. The direct descriptor refuses
`scanScopeRef`; it does not silently interpret it as whole-repository scope.
The adapters retain their existing per-file defaults. Full custom-limit and
alternate-target parity remain unqualified. `context:build` remains DAG
metadata; actual standalone dispatch works without that artifact and is not
credited as dependency execution ordering.

## Native evidence

Final sequential J173:
`/tmp/kuzushi-secret-module-audit-20261010/final-tui/20261010-133259/J173`.
Native SHA-256:
`2165dbb8f8f2b79376d1b688d169d312cc97477552a445f8533a4c0db9f306b3`.

There are 12 machine passes, zero failures and 22 authenticated live text/ANSI
captures. The visible `z` action opens a full transcript reader at 160x48,
120x36, 96x89, 80x24, 60x20 and 40x12. Eight actual compact page steps reach the
entry gap, exclusions, validity qualification and content reservations. The
unexpanded compact transcript had too little content space while its notice
was open; the final journey exercises its existing visible reading affordance.

Three explicit native tool invocations exercise finding, aggregate-read and
entry caps. All three emit partial receipts. Four observations remain over two
signal-only findings. Review records one explicit human false-positive reason
for an owned synthetic example. JSON export preserves it and discloses partial
coverage. No-color restart retains the same decision and observations without
rescanning. Source hashes remain unchanged; provider reservations and
investigation work attempts remain zero. No source is executed.

Four scoped assistant judgments are recorded separately in
`assistant-screen-review.json`. Raw status remains REVIEW_REQUIRED and operator
approval remains false. These judgments do not establish physical-terminal
accessibility, every document size or full reference-product TUI acceptance.

## Verification and retained failures

Thirty-nine distinct focused Core checks pass. They cover real shared dispatch,
canonical aliases/ranges, exact membership, budget refusal, overflow, retained
observations, pre/during-scan cancellation, stable symlink cycles and external
paths, a 250-directory tree, unread paths, redaction and next-consumer output.
The workspace build and all ten summary gates pass. The risk proxy passes for
715 changed code files. The quick receipt records platform/CI omissions and
dirty/drift state; those flags do not establish an external writer.

Initial traversal test assertions did not account for macOS temporary-directory
aliases. The final tests compare canonical paths. An initial patch context
failed atomically and was retried against the formatted source. The first
native helper could not open a checkpointed WAL database read-only after its
sidecars disappeared. It now copies a verified stable checkpointed image for
immutable read-only inspection; a live WAL uses normal read-only access. The
original failure and subsequent successful check are retained. No live journey
or fixture was edited while its process was running.

## Live-test preparation

The default stored OAuth credential remains expired. No credential values are
logged, renewal is not attempted, and no provider authentication request occurs.
The previous retry has zero approved allowance revisions. Its source file still
matches the original receipt, but that alone does not authenticate all current
conditions.

A fresh unapproved context-study draft binds current source/configuration to
one tool-free defensive lesson job over the existing labeled synthetic greeting
observation. It uses GPT-6 Luna, low reasoning, one worker and one allowed
attempt. The proposed allowance has two total provider calls, with one protected
for Review and one available for Learning. Source is bounded to 4096 bytes.
Output requests 1024 tokens but the OAuth adapter does not enforce that ceiling;
dollar consumption remains unknown and no strict dollar ceiling is claimed.

Reviewable artifacts are in
`/tmp/kuzushi-secret-module-audit-20261010/live-review`.
Fresh plan digest:
`sha256:62a673e3f1e73c2d05f3734c7f50f161ece16c08e53cc1189980ef6da720f979`.
Source identity:
`tree:79b50d88175d5886006925c265647a7ad830fce83c6c6e18fcf22597a1186d9f`.
The operator configuration remains unchanged. No allowance is approved, job
launched, model request made or lesson automatically accepted.

## Remaining acceptance

Source-race timing, concurrent inspection, all interfaces/options, full scope
parity, calibrated precision, complete live investigation and physical TUI
acceptance remain unproven. A source read ceiling is not a strict dollar ceiling.
No module is promoted or retired. Evidence is now assigned to 67 of 110 tools;
43 remain unassigned, including seven excluded reproduction/patch actions.
All nine broad milestones remain open. OAuth renewal and this exact live retry
remain pending specific operator approval. No commit or push occurs.
