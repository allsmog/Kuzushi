# Lesson identity, paging and review confirmation

Saving a lesson on page two moved it to the beginning of the book while the
cursor stayed at the old row. The reader silently selected another lesson.
Refreshing after an external edit had the same problem. Compact layouts also
omitted selection, paging and refresh from their key metadata, and review
confirmations omitted the lesson title.

Lesson selection now retains its ID and a bounded recorded snapshot. A saved
receipt replaces the snapshot only after its record and reference agree.
Refresh keeps the selected identity. An off-page record, or a recorded revision
newer than a cached page, appears before the action controls with its title,
state, revision and ID. Further writes still use the exact reference and Core's
current-state checks. Explicit navigation selects a visible row again.

Compact readers show Space, paging and refresh controls and retain the full key
list. Counts say how many records are on the current page. Review confirmation
names the title, revision and origin before the commit controls. The same
identity summary is used for draft confirmation without repeating it.

These are shell state and presentation changes. Tool descriptors, public module
options, ledger formats, context selection policy and finding decisions retain
their existing contracts. No alternate lesson store or execution path is added.

## Verification

The focused Rust command reports 43 passes, zero failures and one ignored
fixture writer. Forty-two tests exercise behavior; one legacy conditional
fixture hook returns without writing when its environment is unset. The new
ignored writer is explicitly invoked by the native harness and is not counted
as a behavior-test pass. Ten new checks cover selection across saves and
refresh, off-page review, late cached and empty pages, explicit reselection,
malformed receipts, compact help and confirmation identity.

TUI all-target Clippy and the workspace build pass. Final risk and repository
summary results are recorded separately in an unsigned dirty draft receipt.
The earlier published signed receipt remains unchanged. Four initial regressions
failed before the selection changes; their logs remain in the evidence root.

Final J365 has **32 machine passes, zero failures, 64 live capture pairs and four
formal operator judgments pending**. Its raw exit remains 4,
`REVIEW_REQUIRED`. The agent answered all four questions with State, Intent,
Honesty and Craft and inspected 26 ANSI cell replays. Replays use Menlo and a
chosen default background; they are not OS screenshots or reference-parity
evidence. Captures cover 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48.

## Two-page learning loop

The owned fixture has sixty manual lesson drafts sharing one labeled greeting
observation. A scripted finding confirmation makes no vulnerability claim.
Fixture preparation executes sixty-one real prepared lesson actions in one
process. Its first lesson is accepted before newer drafts are created, placing
that accepted lesson at the end of page two. A separate headless probe verifies
the real CLI draft-save path.

The keyboard journey selects that lesson and creates an inactive context copy
with accepted revision 2. Editing produces draft revision 3 and moves it to
page one; the reader stays on page two with the correct recorded selection.
The original context copy becomes ineligible for new lesson reuse. A separate
acceptance produces revision 4, which enters a second explicit context copy.
Retirement produces revision 5 and blocks reuse of both copies.

Restart retains all sixty lessons, both complete historical snapshots, the
single finding observation and its single scripted confirmation. Source bytes
and the globally active base context stay unchanged. Independent checks confirm
all capture dimensions, native identity, full narrow-page origins and review
reasons, and no color SGR codes after restart. Bold and dim attributes remain.

The first native attempt failed in its helper before launching the TUI because
an unused allowance table did not exist. That check now accepts absent tables.
The second attempt reproduced missing controls and selection drift, with ten
passes and three failures. The third preserved identity and completed the loop
but exposed the two missing confirmation titles, with 28 passes and two failures.
All failures and their operator questions remain recorded separately.

## Evidence and limits

Local root: `scripts/devex/artifacts/lesson-book-20261025/`. Focused checks and
build logs are under `repair/`. The final native run, independent checks, agent
answers and images are under `native-attempt-4/`. Fourteen programs, including
the explicitly invoked fixture writer, and 6,608 repository inputs stay unchanged
during that run. Later documentation is recorded separately.

Native SHA-256:
`2f98b778c5c0eb6f829b2aeafec0cfdd177df96cbb461d1d07e0a0d9d63c0384`.

There are zero provider requests, source executions, campaign plans or discovery
jobs. This does not test generated-lesson usefulness, model-guided improvement,
large-book throughput or eligibility across repository SHAs. Lesson revision
numbers remain distinct from repository revisions; this fixture's source is
unversioned. The pending twelve-file dependency-metadata checkpoint is preserved
byte for byte. No broad delivery checkbox or module maturity tier changes.
