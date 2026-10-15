# Stored result readers

This increment audits `fuzz:status` and `fuzz:import` as readers of existing
external history. Both stay Labs. No engine generation, execution, reproduction
or vulnerability patching is part of this work.

Status previously converted unreadable indexes into an absent index, discarded
malformed-row counts and scanned the target directory without a count limit.
It now distinguishes missing inputs from read failures, limits inspection to
10,000 target entries, 10,000 nonempty index rows and 64 MiB of index text,
checks cancellation between entries/rows and reads contained regular markers.
Latest recorded flags determine counts without quadratic finding folding.
The output describes stored markers and external verification claims rather
than certifying build validity, local reproduction or current-source coverage.

Import now returns partial receipts when malformed rows were skipped. Per-run
log reads must stay under the supplied data root. Actual prepared dispatch
tests preserve repeated-import identity, a human FP decision and the absence
of local verification. Existing ledger integration and severity behavior stay
unchanged. Both descriptors disable Scan phase results while retaining their
names, aliases, declared phase and compatibility fields.

The native journey also exposed an unrelated reading defect: opening a new
Replay retained the prior run's scroll offset, hiding the outcome. The shared
router now resets scroll when a changed Replay or Trace selection is opened.
Reopening the same run preserves scroll. Focus, draft, cursor and navigation
origin remain unchanged; preparing a run selection cannot reset another view.

## Limits

These results qualify the documented reader cases only. Import still uses
quadratic folding, may reread a run log for each finding, lacks an aggregate IO
allowance and does not interrupt an import already in progress. Import-time
grounding does not authenticate the original source SHA. External confidence,
verification and reproduction claims remain unassessed. There is no engine
quality or historical fixed-status verdict.

Status cancellation checks do not bound filesystem syscall latency. Directory
iteration containment does not establish immunity to concurrent directory
replacement. Status's row and entry caps fail explicitly rather than publishing
counts for an uninspected remainder. The existing parser tolerates unrecognized
event types, which count against the row budget but add no finding count.

No Core promotion or speculative deletion follows. Model allowance remains
exhausted at six requests; this increment uses none. Full module qualification,
broader investigation acceptance and operator judgment of TUI quality remain
open.

## Evidence

Sixty distinct focused Rust tests pass across status inspection, contained
stored logs, actual registry dispatch, run navigation, Replay and the registry
policy contract. The final workspace build passes. An initial test used the
tool's empty maturity override instead of its inherited module tier; the
corrected assertion checks effective Labs maturity. That failed run is retained.

All ten exact quick-plan commands pass, including 391 Node tests, formatting,
workspace checking, architecture and model-safety contracts, docs and the
CRAP-risk proxy over 490 changed code files. The commands ran directly because
of the known pinned package-manager signature issue; verification was not
disabled. These checks do not claim a full Rust suite run.

Both native headless readers return a `partial` envelope with exit code 4 on
owned synthetic metadata. J230 records 13 machine passes, zero failures and 15
live capture sets across six terminal sizes and no-color restart. Its two human
questions remain pending, so the harness returns `REVIEW_REQUIRED` with exit 4.
These two exit-code meanings belong to separate interfaces.

Six captures were inspected as text and all 15 checked for native identity and
dimensions. At 40x12, the first frame shows partial status, the next page shows
external verification and coverage caveats, and the following page shows cost
and continuation. At 60x20, the caveats and continuation fit before diagnostics.
A new failed Replay opens with its outcome and recorded error. Restart retains
the original partial receipt. Duplicate output in the full receipt and the need
to page narrow views remain visible limits of this review.

The fixture records two partial receipts, one failed read, one synthetic finding,
zero provider requests, zero Scan attempts and unchanged source bytes. No source
or engine executes. The original wrapper-selection failure and the native
scroll failure remain retained; the successful rerun uses the unchanged journey.

Native SHA-256:
`9abf16a3be98e3de8727482cb83b21a7118f955a701c3719143607913afbbb28`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/stored-results-verified-tui/20261013-053843/J230`.
Tests, initial failures, headless receipts and assistant capture review:
`/tmp/kuzushi-tui-integration-20261012/stored-results-audit`.

The current catalog still has 113 visible tools: 98 Core, 11 Labs and four
Compatibility. All names have audit rows and compared descriptor fields agree.
Twenty-two in-scope tools still have no assigned functional verdict, in addition
to eight explicitly excluded tools. Scoped evidence for other tools also retains
its documented gaps; this count is not a completion percentage.
