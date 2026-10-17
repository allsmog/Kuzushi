# Recovering study reads without changing scope

The earlier read-error screen kept the selected study but showed `0 matches`,
`previous results below` and a reset hint. Its suggested `findings` command
cleared ordinary filters. Restoring the missing plan also left the separate
study-summary cache unavailable until the operator reopened that study.

The shell now distinguishes a pending or failed study read from an empty
successful query. Its shared presentation data supplies an unavailable heading,
the retained study/filter chips, `findings refresh` and explicit `batch clear`
recovery controls. An unavailable query does not show a zero-match conclusion
or empty facet counts. The same renderer serves terminal and plain output.

`findings refresh` is a declared shell command exposed in help, completion and
the palette. It reloads the current query without clearing ordinary filters,
study membership, cursor or navigation origin. It does not start a scan or
model request. The existing `findings` and `findings filter clear` commands
keep their explicit filter-reset behavior.

The core finding-page snapshot now returns the study report that established
membership and bound the page cursor. The shell applies that report with the
page, and invalidates a failed study's display data while retaining its selected
identity. A later successful refresh recovers both rows and study details.
The old page-reading API remains compatible. No ledger or module artifact
format changes are required.

The legacy chain-screen test assumed that the default `C` shortcut opened a
capability already curated to Labs. Tests now separate the curated default
from an already-open compatibility reader. Production discovery and execution
policy remain unchanged. This does not qualify experimental composition or
enable excluded operations.

## Verification

The current workspace build, architecture gate and ten summary checks pass.
There are 327 distinct focused passes: 29 Core and 298 TUI checks. These include
command catalog coverage, strict refresh parsing, retained input/cursor/view,
read-error layout, plain scripted output, help, cursor/provenance compatibility,
and actual recovery without reopening the study. The risk proxy passes for
305 changed code files with fifteen passing support checks.

Final sequential J313/J304 have 101 machine passes, zero failures and 82 capture
pairs. Fourteen frozen programs, 4,330 source inputs and 758 runtime inputs stay
unchanged. J313 preserves all 504 synthetic observations, the ordinary filter
and selected F-0503 through metadata failure and recovery. Both recovery commands
remain visible at 40 columns. No-color failure and recovery are also checked.
J304 retains six settled intercepted requests, six observations, one explicit
fixture decision and retired guidance through restart.

The six-size error replays and recovery views were inspected. These are ANSI
cell replays of live tmux captures, not OS screenshots or reference-parity
proof. Eleven human judgments remain pending in these journeys. This does not
qualify broad operator delight, model usefulness or experimental chain results.

Evidence is in `/tmp/kuzushi-study-read-state-20261016/native-evidence.json`,
`focused-checks.json` and `verification-summary.json`. There are no new live
provider requests; fourteen earlier live experiment requests remain spent with
no further approved capacity. The original 366-file publication proposal and
seven-file staged patch remain drafts. The verification receipt is dirty,
unsigned and marked drifted. All nine broad acceptance milestones remain open.
