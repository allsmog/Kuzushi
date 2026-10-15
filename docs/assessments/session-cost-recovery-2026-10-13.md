# Session cost reading and halt recovery

The Cost view now preserves unknown and estimated accounting throughout its
budget rows, percentages, status log and spending-halt displays. An incomplete
zero-valued subtotal stays `>=$0.00 (metering incomplete)` with an unknown budget
share. It has no filled percentage bar. Estimates retain their `~` qualifier.
Accounting errors do not become a zero amount or a full bar. A known zero remains
zero, including a fresh session or runtime-free work. Current-session totals and
saved-run consumption describe different sets of work.

The previous halt consumed exit and inspection keys. Escape now acknowledges the
halt's controls and restores the reader while keeping the execution guard and
approved amount intact. Model-backed launches remain blocked. Ctrl+C and Ctrl+D
reach the existing cancellation or exit handling, including exit confirmation
when needed. Reviewing a cap still requires a specific amount; incomplete
accounting cannot be bypassed by pressing `c`. No cap doubling, new job, model
substitution or extra request is introduced.

Cost now uses the shared paged reader and clamps its position after resize.
Budget and spend details wrap, and the narrow footer keeps the paging shortcut
visible. The budget editor and exit confirmation own their controls without a
competing halt card. The editor retains the qualified spend and halt state. These
changes repair presentation and input ownership, not the spending ledger or
provider metering.

## Bounded validation

J227 uses the native application, a fixed approved context-question job, an owned
inert source fixture and a strictly intercepted provider transport. The fixture
has dummy credentials, no network fallback and no source execution. The one
synthetic answer deliberately omits billing telemetry to exercise real receipt
normalization and the shell halt. A second launch must be refused before another
provider reservation. The existing protected Review call remains available.

The journey covers six terminal sizes, Cost paging, cap refusal, Report, exit,
and a no-color restart into the original saved receipt. The unknown saved cost
must remain distinct from the fresh session's known zero. Source, accepted
context and approval limits must remain unchanged.

This is offline workflow validation. The separately approved live allowance is
still exhausted at six of six requests. No further live request was made. A
session dollar stop still relies on reported costs and may overshoot before a
receipt arrives; this change does not establish a strict dollar ceiling. Human
visual approval, full reference-product parity and the broader delivery
milestones remain open.

## Results and remaining limits

Seventy-seven distinct focused TUI tests pass. They cover qualified amounts,
unknown shares, draft preservation, halt admission, exit handling, compact
editor controls, scrolling and footer visibility. The workspace build and all
ten quick-plan commands pass. The commands were invoked directly from the
checked-in package definitions because the pinned package-manager signature
check fails; signature verification was not disabled. The CRAP-risk proxy
covers 476 changed code files relative to its repository baseline.

Final J227 records 19 machine passes, zero failures, 18 live capture sets and
three open human judgments. The helper confirms one intercepted request, one
provider reservation, unchanged source and accepted-context manifest, zero
finding observations, and unchanged approval limits. The second request is
refused in Report. No-color Replay preserves the original incomplete receipt.
The raw verdict remains `REVIEW_REQUIRED`, with `operatorApproved: false` in
the assistant review record.

The final native bundle SHA-256 is
`4f6d7367afb980f9435a097c08507346076af8d5651a3b1755c7a96d67a1d339`.
Captures are retained at
`/tmp/kuzushi-tui-integration-20261012/cost-recovery-accepted-checks-tui/20261013-035504/J227`.
Test logs and the verification summary are under
`/tmp/kuzushi-tui-integration-20261012/cost-recovery-audit`.

Earlier failed attempts remain retained. They exposed the missing Cost paging
and hidden paging hint, and corrected fixture assumptions about output-token
minimums, approved job binding, halt labels, exit confirmation and wrapped text.
None is counted as a successful native run. A focused render test additionally
caught the halt card crowding the budget editor's input field.

At 40x12, the first Cost frame cannot show both budget rows; visible Page Down
controls reach their complete uncertainty and cap labels. Before acknowledgement,
the halt card explains Escape, cap review and abort, but the ordinary footer
still advertises broader shell actions. Aligning that footer with the halt's
input ownership remained a UX follow-up at that checkpoint. This fixture does not qualify report
export, live model usefulness, active-request cancellation or every session
accounting path.

## Halt input ownership follow-up

The footer and inactive prompt now name only the halt's actual controls before
acknowledgement. Notification hints use the same ownership rule, including the
first Escape action. Paste cannot mutate the held draft or its cursor while
the halt owns input. Escape restores ordinary reading and editing without
clearing the spending guard. The active-work interrupt label distinguishes an
abort request from cleanup already in progress. This adds no provider work or
automatic cap revision.

The follow-up records 190 distinct passing focused TUI tests. Its J227 run has
30 machine passes, zero failures and 20 live capture sets across the six
viewport sizes, plus no-color restart. Human review remains required. The native
SHA is `aa9f0a5952871c0e7312ea2a7819e4bc03f492f302ee35ddd0f04e8f0ae6fc2f`;
captures are under
`/tmp/kuzushi-tui-integration-20261012/halt-inventory-verified-tui/20261013-042953/J227`.
The request is strictly intercepted with dummy credentials. This uses one
synthetic request and zero live provider requests. The approved live allowance
remains exhausted at six requests. Ten quick-plan commands and the workspace
build passed before the subsequent Git acquisition change. The corresponding
CRAP-risk gate covered 478 changed code files. Selected assistant capture
judgments and metadata checks are recorded in `halt-input-audit` beside the logs.
