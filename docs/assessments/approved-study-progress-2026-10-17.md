# Approved Scan study progress

Scan now shows the recorded progress of its approved fixed discovery study.
The held-request view identifies one completed, one running and one queued job
instead of presenting a completed engine as the overall result. Completed,
running, queued, failed, deferred and unknown counts remain separate. A queue
label records the last read; it establishes neither process liveness nor
repository coverage.

The reader requires the campaign-specific approval and unchanged plan digest,
validates fixed membership, bounds the queue read and rejects malformed states,
unsafe run references, extra jobs and external symlinks. A missing queue means
the approved jobs have not recorded queue state. An unreadable queue remains an
explicit error. Refreshes happen asynchronously and retain the prior read
without moving focus or changing a draft.

The current target and owned dispatcher origin determine the study. Selecting
another campaign row cannot replace the owned study. Loading or failed reads
cannot substitute a terminal legacy engine. Existing selected result receipts
remain separate from the current plan and its per-job scopes. Plain output uses
the same distinction.

In Navigate mode, `c study jobs` opens the exact existing study deck. Enter
inspects a job; Esc returns to its jobs and then the originating Scan view.
Draft, cursor, filter, scroll, layout and input mode survive that return. Opening
the reader creates no job, request, allowance or approval. Existing launch,
stop and approval controls retain their separate behavior. A selected stopped
study returns to its ordinary result presentation.

## Verification

There are 334 distinct passing focused Rust tests, including approval and queue
validation, Scan receipt authentication, cache isolation, input ownership,
navigation restoration, six viewport sizes, plain output and no-color behavior.
The workspace build, Core/TUI all-target Clippy, CRAP-risk gate and ten quick
repository gates pass. The risk proxy covers 36 changed production code files.

Sequential native J121 has 185 machine passes, zero failures, 115 capture pairs
and nineteen pending human judgments. Thirteen copied binaries, 4,600 source
inputs and 806 runtime inputs are hashed before and after execution. The held
request preserves its original dispatcher, admitted bridge, fixed queue,
completed-pass findings and call count while the operator inspects the same
study twice, returns to Scan, opens the palette and resizes with a Unicode draft.

Independent checks confirm three fixed Scan jobs, four attempts including one
cancellation, four raw observations, two findings and three human decision
records. Partial acceptance, protected Review capacity, a specific allowance
revision, completion of the original remaining job, Report, export, no-color
restart and missing-context recovery remain covered. Accounting ends at five
of seven calls, one unsettled reservation and two protected Review calls.
Dollar consumption is unavailable.

Fifteen ANSI cell replays were inspected, including study navigation, held work,
palette return, partial Scan at all six sizes, settled Report and restart.
These reconstructions are not OS screenshots and close no formal human
judgments. Requested terminals are 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48;
tmux reserves one row for its status line. The replay font does not render every
symbol faithfully. The linked study deck retains legacy density and generic
navigation copy; command-hint consistency still needs UX review.

Transport is intercepted. No live inference or target-source execution is
added. Historical live requests remain fourteen with no approved capacity left.
This checkpoint does not establish real-model usefulness, actual cross-commit
finding comparisons, general module readiness or reference-level UX parity.
All nine broad milestones remain open. Public artifact formats and dispatch
contracts are unchanged.

Evidence root: `/tmp/kuzushi-study-progress-20261017`. Native manifests,
capture provenance, exact capture selection, ledger/export verification and
active-work evidence are under `native-v1`. Temporary evidence paths are local
and are not repository artifacts.
