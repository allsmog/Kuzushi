# Rejected context output and recovery

October 5, 2026, local uncommitted implementation on `5dcaa600e`.

The real OAuth context test exposed a diagnostic gap: its saved safe error did
not retain the specific validation failure or rejected model output. This
increment makes future failures inspectable without accepting invalid context
or spending more requests during inspection. It cannot recover text lost by
historical runs.

`saveRejectedOutput` is a descriptor-owned option, disabled when absent in direct
calls. New context studies freeze it as enabled unless explicitly disabled. The
TUI discloses bounded local retention before preparation and offers `s` to change
the draft. A frozen plan requires a separately approved replacement to change
that choice. Existing canonical inputs and historical plan hashes stay intact.

Single-synthesis build rejection after the existing one-repair contract may
publish a diagnostic in the owning run. It is at most 24 KiB plus its final
newline, can contain source or sensitive model text, and is owner-readable on
Unix. Authentication and transport failures do not publish raw errors. The
normal failure message stays redacted; no context revision is committed or
activated. Unsupported pipelines and missing or foreign run workspaces fail
explicitly.

The application reader authenticates the frozen input, contained file path,
size and published content object. Routine hydration does not load the model
body. Explicit `d` inspection opens a full-frame unaccepted-output document with
model/source/run identity, paging position and back controls. Workflow keys are
inert there. Esc restores the prior view and scroll. Control characters in both
text and metadata are escaped. Corrupted input remains a visible unavailable
state with an inspectable reason, rather than hiding the diagnostic action.

Focused verification passes: five rejection/retention tests, twenty context-study
tests with one intentional fixture export ignored, forty-eight structured-output
tests, 196 artifact regressions plus their subprocess cases, five shared CLI
approval tests and sixteen TUI context tests. Workspace build passes. All ten
quick gates pass in `.git/bounded-investigations/rejected-context-final-gates.json`,
finished `2026-10-06T06:08:19.276Z`. Dirty source and conservative drift are
explicit. The receipt excludes full CI, broad Rust tests and the platform matrix.
Documentation closeout follows that receipt and is checked separately.

J90 at `/tmp/kuzushi-bounded-investigations-tui/20261005-230615/J90/` has thirty
machine passes and five separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. Captures cover six terminal sizes, actual 40x12
paging to the tail, inert actions, actual exit, no-color restart and refusal
after the recorded input changes. Its native binary SHA-256 is
`7a1f54d8c7367a65bbaaf49ca1991a17a4eed204c4148288def4789c65e651ed`.
The real executor and adapter receive explicitly intercepted invalid initial
and repair responses. Two request reservations and one work attempt remain;
source bytes are unchanged and no context is accepted. There is no live
inference or source execution in this journey.

Failed native predecessors at `20261005-225129/J90` and `20261005-225823/J90`
remain with independent judgments. The first driver stopped paging at 211/225;
the second reached 225/225 but expected a sentence that wrapped across lines.
The final status fits on one narrow line. Earlier compile and fixture-label
failures remain in local logs; the corrected focused checks pass.

The existing live ledger still has six consumed calls out of eight, including
two unused protected Review calls. No additional live context request is
authorized. A reviewable one-job diagnostic plan proposes two additional context
requests, retaining spending and Review capacity; approval remains pending.
Live context usefulness, the complete scan/triage/report flow, multiple-scope
execution, context experiments, reviewed lessons and reference TUI parity stay
open. No delivery milestone is marked complete by this increment.
