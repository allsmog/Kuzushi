# Explicit zero-provider-call investigations

The previous descriptor, ledger validation, numeric editor and checkpoint reader
required a positive provider-call limit. An operator planning only local work
had to grant model capacity. The owned pre-change CLI reproduction rejects zero
with `must be at least 1, got 0` before creating an allowance.

All four boundaries now accept an explicit zero total. Protected Review calls
must also be zero. Existing positive defaults and explicit model selection are
unchanged. The approval reader explains that zero blocks all provider requests,
including retries and model-assisted Review or Report. Human decisions and
stored reports remain available. No model fallback or implicit Review reduction
is added.

The native resource estimate now states the exact protected Review limit,
including zero and unset choices. It no longer claims capacity remains reserved
when the limit is zero. Local compute and scanner-service costs remain outside
the provider estimate.

The existing atomic admission boundary refuses zero-capacity requests before
inserting reservations. A later increase requires the current approval revision.
A reduction cannot discard committed or unresolved calls. Existing version 1
artifacts and public tool names are unchanged; the valid numeric range expands.
Older validators enforce a positive minimum. The release note requires an
upgrade before approving or restoring zero choices.

Evidence is retained under `/tmp/kuzushi-zero-calls-20261015`.

| Verification | Result |
| --- | --- |
| Core allowance, shared prepared dispatch and runtime admission | 90 passed |
| TUI allowance, numeric editing, checkpoint recovery and resource estimates | 94 test executions passed |
| Combined focused checks | 183 distinct checks, 184 executions, zero failures |
| Workspace build | Passed; existing vendored terminal and dead-code warnings remain |
| CRAP-risk proxy against `origin/main` | Passed for eight changed code files |
| Final native J279 | 29 machine passes, zero failures, 26 text/ANSI capture pairs, five human judgments pending |

The six new core checks cover all six accounting categories and retries, eight
concurrent zero-capacity admissions, restart, explicit allowance revisions,
retained consumed/unresolved calls, runtime refusal before a request, and three
real local passes with a fourth refused. TUI checks distinguish zero from unset,
preserve positive Review choices instead of lowering them, and restore zero
choices without restoring execution authority.

The final J279 run is `tui-v4/20261015-062548/J279`. It accepts owned manual
context, approves three local discovery jobs with one worker and one attempt
each, and explicitly sets both call limits to zero. The real scanner completes
three distinct runs. Six raw observations consolidate into two findings, each
recurring in three completed passes. Two human false-positive decisions survive
JSON export and no-color restart. The source remains unchanged and the durable
ledger contains no provider reservations. Source text is labeled synthetic,
uses a public example credential shape, and is never executed.

The approval reader is captured at 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12.
The narrow reader keeps paging, cancellation and end-of-document approval
visible. Assistant inspection is distinct from the five pending operator
judgments. Exit 4 records `REVIEW_REQUIRED`, not a human approval.

The frozen native CLI SHA-256 is
`efc9985cb395c0216a9e19571811e1a2470fb57352fde43fc258eba94ba1907b`.
All 4,182 Rust/build inputs remained unchanged across the final checks, build
and capture; all 268 runtime/journey inputs remained unchanged during the final
journey. Thirteen native executables are retained together in `native-v4`.

Earlier retained J279 runs stopped before allowance approval: the initial
fixture lacked a recorded revision and grouped both files into one DFD node;
the second fixed the revision but still lacked the Map evidence threshold;
the third paged past the notice before its assertion. The final fixture records
two actual files as separate nodes, adds no invented flows or threats, and checks
the notice on its real page. Inspection also found and corrected the misleading
Review reservation copy. A pre-existing question-guard assertion now checks the
current refusal message and structured failure class. The resource-copy test
was updated to the exact limit wording. Failed logs and source versions remain
retained.

This is a bounded spending-control increment. It does not qualify real-model
discovery, the complete module audit, reference parity, operator delight or the
whole plan. No live request is added to the eight already spent. The separate
live Scan allowance remains unanswered. Exploit development, reproducers and
vulnerability patching remain excluded.
