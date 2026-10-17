# Partial Scan counts after a canceled attempt

A current-source run of the full J121 investigation has 136 machine passes,
zero failures and 100 authenticated capture pairs. Its screen review exposed a
count inconsistency: the selected partial Scan displayed three findings while
Review and the ledger held two distinct findings from three observations.

## Cause and repair

A canceled parent has no completed Scan stage. The Scan page correctly keeps
its summary fallback instead of presenting the remaining stages as complete.
That fallback used only parent run references for attribution, losing the
child engine references in the valid neighboring receipts. The result banner
already used the complete hydrated membership and counted two distinct findings.

The page now uses that same membership resolver. A known missing stage remains
compatible with a canceled or legacy parent. Loading or damaged membership
retains the original reported total without a guessed distinct count or ledger
severity breakdown. Original parent references, fixed jobs,
canceled attempts, partial disposition and persisted artifacts stay intact.
Reading starts no work and changes no finding or decision.

The native resize check also exposed automatic layout hiding the selected
Scan pane below the wide layout. Scan receipts and findings now retain their
reading focus when shrinking the terminal, using the same policy as Review
details. This leaves explicit zoom state unchanged and yields to pending
decisions. Missing panes are never manufactured.

The count label wraps within its pane, keeping each observation number beside
its unit. Plain output uses the same lines. The full journey assertions
also now check explicit FP, deferral, pending and source-review counts in Report.

## Verification

The before-fix focused regression fails with three rather than two findings,
matching the native capture. All 107 focused Scan model, rendering, result-control, viewport and reading-focus
checks pass, along with the workspace build and ten repository gates. The risk
proxy covers 504 changed code files. The resize regression also failed before
its repair.

Final J121 has 142 machine passes, zero failures, 106 authenticated capture pairs
and eighteen pending human UX judgments. Eighteen terminal-cell replays were
inspected. All 4553 Rust/build inputs, 802 runtime inputs and thirteen native
programs retain their recorded hashes throughout the final journey. The final
bundle and captures are in the evidence directory under `final/`.

The journey checks all six terminal sizes for the partial Scan delta.
It retains fresh Setup, executed Map preparation, explicit context acceptance,
three fixed discovery passes, an admitted cancellation, protected Review
capacity, an explicit allowance revision, manual triage, export and restart.
The final run uses five intercepted requests and no live request. No target
source is executed. Three fixed Scan jobs finish with four retained attempts,
including one canceled attempt. Four observations fold into two findings. Three
manual decision records retain an FP and a reassessed deferral. The seven-call
allowance keeps one unresolved commitment and two protected Review calls.

Two earlier native candidates remain available. The first confirmed corrected
counts but exposed split units and a fixture navigation mistake. The second
confirmed complete count labels but reproduced loss of the selected pane during
resize. Neither failed candidate qualifies the final workflow.

## Remaining acceptance

This case uses owned inert source and synthetic nondeterminism. It does not
qualify real-model usefulness, actual cross-commit finding comparisons, every
historical attribution path, reference parity or operator delight. Loaded
finding attribution still needs qualification for observations between earlier
and later representative source runs. The wide Scan sidebar still reports session consumption separately from the
shared investigation; making that accounting visible throughout the journey
remains a Core UX task. Formal human judgments remain open.
All nine broad milestones remain open. Publication stays a draft on main.
Historical live requests remain fourteen with no remaining allowance. Exploit
development, reproducer work and vulnerability patching remain excluded.

Evidence: `/tmp/kuzushi-core-journey-20261017` retains the before-repair full
journey; `/tmp/kuzushi-partial-scan-counts-20261017` records the repair checks.
