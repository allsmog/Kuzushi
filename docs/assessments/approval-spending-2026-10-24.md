# Spending at approval and the complete keyboard journey

The approval reader kept the total call limit, model and fixed workload visible,
but scrolled existing spending and remaining capacity out of view at the approval
control. An operator increasing six calls to seven had to return to earlier terms
to see that four were already committed and only one Scan call remained available.

The reader now uses the existing accounting projection for both the document and
its pinned summary. Wide views retain committed and unsettled calls plus remaining
Scan and protected Review capacity. Compact views retain used calls and both
remaining capacities beside the approval control. The detailed document keeps
unsettled accounting and dollar uncertainty. If large values cannot fit, the
summary preserves room for readable terms and the approval control. Missing,
unrelated or stale accounting never supplies invented zeroes.

This changes presentation only. Approval, reservations, model selection, fixed
jobs and stored formats use their existing shared boundaries.

## Verification

- A failing screenshot assertion reproduces the missing spending summary.
- Thirty-seven focused TUI checks pass, including all six viewport sizes, both
  document ends, stale identity/revision, unavailable accounting, consumed Review
  capacity, large values, cancellation and plain output.
- The workspace build, TUI all-target Clippy and risk gate pass. The risk gate
  checks six changed code files; earlier history checks remain separate.
- The first current-build J121 has 231 machine passes, zero failures, 135 capture
  pairs and 21 formal operator questions. Screen review identifies the approval
  issue. Its evidence remains preserved.
- The final sequential J121 has 239 machine passes, zero failures, 137 capture
  pairs and 21 formal operator questions. It adds explicit checks for spent and
  remaining calls at approval, compact resize and return.
- All 6,562 repository inputs and thirteen frozen programs remain unchanged
  during the final run. The CLI SHA-256 is
  `acfc552e4d0cf243f6508b32a18b9585044bc7febf6e522416f3949498b73ff0`.

The complete fixture journey prepares and accepts context, approves three fresh
Scan passes, holds a real dispatched request, preserves its cancellation and
unresolved reservation, exports partial work, explicitly revises the allowance,
and finishes only the original remaining job. Four Scan attempts retain four raw
observations and two finding identities. Human FP and deferral decisions survive
rediscovery, source reassessment, bundle export failure/retry and no-color restart.
The final accounting is five committed calls out of seven, one unsettled call and
two unused protected Review calls. Losing the context manifest produces an honest
unavailable outcome; fixture metadata is then restored exactly.

## Screen review and limits

Agent review answers all 21 questions from captured evidence. Eleven final ANSI
cell replays are inspected, including the two revised approval layouts, active
work, refusal, source reassessment, export, report controls, restart and missing
context. The earlier run has 26 inspected replays. The final bounded journey has
no reproduced dead end; compact readers still require paging. Raw harness status
remains `REVIEW_REQUIRED`; formal operator judgments are not fabricated.

These are actual tmux captures with controlled, labeled model responses. They
add no live provider requests or target-source execution. Real experiment usage
remains sixteen with no allowance left. ANSI replays are not OS screenshots,
general detector/model-quality evidence, performance benchmarks or complete
reference-product parity. Four broad milestones retain local acceptance and five
remain open.

Evidence: `scripts/devex/artifacts/current-complete-investigation-20261024/`.
