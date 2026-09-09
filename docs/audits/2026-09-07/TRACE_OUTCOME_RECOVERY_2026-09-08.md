# Trace outcome recovery — 2026-09-08

The real GPT-5.5 OAuth expansion completed in 19 seconds with zero new steps,
one unresolved-caller question and two evidence notes. That is a valid outcome.
The old reader lost the question and notes on restart, while the completion
claimed no model calls and created a selectable Prove result for Trace.
The execution and failed restart captures are retained.

Complete Trace outcomes now recover from the canonical result reference tied
to the exact tool call. Recovery checks the recorded digest, size, status and
contract, and includes zero-step outcomes. Existing step-only history remains
readable; unverifiable complete results produce an explicit error. New empty
question/note lists replace previous lists. The reader shows the saved run and
source status and keeps the full notes reachable through scrolling.

Trace now emits the shared exact-or-incomplete monetary contract. Both the
lifecycle and compact cost formatters stop inferring model-call counts from
zero dollars. New expansions use the shared source-snapshot boundary. A
foreground completion restores reading controls when its Prove detail has no
new draft; newer drafts and background focus are preserved.

## Validation

Fourteen new regressions pass. Focused groups pass: 22 core Trace tests, one
core cost-label test, 41 TUI Trace tests, 74 Run Focus tests, 34 cost tests and
seven context-strip tests. Groups overlap. The first dispatch and reader tests
reproduced their defects. Recovery tests also caught an incorrect initial use
of the terminal-intent digest; the implementation now uses the correlated
result-artifact digest. The locked CLI build succeeds with seven existing
warnings. All ten repository quick gates pass, including normal CRAP-risk.

| Final restart run | Size | Machine checks | Reviewed checkpoints |
| --- | --- | --- | --- |
| `20260908-220620/J54` | 80×24 | 6 pass | 4 pass |
| `20260908-220714/J54` | 40×12 | 6 pass | 4 pass |

These runs use the ordinary launch path and native SHA-256
`e3f63ff9f0961ca15e4387a0cd487fb3196ca8545086ffa9bd9d3ae7162282e6`.
All 20 recorded Rust source/test hashes match. The original five canary files,
32 baseline run/result files, operator config and three proof events are
unchanged. There are now 34 run/result files: the two additions belong to the
real expansion performed before these repairs. The restart checks made no
model request and selected no result. Owned journey sessions exited. Nothing
was staged, committed or pushed.

## Still open

Trace is still incorrectly offered as a selectable Prove result and shadows
the prior pending verification. The next repair must separate phase-result
participation from descriptor autonomy/effect policy and preserve historical
run and proof evidence. No proof result was accepted to hide this defect.

The old run retains its incorrect exact-zero monetary receipt in immutable
history. The corrected producer and foreground-return behavior have regression
coverage, but a fresh real expansion after those repairs remains to be checked
after phase-result ownership is fixed. Source binding for new expansions is
wired through the shared boundary; the saved real run predates it and is
explicitly labeled as lacking source identity. Large-history recovery latency,
empirical execution, Fix completion and the ten broad interaction checklist
items remain unverified or open. Cyber-program enrollment is taken as given;
Daybreak access through Kuzushi has not been established. The selected model
remains `openai-oauth:gpt-5.5`.

Review was by the director only. The dirty workspace is not a clean immutable
verification receipt; source/native hashes were checked separately.
Evidence: `~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/trace-expansion/`.
`PRESERVATION.json`, `tested-source-hashes.json`, `verify-quick.json`, per-run
judgments, `pass.patch` and `SELF_REVIEW.md` retain the checks and limits.
