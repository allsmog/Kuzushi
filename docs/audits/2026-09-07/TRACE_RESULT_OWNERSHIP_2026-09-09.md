# Trace result ownership — 2026-09-09

Trace expansion no longer replaces a pending verification or offers its
supporting evidence as a selectable proof set. The new descriptor field
`phase_result` defaults to existing behavior; Trace opts out while retaining
its Prove authorization phase, workspace-write effect and model requirement.
Shell preparation, completion receipts and shared workflow writers enforce
that distinction. Recovery excludes historical Trace attempts from active
phase selection without rewriting raw workflow events or run artifacts.
Unknown historical tools retain the existing checks and visibility.

The real pending verification is restored. One new explicit
`openai-oauth:gpt-5.5` expansion completed in 21 seconds with zero new steps,
one unresolved-caller question and one evidence note. Its canonical result
records incomplete metering and the current source identities. No selectable
phase attempt was created. Both workflow ledgers, all 34 baseline run/result
files, five canary source files, three proof events and the operator config
remain unchanged. The new expansion adds two run/result files.

## Evidence

Nine new regression tests cover admission, historical selection, v1/v2
recovery, unknown tools, unchanged authorization, descriptor serialization,
shell preparation and completion. Focused groups pass: 91 workflow tests,
two descriptor-policy tests, 60 phase-result UI tests, 56 runtime-drain tests
and 74 Run Focus tests. Groups overlap. All ten repository quick gates pass,
including the normal CRAP-risk gate. The locked CLI build succeeds.

| Journey | Size | Machine checks | Director review |
| --- | --- | --- | --- |
| `20260909-072101/J54`, old history | 80×24 | 6 pass | 5 pass |
| `20260909-072219/J54`, new expansion | 80×24 | 8 pass, 1 fail | 2 pass, 1 partial |
| `20260909-072414/J54`, new result restart | 80×24 | 6 pass | 5 pass |
| `20260909-072651/J54`, new result restart | 40×12 | 6 pass | 5 pass |

The live expansion returns to Trace with working reader controls and complete
question/note text. Its immediate cache omits the saved run/source receipt;
reopening restores it. The first Escape dismissed the explicitly visible
completion notice, so the execution recipe's back-navigation check failed and
stopped. Restart checks verify return to the original pending verification.
The failed execution journey remains evidence; it is not counted as a pass.

All captures use native SHA-256
`79c6f1cb6515c167ec366852cb378d6e8c2d9426e11831e5c055c391243a8d52`.
The 16 recorded Rust source/test hashes match, as do unaffected files from the
previous Trace repair. Quick verification ran in the existing dirty workspace;
these separate hashes support bounded source attribution, not a clean-tree
receipt. Owned journey sessions exited. Nothing was staged, committed or pushed.

## Remaining work

Refresh the live Trace receipt after durable completion and clarify notice/back
controls. The older Trace run keeps its incorrect historical exact-zero cost
receipt; no historical monetary artifact was rewritten. Large-history latency,
local reproduction, complete Fix/report acceptance, authentication recovery and
the ten broad interaction checklist items remain open. The labeled canary is
not a blind scanner benchmark, and no runtime proof was established here.

Evidence is retained under
`~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/trace-result-ownership/`,
including `PRESERVATION.json`, `real-expansion.json`, per-journey judgments,
`tested-source-hashes.json`, `verify-quick.json` and `SELF_REVIEW.md`.
