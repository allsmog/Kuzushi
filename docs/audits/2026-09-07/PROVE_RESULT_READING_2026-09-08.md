# Prove result reading and inconclusive assessments

The audit remains relevant. A real GPT-5.5 OAuth verification returned
`insufficient_finding_detail`, but Kuzushi presented it as
“likely-not-exploitable.” The verifier prompt explicitly mapped incomplete
evidence to false, and consensus treated a tied panel as a negative. Selection
rejected that result and preserved the previously accepted model proof.

Explicit incomplete model outputs now normalize to null. Incomplete evidence,
unsupported language and unresolved panel votes produce a partial, inconclusive
result. Supported positive and negative conclusions remain boolean;
contradictory or unknown proof verdicts are rejected. An inconclusive gate
continues to the configured verifier, and an inconclusive tie-break cannot
invent a negative. Cost and source receipts are retained. Partial Prove
receipts offer inspection and retry without selection or continuation to Fix.
The migration is documented in `docs/modules.md` and `RELEASING.md`; historical
run files are untouched. This protects explicit unresolved outputs, not model
accuracy itself. Post-fix live runs returned positive assessments; the corrected
inconclusive branch is covered by focused regressions.

Pending Prove results now have a scrollable body. The published result summary
precedes its receipt, and selected identity stays in the title while paging.
Status and the next action precede evidence. The title labels the current
selection rather than asserting that a different pending result concerns that
cursor. A new result resets its reading position; refreshing the same result
preserves it. Open reaches the pending result. Explicit Investigation and Trace
views take display priority, and their existing close controls restore the
result. Rerun editors keep their layout.

Two integration failures were found during this pass. The new result body
initially covered an opened Investigation form while its controls were active;
that priority is corrected and tested with real keys and rendering. Longer
indented output also made the final lineage row unreachable at 40 columns.
The shared pane counted rows with a whitespace-collapsing helper while Ratatui
preserved indentation. It now measures and renders the same Paragraph. The
failing Buffer regression is retained, and final live reading reaches lineage
at both 80×24 and 40×12. The reader exposes the bounded published summary and
receipt, not every raw model field or an unbounded transcript.

Three real model runs were made. The first incomplete result remains unselected.
The second returned a positive model assessment with confidence 0.78; explicit
selection at 40 columns and restart preserved model/NotAttempted/L2 with no
harness or crash evidence. All four candidates still require Review. The third
returned a positive assessment with confidence 0.93 and exercised the final
scroll fix; it remains unselected. Observed cost is zero with provider spend
unresolved, not a claim of free execution. These labeled canary runs are not a
blind accuracy benchmark.

Validation passes: 180 verification tests, 16 shared receipt tests, 32
phase-result tests, 19 layout tests, 62 Prove tests and 62 shared pane tests
(the filters overlap). The normal CRAP-risk gate passes for 293 cumulative
changed code files. The locked native build passes with seven existing
warnings. All ten quick repository checks pass; the final receipt finished at
2026-09-09T03:26:45.102Z with `dirty=true` and `driftedDuringRun=true`.
Final reading used native `d41e4d2bfa7f…`; selection/restart used the preceding
build with identical proof-selection policy. The dependency lockfile, saved
model configuration, five canary source files, 26 preexisting run metadata/result
files, main HEAD and empty staging area are preserved. The database integrity
check passes.

Nine sequential J54 journeys produced 108 numbered captures. All 17 issued
review questions are judged: 16 pass and one records the historical narrow
scroll failure. The failed wrapped-text assertion and covered-form journey
also remain in the evidence. No independent review, native screenshot, empirical
proof, commit or release certification is claimed.

The broader interaction checklist remains open, including supported local
reproduction through Fix. This host lacks the required Linux/bubblewrap backend.
GPT-5.5 OAuth is verified; Daybreak access through Kuzushi is unverified.
Result-subject identity with a different selected finding and complete Trace
keyboard behavior under pending-result attention still need dedicated coverage.

Evidence: `~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/prove-result-reading`,
especially `REVALIDATION.json`, `REVIEW_JUDGMENTS.json`,
`live-results-projection.json`, `selected-proof-final.json`,
`verify-scroll-receipt.json` and the archived recipes.
Selected run: `tool-1788923292664-81f8b87ab38e`.
Final unselected reading run: `tool-1788924311134-160b24d122ae`.
