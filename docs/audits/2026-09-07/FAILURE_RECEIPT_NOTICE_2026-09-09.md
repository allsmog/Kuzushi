# Failure notices after run completion — 2026-09-09

Final receipt publication now preserves the current run's actionable error.
It retains current warnings unless the terminal outcome is failed, which must
remain an error. A notice from before the run does not hide a new completion.
When no current alert exists, failed/partial/blocked receipts disclose their
severity and point to `/activity`. The complete receipt and summary remain
recorded. This repairs the overwritten notice; complete failure-detail reading
is still partial.

The publication method moved into the small `runtime_event_drains/receipt_notice.rs`
module. Its existing enrichment, phase reconciliation, persistence and
destination behavior are unchanged. Six new tests exercise real idle
finalization, including persistence errors, old alerts and incidental warnings.
The initial regression run reproduced four failures. The final surrounding
runtime-event group passes all 62 tests. The normal CRAP-risk gate and all ten
quick gates pass; the quick receipt finished at `2026-09-09T15:38:28.480Z`.
Its dirty-tree drift is disclosed and supplemented by three tested-source
hashes. The workspace build used below is `3d77cae2…`.

## Observed behavior

J54 `20260909-083826`, at 80×24, repeats the previously observed missing-helper
failure using an explicitly labeled missing path in that terminal's adapter
environment. Installed binaries are untouched. Run
`tool-1788968317049-a1f28c471d3d` fails through the real adapter; it is not
presented as a successful provider request.

Capture 07 retains the red error and complete `cargo build --workspace` remedy.
The first Escape clears the alert while retaining Trace; the second restores
the original pending verification. Activity reopens the failed run. That
journey has 14 passing machine checks and director judgments of PASS, PASS,
PARTIAL: the captured Activity viewport does not reach the explanation.

Read-only follow-ups preserve two inadequate checks. The first incorrectly
expected `/replay` to open Run Focus and stopped at its required-screen check.
The next followed Replay's advertised “Esc nav mode” hint; Escape actually
returned to Prove, so those pages do not establish failed-run reading.

The final read-only journey, `20260909-084344`, waits for healthy Replay and uses
Page Down directly. Paging works, but captures 04–05 horizontally clip the
error after “from”, hiding the build remedy. Later pages reach the end without
revealing it. This is a remaining product defect, not a successful reading
check. The same surface still advertises the incorrect Escape hint.

## Preservation and next work

All 40 baseline run/result files, both workflow ledgers, five canary source
files, three selected-proof tuples and the saved model configuration remain
unchanged. The isolated failure adds two run/result files; the Replay checks
add no tool executions. No proof was selected or workflow attempt added.
No staging, commit or push occurred.

Next: wrap complete Replay text using shared reader geometry, correct its
Escape hint, and verify the existing failed result at 80/40 columns without
another model request. The narrow failure banner and full Activity reading
also remain unverified. All ten broad interaction categories remain open.

[Evidence, recipes, failed checks and preservation](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/failure-receipt-notice)
include the director judgments and self-review; no independent review is claimed.
