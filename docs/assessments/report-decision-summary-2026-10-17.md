# Report decisions stay distinct from discovery severity

The Report footer previously showed severity from all findings loaded in the
shell, while the document used a selected study. A focused regression reproduced
an unrelated high-severity workspace row in the footer while the study was still
loading. The zero-call investigation also showed two high findings in the footer
after both had human FP decisions.

Report now uses one selected review projection for its headline and footer.
The headline shows pending, TP and FP counts, with nonzero deferred, accepted-risk
and suppressed totals. The footer begins with pending work and reports the same
decision categories. Loading and unavailable report/source checks stay explicit;
they never fall back to raw severity from unrelated loaded rows. Workspace
history uses a separate asynchronous read of full export membership, so a list
filter, selected Scan or load limit does not become a report count. Report `r` refreshes its read while
preserving scope, format and scroll.

## Shared decision and source semantics

`ReviewDecisionCounts` is a pure domain value. The existing source-applicability
fold records effective terminal decisions only after its conflict and source
checks. Existing `reviewed` and `confirmed` fields remain unchanged. Study,
context-matrix and scope-study receipts add the same `reviewDecisionCounts`
object; consumers receive the exact selected observation set. Historical
`to_fix` decisions remain a separate exported category and contribute to the
existing TP meaning. Reading them adds no patching work.

A later observation or changed source does not prove a fix, nor does it
silently reuse an earlier FP decision. Such decisions remain in history and
pending where the shared policy requires reassessment. Unreviewed findings and
source reassessments remain distinguishable. Report does not change severity,
raw observations, review authority or the append-only decisions. Generated
exports preserve the original high severity beside an FP decision.

New output fields are additive to version 1 receipts. Historical artifacts are
not rewritten, and exact tool names, options, maturity, allowance policy and
phase contracts are unchanged. The migration for Rust struct literals is in
`RELEASING.md`.

Workspace report reads carry the last observed ledger watermark. A previously
loaded ledger that disappears or moves backward is unavailable, rather than an
empty report. A target without a known ledger may still report an empty ledger
without creating one. These reads change no observations or decisions.

## Verification

Evidence is retained in `/tmp/kuzushi-report-decisions-20261017`:

- All 332 distinct focused Rust checks and the workspace build pass. This
  includes 204 Report cases, source reassessment, shared export consumption,
  keyboard ownership, complete workspace membership and the known-ledger guard.
- All ten repository summary gates pass. The risk gate passes for 464 changed
  code files and all 15 proxy checks. The receipt records a dirty draft; it is
  not a clean signed publication receipt.
- The fresh production Core registry has 189 actions and 118 visible tools.
  Full descriptors and the visible catalog are unchanged: 81 Core, 32 Labs and
  five Compatibility entries. The existing dispatch-policy test also passes.
- Final sequential J279/J199 have 77 machine passes, zero failures and 66 live
  capture pairs. Five J279 and three J199 human judgments remain
  `REVIEW_REQUIRED`. All 4,540 source inputs, 796 runtime inputs and six frozen
  programs are unchanged before and after both journeys.
- J279 completes three local passes, six raw observations, two human FP
  decisions, JSON export and no-color restart under a zero-provider-call ceiling.
  All six Report sizes show the same decisions. The original high severity
  remains in exported rows. History, selected study and `r` preserve their state.
- J199 uses real Git revisions and a dirty captured source. Its earlier FP is
  pending after source drift; only the explicit captured-source deferral changes
  the summary to one deferred and zero pending. Four observations and both
  decisions remain, with no new source execution or investigation jobs.
- Fourteen of 66 generated ANSI terminal-cell replays were inspected. They
  cover all six Report sizes, narrow tail controls, history refresh, no-color
  recovery, source-stale/current decisions and captured code. These are not OS
  screenshots or formal human signoff. Both journeys use no model transport.

The original finding/severity regression, a known missing ledger incorrectly
returning an empty report, and initial test-shape compile errors are retained.
The first native history check captured a loading frame and the generic command
helper left Report while submitting a new command. The final flow uses a visible
`r` control and waits for loaded counts. The risk gate required local extraction
of report hydration routing and a test's setup, without weakening its limits.

The counters remain readable at 40 columns. Report still repeats format/path
metadata and long context identifiers, and the wide ambient rail could label
its workspace severity more clearly. Human UX and full reference parity remain
open. Two hidden Core qualifications and all nine broad milestones remain open. Publication remains
a draft on `main`, with no project commit, push or new live-model request.
