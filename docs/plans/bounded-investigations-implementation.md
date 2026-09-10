# Bounded investigations implementation

This checklist tracks the accepted September 9, 2026 implementation plan.
Checked items require implementation and recorded verification; registration or
documentation alone is not functional evidence.

## Contract

- Repository → context/scope → approved finite plan → findings → triage → report.
- AI scope planning is optional and budgeted; no automatic subdivision or follow-up jobs.
- Curate Core/Labs/Compatibility discovery before proposing deletion.
- Scope planning, context work, discovery, review, and learning share the allowance.
- Keep the selected runtime/model; no silent fallback or automatic cap increase.
- Exploit development, reproducers, and vulnerability patching are excluded.
- Compare findings by durable identity across exact source revisions: commit SHA,
  inspected content hash for dirty or unversioned trees, and per-run source drift.
- Distinguish seen again, not observed in covered work, and not reassessed.
  Absence in a nondeterministic scan never establishes a fix; source or scanner
  changes and missing coverage must remain visible. Fix conclusions need evidence
  tied to the compared revision and cannot carry across branches automatically.
- Preserve public contracts and existing uncommitted work; no automatic commits.

## Delivery

- [ ] Bounded iterative inventory and inventory-derived scope suggestions.
- [ ] Registry-derived per-tool functional matrix and curated phase readiness.
- [ ] Explicit allowance, durable reservations, and honest unknown-cost states.
- [ ] Accepted context references independent of the global active model.
- [ ] Finite study plans with three-pass defaults and restart recovery.
- [ ] Optional AI scope proposals, coverage checks, and TUI scope editing.
- [ ] Comparable context experiments and complete observation provenance.
- [ ] Reversible review relationships and accepted reusable lessons.
- [ ] Complete TUI journey, report, layout and recovery verification.

## Verification

Record focused tests and integration results here as work completes. Live model
validation requires an explicitly approved test allowance and runs sequentially.

## Current implementation evidence

September 9, 2026: implementation is in progress. Delivery milestones remain
unchecked because this is a foundation increment, not the complete journey.

Provider admission now works through an explicitly bound LangGraph runtime,
including tracing, query and next-step calls. The full adapter suite passed 136
tests. Ten real bridge-process admission tests use an intercepted local provider,
including internal turns, quota retries within one process, outer transport
retries, parallel calls, cancellation/restart, unsupported adapters, startup
timeout and persisted failure-artifact consumption. They preserve GPT-5.5 medium
selection and incur no live provider charges. Core allowance/binding and failure
metadata checks, Node protocol checks and focused TUI recovery checks also pass.

The TUI failure reader now wraps values within their label column, exposes
paging and separates recovery actions. Its opening notice no longer claims
saved details are absent before hydration. The 80×24 J58 tmux journey passed 16
machine checks and all three reviewed questions at
`/tmp/kuzushi-bounded-investigations-tui/20260909-195722/J58/`. Earlier captures
retain the clipped text, missing paging and harness prompt-prefix defects found
and corrected during this audit. Width tests cover all six supported sizes,
with keyboard paging and leaving the tail checked at 40×12. This is a synthetic
failure-to-Report journey, not full investigation acceptance.

Shared prepared dispatch now accepts descriptor-declared `allowanceRef`, checks
the approval and explicit model before preflight, derives spending category from
the tool phase and binds the runtime through nested execution. New campaign
approval/status tools preserve exact revisions and start no jobs. An intercepted
provider test consumes the real context executor's structured artifact and
proves its next call cannot spend the protected review allocation. Missing
provider price receipts remain unavailable, including after settlement.

Discovery scan batches now bind their accepted jobs automatically. The remaining
spending boundary covers context, review and learning job planning and every
guided model action, plus the dedicated allowance editor. The current shell
confirmation requires 80×24 to expose its terms and blocks approval on smaller
screens while preserving cancellation. Ordinary unbound operator calls retain
their existing behavior. Source
revision comparison is implemented, while revision-specific fix adjudication,
immutable accepted context and the complete three-pass workflow remain open.

- Iterative inventory returns limits and omissions and derives at most eight
  candidates. Whole-repository proposals preserve loose source files, manifests,
  documentation and uncovered siblings. Partial inventory cannot install scopes.
  Snapshot-level inventory reuse and the AI scope editor remain.
- Budget halt opens an explicit cap editor instead of doubling the cap. Cancel
  preserves the halt and origin. Unknown strategy cost is blocked under a cap.
  Shared durable admission for every operator action remains.
  The existing deposit path now reserves atomically across SQLite connections
  and reads current durable operation caps. A new allowance API persists exact
  approved revisions, model selection, shared call reservations and protected
  review/report calls. It preserves unresolved reservations after restart and
  rejects stale revisions, model changes and request-id reuse. The bundled
  LangGraph adapter now supports opt-in admission for each underlying provider
  attempt. Shared dispatch and explicit shell approval are now available, but
  context/review/learning plan binding and the complete allowance editor remain open.
- Revision comparison shows full recorded SHAs and available content hashes.
  Shared coverage checks separate not observed from not reassessed. Missing
  snapshots, partial work and uncovered paths cannot establish absence. Legacy
  deterministic resolution fields remain compatible; evidence-backed fix
  adjudication per revision and branch is still required.
- The [registry baseline](../assessments/bounded-investigation-tools.json) covers
  93 visible tools, all 164 built-in policy tuples (including 71 outside the
  captured operator catalog), and narrow execution evidence for five
  deterministic tools.
  It is not a readiness certification. Functional audit and curation remain.
  Report descriptors now use a separate Report surface, with export approval
  retained and no workflow advancement. Guided phase rows and catalog actions
  share Core visibility. Whole-repository planning stays available regardless
  of file count; subdivision requires explicit selection, including retries.
  These changes do not certify every Core tool or complete the readiness audit.

Focused checks before the final non-source-membership addition passed: inventory
89 (one ignored), shards nine, shared revision/coverage checks, CLI comparison ten,
TUI comparison thirteen including six viewport widths, budget 56 (three ignored),
and unknown strategy cost one. Local `.git/bounded-investigations/` receipts record
subsequent reruns. Workspace build and harness contracts passed. No live model
calls were made.

The second J55 run at 120×36 produced twelve machine passes and no failures.
Reviewed captures under `/tmp/kuzushi-bounded-investigations-tui/20260909-173310/J55/`
show complete SHAs/content hashes, both absence categories and the uncovered-path
reason. Both review questions pass for that synthetic offline comparison surface.
The first run exposed clipped hashes and a harness navigation-footer mismatch;
both were corrected. Full investigation acceptance, smaller live terminal sizes,
multiline paste and restart recovery remain outstanding.

The phase audit separated Report from Fix in tool descriptors and shared
authorization, including KWP compatibility. Prepared dispatch under Review
writes a real report artifact. Reports cannot authorize repository execution or
external actions, and target-file export retains explicit approval. The two
changed policy tuples were reviewed before updating the registry fingerprint.

The first J56 Report run at 120×36 had seven machine passes and two reviewed
passes. At 80×24 it exposed a clipped autonomy ceiling; the footer now protects
the selected ceiling ahead of diagnostics. A subsequent 80×24 run had ten
machine passes and both review questions passed. Captures are under
`/tmp/kuzushi-bounded-investigations-tui/20260909-181526/J56/`. These use synthetic
run artifacts and an empty authoritative findings ledger, not a full live scan.
Final footer spacing and layout verification are recorded in local receipts.

The layout audit found an outdated Review gauge assertion: the existing compact
queue names the evidence level in words. Its source count was below the tiny
viewport, so the count accompanies finding identity when later card rows cannot fit. Failure snapshots also
needed to reflect existing source-identity acceptance guards: a partial result
without a usable source identity offers inspect/rerun, not acceptance as current.

Final layout verification passed all 13 composition checks: 120 phase/size/color
buffers, 30 plain projections, 30 checked snapshots and the failure screens.
The final 80×24 J56 capture at
`/tmp/kuzushi-bounded-investigations-tui/20260909-182841/J56/` passed ten machine
checks and both reviewed questions. Workspace build passed. The local
`.git/bounded-investigations/` directory retains failed attempts and focused
reruns as well as final verification receipts. No live model calls were made.

The resource audit found context-generation failures refunded as zero and gap
fill accepting incomplete cost as a final receipt. Stage settlement now retains
those deposits and uses complete cost evidence from structured-output failures
when available. The dollar editor and operator docs disclose retrospective
stopping instead of claiming a strict ceiling. Focused spending checks passed
28 tests before this Map-stage correction; final reruns are recorded separately.
The registry matrix includes resource evidence for the inspected Map, chunked
scan and campaign paths, with provider admission and internal-loop gaps explicit.

Final spending verification passed 28 ledger checks, 51 staged-Map checks,
56 TUI budget checks (three ignored), the workspace build and all ten quick
verification gates. Budget-editor rendering covered all six supported viewport
sizes. J57 at 40×12 passed 18 machine checks and both reviewed questions; captures
and review verdicts are under
`/tmp/kuzushi-bounded-investigations-tui/20260909-190146/J57/`. Its first run used
the wrong expected validation text; the captured rejection was correct, and the
journey was corrected and rerun. The complete save/cancel controls remain visible
in the editor body, although the repeated global footer hint clips at 40 columns.
These checks validate the spending foundation and existing dollar editor, not
the pending shared allowance approval or provider-admission journey.

The following shared-dispatch increment passed 22 core allowance checks, all 138
adapter tests (including twelve admission scenarios across bridge processes and
inherited runtime binding), both
registry policy checks and ten confirmation rendering tests. The six-viewport
approval test verifies that hidden terms cannot be accepted. Workspace build,
CRAP-risk and all ten quick verification gates passed; the receipt describes a
dirty implementation tree, not a release certification.

J59 now exercises real allowance administration through the shell, including
80×24 → 40×12 → 80×24 resize while approval is pending. Pressing `y` at 40×12
does not approve or discard the request. After restoring the terms, explicit
approval and a separate status read preserve nine total calls, three protected
review calls and zero committed requests. The final journey passed twenty
machine checks and all four screen reviews at
`/tmp/kuzushi-bounded-investigations-tui/20260909-203453/J59/`. The earlier fourteen
check run also passed review. Earlier failed runs retain the long-command
harness limit and missing human-readable result receipt found and corrected.
The harness now has a live `resize:` directive and its contracts pass. This is
an offline allowance journey; it does not validate a full scan plan or replace
the pending responsive allowance editor.


The finite-work increment adds `campaign:study`, a draft-only entry to the
existing scan-batch compiler. Three passes and one worker are its defaults.
Approval checks the exact plan digest/count and freezes a per-job attempt
limit. Shared dispatch verifies prepared input, indexed source identity and
configuration, then atomically claims a durable attempt before executor entry.
Cancellation/restart do not refund a start; an approval revision cannot reset
or repurpose consumed work. The campaign dispatcher attaches allowance
references and counts quota failures against the approved attempt limit.

Current evidence: 31 focused allowance/dispatch checks, 59 campaign dispatcher
checks, four allowance-related TUI checks, and a real three-pass offline
`secret-scan` execution through shared dispatch. The fourth dispatch is refused.
J60 passed 22 machine checks and four reviewed questions, including bracketed
paste of the approval, 120×36 → 80×24 → 120×36 resize, refusal while small,
and the real durable approval receipt. Evidence is at
`/tmp/kuzushi-bounded-investigations-tui/20260909-211054/J60/`.
This is draft/approval UI evidence; the responsive plan editor remains open.

The CLI source-identity check exposed an existing ancestor-filter defect:
repositories located beneath `target`, `dist`, `node_modules` or `bazel-*`
could produce an empty indexed content identity. Both hash-only and full-index
walks now apply exclusions relative to the selected workspace. All 37 focused
incremental-index tests pass, including two distinct dirty edits at one SHA.
Previously recorded identities from affected paths must be recomputed; they
cannot establish unchanged source content. This fix does not claim that the
indexed file universe is complete repository coverage.

Still open: immutable accepted context independent of the active threat model,
context/review/learning job plans under the shared allowance, full model-backed
three-pass aggregation/triage/report/restart, optional AI scope review and the
responsive investigation editor. Discovery-only work approvals currently cannot
plan model-backed review or learning jobs; protected review calls remain held.
No live provider requests were made. Implementation remains uncommitted.


After the source-identity correction, the real CLI campaign completed three
separate offline child runs and reopening the batch created no further jobs.
Its SQLite ledger retained exactly three started attempts and zero provider
calls. Two dirty edits at the same full SHA produced distinct content hashes;
a new commit produced a different SHA, and post-draft dirty drift refused
approval. Evidence: `/tmp/kuzushi-finite-study-e2e-4cglax1x/receipt.json`.
The earlier CLI fixture is retained as evidence of the ancestor-filter defect.
The 15 existing scan-batch tests and two complete registry policy checks also
pass; the workspace build passes. These are offline source-analysis checks,
not live model validation or evidence of finding resolution.
