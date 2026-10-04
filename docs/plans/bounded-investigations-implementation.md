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

## Operator experience acceptance bar

The operator experience must meet the quality bar of the upstream terminal
assistants in the [reference baseline](../quality/tui-reference-baseline.md).
This is a requirement for the complete supported journey, not a claim that
Kuzushi already matches either product. A passing screenshot or isolated
interaction repair cannot close this requirement.

- **Predictable input:** typing, multiline paste, Unicode, cursor movement,
  selection, completion and history have one clear input owner. Opening a
  picker, viewing evidence, receiving a background result or canceling an
  action preserves the draft and navigation origin. Hints name the keys that
  actually work in the current state.
- **Discoverable actions:** primary actions are visible where they are needed;
  the searchable palette, shortcuts and typed commands agree. Operators can
  complete ordinary work without memorizing commands, editing JSON, or leaving
  the TUI to repair an artifact. Unsupported work and missing prerequisites have
  distinct explanations and a useful next action.
- **Clear hierarchy:** each screen makes the current question, scope, result
  and next decision apparent. Finding claims and evidence precede internal
  identifiers. Full provenance remains accessible. Advanced engine controls
  and diagnostic details do not crowd the ordinary investigation path.
- **Calm, responsive work:** typing, scrolling and resizing remain usable while
  work runs. Progress shows the approved finite workload and its real outcomes.
  Completions preserve focus; cancellation has a visible, recoverable state.
  Input latency and behavior under activity need observed evidence, not an
  assumed performance equivalence with the references.
- **Deliberate spending:** the operator sees the model, scope, passes, workers,
  allowance, protected review capacity and estimate uncertainty before approval.
  Limit, retry, partial-result and restart screens preserve both the work and
  its spending history. A visually polished approval cannot hide a tradeoff.
- **Consistent reading and recovery:** scope trees, context revisions, DFDs,
  findings, run comparisons and reports share selection, paging, back and detail
  patterns. Results remain understandable after restart, source drift and
  context changes. Missing observations never imply a fix at a different SHA.

Acceptance must exercise Repository → Context/scope → Plan/allowance approval →
Scan → Review → Report as one keyboard-only journey, including cancellation,
partial work, exhausted allowance and restart. Each delivered increment needs
its failure states and TUI work, rather than postponing interaction quality to
a final styling pass. Review captures at 40×12, 60×20, 80×24, 96×89, 120×36 and
160×48, plus plain/no-color behavior. Machine checks establish state and key
behavior; a recorded screen review must also assess hierarchy, readability,
discoverability and recovery. Keep observed gaps open until that evidence exists.

The pinned [source reference baseline](../quality/tui-reference-baseline.md)
records the inspected input and command patterns. Preserve Kuzushi's bounded
security investigation workflow while adopting their interaction discipline.

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
No live provider requests were made. This checkpoint was subsequently committed
and pushed as `14130a4eb76ef10fc376edbb32e30bc6b0966702`.


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

### Immutable threat-model reader checkpoint

Discovery and triage now consume an explicit immutable `threatModelRef` without
activating it globally. Explicit omission stays omitted. Campaign compilation
preserves the selected revision; changed active pointers no longer invalidate
that selection. Selected MCP attachments authenticate their object on each
query. Deep triage receives the same advisory digest on every pass. Run
comparisons expose recorded context independently of full source SHA and
indexed content identity. Auxiliary context bundles remain unfinished.

Focused Rust checks cover selection, corruption, dispatch, campaign compilation,
MCP binding, triage propagation and comparison projections; the workspace build
and the CRAP-risk gate pass. The prompt test initially assumed quoted data would
remove ordinary words; it now checks the encoded line boundary and lossless
derived-record decoding. The existing synthetic secret fixture is unchanged;
its reviewed whole-file hash was refreshed after a revision-binding test edit.

J61 runs two real offline CLI `secret-scan` jobs against labeled imported context
revisions. Its fixture confirms exact `scan-input.json` references and an
unchanged global active pointer, with zero provider calls. The TUI audit is
**not passed**. Evidence is retained at
`/tmp/kuzushi-bounded-investigations-tui/20260909-221651/J61/` and
`/tmp/kuzushi-bounded-investigations-tui/20260909-221835/J61/`.
Keyboard paging and return work, but refresh can temporarily replace a recorded
context with unavailable/loading state. These headless tool runs also lack the
`findings.json` snapshots consumed by comparison. Their absent source metadata
is disclosed as unknown, so these fixtures cannot establish SHA comparison or
coverage. The earlier CLI source-identity receipt remains separate evidence.

A further receipt defect remains open: the top-level `run.json` provenance
captures the globally active model at startup even when the explicit scan input
selects another immutable revision. The new comparison reads the recorded scan
input, but other consumers of the summary can still misattribute context. Fix
shared start-time provenance before claiming context consistency end to end.
The latest J61 waits for loaded run status and tests return navigation, but
still needs a passing audit after hydration and receipt corrections.

Per-revision fix adjudication also remains open. A decision must identify the
source SHA and dirty content identity that supplied its evidence, with branch
ancestry considered when carrying it forward. A nondeterministic miss is an
observation, not a global resolution decision. This checkpoint does not claim
that a finding is fixed on any revision.

### Source and context comparison repair

The shared run writer now preserves explicit threat-model input in the starting
summary, including explicit omission; terminal writes retain those references.
Older summaries are not rewritten. SAST writes its discovery observations to
`findings.json` before optional post-processing, so comparison reads the run's
own saved evidence. Its result records the indexed starting snapshot and tree
hashes, and becomes partial when final source verification detects drift.
The source-change test preserves the starting hash and partial observation
snapshot rather than relabeling them as current.

The TUI defect was an eight-entry artifact cache competing with a two-run
comparison and its origin. It now permits 32 entries under the same shared
64 MiB payload ceiling. Pending context reads say loading; unavailable data
remains a separate state. Focused tests cover simultaneous artifact hydration,
the byte ceiling and missing/omitted/loading comparison states. This does not
certify arbitrary large comparisons beyond that payload ceiling.

J61 now executes three real offline source scans: two committed source
revisions with distinct selected contexts, then a dirty edit at the second SHA
with explicitly omitted context. Each retains one observed fixture finding.
The starting/terminal summary references, saved observations, full SHAs and
distinct content hashes are checked against real artifacts. The active context
does not change. The final journey passed 21 machine checks and five manual
screen reviews at
`/tmp/kuzushi-bounded-investigations-tui/20260909-223608/J61/`.
The captures cover 120×36 and 80×24, paging/return and both comparison pairs.
The preceding Git-backed fixture failed because its blanket ignore rule hid
the trackable scope file; that fixture was corrected. Earlier failed evidence
remains available.

Focused Rust tests, workspace build, CRAP-risk and all ten quick verification
gates passed. The local receipt describes an uncommitted working tree, not a
release certification. No provider requests or target-code execution occurred.
Per-revision fix decisions, full immutable auxiliary context, remaining phase
contracts and the complete approved model-backed journey are still open.

The legacy `resolve_stale_state` inference is being replaced: disappeared
observations must retain the original human verdict and be disclosed separately.
Review decisions still carry only event-log provenance, without a source
SHA/content binding; removing the false fix inference does not complete that
revision-specific decision contract.

### Comparison reading experience

The TUI comparison now leads with finding counts and the absence caveat. A
pinned Findings / Sources & context tab row keeps full SHA, dirty-content and
immutable-context references one keyboard action away. Each tab restores its
own scroll offset; a new comparison resets both. Empty-composer Tab switches
views, while typed input retains composer ownership and the footer describes
the actual action. The selected tab uses the shared selection style and remains
identifiable by brackets without color.

The ten-row category cutoff is removed. Unchanged observations are readable in
SEEN AGAIN, rather than available only as a count. Empty category headings no
longer displace real evidence. Plain output includes both findings and complete
provenance regardless of the interactive tab or scroll. These are presentation
changes; neither recurrence nor an absent observation changes a finding verdict.

J61 passed 32 machine checks and ten manual reviews at
`/tmp/kuzushi-bounded-investigations-tui/20260909-225645/J61/`.
It covers 40×12, 60×20, 80×24, 96×89, 120×36 and 160×48; full references,
clean/dirty source distinction, tab access and exact restoration of the source
reading window are backed by captures. The prior run at `20260909-225229/J61`
failed because it captured observations before context finished loading and
expected a section heading outside the tiny tail viewport. The corrected
journey waits for both artifacts and checks the actual tail observation. The
40×12 hierarchy was also changed so counts and the caveat appear first.

Focused comparison and footer tests cover multiline draft/cursor ownership,
new-pair reset, full hashes at every width, thirty-observation tail access and
exhaustive plain rendering. The first broad gate caught plain-mode routing
inside the renderer; that routing now uses the existing PlainRenderMode DTO
and the architecture gate passes. No provider calls were made. This validates
the comparison surface, not the complete investigation journey.

Large-result work remains: the shared artifact cache has a 64 MiB ceiling and
the generic document scroll offset is still u16. Removing the ten-row cutoff
does not certify arbitrary-size interactive comparisons. Revision-bound fix
adjudication and the other outstanding phase contracts above remain open.

Verification for this increment concluded with 18 comparison tests, 28 footer
tests, workspace build and all-target checking passing. The architecture rerun
and remaining model-safety, docs, CRAP-risk and formatting gates also passed.
The original quick-summary receipt retains its earlier architecture failure;
focused follow-up logs live in `.git/bounded-investigations/comparison-ux-*`.


### Observation gaps and Review consistency

The ledger no longer turns a disappeared observation into `fixed` or `removed`.
Open and confirmed findings retain their review state and relevance. A separate
optional observation gap carries the last-seen and comparison run IDs plus the
event sequence/hash. Re-observation clears the gap; suppression changes and
restart preserve it. Producer-supplied gap claims cannot replace ledger truth.
Operator identity-policy lists now hydrate the same annotations as headless
reads. List JSON and text use saved review decisions independently of the
scanner's original triage fields, fixing a real CLI display disagreement.

Review leads with the saved verdict and absence caveat. At 40×12 with an active
filter, both fit the two available detail rows; paging remains visible after
the footer's own wrapping pass. Full run references remain in the detail and
comparison. JSON, JSONL, CSV, Markdown bundle, workspace SARIF, external findings
JSON and confirmed SARIF preserve the gap and limitation.

J62 uses two real offline static scans at distinct Git commits and one labeled
human confirmation. Its final run at
`/tmp/kuzushi-bounded-investigations-tui/20260909-234240/J62/` passed 25 machine
checks. Eight manual reviews record six passes and two partial results; the
observation-gap behavior passes, while the complete operator quality bar remains
unmet. Captures cover 40×12, 60×20, 80×24, 96×89, 120×36 and 160×48, plus restart
without color. Seven real export paths are checked. No provider requests or
target-code execution occurred.

The failed runs at `20260909-232722`, `20260909-233307` and
`20260909-233850` remain in the same artifact root. They exposed the stale CLI
review label, an incorrect shell filter example, insufficient compact reading
space, a second footer-priority layer, and premature capture predicates. These
were corrected rather than treating machine assertions as visual approval.

Validation includes the findings suite (385 tests), workspace suite (602 passed,
one ignored), focused confirmation/identity-policy tests, detail and footer
tests, the 12-test viewport matrix, workspace build and shared all-target checks.
The current quality verification receipt is
`.git/bounded-investigations/observation-gap-delivery-verification.json`.

Next: remove legacy Prove/Fix guidance from the supported Review journey,
consolidate its repeated decision metadata, and provide a visible comparison
action that returns to the same finding. Full revision-bound human decisions
are still absent: the gap's run references are not an adjudication of a fix at
a specific SHA. The remaining context, finite orchestration, scope and allowance
milestones remain open; this increment does not establish full product parity.


### Review reading and return navigation

Review Enter now opens the selected finding within Review. The detail presents
one effective decision, its reason, source evidence and observation uncertainty
before actions. Newer automated decisions remain in history when a human
verdict has authority. The display uses the same authority resolution as the
ledger instead of choosing whichever history row is newest.

A visible **compare scans** control opens the observation gap's exact run pair
on Sources & context. It compares the visible row, even when another finding is
pinned outside the list. Escape preserves the finding cursor, filter, focused
pane, zoom and scroll. Draft text retains input ownership. The command and
hotkey reuse the existing run comparison; no additional scan jobs are created.
The action can be remapped or unbound through the existing keymap configuration.

Removed the unused internal detail-rendering path and its verification/patch
recommendations after confirming that Review was its only production caller.
Shared evidence, source, provenance and history rendering remain tested. No
public module implementation or dispatch alias was retired.

Validation: 237 Review-related tests, 122 Workbench renderer tests, two Enter
selection tests, 20 run-comparison tests, 32 keybinding tests, the 12-test layout
matrix, current-decision authority and remapping tests, and workspace build.
All ten quick verification gates pass in
`.git/bounded-investigations/review-reading-verification.json`.

The final J62 evidence is
`/tmp/kuzushi-bounded-investigations-tui/20260910-000911/J62/`:
44 machine checks pass; ten manual judgments record eight passes and two
partial results. The reading/comparison behavior passes at every viewport,
including return to a scrolled 40-column detail and restart without color.
Both full SHAs match the real offline scan receipts. Seven exports retain the
observation gap; provider requests remain zero.

Earlier runs remain preserved. The `20260910-000600` run captured a blank frame
immediately after resize and failed. The journey now waits for a completed
redraw within a finite timeout. The `20260910-000734` run passed its machine
checks but captured inconsistent text/ANSI focus; the final predicate waits for
the exact focused detail heading. These are capture corrections, not evidence
that resize latency or focus behavior matches the reference applications.

The complete product quality bar is still unmet. The outer phase rail and
journey progression still expose legacy Prove/Fix concepts; raw decision times
and diagnostic footer labels need refinement. The scope of this increment is
Review reading and comparison. Revision-bound human adjudication, finite scope
planning, complete allowance enforcement, context experiments and the broader
end-to-end milestones remain open.


### Guided Review → Report completion

The guided phase projection, default page keys, planner arrows and automatic
phase completion now use Map/Scan/Review followed by the separate Report surface.
All reviewed findings, including confirmed or explicitly deferred findings,
permit Report. A partial or unselected earlier attempt still requires its normal
resolution. Historical Prove/Fix attempts and in-memory failures remain retained
but do not redirect the completed source-analysis investigation or enter its
retry offer. Explicit compatibility dispatch and persisted phase values remain.

Navigate `r` and next-page navigation from Review open Report. Escape preserves
the Workbench page, finding, focus, zoom, scroll, input mode, draft and cursor.
The Report shortcut can be remapped or unbound. Review list guidance no longer
recommends patching based on proof level. The legacy BuildReport task is no longer
offered inside Fix: its descriptor already declares the separate Report surface.

Report gives its content the rows previously occupied by recent command history.
The sidebar names SESSION COST and uses shared complete/incomplete/unavailable
accounting; missing metering cannot show a complete budget percentage. This does
not establish a durable workspace total or close the broader allowance milestone.

Final tmux J63 captures are at
`/tmp/kuzushi-bounded-investigations-tui/20260910-004107/J63/`:
28 machine checks and nine recorded screen reviews pass. They cover recording a
real TUI decision, Review → Report → exact zoom return, `next`, JSON export,
all six viewports, and no-color restart. The exported two-finding report retains
the human decision and observation-gap receipt; provider calls are zero.
Earlier `002813` and `003351` runs preserve capture-predicate failures. The
`003603` run passed 26 checks but its manual review found crowded small-screen
reading and ambiguous spending labels, corrected in the final capture.

The complete quality bar remains unmet. Decision/export timestamps and diagnostic
footer copy need refinement. The complete context/scope/allowance approval flow,
finite studies, scoped monorepo execution and revision-specific human adjudication
remain open. This increment does not claim full reference-product parity.

The full TUI suite passed 3,433 tests (four ignored), including the 120-profile
composition matrix and checked snapshots. Workspace build passed. All ten quick
verification steps passed in
`.git/bounded-investigations/source-investigation-verification.json`. The receipt
marks the working tree dirty and therefore sets its conservative drift flag;
it is not an immutable-tree certification. Subsequent allowance-review work has
its own focused validation.

### Paged allowance approval

Allowance and finite-work approval now open a full-frame disclosure instead of
requiring an 80×24 or 120×36 terminal. The same wrapped document drives the
visible page and approval gate. The operator can read every term with Page Up /
Page Down, arrows, Home/End or the mouse wheel; approval is available at the end.
The exact model, total calls, protected review calls, approval reason, fixed job
count, attempt limit and full plan digest remain readable at all six sizes.
Dollar uncertainty and the fact that approval starts no jobs remain explicit.

Escape preserves the composer, cursor and navigation origin. Paste and unrelated
keys cannot change the hidden draft. Mouse input belongs to the approval surface
and cannot change the underlying view. New requests reset the disclosure;
resizing reflows it and rechecks approval. Remembered affirmative approval stays
unavailable. Plain output contains all terms independently of the TUI scroll.

The final sequential J60 run is
`/tmp/kuzushi-bounded-investigations-tui/20260910-010353/J60/`: 43 machine checks
and 12 recorded screen reviews pass. It approves the real offline three-job
draft at 40×12, then inspects its saved allowance after restart without color.
The independent CLI/ledger check proves one approval revision, zero work
attempts and zero provider calls. Earlier evidence at `20260910-010007` remains
failed: its restart predicate expected the status result to stay foreground,
and a draft capture paired text with an earlier ANSI frame. The capture adapter
now derives plain text from its single ANSI capture; focused harness contracts
cover the redraw failure and preserve strict live-state waits.

Validation: 11 allowance-related tests, 105 confirmation-related tests, workspace
build, the CRAP-risk gate for 96 changed production files, both DevEx harness
contract suites, and all ten quick verification steps in
`.git/bounded-investigations/allowance-review-verification.json`. The quick receipt
marks this intentionally dirty working tree and predates the separately tested
capture-adapter change.

This closes the terminal-size restriction, not the complete spending-control
milestone. Study inputs still need declared tool options, and status inspection
currently requires opening Logs after command completion. The next supported
surface needs integrated context/scope/allowance editing and durable study status,
with all model actions bound to that approved work. Full product parity remains
unmet.

### Finite study form and saved allowance

The Scan page now exposes `b plan study and allowance`; the command palette and
`scan batch` open the same form. It defaults to three discovery passes and one
worker. Call and protected-review limits remain unset until the operator enters
them. Preparing a draft runs the descriptor-backed `campaign:study` tool through
the shared background dispatch path. Approval, opening the fixed job list and
launching it are separate visible actions.

The source/context row shows the frozen source-content identity, Git SHA when
available, explicit context omissions, model, scan options and plan digest.
Draft revisions retain their investigation accounting and prepared scanner
options even when session defaults change. Unknown scanner selections now fail
before a draft is published. Saved studies reopen with `a` from their job view,
including the same durable allowance revision, consumption and protected review.
Launch checks the exact study approval before spawning the controller. Refresh
also reloads the shared findings projection, preserving its active filter, so
detached scan results agree with the shell count and subsequent triage.

The form uses a centered reading width with side-by-side details on wide
terminals and a stacked layout on smaller ones. Paging, numeric editing,
multiline-paste rejection, errors and back navigation retain their own input
ownership. Returning to Scan restores its previous zoom, selection, scroll,
input mode and composer draft. Background receipt completion updates the draft
without changing focus. Plain output uses the same complete details.

Final sequential J64 evidence is
`/tmp/kuzushi-bounded-investigations-tui/20260910-020733/J64/`: 34 machine checks
and 11 recorded manual reviews pass. The real deterministic secret scanner ran
exactly three jobs with one attempt each, produced one recurring finding from
three observations, and reserved zero provider calls. Approval and opening the
job list each left all jobs unstarted. Restart without color restored the same
allowance directly. The six viewport captures range from 40×12 to 160×48,
including complete paging to the final source/context disclosure at 40×12.

Failed evidence remains retained. The `013545` run exposed malformed scanner
selection and a harness prerequisite that did not stop dependent actions. The
`014400` run retained a wrapped-copy assertion failure and truncated action
labels. Manual reviews rejected `015833` for capturing before the completion
redraw and `020440` for a stale shell finding count despite correct job results.
The final recipe waits for actual rendered completion and checks the shell count;
the shared campaign refresh fixes that count. An earlier interrupted `013232`
run exposed module-prompt recognition in the harness, covered by focused tests.

Validation includes four core study tests, seven focused TUI study tests,
five final interaction tests, 15 campaign tests, 30 canonical snapshot tests,
both harness contract suites, workspace build and the CRAP-risk gate for 122
changed production files. The full TUI run passed 3,438 tests and found five
failures (four ignored); all five failures were corrected and passed focused
reruns. That is not a claim that the full suite was rerun after every correction.
All ten quick verification steps passed in
`.git/bounded-investigations/study-verification-final.json`; the subsequent
campaign finding-refresh correction has its own focused tests, workspace build
and CRAP-risk validation. These receipts cover an intentionally dirty working
tree, not an immutable commit.

This closes the previous requirement to inspect study approval through Logs.
The complete module-functionality audit, context generation/editing/acceptance
journey, scope-review tree and monorepo execution, approved context experiments,
reviewed lessons, revision-specific human fix adjudication and live model
validation remain open. Job-deck presentation and its transition into triage
still need broader refinement. Full reference-product parity is not established.

### Inspect and select immutable context in the study

Enter on the study's Source and context row now opens a revision browser. It
lists every recorded revision and explicit omission, keeps selection stable by
immutable identity, and reads a selected revision through the shared prepared
`threat-model:read` dispatch. The added `threatModelRef` option authenticates the
exact stored scanner document and rejects scope/output/methodology overlays.
Unbound reads preserve their existing behavior. No active-model change or model
request is needed to inspect or choose study context.

The browser presents repository, scope, recorded source revision and grounding
status before acceptance. Summary and complete-document tabs share paging and
back controls. The complete document retains its indentation; short revision
lists return unused vertical space to the document. Escape leaves the original
study draft unchanged. Late or foreign revision results cannot replace the
selected preview or steal focus. Accepting changed context invalidates the old
draft while retaining scanner options and investigation accounting. A newly
prepared and approved plan is required before execution. Explicit omission has
its own visible choice and persists as null context.

Final sequential J65 evidence is
`/tmp/kuzushi-bounded-investigations-tui/20260910-023251/J65/`: 28 machine checks
and all ten recorded screen reviews pass. Real tool dispatch imported two
labeled fixture contexts, inspected the inactive revision, prepared one study
bound to it, then prepared an explicitly omitted-context replacement. Both
drafts retained the same investigation; the active workspace model remained the
other revision. Restart without color reopened the original study's selected
revision and its grounding failure. No jobs or provider calls started.

The first `20260910-022650/J65` run remains failed: its fixture expected allowance
tables before first approval, and manual review found wasted list space, an
unreadable epoch timestamp, lost JSON indentation, and grounding failure hidden
from the main preview. All eight recorded judgments remain with that run; the
subsequent captures verify the corrections at all six supported sizes.

Validation: two core exact-context tests through shared dispatch, 22 batch-scan
tests before the final presentation refinements, seven final context tests
(including all six viewports and plain output), workspace build, and CRAP-risk
validation for 129 changed production files. All ten quick verification steps
passed in `.git/bounded-investigations/context-picker-final-verification.json`.
The final descriptor-help wording change has a separate workspace build. These
receipts cover an intentionally dirty working tree.

The next required work is context generation, questions and editing under the
shared approved allowance, followed by scope review and the remaining complete
journey acceptance. Choosing a revision for one study is now supported; the
broader accepted-context and full product-parity milestones remain open.


### Budgeted context generation through the study and campaign queue

`campaign:context-study` now compiles one repository-wide, source-only
`threat-model:build` job without calling a provider. Shared preparation freezes
its model, source content identity (including the Git revision where available),
configuration, generation limits and explicit prompt text. The initial action
uses `pipeline=single`, `seedMode=fresh`, a new lineage and `activate=false`.
Scope overrides, external seeds, staged work, automatic variants and activation
are rejected for this plan. Context work allows one attempt; another generation
requires a new draft and explicit approval under the same investigation.

The existing allowance approval accepts the context plan and authenticates its
exact digest, single job, model, source and input. Shared dispatch and the existing
campaign dispatcher consume its admitted attempt and provider calls. Context
calls use the Context category and cannot spend protected Review/Report calls.
The real generator integration test uses a mocked provider, produces a usable
immutable DFD/context revision, leaves the active context unchanged, refuses a
second attempt, recovers the run-associated revision, and approves a subsequent
three-pass scan plan without resetting the consumed call. Unavailable price
remains unavailable after that approval. This is execution evidence for the
new planning tool; the registry matrix records the narrow proof separately from
unverified live model quality and the remaining per-tool audit.

In the study context browser, `g` opens generation planning; `t` and `r` edit
total and protected calls. Enter prepares the plan, then reviews its allowance,
then opens its approved job. The existing campaign `L` launch remains separate.
The summary shows the job bounds, selected model, source identity, generation
limits and coverage uncertainty. Tab shows formatted exact options. Approval
returns to the newly available action. Context review reopens with `a` after
restart; completed jobs resolve only the immutable revision associated with
that run. Inspection and selection for scanning remain explicit. Numeric input,
paging, return navigation and background completion preserve the operator draft.

Final sequential J66 evidence is
`/tmp/kuzushi-bounded-investigations-tui/20260910-031455/J66/`: 26 machine checks
and all 12 recorded manual screen reviews pass. The journey covers all six
viewports, exact options, paged approval, the separate launch affordance and
restart with no color. Its real saved plan has one job, one worker and one
attempt; its allowance has five total calls and two protected review calls.
It starts zero jobs and makes zero provider calls. No live test allowance was
used. The earlier `20260910-030212/J66` failure is preserved with all nine manual
judgments: approval left the old scroll offset hiding the next action, and
minified options crowded the summary. The final captures verify both fixes.

Verification: three core context-study tests, 31 allowance tests, three focused
context-generation TUI tests, the earlier 22 batch-scan regression tests,
workspace build, `git diff --check`, and all ten quick summary gates passed.
CRAP-risk passed for 139 changed production files. Logs and the retained
verification receipt are under `.git/bounded-investigations/context-generation-*`.
This is still an intentionally dirty implementation checkpoint, not full TUI
parity or completion of the original delivery plan.

Remaining: connect the initial Setup/Map actions to the same investigation
allowance; add context questions, editing/selective regeneration and explicit
synthesis-cache behavior; make accepted study context drive the corresponding
DFD and scope surfaces; complete AI scope review, finite monorepo execution,
review/learning allowance integration and the full functional tool matrix.
The complete live-model journey still requires an explicitly approved test
allowance. Exploit development, reproducer execution and vulnerability patching
remain outside this work.


### Setup enters the same finite context plan

Setup's model-backed Map selection now opens the context-study form from either
Allowance or Start Map. It freezes one source-only context job and up to two
selected deterministic preparation jobs (`context:build`,
`entry-points:extract`). Exact operator inputs remain visible. Unsupported Map
combinations fail with an explanation before entering the legacy queue. The
shared descriptor/prepared-dispatch path validates every job, while the existing
campaign executor enforces one worker and one attempt per job. DAG metadata is
not credited as execution ordering or artifact-consumption evidence.

Back preserves the Setup selection, row, composer, plan, options and shared
allowance. A late planning completion updates the retained draft without taking
focus. The context form owns Escape before Campaign navigation. The approved
queue names every selected tool and keeps launch separate from approval.
Preparations execute through real shared dispatch in focused integration tests;
the context engine remains responsible for its source grounding, and individual
preparation outcomes are not disguised as successful synthesis.

Sequential J67 evidence is
`/tmp/kuzushi-bounded-investigations-tui/20260910-041224/J67/`: 35 machine checks
and all 16 manual screen reviews pass, across all six supported sizes. Its local
approval contains three jobs, five total calls and two protected review calls;
zero jobs and provider calls start. Actual exit is verified before a fresh
no-color process recovers the exact plan and allowance; the captured ANSI has
no color codes. Earlier attempts are retained as failed or incomplete evidence.
They exposed an invalid `Esc` key spelling in the recipe, a queue that hid tool
names, and relaunch commands typed into a quit prompt instead of a fresh shell.
The harness now requires terminal ownership to return to its shell before
relaunch. Earlier J66 restart claims are not independently strengthened by this
result; its updated recipe still needs a fresh run.

Validation: five core context-study tests, the CLI exact-job/worker integration
test, 28 batch-scan TUI tests, 11 Setup readiness tests, 11 Setup renderer tests,
four notice tests and 13 campaign renderer tests passed. The workspace build,
CRAP-risk gate (149 changed production files), harness contracts and all ten
quick summary gates also passed. The final summary receipt is
`.git/bounded-investigations/setup-context-final-verification.json` (completed
2026-09-10T11:18:33.819Z). These checks cover the intentionally dirty tree, not a
complete live investigation or full product parity.

Remaining: context questions and editing/selective regeneration; explicit
synthesis-cache behavior; accepted context driving its DFD and scope surfaces;
AI scope review and finite monorepo execution; shared review/learning accounting;
and the complete per-tool functional audit. Legacy diagnostic chrome still
needs curation. Full live-model validation requires an explicit test allowance.


### Inspect the selected context through its own data-flow diagram

The study context browser now offers `v` after an exact revision has been read.
It builds the existing DFD projection from that authenticated document, without
reading the active Map as a substitute. The revision label and grounding status
stay visible. Arrows select every component, flow and boundary; Enter opens a
complete, paged detail reader with purpose and linked source evidence. Escape
returns to the same context selection and reading position. Reopening the
reader retains its selected element and detail state within the session.
Selecting context for scans remains a separate action and does not activate it.

The shared diagram renderer now draws one-cell vertical connectors, preserves
upward and reverse cross-zone direction, and counts boundary evidence through
its recorded crossing flows consistently with the detail reader. Read-only
inspection owns its own key hints; the widget no longer promises that Enter
will rebuild context. Empty, unlinked and malformed context states remain
explicit and cannot dispatch generation. Plain output includes every element,
recorded evidence, grounding status and the exact context identity.

Final sequential J68 evidence is
`/tmp/kuzushi-bounded-investigations-tui/20260910-044815/J68/`: 29 machine checks
and all 12 recorded manual judgments pass across all six viewport sizes. Real
offline tool dispatch imports two labeled fixture contexts, reads the inactive
revision, compiles a three-pass study bound to it and recovers that exact
revision after verified exit into a fresh no-color process. The active model
stays different; zero scan jobs and provider requests start. Diagram selection
is retained during navigation, but is not persisted across process exit.

Failed attempts remain retained. They exposed the absent internal arrow,
approximate reverse direction, contradictory boundary evidence counts and
recipe mistakes around prompt aliases and Escape chords. The `044356` run is
explicitly failed by manual review despite all machine checks passing. The
harness now recognizes both module prompt aliases and stops after a failed
submit instead of continuing dependent actions.

Validation: 31 batch-scan TUI tests, 39 shared diagram tests, workspace build,
harness contracts, `git diff --check` and all ten quick summary gates passed.
The final source verification receipt is
`.git/bounded-investigations/context-diagram-final-verification.json`, completed
2026-09-10T11:51:08.310Z. Documentation closeout has its own subsequent docs check.
These are bounded offline interaction proofs. Live model quality and the full
[reference quality bar](../quality/tui-reference-baseline.md) remain unverified.
The broader delivery checklist remains open.

Next: finish generated-context recovery and the accepted Map/DFD bridge, then
context questions/editing/regeneration, AI scope review and finite monorepo
execution, shared review/learning accounting and the remaining per-tool audit.
The full live-model journey still requires an explicit test allowance.
