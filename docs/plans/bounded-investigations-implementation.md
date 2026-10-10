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

October 8, 2026: the module outcome audit corrects suppression prerequisites,
write effects, auxiliary phase ownership and implicit report selection. Native
finding paging now survives its own run bookkeeping while retaining content,
decision and source checks. JSON and Review distinguish suppression from a
human dismissal or refutation. J135 records 14 machine passes, six sizes and
no-color recovery. All ten summary gates pass; narrow detail guidance and
human acceptance remain open. The matrix has qualified evidence for 37 of
109 tools, with 72 still unassigned. See
[review-module-contracts-2026-10-08.md](../assessments/review-module-contracts-2026-10-08.md).

October 8, 2026: prior-study history now loads directly from the resource picker
through the shared background reader. Explicit limits, partial results, failures,
refresh and late completion preserve the draft and selection. J134 records 24
machine checks, six sizes, real narrow paging and no-color cold restart. Evidence
and remaining acceptance are recorded in
[bounded-study-history-2026-10-08.md](../assessments/bounded-study-history-2026-10-08.md).

October 8, 2026: an explicitly selected prior study now supplies frozen per-case
historical spending scenarios for scope studies and context matrices. Exact
conditions and complete receipts are required; unknown cases and prices never
become zero. Approval includes workload, scenarios and available calls. J133
records 23 machine checks with cancellation and no-color recovery. The evidence
and remaining limitations are recorded in
[study-resource-scenarios-2026-10-08.md](../assessments/study-resource-scenarios-2026-10-08.md).
The full journey, live validation and broad acceptance remain open.

October 8, 2026: the maximum nine-boundary fixture executes 27 fixed jobs under
an explicitly revised shared allowance, preserving two Review calls. A separate
Stop experiment retains interrupted attempts and unresolved reservations after
restart. Long job readers retain visible controls and keyboard selection.
The native receipts, observed limits and remaining acceptance are recorded in
[nine-boundary-recovery-2026-10-08.md](../assessments/nine-boundary-recovery-2026-10-08.md).
These owned intercepted experiments do not close the broad delivery milestones.

October 8, 2026: model-backed preparation now has iterative traversal, entry/read
bounds, cancellation, immutable prepared options and honest coverage receipts.
Study review exposes the frozen limits, and Scan/Report retain preparation
warnings without claiming complete repository coverage. Evidence and remaining
scope contracts are recorded in
[agentic-preparation-audit-2026-10-08.md](../assessments/agentic-preparation-audit-2026-10-08.md).

October 8, 2026: the per-tool matrix now includes every audit dimension for all
109 visible tools, keeping missing outcomes pending. Legacy Campaign planning
and progress are Compatibility actions; operational reads preserve analysis
report sources and historical cost cannot become current execution spend.
The defects, fixes and remaining acceptance are recorded in
[operational-module-audit-2026-10-08.md](../assessments/operational-module-audit-2026-10-08.md).
The follow-up history experiment caps reads at 1 MiB and 90 snapshots, preserves
unresolved spending, and makes complete trend labels reachable at 40x12. J124
and the settled J123 regression each record eight machine passes and no failures.
Whole campaign-history enumeration and cancellation remain open; this does not
complete the per-tool audit or the full TUI acceptance.

October 8, 2026: supporting scan context now has an authenticated immutable
binding and historical inspection. A fresh complete investigation experiment
executes actual Map preparation and discovery through the shared boundary,
including explicit spending revision and conservative source reassessment.
The scoped evidence and remaining limits are recorded in
[bounded-investigation-experiment-2026-10-08.md](../assessments/bounded-investigation-experiment-2026-10-08.md).

October 8, 2026: bounded model lesson generation now uses the existing fixed
study approval and durable Learning allowance. The exact original confirmation
and observation are frozen, source captures are bounded, and the one tool-free
response stays a draft. Invalid output has no repair loop. Current lesson records
are preserved by JSON, JSONL, SARIF and Markdown exports; other formats disclose
omission. Exported lesson text cannot enter automatic artifact context.

The native generation and report experiments, live OAuth authentication failure,
verification receipts and remaining limits are recorded in
[lesson-generation-2026-10-08.md](../assessments/lesson-generation-2026-10-08.md).
Live model usefulness, large lesson books, the full module audit, reference
parity and complete investigation acceptance remain open. All nine delivery
milestones retain their existing status.

October 8, 2026: explicit bulk relationship review now captures up to fifty
records, inspects either exact finding generation, collects a reason and
confirms the set before one atomic event. Stale records refuse the entire batch;
finding verdicts and identities stay independent. J117 passes twenty-seven
machine checks and six separate scoped screen reviews, with all ten repository
gates passing. See the
[bulk-review assessment](../assessments/bulk-relationship-review-2026-10-07.md).
Reviewed reusable lessons and complete investigation acceptance remain open.

October 7, 2026: grouped Review now separately discloses selected observation
history and the displayed current generation. A three-run regression confirms
the existing projection retains middle-run membership; no identity or verdict
policy changed. J116 passes sixteen machine checks and five separately recorded
scoped screen reviews, including full narrow-history paging and no-color restart.
All ten repository gates pass. See the
[run-history assessment](../assessments/group-run-history-2026-10-07.md).
This closes one provenance clarity gap; the nine delivery milestones remain open.

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

### Generated-context recovery and honest job outcomes

The current main branch included the earlier recovery implementation. This
checkpoint revalidated it, completed the result presentation and exercised its
real input path through the local terminal harness. Setup now presents a
distinct context result with its exact inspection action and retained allowance,
without repeating preparation guidance after completion. Reading the result
keeps the Setup navigation origin and selects the exact inactive revision for
the next fixed scan plan.

Recovery keeps planned and running work pending. Failed, parked, partial and
unrecognized generation states require inspecting their recorded outcome.
Completed work must have exactly one authenticated revision associated with its
run. Missing, ambiguous or unreadable output cannot appear as another launch.
Replacement preparation is explicit and retains investigation accounting.

The job deck now wraps complete recovery notices, distinguishes missing costs
from known zero charges and offers context-result review after all context jobs
complete. Focused tests cover mixed known/unknown cost receipts and the restored
result surfaces at 40×12, 60×20, 80×24, 96×89, 120×36 and 160×48. Current-state
verification passed six core context tests, 35 batch TUI tests, 20 campaign
renderer tests and the workspace build.

J69 at `/tmp/kuzushi-bounded-investigations-tui/20261004-235128/J69/` records
53 passing machine checks and 16 passing manual judgments. It covers Setup
return, exact result inspection, DFD access, selected-context study compilation,
missing and failed result reading, shared allowance preservation and proven
process exit followed by a fresh no-color restart. Earlier failed runs and
their observed defects remain retained.

This is an offline recovery proof. Its context is a labeled import and its
queue outcomes are injected; no generation or discovery job and no live
provider ran. Actual context synthesis has separate core tests with a mocked
provider. Durable accepted Map projection, context questions/editing, AI scope
review, finite monorepo execution, shared review/learning accounting and the
complete tool audit remain required. All nine delivery milestones stay open.

All ten quick summary gates passed. The source verification receipt is
`.git/bounded-investigations/context-recovery-final-verification.json`, finished
2026-10-05T06:58:01.354Z. Documentation closeout is checked separately after
recording this receipt.

### Accepted Map drives its own diagram and default study context

Map now reads context from authenticated call-correlated run artifacts and an
exact immutable revision. Review, accepted and historical states remain
distinct from grounding status. Missing, corrupt or loading recorded evidence
never substitutes the globally active model. Global context editors retain
their explicit active-model behavior. Pending and accepted Map contexts can be
hydrated together, and background reads do not take focus.

The shared study planner defaults to the accepted current-source Map revision.
The TUI binds this selection before shared preparation can freeze active global
context. Explicit stored or inline revision choices and explicit omission keep
precedence; existing frozen drafts remain unchanged. An accepted Map from prior
source content requires a new acceptance or an explicit context choice. Legacy
recorded documents remain readable without inventing an immutable reference.

Local import results now include their normalized document and indexed source
receipt, enabling authentic Map selection. Their index limits and exclusions
are disclosed in the migration notes; this does not establish deep-tree or
cancellation safety for every source-indexing path. Grounding failure remains
visible even after the operator accepts the context.

J70 at `/tmp/kuzushi-bounded-investigations-tui/20261005-013949/J70/` passed
37 machine checks and all 15 recorded screen judgments. It uses actual offline
imports, TUI Map acceptance, fixed study compilation, exact reads and verified
fresh-process recovery, followed by missing-object inspection at 40×12.
No provider request, generation or discovery job ran. The labeled context fails
grounding and is never presented as a useful generated security model. Earlier
failed captures remain, including a blank resize and a hidden recovery action
that manual review caught after green automated checks.

Focused validation passed authenticated Map-reader tests, actual import and
study binding tests, immutable-object readers, batch preparation, tiny DFD
inspection, six-viewport recovery controls, failure snapshots and the workspace
build. The current canonical-buffer test also passed all 30 phase snapshots;
all six failure-card tests passed after inspecting and updating the two changed
Map snapshots. All ten quick summary gates passed, including CRAP-risk checks,
in `.git/bounded-investigations/map-context-reviewed-verification.json`,
completed 2026-10-05T08:43:19.465Z. The receipt marks the intentionally dirty
tree as drifted, so it is not a clean committed-snapshot claim. Documentation
closeout is checked separately after recording this evidence.

Next required work remains generated campaign context becoming a durable Map
result, context questions/editing/regeneration, reviewed scope proposals and
finite monorepo execution, review/learning accounting, revision-specific finding
decisions and the complete per-tool usefulness audit. Full end-to-end and
reference-quality acceptance remains open. All nine delivery milestones stay
unchecked; live model quality needs an explicitly approved test allowance.

### Generated context enters durable Map review

Completed context campaigns now use the shared `campaign:context-map` handoff.
It authenticates the frozen plan, current source, completed recorded calls and
immutable generated revision before recording one Map attempt for explicit
acceptance. Reopening preserves its identity, interrupted compatibility writes
recover that identity, and discarded or damaged results cannot be recreated.
The TUI offers visible `m Review Map` controls across the six viewport sizes,
refreshes durable phase history before foreground navigation and preserves
background focus and operator typing.

Observed generator testing exposed an inactive-build artifact defect: it
advertised an unwritten active-model mirror. Builds now declare their actual
immutable object and describe inactive persistence honestly. A persistence
failure can also append its mandatory recovery notice without overflowing the
lifecycle preview limit. Map no longer claims no model exists beside an
authenticated recorded diagram merely because global context artifacts are absent.

J71 at `/tmp/kuzushi-bounded-investigations-tui/20261005-023106/J71/` passed
34 machine checks and all 12 separately recorded screen judgments. It proves
generated-result recovery, explicit Map review and acceptance, DFD inspection,
fresh-process no-color recovery, changed-source refusal and exact historical
inspection after dismissing that refusal. The generator and observed artifact
recording are real; its provider is mocked and its completed queue is injected.
The fixture consumes one approved test reservation, never a live provider call,
and starts no discovery work. Grounding and Git revision remain unrecorded.
Earlier failed runs and their judgments are retained.

Focused checks passed 11 core context-study tests, the lifecycle preview-limit
regression, 13 context-generation TUI tests, three handoff/focus tests using
durable history, the recorded-context empty-state regression, all 30 canonical
phase snapshots, the workspace build and harness contracts. All ten quick gates
passed in `.git/bounded-investigations/generated-map-reviewed-verification.json`,
finished 2026-10-05T09:32:00.027Z. That receipt describes a dirty working tree,
not a clean committed snapshot. Documentation closeout follows this entry.

The complete journey remains open. Next work includes automatically retaining
the accepted generated Map's investigation accounting when opening an ordinary
new scan study, then context editing/questions, scope review and finite monorepo
execution, shared Review/Report/learning accounting, revision-specific finding
decisions and the full per-tool usefulness audit. Selecting a context within
its existing study retains that study's accounting; opening a separate generic
scan form still initializes a new investigation and must not become the default
continuation. All nine delivery milestones remain unchecked. Live model quality
still requires an explicitly approved test allowance.

### Accepted Map retains investigation spending for new scan work

Shared prepared dispatch now attaches an authenticated, host-owned allowance reference
to its result envelope. Engine-supplied claims are replaced or removed, and
ordinary engine inputs still exclude governance metadata. Authenticated Map
results can therefore retain their investigation without trusting prompt output.
Legacy results without accounting metadata remain readable and do not invent
earlier consumption.

Ordinary scan forms and shared study preparation now inherit the selected Map's
investigation and latest recorded allowance. A new draft does not approve new
work. Replacing the approved plan advances the allowance revision while preserving
committed and unresolved reservations. Explicit investigation choices remain
available. Missing recorded accounting blocks both scan and replacement-context
drafts instead of presenting a reset allowance.

Explicit replacement Map planning can read historical accounting after source
drift without treating historical context as current discovery evidence. Current
Map selection is refreshed before binding an implicit context. Regression tests
cover changing source while the form is open and canceling replacement-context
generation, so neither path can silently freeze stale globally active context.
Worker previews cannot overwrite the primary continuation refusal. Recovery copy
places the work refusal and restoration action on separate readable lines.

J72 at `/tmp/kuzushi-bounded-investigations-tui/20261005-034035/J72/` passed
44 machine checks and all 14 recorded screen judgments. It covers Map acceptance,
ordinary three-pass planning, separate replacement approval, six viewport sizes,
actual process exit, no-color restart, unchanged-SHA source drift and damaged
approval recovery. Harness status remains `REVIEW_REQUIRED`; separate judgments
and capture hashes are recorded in `manual-review.json`. Earlier failures remain,
including the manually rejected `033146` partial redraw despite green machine
checks. Capture synchronization now waits for the completed form footer.

The generator and observed dispatch are real, with a mocked provider and injected
completed queue. No live provider or discovery job runs. The isolated Git fixture
borrows an existing commit solely as metadata; its worktree differs from that
commit and creates no new commit. Source drift preserves the SHA and dirty flag
but changes the inspected content identity. It cannot authorize a new implicit
study and makes no claim that findings have been fixed. Three jobs are approved
with only two context/scan calls available; this is an accounting and approval
proof, not evidence that all three discovery passes can finish under that ceiling.

Focused validation passed 45 batch TUI tests, 14 core context-study tests, eight
allowance-dispatch tests, seven authenticated Map-context tests, harness contracts
and the workspace build. One explicit fixture-export test remains ignored outside
fixture generation. All ten quick gates passed in
`.git/bounded-investigations/map-accounting-reviewed-verification.json`, finished
2026-10-05T10:32:41.827Z. This receipt describes the intentionally dirty tree,
not a clean committed snapshot. Documentation closeout is checked separately.

The prior default-continuation accounting gap is closed. The complete journey
still needs three fresh discovery executions, aggregation, reversible triage,
reporting and recovery under approved limits. Context editing and questions,
scope review and finite monorepo work, shared Review/Report/learning accounting,
revision-specific finding decisions, context experiments and reviewed lessons,
the full per-tool usefulness audit and reference-quality interaction acceptance
remain open. The narrow budget disclosure and repeated error prefixes still
need polish. All nine delivery milestones remain unchecked. Live model quality
requires an explicitly approved test allowance. No source commit or push ran.

### Three fresh discovery passes reach triage, report and restart

Approved finite campaigns with call limits and no dollar ceiling now continue
when dollars are unpriced. Every job must have authenticated work approval;
shared runtime admission still reserves each request, including internal turns
and retries. A dollar ceiling continues to require usable dollar evidence.
Unknown scan totals are unavailable rather than zero or a fabricated lower bound.

The scanner now includes accepted architecture-only context in its bounded
threat-model digest: nodes, flows, boundaries and open questions, with twelve
entries per section and two hundred characters per field. Omissions are named.
Three real fresh discovery processes receive the same immutable generated Map
revision without changing or reading another globally active threat model.

The batch controller writes an unselected durable Scan attempt after execution.
Completion, partial work and source drift remain distinct; retrying receipt
publication is idempotent and cannot accept an attempt. Parent-run identity is
preserved. Authenticated Scan results connect their engine observations to the
journey count, so two findings no longer become a false clean Scan or a zero-count
Report. Every parent receipt contributes to the resting Scan page. Its two
distinct findings, two additions and one update remain separate. Missing or
damaged receipts cannot silently contribute only the final pass.

Campaign reading supports PgUp/PgDn at 40x12 without changing job selection.
Pasting from Navigation transfers ownership to the composer, retains its cursor
and draft, and still requires Enter. Refresh recovers external Scan history
without moving focus or automatically selecting the result.

J73 at `/tmp/kuzushi-bounded-investigations-tui/20261005-052517/J73/` passed
53 machine checks and all 15 separate recorded screen judgments. It completes
generated Map acceptance, revised allowance approval, three fresh scans,
aggregation, smallest-viewport paging, explicit Scan acceptance, human
false-positive and deferral decisions, JSON export, actual exit and no-color
restart. The raw harness remains `REVIEW_REQUIRED`; judgments and hashes live
in `manual-review.json`. Earlier failures remain, including a machine-green
partial Report redraw that was manually rejected. Report capture now waits for
its completed footer. No-color restart uses attributes without color sequences.

The scanner, dispatcher, transport admission, observation import and local
export execute through the real paths. Provider transport is intercepted and
findings are labeled synthetic. Generated Map still uses a mocked provider and
injected completed context queue. One context call plus three discovery calls
remain committed within six total calls, preserving two review calls. This
does not establish live scan quality, source grounding, monorepo scope
enforcement, complete module functionality or revision-specific fix evidence.

Focused checks passed four authenticated Scan-result tests, parent/engine
finding-membership and damaged-receipt recovery, eighteen Scan projection tests,
the unpriced-cost label, eighty-six phase view-model tests and eighteen renderer
contract tests. The renderer checks include 120 phase/viewport/profile buffers,
thirty canonical snapshots and plain output across all six widths. The workspace
build and CRAP-risk gate passed. All ten quick gates passed in
`.git/bounded-investigations/study-reviewed-verification.json`, finished
2026-10-05T12:20:32.461Z, on a dirty working tree. Documentation and new failure
journey closeout are checked separately.

Next is actual allowance refusal with partial discovery and protected review,
followed by cancellation/recovery, context editing and questions, visual scope
review, finite monorepo execution, context experiments, reviewed lessons,
revision-specific finding decisions and the full per-tool usefulness audit.
Reference-quality interaction acceptance remains open. All nine delivery
milestones remain unchecked. No live provider, source commit or push ran.

### Allowance refusal retains source evidence and reaches partial review

J74 now exercises a real admission refusal under fully intercepted transport.
With one context call already committed, five total calls and two protected
review calls admit only two of three discovery requests. The third job remains
failed, its work attempt remains consumed and no third provider fetch occurs.
Approval shows retained commitments and net discovery/review capacity before
the operator approves this fixed work. No allowance is silently increased.

The first run exposed a recovery defect: an executor error dropped the source
snapshot captured before discovery, making the partial Scan unselectable on a
dirty or unversioned target. Source-bound errors now carry that host evidence
through shared observed settlement. Failed, canceled and interrupted status is
preserved. No source is recaptured after failure to make old work look current;
content drift and tampered result artifacts still block reuse. Existing public
error behavior and runtime failure categories remain intact.

The operator must explicitly acknowledge the partial Scan. The Navigation
footer displays `u Acknowledge & use partial`. One retained synthetic finding
then reaches a human false-positive decision, local JSON finding export, actual
exit and no-color restart. Three calls remain committed and two review calls
remain protected. Failed discovery is not automatically retried.

`/tmp/kuzushi-bounded-investigations-tui/20261005-055219/J74/` passed 51 machine
checks and seven separate recorded screen judgments. Raw `REVIEW_REQUIRED`
remains unchanged. The earlier failed run and its failed source-recovery
judgment are retained. The provider answers and findings are synthetic. Map
generation uses a mocked provider and a completed context queue fixture. No
live provider, source commit or push ran.

Focused verification passed three source-snapshot tests, five terminal
settlement tests, four approval accounting tests and seven six-viewport approval
reader tests. The workspace build passed; the CRAP-risk gate passed for 94
changed code files. The module matrix records this limited real executor
evidence without assigning full readiness or changing maturity.

Partial Scan still uses an honest but noisy degraded receipt layout. Finding
exports do not yet contain the full investigation coverage and allowance
receipt. Those remain product gaps alongside cancellation/recovery, context
editing and questions, finite monorepo scope review, experiments, reviewed
lessons, revision-specific decisions and the full per-tool usefulness audit.
All nine delivery milestones and reference-quality interaction acceptance
remain open. Repository summary verification is recorded separately.

All ten quick gates passed in
`.git/bounded-investigations/study-limit-summary-verification.json`, finished
2026-10-05T13:03:33.157Z. The receipt marks the tree dirty and drifted; this is not a clean committed
snapshot or the full CI matrix. Earlier failed receipts remain available.
Closeout repaired two test-only guard conflicts: the synthetic scanner sentinel
is assembled at test time with the existing fixture digest pinned to exact
bytes, and allowance test setup names its explicit model as a test constant.
Eight secret-check tests and the existing production scanner lifecycle fixture
pass. These repairs do not change runtime/model policy. Documentation closeout
is checked separately after recording this receipt.

### Selected-study reporting survives partial work and restart

Report now loads the selected study from authenticated Scan references through
the shared workspace application service. It does not depend on visiting
Campaign first. `s` explicitly selects study or workspace history; `p` reveals
the frozen source, context, configuration/prompt references, coverage limitations
and export receipt. Loading or damaged study evidence blocks export until ready
or until the operator explicitly selects workspace history. Draft, destination,
format and return origin are preserved. Study facts precede long paths, and the
process-local session-cost sidebar is omitted from this durable reporting view.

The descriptor-backed `campaignId` option and CLI `--campaign-id` select only
authenticated attempt observations. Safe finding projection is shared with
Review, including historical weak/strong generations and merged evidence.
The first terminal run exposed a count mismatch between Report and Review;
the repaired regression also protects distinct weak observations from merging.
Human review completeness remains separate from repository coverage.

All six formats write a version-1 investigation receipt with fixed work,
recurrence, observation run references, source identities, accepted context,
configuration and prompt digests, human review counts and shared allowance.
JSON, JSONL and SARIF embed it; Markdown links and hashes it. CSV and external
scanner rows retain their public contracts. Historical approval can be inspected
after later work without granting execution authority or refunding consumption.
Unknown observed dollars serialize as null in this report-only receipt. The
exporter declares Report rather than Map and starts no model or follow-up work.

J75 at `/tmp/kuzushi-bounded-investigations-tui/20261005-070922/J75/` passed
72 machine checks and 21 separate recorded screen judgments across all six
sizes, with actual exit and direct Report recovery after no-color restart.
Earlier failed judgments remain, including the count mismatch, conflicting
wide-screen budget sidebar and unsettled resize capture. Raw
`REVIEW_REQUIRED` is preserved alongside `manual-review.json`. The real scanner,
controller, admission, import, review and exporter execute with intercepted
provider responses. No live provider, source commit or push ran.

Focused checks passed three report-service tests including shared prepared
dispatch and alias normalization, the six-format/manifest check, historical
allowance reporting, six safe-identity tests, five workspace-tool tests, fourteen
CLI export tests and 125 TUI tests selected by report behavior. Workspace build
and the CRAP-risk gate passed. All ten quick gates passed in
`.git/bounded-investigations/report-reviewed-verification.json`, finished
2026-10-05T14:10:40.775Z. This is a dirty, drifted working-tree receipt, not the
full CI matrix. The earlier failed wording check remains recorded. Documentation
closeout is checked separately.

The receipt does not yet bundle all raw artifacts or describe complete
inventory/engine omissions and actual provider prompt context. Human decisions
remain ledger-wide rather than source-bound; export aliases and review order
are relative to their selection. Partial Scan needs a calmer presentation.
Cancellation/recovery, context editing and questions, visual scope review,
finite monorepo execution, experiments, reviewed lessons and the full per-tool
usefulness audit remain. All nine delivery milestones and complete reference
interaction acceptance remain open.

### Selected capability preparation and reliable input ownership

The capability picker now keeps its preparation hint attached to the selected
action. Shared registry input preparation and runtime policy honor stored
deterministic options and explicit tool-model selection without fallback.
Missing target, model or required input are visible; other actions ask for
review rather than claiming readiness from registration or model selection.
Only the selected action's input is checked during projection.

The live terminal audit exposed conflicting input ownership: the footer said
Esc entered navigation while the contextual picker closed instead. Empty
composer arrows and Enter now select and load directly. A nonempty draft keeps
editor keys, and Esc clears the draft before returning from the picker. Loading
states that no work started. Cancellation remains the first active-work control.
Clearing the draft and resizing retain the selected action. Explicitly reopening
`modules` retains its existing reset behavior.

J76 at `/tmp/kuzushi-bounded-investigations-tui/20261005-075324/J76/` records
22 machine passes and nine separate passing screen judgments at all six sizes
and after actual exit/no-color restart. Text/ANSI hashes and dimensions are in
`manual-review.json`; raw REVIEW_REQUIRED and earlier failures remain intact.
No recorded tool runs or live provider calls occurred. Focused catalog tests
passed 78 cases, footer tests passed 27, and the added draft-clear assertion
passed separately. Workspace build and the CRAP-risk gate passed.

All ten quick gates passed in
`.git/bounded-investigations/readiness-reviewed-verification.json`, finished
2026-10-05T14:59:00.031Z. The initial receipt and focused architecture diagnostic
retain the documentation wording failure. This remains a dirty working-tree
receipt and excludes the full CI matrix; documentation closeout is separate.

This is preparation guidance, not a completed functionality audit. External
dependency and prerequisite inspection, supported target and scope evidence,
credential/allowance readiness and useful phase-to-phase module output still
need per-tool evidence. The source-bound decision, scope-review, cancellation,
context-editing, experiment and learning gaps above remain. All nine delivery
milestones remain open.

### Scoped discovery must match approved work

The module audit found native file selections silently becoming parent-directory
scans and delegated memberships being dropped. Shared preparation now refuses
unsupported scopes before study publication. Native directory roots use the
existing containment/symlink invariant; outside-root and parent-traversal
finding paths cannot become apparently in-scope evidence. Execution checks
membership again. Whole-repository discovery remains an explicit separate plan.

The [per-engine scope audit](../assessments/discovery-scope-2026-10-05.md) records
what was actually exercised and what remains unverified. Eight guard tests
include real source-only secret discovery and consumable persisted findings;
ten runner tests, five path tests, six delegated adapter tests and three
context/source-drift regressions pass. Scope preparation avoids subprocess
availability probes on the TUI thread. The
workspace build and CRAP-risk gate pass. J77 at
`/tmp/kuzushi-bounded-investigations-tui/20261005-083800/J77/` has 19 machine
passes and nine passing screen judgments, including six sizes, 40x12 paging,
actual exit and no-color restart. Planning starts no scan jobs or provider calls.
Earlier recipe failures and the canonical temporary-path test failure remain
in their own evidence.

This remains partial module functionality evidence. Model-tool/MCP access
isolation, per-engine coverage and scope enforcement, directory-specific
prerequisites and the first-class scope editor still need work. No module is
retired or promoted from this evidence. All nine milestones remain open.

Final source verification for this increment passed all ten quick gates in
`.git/bounded-investigations/scope-final-verification.json`, finished
2026-10-05T15:38:45.544Z. This remains a dirty working-tree receipt,
with later documentation closeout separate and the full CI matrix excluded.

### Retained native observations and readable partial coverage

The SAST native path now retains usable observations when an engine reports
coverage errors. Each engine and selected directory has a version-1 coverage
receipt, authenticated with the run artifacts. Partial native runs persist
their findings and never resolve older findings because they disappeared.
Independent engines retain their separate outcomes. Public scalar callers
still receive a coverage error after observations are retained; existing
`ScanRun` fields and finding formats remain unchanged.

The [native coverage audit](../assessments/native-partial-coverage-2026-10-05.md)
separates scripted adapter evidence, real permission denial and installed
Semgrep evidence. Descriptor-backed local rule and executable options feed
the same prepared dispatch. An intentionally incompatible rule produces an
actual omission report alongside one labeled source observation. Unreadable
source identity still blocks before discovery. The tested malformed source
did not produce parser errors, and no parser-gap success is claimed.

The TUI now gives recorded partial engine evidence the available reading area,
uses a compact pending receipt, wraps omission details and preserves readable
acceptance controls. Page ranges disclose overflow; actual result keymaps page
the evidence without accepting it or changing the composer draft. Guided
failure cards retain their space. The selected receipt wraps partial
acknowledgement after restart.

J78 at `/tmp/kuzushi-bounded-investigations-tui/20261005-101159/J78/` records
25 machine passes and 10 separate passing screen judgments across all six
sizes, 40x12 PageDown, explicit human review, settled Report and actual exit
with no-color restart. One native job and zero live provider calls are verified.
The report is a preview, not an export. Raw `REVIEW_REQUIRED`, failed runs and
their separate judgments remain intact. Text/ANSI/native hashes and actual
dimensions are in `manual-review.json`.

Focused verification passed 389 core scan tests, 32 result tests, 88
phase-cockpit tests, six canonical failure-card tests and 21 result-keymap
tests. The final Scan receipt-wrapping check passed eight tests. Workspace
build and the CRAP-risk gate passed. All ten quick gates passed in
`.git/bounded-investigations/partial-acknowledgement-quick-verification.json`,
finished 2026-10-05T17:13:53.651Z. This is a dirty, drifted working-tree receipt,
with documentation closeout separate and the full CI matrix excluded.

Fatal engine errors, cancellation and later static-indexing failure still need
retention work. Standalone native modules need their own scope, lifecycle,
resource and interface evidence. Native tests do not certify accepted-context
isolation. Source-bound decisions, complete coverage export, scope review,
finite monorepo execution, context editing, experiments, reviewed lessons and
the full per-tool usefulness audit remain. No module is promoted or retired;
all nine delivery milestones and complete reference interaction acceptance
remain open.

### Standalone native truth and source binding

The same module audit found standalone Semgrep and CodeQL returning completed
envelopes and findings lifecycles despite reported omissions. Both now return
and persist partial outcomes. Shared finding commits retain measured deltas,
including empty partial observations, and reject unsupported status inputs
before writes. Both executors reuse the existing source snapshot guard before
discovery so a current-source selection has authenticated identity. Full
reported omissions remain in the result; recorded summaries add a bounded
preview beside the primary reason.

J79 at `/tmp/kuzushi-bounded-investigations-tui/20261005-105209/J79/` records
22 machine passes and nine separate passing screen judgments across all six
sizes, actual 40x12 paging, explicit acknowledgement, human review, settled
Report preview and actual exit/no-color restart. One installed Semgrep job
uses explicit local rules; no extra scan jobs or model calls run. Failed
predecessors and raw REVIEW_REQUIRED remain unchanged. Their recipe errors
do not establish DAG execution ordering. Capture hashes, dimensions and the
native binary digest are in the separate `manual-review.json`.

Focused checks passed 88 native-module tests, 389 scan regressions, one
finding commit-status guard, three source-guard tests and nine run-receipt
tests. Workspace build and the CRAP-risk gate passed. All ten quick gates
passed in `.git/bounded-investigations/standalone-native-final-verification.json`,
finished 2026-10-05T17:51:17.743Z. This is a dirty, drifted working-tree receipt;
documentation closeout is separate and the full CI matrix is excluded.

CodeQL evidence is a report-adapter fixture, not an installed analyzer run.
J79 does not certify useful default coverage, scanner precision, accepted
context inheritance or a report export. Standalone scope membership, native
resource limits, cancellation, source-drift ledger settlement and full
interface parity still need work. Source-bound decisions and the broader
scope/context/experiment/learning work remain open. All nine milestones remain
unchecked, with no maturity promotion or retirement inferred.

### Stopped native plans retain observations and readable recovery

The [native audit](../assessments/native-partial-coverage-2026-10-05.md) now covers
fatal native errors, real cancellation and later indexing failure. Earlier
observations that passed scope checks persist before indexing. One fixed list
records completed, stopped and unstarted jobs; no remaining job starts after a
failure. Failed/canceled/interrupted runs never reconcile disappearance.
SAST and shared terminal settlement retain authenticated findings counts, phase
stages, native coverage and source identity. New native schema-2 receipts have
explicit dispositions; the updated reader preserves legacy schema-1 omissions.
Public scan fields and unrelated terminal digest seeds remain compatible.

The TUI audit exposed guided-result input swallowing advertised coverage paging
and cancellation showing a failed engine. Paging now works without changing the
draft or accepting the result, and unfinished canceled engines show stopped.
Report history reuses the cached Scan projection to disclose the displayed
attempt, source freshness, scope and omitted work. Full coverage export remains
a separate requirement.

J80 at `/tmp/kuzushi-bounded-investigations-tui/20261005-120452/J80/` records
20 machine passes and 12 separately judged passing captures. Failed results
are readable at all six sizes, and actual 40x12 paging exposes unstarted c.
Actual cancellation retains one finding, leaves the shell open and never starts
c. Report preview and real exit/no-color restart preserve this truth. Two plans
are separately initiated; each approves three scopes and only invokes a/b.
Installed Semgrep analyzes a with a local labeled rule, while b uses an explicit
stop seam. Zero live provider calls run. The fixture is unversioned; authenticated
content is not Git SHA transition evidence. No human decision or export occurs
in this journey. Raw REVIEW_REQUIRED and failed predecessors remain intact;
actual dimensions and text/ANSI/native hashes are in `manual-review.json`.

Focused native, shared dispatch, lifecycle, terminal digest and TUI checks passed.
The final TUI checks cover 22 result-key tests, 14 Scan projections, three report
receipts and five Report renderer cases. Workspace build and the CRAP-risk proxy
passed. Quick verification is recorded separately in
`.git/bounded-investigations/native-stop-tui-final-verification.json`: all ten
gates passed at 2026-10-05T19:10:08.628Z. It records a dirty working tree and
the conservative drift flag, excludes full CI, and precedes documentation
closeout.

Standalone aborts, persistence faults, later delegated-failure receipt
propagation, source-drift ledger settlement, native resource limits and useful
default coverage need further evidence. Accepted-context isolation, source-bound
decisions, full coverage export, scope review, context editing/experiments,
reviewed lessons and the complete module audit remain. All nine milestones stay
unchecked. This work does not certify full reference interaction parity or
promote/retire a module.


### Checkpoint: source-bound scope revisions and native scope review

Scope proposals now use versioned immutable inventory/revision objects and the
existing strategy queue as their mutable head. Shared `pack:scopes` dispatch
supports create/read/edit/accept/file paging without a model or Map completion.
Coverage validates all literal membership, keeps loose root files visible,
requires explicit limitation/overlap/exclusion acknowledgement, and refuses
uncovered or unbound included source. Scope edits preserve exact history and
failed publication cannot make an orphan acceptance consumable. A newer draft
does not invalidate an earlier committed acceptance; scan consumers must bind
an exact accepted reference and recheck source. Changed Git SHA with identical
files is covered in an isolated fixture test. No finding is declared fixed from
a later pass or revision alone.

The [scope review assessment](../assessments/scope-review-foundation-2026-10-05.md)
describes the initial `scopes` TUI, visible actions, shared field editing,
acceptance controls, source receipts and membership paging. Native J81 at
`/tmp/kuzushi-bounded-investigations-tui/20261005-142100/J81/` has 23 machine
passes and 14 separately judged passing captures. Actual resize covers
160x48, 120x36, 96x89, 80x24, 60x20 and 40x12. Multiline paste, loose root
membership, exact acceptance, retained source-stale edit and no-color restart
are driven through the native binary. Input ownership fixes prevent a hidden
catalog or exit guard from conflicting with the visible scope surface. Driver
failures and raw REVIEW_REQUIRED remain intact. The fixture's SHA is unavailable;
this journey proves content drift and recovery rather than SHA transitions.

Final receipts record 35 focused core scope tests, 11 scope-named TUI tests,
two command contracts, ten paste regressions, 12 native CLI cases, workspace
build and CRAP proxy success for 212 changed files. All ten quick gates passed
in `.git/bounded-investigations/scope-review-tui-quit-final-verification.json`
at 2026-10-05T21:20:50.295Z, before documentation closeout. Dirty/conservative
source-drift flags are recorded and full CI is excluded. Zero live model calls
and zero scan jobs run in this increment.

The shared source-identity walk still needs iterative traversal, lock-wait
cancellation and deep/wide performance evidence. AI scope proposals, inherited
scanner context, fixed logical-scope study compilation, complete module audit,
context experiments, reviewed lessons and full investigation export remain.
Every milestone stays unchecked. No commit or push is performed.


### Checkpoint: bounded source identity and cancellable scope history

The [source traversal assessment](../assessments/source-traversal-2026-10-05.md)
records the iterative source walker shared by hash-only identity and blob
indexing. It guards repository containment, repeated directory visits and an
additional million-entry ceiling, while preserving source membership and
content hash serialization within the limits. Entry limits include empty
directories and ignored entries. Read chunks and lock acquisition honor the
existing cancellation signal. Actual captured bytes consume the remaining
aggregate allowance, including growth during a read.

Scope opening and refresh now use descriptor-backed `pack:scopes latest` in a
background worker; the previous synchronous latest-head helper could freeze the
TUI while another process held the proposal ledger. Exact reads, paging, mutation
and inventory also use cancellable ownership. An actual canceled tool event now
clears the pending scope overlay and preserves the draft, without automatic retry.

J82 at `/tmp/kuzushi-bounded-investigations-tui/20261005-151131/J82/` records
11 machine passes and six separately judged passing captures. Real lock holders
remain live during cancellation, the shell remains usable at 120x36 and 40x12,
and explicit recovery keeps a 300-level/128-sibling fixture in one whole-repo
scope. No provider calls, scan jobs or additional proposal revisions are created.
Failed native and small-stack predecessors remain. Raw REVIEW_REQUIRED is not
rewritten into a machine pass.

Evidence includes 46 incremental-index tests (nine new traversal cases), eight
lock-matched tests, 38 scope tests, three source-binding regressions, 13
scope-named TUI tests, an actual canceled scope-event regression and the existing
SAST cancellation regression. Workspace build and CRAP proxy pass. All ten quick
gates pass in `.git/bounded-investigations/source-scope-final-verification.json`
at 2026-10-05T22:11:26.432Z, before documentation closeout. The dirty and
conservative drift flags remain disclosed; full CI is excluded.

Logical-scope study compilation, source/context binding per job, budgeted AI
scope proposals, full module usefulness audit, context experiments, reviewed
lessons and complete coverage/report acceptance remain. Platform and large-scale
source performance still need evidence. No milestone is marked complete.

### Checkpoint: accepted file membership and single-scope study handoff

The [exact-scope assessment](../assessments/exact-scope-discovery-2026-10-05.md)
records `scanScopeRef` through shared prepared dispatch, full immutable membership
resolution, exact-file secret/Semgrep execution, honest coverage and source-drift
refusal. Existing version-1 studies repeat one selected boundary with a fixed job
list and bind its reference into equivalence. Other scopes are not scheduled.
Unsupported adapters refuse work; model-backed exact-file discovery remains open.
The public `ScanRunOptions` layout and legacy directory behavior are preserved.

The owning scope surface supplies the reference through **Plan selected scope**
and `p`. No JSON reference editing is required. Three passes and one worker remain
the defaults, engine choices are preserved and Back restores scope reading state.
Source authentication runs in the campaign worker. Saved Scan receipts direct
reruns to review original owner options rather than an empty engine command.

Final J83 at `/tmp/kuzushi-bounded-investigations-tui/20261005-170335/J83/` has
23 machine passes and eight separate passing screen judgments. It covers six
viewport sizes, actual narrow paging, one real installed-Semgrep scan over literal
selected files, refusal after source drift, actual exit and no-color restart.
Three planned study jobs remain unstarted. Zero live provider calls occur. Native
SHA transitions are not claimed; the focused scope suite separately tests changed
Git revision with unchanged content. All failed predecessors remain available.

Focused tests, workspace build and CRAP proxy checks pass. The ten quick gates
pass in `.git/bounded-investigations/exact-scope-final-verification.json`, with
dirty/conservative drift flags and full CI excluded, before documentation closeout.
The phase contract's plain-output check passes after replacing its empty-input
rerun expectation. No commit or push is performed.

Multi-scope job/recurrence semantics, scoped model tool access, inherited context,
native resource estimates, study engine selection, less verbose receipts, full
per-tool audit, AI proposals, context experiments, reviewed lessons and complete
coverage/export acceptance remain. Every milestone stays unchecked.


October 5, 2026: study engine selection is implemented and locally verified.
The visible picker edits a study-local engine draft, explains unsupported exact
scope contracts, preserves source/context/custom options and investigation
accounting, and keeps the existing plan when choices are unchanged. It has
complete narrow-screen paging, paste ownership and no-color restart evidence.
J84 passes 29 machine checks and eight separate screen reviews; the raw harness
remains `REVIEW_REQUIRED`. Eight focused selector tests and two shared core
planning tests pass; the wider study run passed 54 tests before final copy
cleanup. Workspace build and the CRAP-risk proxy pass. The audit inventory now
matches 97 visible registry tools, with functional outcome dimensions explicitly
pending. No discovery or provider work starts in this increment. The
[selector assessment](../assessments/study-engine-selector-2026-10-05.md) records
captures, retained failures and limits. All nine delivery milestones remain open.

The selector checkpoint's ten-gate quick summary passes in
`.git/bounded-investigations/study-engine-final-verification.json`, finished
`2026-10-06T01:09:19.478Z`. Dirty source and conservative drift remain explicit;
full CI and live-model acceptance remain open. The final documentation closeout
is checked separately.


October 5, 2026: live-model preparation exposed and fixed stale OAuth client
construction and missing context-job failure details. The bridge rejects expired
credentials after failed refresh, campaign readers surface a matching terminal
run's bounded safe error, and count reads reject escaped run paths. Context
planning now labels output tokens as requested; the OAuth adapter cannot enforce
that ceiling. The [OAuth recovery assessment](../assessments/oauth-preflight-context-recovery-2026-10-05.md)
records 167 adapter tests, five projection tests, existing count/recovery
regressions, thirteen TUI context tests and J86's 23 machine checks plus five
separate screen reviews. Workspace build, CRAP risk and all ten quick gates pass.

The actual GPT-6 Luna OAuth test remains pending the operator's exact request
allowance. The isolated test credentials and frozen source-only job are prepared;
no live inference has run. All nine delivery milestones remain open.

October 5, 2026: conflicting saved path filters have a visible study-local
repair. It preserves global settings and accounting, cancels reversibly and
requires a new plan. Eleven focused tests, workspace build and CRAP risk pass.
J87 records 28 machine checks and five separate passing screen reviews across
six sizes, actual paging and no-color restart. No scan or model work starts.
The [recovery assessment](../assessments/scope-filter-recovery-2026-10-05.md)
retains the earlier fixture failures and small-screen defect. Milestones and
live-model acceptance remain open.
All ten quick gates pass in
`.git/bounded-investigations/scope-path-filters-final-verification.json`, with
dirty/drift flags and full CI excluded, before documentation closeout.


### Optional scope proposal and live validation update

The existing context-study machinery now supports one `pack:suggest-scopes` job.
The TUI has a multiline priority editor, explicit context omission, model-picker
origin recovery, shared allowance review and separate boundary acceptance. The
executor reuses the bounded inventory, validates model membership, retains
operator exclusions and records immutable generation provenance. Descendant
scope revisions retain the proposal's accounting. Multi-scope orchestration and
live scope usefulness remain open.

A real sequential OAuth test used GPT-6 Luna with low reasoning and an approved
eight-request limit, including two protected Review requests. Context generation
failed after one schema repair, consuming two calls. A fixed three-pass scan
completed one pass with no findings and stopped the other two at the allowance
boundary. Six calls remain recorded; two Review calls are unused. No context
was accepted and live triage was not exercised. A partial report preserves these
limits and the source fingerprint. This is evidence of working request admission,
not completion of the operator journey. All delivery milestones remain open.

### Rejected context output checkpoint

Future single-synthesis context failures can retain a bounded local diagnostic
under the descriptor-owned `saveRejectedOutput` option. New context plans
disclose and freeze the choice. Explicit TUI inspection authenticates input and
content, labels output unaccepted, keeps workflow actions inert and restores the
prior view. Missing or corrupted evidence remains an honest unavailable state.
Historical lost output stays unavailable. Inspection spends no allowance.

The [diagnostic assessment](../assessments/rejected-context-output-2026-10-05.md)
records focused core/shared-dispatch/TUI checks, workspace build and all ten
quick gates. J90 has thirty machine passes and five separate passing screen
judgments across six sizes, actual paging, no-color restart and changed-input
refusal. Its responses are intercepted; no live inference runs. Earlier failures
remain available. The live ledger retains six consumed requests and two protected
Review requests. A separate two-request diagnostic allowance is proposed and
awaits explicit approval. Every delivery milestone remains open.

### Resource preview and cold-start checkpoint

The study surface now retains observed provider requests when dollars are
unavailable. Future estimates require authenticated matching conditions and
complete engine work, include maximum starts, and disclose shortfalls against
the net proposed allowance. The chosen baseline is frozen outside scanner input
and survives restart. Changing it requires a new plan review and preserves
spending. Read-only shared dispatch exposes admitted-run request counts.

The [resource assessment](../assessments/study-resource-preview-2026-10-06.md)
records focused tests, workspace build, all ten quick gates and J91's eighteen
machine checks plus five independent screen reviews. Six sizes, actual narrow
paging, approval cancellation and no-color restart pass. Transport is intercepted;
no live inference runs. Cold headless sequencing also exposed and fixed a missing
shared projection schema stamp. Earlier failures remain. The real live ledger
still has six consumed calls and two protected Review calls. All delivery
milestones remain open.


### Background study usage and older baseline recovery

October 6, 2026: historical usage no longer blocks study opening or refresh.
The shared background reader supplies a disclosed 100-record choice window
and detailed evidence for one selected run. A frozen older baseline remains
readable outside the window; refresh, failure and restart preserve selection,
draft, navigation and spending. No run, allowance or consumption is created
by these reads. Failed readers wait for explicit retry, and visible controls
expose refresh at all supported widths.

Nine core checks, 57 view-reader regressions, eight study-configuration checks,
eight presentation/control checks, workspace build and CRAP-risk pass. J92
records 23 machine passes and five separate passing screen judgments over
six sizes, narrow paging, metadata failure/recovery, approval cancellation and
no-color restart. The initial screen-review failure remains recorded. See
[the usage-loading assessment](../assessments/study-usage-hydration-2026-10-06.md).
This closes the synchronous historical-usage defect, while cold index rebuild
scale, real terminal latency, full module readiness and complete investigation
acceptance remain open. No additional live requests were authorized or made.

### Real Map producer and consumer checkpoint

October 6, 2026: four deterministic Map tools now have real shared-dispatch
producer/consumer evidence in the registry matrix. Flask decorators no longer
inherit a FastAPI label from shared syntax. Catalog facts own the framework
shown by the TUI; older extraction policy requires rebuilding context and
catalog together. Partial deterministic Maps disclose artifact-review-only
limits in the diagram, summary and plain output.

The entry-point gallery now keeps evidence readable at 40x12. Six integration
checks, 84 scene checks, focused regressions, workspace build, CRAP-risk and all
ten quick summary steps pass on the dirty working tree. J93 has 16 machine
passes and four separate passing screen judgments over six sizes, actual
tail paging and no-color restart. Failed predecessors remain recorded. See
[the Map functionality assessment](../assessments/map-module-functionality-2026-10-06.md).
No source execution or additional live requests occurred. Complete module
readiness, real context quality and end-to-end
acceptance remain open. No delivery milestone is closed by this checkpoint.

The follow-up removes standalone artifact inference from Map acceptance while
preserving historical completed scan reading. The entry-point overview now
puts source evidence before detailed provenance, which remains fully pageable.
Forty-five workflow regressions, 85 scene checks, workspace build and CRAP-risk
pass. The final J93 run at `20261006-034301/J93` has 21 machine passes and five
separate passing screen judgments, including unchanged Map acceptance after
actual restart. No further provider requests were made. Complete journey and
reference parity acceptance remain open.

### Existing context and explicit Map handoff

October 6, 2026: an inspected exact context revision can use the existing
`campaign:context-map` dispatch without regeneration or active-context changes.
Its original run and source are authenticated, partial status is preserved,
and acceptance remains explicit. Deterministic build and verification receipts
now carry authenticated snapshots; new imports and verification revisions keep
run attribution. Invalid partial acknowledgement is rejected before persistence.
Explicit context experiments on new source retain historical spending and
require a new finite-plan approval.

Three real admission checks, 104 workflow regressions, nine import regressions,
23 context-study checks, 12 TUI context checks and workspace build pass. J94 at
`20261006-050744/J94` has 18 machine passes and five separate passing screen
judgments over all six sizes, actual 40x12 paging and no-color restart. No jobs
are approved or executed and no provider request occurs. Failed predecessors
remain in the [handoff assessment](../assessments/existing-context-map-2026-10-06.md).
The full real-model three-pass journey, per-tool audit, multi-scope execution,
context experiments and TUI reference parity remain open. All nine delivery
milestones remain unchecked.

### Live context succeeds and reaches Map acceptance

October 6, 2026: the approved two-request diagnostic completed with one real
OAuth request using GPT-6 Luna low. Its draft matches the tiny source fixture
and records unknown reachability. The first failed request and successful
request share the recorded model and prompt fingerprint; success does not
establish reliability. Spending is seven settled requests of ten approved,
with two protected for Review and unknown dollars. No source execution occurred.

Real receipt inspection found that Back lost the completed context form's
origin. The fix preserves result, options, scroll, draft, cursor and allowance;
explicit selection still enters study preparation. Eighteen generation checks,
twelve picker checks, workspace build and changed-code CRAP-risk pass. J96 at
`20261006-113921/J96` has 21 machine passes and seven separate passing screen
judgments across six sizes, actual paging and no-color restart. The exact
context is now accepted as Map while global active context remains unset.

A three-pass plan inheriting that context is prepared but unapproved and
unstarted. Its proposed total allowance is 21, preserving seven spent requests
and two protected Review requests. The old context-omitted study is a different
condition. See the [live context assessment](../assessments/live-context-validation-2026-10-06.md).
All nine delivery milestones remain open, including complete live triage/report,
module readiness, monorepo execution and TUI reference parity.

### Accepted context stays readable and distinct from repository index

October 6, 2026: `main` at `799bfa2870` retains existing commits and pending
changes. The strip now names optional repository-index evidence and preserves
stale/unverified states. Summary shows actual content in tiny panes, sizes wide
descriptions honestly, and shares reading geometry with page keys. Page Up at
the start no longer jumps to the component tree. Fresh-session accounting names
its dollar-cap scope and points to prior usage in Report.

J97 at `20261006-131153/J97` has 32 machine passes and six separate passing
screen judgments over all six viewports, actual narrow paging and no-color
restart. Earlier failures remain recorded. Seventy-one Summary regressions,
five overview tests, eleven rail tests, workspace build and changed-code
CRAP-risk pass. See the
[reader assessment](../assessments/accepted-context-reading-2026-10-06.md)
for final verification receipts and limits. This increment makes no model
request; seven requests and two protected Review requests remain unchanged.
The three-pass plan remains unapproved, and all nine milestones remain open.

### Accepted scope in study reports

October 6, 2026: a study planned from an accepted scope now carries that exact
proposal revision into its investigation receipt and every export that embeds
the receipt. Reports keep the originally accepted boundary after source changes.
Missing scope evidence blocks study export before any file is written, and the
TUI keeps workspace history as an explicit choice. The Report separates the
planned boundary from completed scanner coverage.

Three core prepared-dispatch checks, neighbor report/export suites, 14 CLI
export tests, 135 TUI report tests (seven new scope tests and a damaged-scope
refusal test), workspace build and CRAP-risk pass. J95 at `20261006-061350/J95`
has 48 machine passes, six passing and one failing screen judgment. The failing
judgment records that after a source change Report falls back to workspace
history and cannot select the earlier study; that choice needs a product
decision. No provider request or source execution occurred. See the
[report scope assessment](../assessments/report-scope-2026-10-06.md). All nine
delivery milestones remain unchecked.

Same day follow-up: Report now falls back to the latest selected study after
source drift, labeled as recorded on earlier source, with export available and
the journey rail unchanged. The shell rereads the phase ledger when another
process writes it, so a detached study's Scan result appears without a refresh.
Workspace history names every run of a multi-run attempt. A stale parity test
from the asynchronous usage change was repaired. J95 at `20261006-064359/J95`
has 54 machine passes and nine passing screen judgments. No provider request
occurred and all nine delivery milestones remain unchecked.

### Report boundary audit

October 6, 2026: the three Report tools were audited against the contract.
Four defects were first shown failing and then fixed. A failed receipt write
no longer replaces the previous export, and both files are written
atomically. `report:build` no longer reports a later export or read-only run
as its analysis source. `report:sarif` accepts `campaignId` and embeds the
study's investigation receipt. Every export record now names the run and
source snapshot its latest review decision was made against, and whether the
finding was later seen on different source, without changing stored events.
Related fixes cover typed Scan receipts for earlier-source attempts, capture
ownership of Enter over the capability picker, picker paging with truthful
labels, and degraded rendering instead of panics in scope and context views.
Stale tests in the committed tree were updated with their intent preserved.
See the [Report boundary audit](../assessments/report-boundary-audit-2026-10-06.md).

The live context diagnostic allowance revision (eight to ten requests, two
still protected for Review) was approved through shared dispatch after
revalidating source, plan and ledger. The job itself has not run in this
session. All nine delivery milestones remain unchecked.

### Review decisions retain their source basis

October 6, 2026: the governing human verdict now retains its own recorded source
basis despite later imported assessments. Captured cited-file comparison replaces
the false inference from run-scoped snapshot ids, with missing captures explicit.
Review shows both recorded revisions through a read-only, watermark-bound
background reader. Explicit Enter reveals detail when a narrow viewport hides
it. New decisions retain earlier history; source changes never create a verdict.

J98 at `20261006-144339/J98` has 26 machine passes and four separate passing
screen judgments. Earlier failures remain recorded. Core exports, hydration,
source reader/presentation, layout matrix, workspace build and CRAP-risk pass.
The fixture uses labeled synthetic findings and commit metadata with real
captured benign file versions. It proves product behavior, not scanner precision
or a real Git SHA transition. See the
[source provenance assessment](../assessments/review-source-provenance-2026-10-06.md).
This increment makes no model request. The live allowance and unapproved
three-pass follow-up are unchanged; all nine milestones remain open.

### Capability recovery follows input ownership

October 6, 2026: selected-action guidance now shares modal/plain rendering,
wraps the full recovery command and checks the existing model/auth binding
policy. Explicit deterministic work stays runtime-free. Native failures drove
minimum-body geometry, visible move/load/back controls, deduplicated hints and
the removal of stale Enter promises after draft loading. Targetless browsing
names and reopens explicit target selection.

J99 at `20261006-152837/J99` records 39 machine passes and six separate passing
screen judgments, with raw `REVIEW_REQUIRED` and predecessor failures retained.
Seventy-nine behavior tests, two integration checks, the plain snapshot and
workspace build pass. See the
[capability recovery assessment](../assessments/capability-recovery-guidance-2026-10-06.md)
for final gates and limits. This does not certify credentials, dependencies,
scope, spending or executor outputs. No tier is promoted and no module deleted.
The live experiment is unchanged and all nine milestones remain open.

### Review completion requires source applicability

October 6, 2026: recorded event order now governs decisions despite skewed display
timestamps or newer embedded triage caches. Exports and TUI source detail use
the exact governing record. Later changed or unverified source keeps the retained
verdict in history while reopening current Review work. Source-qualified counts
serve the unfiltered journey and investigation report; JSON and Markdown name
the qualification. Missing or identical dirty metadata cannot prove reuse.

J100 at `20261006-164751/J100` has 24 machine passes and four separate passing
screen judgments, including six sizes, contiguous 40x12 paging and no-color
restart. Its predecessor retains the failed compact-label judgment. Six resolver
checks, 124 workspace application checks, 285 Review checks and the workspace
build pass. See the
[Review completion assessment](../assessments/review-source-completion-2026-10-06.md)
for final gates and limitations. Two failure-state regressions first failed;
all 15 refresh checks pass after retaining terminal decisions in the open queue
and clearing current confirmed counts when source comparison fails.
Historical export filters remain compatible;
dirty/unversioned source reuse, real Git transitions and large-ledger latency
remain open. No model request occurs and all nine milestones stay unchecked.

### Large-ledger Review disclosure and filtering

October 6, 2026: a 1,000-finding experiment found that the 500-row loaded list
looked complete. Review now names loaded/matching populations, qualifies empty
partial subsets and exposes the existing global filter through Ctrl+F in empty
Navigate mode. Composer controls remain intact. The tiny-footer regression
failed before its repair. J101 at `20261006-175449/J101` has 29 machine passes
and five separate passing screen judgments across six sizes and no-color.
All 26 model, 37 keybinding, 294 Review and seven footer checks pass, plus the
workspace build and final snapshot verification. See the
[large-ledger assessment](../assessments/large-review-ledger-2026-10-06.md).
Synchronous refresh measured about 407 ms and individual durable decision writes
about 700 to 800 ms on the debug host; neither cost is optimized by this repair.
Complete paging and responsiveness remain open. No model request occurs, no
tier is promoted and all nine milestones remain unchecked.

### Background Review reads and recovery

October 6, 2026: interactive Review refreshes now use the existing bounded
artifact workers with one pending request and target/query/ledger guards.
Passive updates preserve pending operator intent, and later input prevents a
delayed open action from taking focus. Invalid filters preserve recorded review
progress; a missing previously loaded ledger retains rows and reports the loss.
All 74 focused findings checks pass. The final workspace build, CRAP-risk gate,
30 snapshot references and focused recovery checks pass. J101 at
`20261006-185552/J101` has 33 machine passes and six separate passing screen
judgments. Its predecessor retains the failing progress-reset judgment.
See the [background refresh assessment](../assessments/background-review-refresh-2026-10-06.md)
for the full-suite limitation and evidence. No model calls or target-source
execution occur. Paging, decision-write cost and the complete approved journey
remain open; all nine milestones stay unchecked.

### Complete Review ledger paging

October 6, 2026: shared `findings:list` queries now expose snapshot-bound cursor
windows and apply scope/SHA provenance filters and confidence order before
paging. The shell offers Ctrl+N/Ctrl+P in empty Navigate mode, carries whole-ledger
aliases into list, detail and engagement rail, retains the cursored finding on
refresh, and resets a new query to its first page. Cursors refuse stale or
changed target/query/ledger inputs. Existing report/artifact contracts remain.
The dedicated CLI list is still a first-window surface, and the underlying
query still reads the matching corpus.

Nine Core checks, the legacy filtered dispatch check, 172 focused TUI findings
checks and nine screen-context checks pass. The workspace build and CRAP-risk
gate pass. Native J102 at `20261006-201403/J102` has 30 machine passes, six
passing review judgments and six passing related layout judgments over six
sizes, previous/next navigation, alias opening, draft ownership, filter reset
and no-color restart. Predecessor failures and raw `REVIEW_REQUIRED` reports
are preserved separately from the screen verdicts. See the
[complete paging assessment](../assessments/complete-review-paging-2026-10-06.md).
No provider request, target-source execution or new decision is made. The
fixture receipt checks source hashes and observation/decision counts only.
Decision-write responsiveness, wider scale, real Git transitions, complete
accessibility/platform coverage, accepted lessons and the full approved journey
remain open. All nine milestones stay unchecked.

### Manual decision responsiveness and narrow receipts

October 6, 2026: interactive verdict/dismissal writes now use one bounded worker
with captured target, identity, watermark and session. Pending state stays
separate from durable decisions. Duplicate submissions, suppression during a
save and exit before a result are refused honestly. Later input/target changes
preserve the current view and draft; stale observations or decisions still
reject the old write. Suppression aliases now resolve over the complete ledger,
and their refresh no longer anchors to an excluded row. Explicit unfiltered
opening loads a later finding's page before showing its detail. Tiny receipts
retain full history while keeping the content visible.

Eight worker checks, 182 findings checks, 12 review-decision checks, 28 keyboard
checks and 12 background-refresh checks pass. Workspace build and CRAP-risk
checks pass. Final J103 at `20261006-212152/J103` records 30 machine passes,
six passing ask judgments and five related layout judgments across six sizes,
eight explicit decisions, false-positive reversal and no-color restart.
Six bounded SQLite locks establish input behavior during commit contention.
Raw failures and judgment receipts remain separate. See the
[manual decision assessment](../assessments/manual-decision-responsiveness-2026-10-06.md).
No model request or source execution is made. Journal/query cost, synchronous
suppression, real Git transitions, platform/accessibility coverage and the full
finite investigation/report still need acceptance. All nine milestones stay open.

### Filtered Review selection and external decisions, 2026-10-06

Explicit query/component pins now keep detail and manual decision targets
consistent, retain stale-write protection and release on list navigation.
Current decision history stays independent of the page, including suppressed
pins. Passive missing-anchor refresh recovers once with its filter and a notice;
explicit requests remain strict. Full-ledger progress controls phase access.
Compact wrapped pin text remains complete at 40x12.

Final native J104 records 21 machine passes and separately judged six ask and
six related-frame passes across six sizes and no-color restart. Raw predecessors
retain their failures. The benign fixture receives four total explicit decisions
including the predecessor, with unchanged observations/source. No model request
or source execution occurs. See the
[filtered Review assessment](../assessments/filtered-review-navigation-2026-10-06.md).
This increment does not close any of the nine end-to-end milestones.

### Exact context edits and inactive copies, 2026-10-07

The study browser now edits inspected exact context text and question answers,
preserves session drafts/cursors, reviews before/after changes and saves an
inactive immutable copy through shared prepared dispatch. Original models,
active mirror and recorded source binding stay unchanged. Inspection and study
selection are separate. Context edits clear old verification and cannot alter
evidence or source metadata. Text/object limits and cancellable store ownership
protect this new action; unknown input and wrong targets remain errors.

Final native J105 has 31 machine passes, seven separately judged ask passes and
11 related-frame passes across six sizes, multiline Unicode editing, real copy
saving, exact three-pass draft binding and no-color restart. Labeled fixture
contexts are unverified; no jobs, model requests or source execution occur.
Focused tests and raw predecessors are recorded in the
[context edit assessment](../assessments/context-edit-copies-2026-10-07.md).
Selective regeneration, context experiments/lessons, the complete functional
matrix and full live investigation still need work. All nine milestones stay open.

### Exact context source checks, 2026-10-07

The context browser checks an inspected immutable revision through shared
dispatch, saves an inactive checked revision, and preserves its recorded source
binding. Exact reads compare source identity separately from the stored check.
SHA, content, dirty-state drift and unknown identity remain visible. Source
changes during store waiting refuse publication; post-save changes retain a
partial receipt. Late results preserve active readers and editors and ignore
foreign-target receipts. The bounded keyboard menu fits all six viewport sizes.

Final native J106 records 26 machine passes, six separately judged ask passes
and 12 related-frame passes, including real SHA/content changes and no-color
restart. Its three-pass draft stays unapproved and unstarted. No model requests
or target-source execution occur. Focused tests, raw predecessors and limitations
are recorded in the [source-check assessment](../assessments/context-source-checks-2026-10-07.md).
This does not close any of the nine end-to-end milestones.

October 7, 2026: selected explanatory-text regeneration now uses the existing
context-study plan, shared provider allowance and immutable context store. Human
guidance and model selection preserve draft ownership. Exact parent comparison
leads with before/after text, and source/model/field receipts remain authenticated
through restart and Map consumption. Final J107 records 45 machine passes,
seven reviewed ask passes and 29 related-frame passes over six sizes and a real
no-color restart. It uses one intercepted request and starts no discovery work.
See the [regeneration assessment](../assessments/context-regeneration-2026-10-07.md)
for focused tests, raw failures and limits. Live generation quality and the
complete supported investigation remain pending; all milestones stay open.

October 7, 2026: explicit context candidates now compare one authenticated
historical baseline pass with a separately approved fixed candidate study.
Only context may differ; other source, scope, options, model, runtime, prompt,
engine and tool identities stay fixed. The baseline's investigation and spending
are retained, including failed allowance reads, explicit retry and restart.
Comparisons select actual candidate passes and preserve decisions and navigation.
Candidate repetitions keep their own identical-condition recurrence.

Final native J108 records 35 machine passes, seven separately judged ask passes
and 26 related-capture passes across all six terminal sizes and no-color restart.
The actual SAST executor consumes Alpha then Beta context in six intercepted
requests while Gamma remains globally active. No live request or target-source
execution occurs. See the [context experiment assessment](../assessments/context-experiments-2026-10-07.md)
for focused tests, fault recovery, raw predecessors and limits. Full matrix
permutations, cohort comparison, reviewed lessons, broader functional audit and
complete investigation acceptance still need work. No milestone is closed here.


### Matrix results enter the durable Scan journey

Matrix dispatch now authenticates its completed or partial work through the
report reader and publishes it into the existing Scan journal. It leaves the
result unselected, keeps every recorded run reference and adds no jobs.
Unstarted plans create no attempt. Current source can support acceptance;
changed or unverifiable source keeps observations as history. Ordinary Report
entry then consumes the accepted matrix without combining case recurrence.

The native audit caught and corrected Use Scan advancing to Review and a
bounded artifact-reference count presented as a total. Use preserves the
inferred result page, while Use & Review owns progression. Receipt links and
recorded files now have distinct labels. A stale cockpit assertion follows the
existing pinned-detail contract.

Final J111 at `/tmp/kuzushi-matrix-handoff-20261007/tui/20261007-164533/J111`
has 17 machine passes, six passing screen judgments and 15 live captures across
four sizes and no-color restart. Raw exit 4 and REVIEW_REQUIRED stay separate
from the recorded judgments. The owned, labeled synthetic fixture runs no
executor, provider or target source. Recovery twice preserves nine completed
jobs, one Scan attempt, one explicit selection, six raw observations and the
unchanged fresh allowance. Earlier failed attempts remain retained.

Fifteen report tests, four phase-result tests, three CLI matrix tests, the
selection regression and 89 cockpit tests pass. Workspace build, all ten
quick gates and the risk gate over 207 changed code files pass. See
[matrix Scan handoff assessment](../assessments/matrix-scan-handoff-2026-10-07.md)
for receipts, limitations and the next work. Native partial acknowledgement,
allowance exhaustion and cancellation remain next. All nine milestones stay
unchecked, and this goal remains active.


### Fixed investigations pause at the call limit and recover by explicit revision

The shared allowance snapshot now checks capacity before model-backed executor
entry and during atomic request admission. Fixed dispatch pauses before another
job attempt when discovery capacity is exhausted. Revised authority requires
review; missing accounting fails closed. Unresolved calls remain committed and
runtime-free work can continue without provider capacity.

Native J112 proved two discovery calls under a four-call allowance with two
protected review calls. Seven of the original nine jobs stayed unstarted.
Partial acknowledgement and exact Report survive no-color restart. A reviewed
eleven-call revision exposes seven remaining discovery calls and starts no jobs
by itself. Explicit launch then finishes only those original jobs. There are
exactly nine distinct starts, six observations, one undecided finding and separate
3/3, 2/3 and 1/3 recurrence. No live request or target-source execution occurs.

This audit corrected paused work labeled finished, explicit launch failing to
resume parked work, and unstarted parked trials counted as failures. New reports
count the latter as pending; original state and reasons remain. The final native
receipt at `/tmp/kuzushi-budget-recovery-20261007/tui/20261007-175133/J112`
records 34 machine passes and eight separate passing screen reviews. Raw exit 4
and REVIEW_REQUIRED remain preserved. See the
[budget recovery assessment](../assessments/budget-recovery-2026-10-07.md)
for tests, failed predecessors, pricing limits and source checks.

Cancellation is next: inspect the deck's hard-kill behavior against supervised
job groups, then verify saved stopped work and unresolved reservations using
owned fixtures. Full module, monorepo, context learning and reference-quality
TUI acceptance remain open. All nine milestones stay unchecked.

### Campaign Stop preserves authenticated partial work

The deck now requests Stop through its held child's original campaign and
keeps the shell responsive while the dispatcher settles supervised jobs.
Session identity prevents stale requests from stopping later launches. A
pre-dispatch check prevents another attempt from being claimed after the saved
request. Interruption recovery authenticates the root result, and a new SAST
start-source artifact preserves source authority through process death. Missing
engine details and unresolved reservations remain visible in Report.

Native J113 proves one completed pass, one interrupted attempt and seven
unstarted jobs from the same nine-job plan. The draft survives dispatcher exit,
partial Scan acceptance is explicit, and report/restart retain the observation,
unknown cost and protected review allocation. All transport is intercepted on
owned greeting source. There are seventeen machine passes and six separately
recorded screen reviews across fourteen live frames. Raw REVIEW_REQUIRED and
exit 4 remain unchanged. See the
[campaign Stop assessment](../assessments/campaign-stop-2026-10-07.md).

This closes the bounded campaign cancellation increment, not the complete
investigation or TUI acceptance. Per-tool functionality, wider layout coverage,
monorepo editing and reviewed learning remain open. All nine milestones remain
unchecked and the full goal stays active.

### Reversible relationship review preserves the authoritative ledger

The per-tool audit found `triage:dedupe` rekeying identities and recording
duplicate false-positive verdicts by default. It now proposes separately
versioned relationships. Human accept, reject and unlink operations require a
reason and exact revision; original observations and finding verdicts remain
independent. The single writer refuses stale model candidates against the
latest recorded observation. Legacy rekey behavior remains an explicit advanced
compatibility option, with its migration documented in RELEASING.md.

Shared prepared tools, asynchronous TUI reading/writing and additive report
metadata are implemented. J114 verifies these on owned, labeled synthetic data
with intercepted provider transport. See the
[relationship assessment](../assessments/reversible-relationships-2026-10-07.md)
for final receipts, retained failures and limitations. Accepted groups do not
yet collapse the Review list or supply reviewed reusable lessons. Large-ledger
candidate loading, full module readiness and the full journey remain open.
All nine milestone checks remain unchanged.

### Complete source-bound group and member paging

Accepted duplicate links now feed a pure presentation grouping projection over
the complete selected corpus before paging. Cycles are iterative, variants and
uncertain matches stay separate, and source changes or unlinking cannot silently
rebind old grouping. The shared `findings:groups` reader and the existing TUI
relationship surface expose groups and every member. Exact generation lookup
supports ordinary per-member Review without confusing an id with a fingerprint.
See the [grouped Review assessment](../assessments/grouped-review-2026-10-07.md)
for native evidence, retained failures and limits. Bulk proposal review,
group-wide decision contracts and reviewed lessons remain open. This does not
complete the full module, monorepo or TUI acceptance; milestones remain open.


October 8, 2026: manual reusable lessons now preserve exact human-confirmed
finding origins, immutable revisions and explicit acceptance. Edits return to
draft; stale/concurrent review and changed confirmation are refused. Selected
accepted lessons create inactive immutable context copies; retirement blocks
shared scan-context loading while preserving exact inspection. Draft and
unselected lesson artifacts stay outside automatic context search.

The Lessons TUI has owned fields, confirmation, selective context reuse and
restart recovery. J118 records 21 machine passes, zero failures, six separate
scoped screen judgments and 23 inspected frames. Ten core and five TUI tests,
the workspace checks, native build and quick summary gates pass. Evidence and
limits: [reviewed-lessons-2026-10-08.md](../assessments/reviewed-lessons-2026-10-08.md).
Model-backed lesson drafting, lesson export, large-book and full viewport
acceptance remain open. No broader milestone is closed by this checkpoint.


### Bounded preparation failures retain their real state

October 9, 2026: automatic dependency inspection now has a bounded process
probe. Comparison capture walks caches and overrides iteratively with shared
entry and byte limits per condition, refuses incomplete identities, and records
the selected Semgrep executable rather than a different PATH executable. The
Source panel exposes recorded facts without treating location as useful
coverage. Source and managed CodeQL checks remain separate.

Native failure inspection found the form showing Preparing after a correctly
saved failure and an expired temporary banner. The form now keeps that failure
until dismissal or retry; cancellation keeps its stopped reason. The same state
feeds plain output and keyboard controls, with draft settings and navigation
preserved.

Final J136 has sixteen machine passes, zero failures and fifty-three live
capture pairs over all six sizes, with expiry waits and no-color restart. Three
scoped screen judgments pass; two remain partial because narrow reading and
engine inspection need too much paging. Raw REVIEW_REQUIRED and operator
approval false remain explicit. No scanner or provider request ran. Focused
tests, native build and all ten quick gates pass on dirty main. See the
[preparation input assessment](../assessments/preparation-inputs-2026-10-09.md)
for exact receipts, retained failures and limits. No full delivery milestone is
closed by these bounded checks. Narrow reading comfort, broader module outcome
auditing and complete live-model investigation acceptance remain open.


October 9, 2026, detail-reader follow-up: z read now expands the selected study
explanation or retained preparation error. Its separate scroll returns to the
original field and form position; arrows scroll text, and Home/End and paging
reach the full document. At 40x12 the reader has six content lines instead of
two. Plain output consumes the same selected-section presentation.

Final J136 now records twenty-two machine passes, zero failures and forty-five
live capture pairs. Five no-color frames, error-expiry waits and return to the
same unapproved study are retained. Four scoped screen judgments pass; Source
verbosity keeps one partial. Raw REVIEW_REQUIRED remains separate from operator
approval. The focused reader, rendering and preparation-failure tests, native
build and all ten quick gates pass. The assessment above retains the earlier
partial review and the final source/binary receipts. Full TUI parity, complete
module outcomes and live-model investigation acceptance remain open.


### Source inspection separates everyday facts from exact options

October 9, 2026: Source and context now has Overview, Inputs and Options views.
Tab and Shift+Tab switch without changing the selected field or dispatching
work. Each view remembers its form and reader positions. Exact options remain
complete, formatted and per case; raw compatibility fields no longer crowd the
overview. Supplemental text is summarized in Overview and fully available in
Options. Plain form output remains exhaustive across all views.

The native screen review removed a passive receipt notice repeated across every
view. Source drift and nondeterministic absence remain explained in Overview.
Missing legacy threat-model references, explicit omission and malformed
references now have separate labels. Core identifier parsers preserve truthful
readable model/revision labels without replacing context authentication.

Final J137 records thirty-one machine passes, zero failures, fifty-six live
capture pairs, all six sizes, backward switching and six no-color frames. The
owned native plan remains unapproved with three fixed jobs, no queue, unchanged
source and zero provider/scanner work. All twenty-five prepared-option keys are
inspected at 40x12. Focused state, source, controls, rendering and study-action
regressions, native build and all ten quick gates pass. The sequential J136
regression retains real bounded preparation failures and expiry behavior. A
retained failure exposed an obsolete three-frame fixture expectation after
Inputs became shorter; full content and actual scrolling checks remain.

See the [Source view assessment](../assessments/study-source-sections-2026-10-09.md)
for exact captures and limits. Raw REVIEW_REQUIRED remains separate from
operator approval. Scanner usefulness, large-case performance, live-model
investigation acceptance and complete interaction parity remain open. No full
delivery milestone or module maturity is promoted by these presentation checks.


### Credential readiness preserves expiry and uncertainty

October 9, 2026: shared OAuth metadata already distinguished current, expired
refreshable and invalid entries, but Setup and Health collapsed them into OAuth
ready. Presentation now preserves refresh required, repair, missing and stored
states. Expired tokens carry attention instead of a success check; presence
does not establish provider acceptance. Model hints and the credential chooser
share those facts, and invalid OAuth blocks only model-backed Setup work. The
selected model, runtime refresh policy and approval boundary stay unchanged.

Final J138 records twenty-five machine passes, no failures, all six sizes and
no-color restart. Four scoped screen judgments pass; one stays partial because
the generic narrow Setup footer clips guidance. Synthetic credentials are
isolated, values stay hidden, credential/source bytes remain unchanged, and no
sign-in, refresh, model request or scanner runs. Focused state/rendering tests,
native build and all ten quick gates pass. Retained assertion and quit failures
are recorded separately. See the
[credential readiness assessment](../assessments/credential-readiness-2026-10-09.md).

This verifies local metadata presentation. Actual provider acceptance, OAuth
recovery, a newly approved live test allowance, complete per-tool outcomes and
full TUI parity remain open. Raw REVIEW_REQUIRED is retained and no full
delivery milestone or module maturity is promoted.

### Confirmed reports preserve decisions across observations

October 9, 2026: a shared-dispatch test proved that confirmed SARIF could omit a
human-confirmed identity after a later observation. It now consumes canonical
effective review and enriched export records. The recorded decision source,
later observation, authority, reason, suppression, relationships and lessons
remain available. A later human false-positive decision reverses confirmation.
Workspace history and investigation scope are explicit; current-checkout
applicability is not assessed and missing observations never establish a fix.

Final J139 records twelve machine passes, no failures, twenty-four live capture
pairs, all six sizes and seven no-color captures. Actual headless and shell
exports retain one confirmation from two labeled observations, with explicit
write approval and unchanged source/ledger state after restart. Narrow detail
paging reaches the source warning and returns to the list. Three scoped screen
judgments pass; one remains partial for tiny viewport comfort. Raw
REVIEW_REQUIRED remains separate from operator approval.

A successful tool without Activity timing now emits a completion notice without
inventing duration or changing draft/view. Compact picker guidance keeps Enter
selection visible at forty columns. One hundred focused report, export,
completion and prompt checks, native build and all ten quick gates pass.
The tool matrix now has qualified evidence for thirty-eight of 109 tools,
with seventy-one unassigned. No maturity or delivery milestone is promoted.
See the [confirmed report assessment](../assessments/confirmed-sarif-provenance-2026-10-09.md)
for exact artifacts, retained failures and limits. Full current-SHA review,
schema interoperability, large-ledger cancellation, full TUI parity and the
complete real-model investigation remain open.

The compact-notice follow-up keeps the finding identity visible beside a
passive receipt at 40x12. Warnings/errors retain their preview and dismissal.
Final J139 at `20261009-042127` has thirteen machine passes and no failures;
the same source, ledger, approval, paging and no-color checks remain. Tiny title
reading and the Prompt navigation hint remain partial. J138 separately records
twenty-seven machine passes and five scoped screen passes after the compact
Setup hint repair, without authentication or model work. Exact receipts and
limits are in the assessments above.

J139 was rerun after the final locked workspace build changed the executable
hash. The `20261009-042918` receipt preserves thirteen machine passes, no
failures and twenty-four live captures that all match the binary currently on
disk. Source/ledger recovery, no-color and scoped comfort limits are unchanged.

### Context comparison and immutable lifecycle

October 9, 2026: the per-tool audit now covers runtime-free context models,
revisions, diff, activation, restore and mirror adoption. Comparison previously
reported no differences after overview/answer edits. It now includes exact text,
matching across reordered component/question rows, removals, changed document
sections, both content hashes and explicit comparison coverage. Complete values
remain in structured output beside bounded previews.

Native activation exposed false partial Map ownership. Activation, restore,
adopt, revise and selective regeneration are now auxiliary actions and cannot
replace Map. Mirror adoption also carried stale verification; it now clears the
old check and marks the new content user-edited while preserving original
objects. The observed mirror digest is authenticated before withdrawal, using
existing recovery records and refusing later edits. No schema or authorization
changes were introduced.

Seventy focused checks, locked workspace build and all ten quick gates pass.
Final J140 at `20261009-053817` has twelve machine passes, fourteen live captures,
six comparison sizes and no-color restart against the current binary. Three
scoped judgments pass and two remain partial for manual revision-id actions and
tiny Logs reading. Sequential J105 preserves multiline edit/draft/selection and
unapproved three-pass recovery with thirty-one machine passes. No model,
scanner or source execution occurs. The matrix now has qualified evidence for
forty-four of 109 tools, with sixty-five unassigned.

See the [context lifecycle assessment](../assessments/context-lifecycle-2026-10-09.md)
for exact source/binary receipts, retained failures and limits. Raw
REVIEW_REQUIRED remains separate from operator approval. Full live acceptance,
large-case behavior, rich context-history controls and complete TUI parity
remain open; no full milestone or module maturity is promoted.

### Keyboard context history and complete local readers

October 9, 2026: `threats models` and the visible `6 MODELS` shortcut now open
an exact revision browser. Selection, inspection, baseline comparison and
explicit activation/restore use the existing cached manifest and shared tools.
Summary/document positions, navigation origin and drafts survive local returns.
Missing immutable objects retain an actionable retry. Exact labels remain
stable during manifest refresh, and completion receipts identify the original
subject after cursor movement. No model or discovery work is introduced.

Sixteen direct history checks, eight existing history checks, eight core diff
checks, four keymap checks and twelve paste checks pass. Final J141 has 24
machine passes, 27 live captures, all six sizes and three no-color captures.
Sequential J140 preserves the prior command/adoption lifecycle with twelve
machine passes. Both retain operator review separately from machine results.

See the [context history assessment](../assessments/context-history-browser-2026-10-09.md)
for exact receipts, retained failures and remaining acceptance. Browser choices
remain session state; immutable history and the active pointer survive restart.
Large-case behavior, richer DFD comparison, live-model usefulness, complete
module qualification and reference parity remain open. No broad milestone or
module maturity is promoted.

### Bounded citation checks and imported history

October 9, 2026: citation inspection now uses bounded candidate/source windows,
separates missing from unavailable, retains partial checks and records source
digests without changing finding verdicts. Drift audits are specific to their
source/revision. Completed ledger replay preserves original observations after
source drift. Both tools are auxiliary Review actions. Imported ids cannot
forge Map/Scan completion, while their history remains accessible for review.

Native J142 records seventeen machine passes, fifteen live captures, six sizes,
an expanded 40x12 transcript reader and no-color restart. Ninety focused checks
cover grounding, import, reader ownership, phase ownership and journey projection.
See the [citation/import audit](../assessments/citation-module-audit-2026-10-09.md)
for exact receipts and limits. Large-case cancellation, richer downstream
presentation, real SHA transitions, full module qualification and live-model
acceptance remain open. No broad milestone or maturity is promoted.

### Bounded pack inspection and explicit legacy discovery

October 9, 2026: pack lint shares declared entry and byte allowances across
iterative target/prompt/model walks and bounded document reads. Unavailable
paths, missing targets, cancellation and limits retain honest coverage; schema
errors still fail. Legacy shard suggestion remains exact Compatibility, with
its bounded inventory and draft format preserved. Both tools are auxiliary Map
operations. The real draft is consumed by lint without accepting scopes or jobs.

J143 records 25 machine passes, zero failures, 24 authenticated captures, all
six sizes, actual narrow allowance paging, palette round-trip and no-color
restart. Source, draft and receipts remain; no phase attempts, model requests,
findings or scan jobs occur. The expanded transcript yields modified keys and
foreground scope ownership, and its visible palette action fits at 40 columns.
The scope footer retains complete menu and finite-plan controls.

See the [pack inspection audit](../assessments/pack-inspection-audit-2026-10-09.md)
for limits, retained failures and exact receipts. The matrix has scoped evidence
for 48 of 109 tools, with 61 unassigned. Large-case IO, cancellation inside one
read, all options/interfaces, full TUI parity and live-model investigation
acceptance remain open. All nine broad delivery milestones stay unchecked.

### Actual Git revisions, scoped absence and self-contained review reports

October 9, 2026: shared decision exports now carry recorded full SHA, branch
and dirty state for the decision and later observation. Markdown bundles retain
the complete structured basis as well as readable Git rows. Missing metadata
stays unknown; export never substitutes current-checkout state.

Native tmux exposed missing empty-scan gaps and premature whole-target fallback
before actual scope receipts existed. Native lifecycle now defers reconciliation
until the owning SAST module saves completed coverage. The ledger consumes that
exact saved data while the outer CLI manifest finalizes, retaining completed-run,
target, engine and path checks. Human decisions remain separate from absence.

J144 has 38 machine passes, no failures and 35 authenticated captures across
six sizes, actual narrow source paging and settled no-color Report recovery.
Four real offline scans cross two observed commits and dirty content at the
same SHA; three observations and two TUI decisions survive a later empty scan
and restart. Eighty-five distinct focused checks, the workspace build and full
risk gate pass. See the [Git source-history assessment](../assessments/real-git-review-history-2026-10-09.md)
for exact receipts, retained failed attempts and scoped screen judgments.
Operator approval remains false; no live-model or complete-product claim is made.
All nine broad milestones remain open. Tool qualification stays 48 of 109.

### Review continuity and exact source bindings

October 9, 2026: passive refresh now keeps the page and cursored finding after
a generation replacement through versioned opaque navigation anchors. Exact
generations remain preferred; fallback requires a unique identity and matching
fingerprint inside the same query. Cursors and public exact anchors stay
compatible. Explicit historical pins retain their original generation, source
watermark and a visible disclosure. Manual decisions and false-positive actions
no longer borrow a newer watermark from a row sharing that identity.

J145 has 27 machine passes, no failures and 25 authenticated native captures
across six sizes, actual narrow detail paging, return to the same later page
and no-color restart. Its owned synthetic ledger has 800 findings and one
external replacement. Headless shared dispatch consumes the same navigation
values; the TUI preserves the draft and old source, then records a new decision
only after explicit current-row inspection. Ninety-eight focused checks, the
workspace build and risk gate pass. See the [generation-continuity assessment](../assessments/finding-generation-continuity-2026-10-09.md)
for exact receipts, retained failures and limits. No provider or scanner work
runs. Operator approval remains false. All nine broad milestones remain open;
tool qualification remains 48 of 109.

### Review resize and explicit current-observation recovery

October 9, 2026: focused Review detail now remains visible in compact layouts
without changing explicit zoom. Expanding restores both panes while preserving
focus, scroll offset, cursor, page and draft. Historical pins offer an explicit
current-observation command only after a unique same-identity/fingerprint match
inside the visible query. The tiny list preserves its selected row and names
the earlier pin in its title when the complete notice cannot fit.

J146 has 42 machine passes, no failures and 31 authenticated live captures
across six sizes and no-color restart. Its owned synthetic ledger retains both
observations and decisions; no provider or scanner work runs. Two hundred
distinct focused checks, the workspace build, risk gate and ten quick gates
pass. See the [Review resize assessment](../assessments/review-resize-recovery-2026-10-09.md)
for exact receipts, retained failures and limits. Operator approval remains
false. All nine broad milestones remain open; qualification stays 48 of 109.

### Operational contract audit and bounded startup classification

October 9, 2026: five operational helpers now have scoped prepared-dispatch and
native consumer evidence. Configuration and routing show readable selected
values; workspace status, methodology listing and legacy harness metadata
cannot own a Map result. The harness action is Compatibility in default tool
discovery and discloses that its recorded budget enforces no allowance and
approves no work. Exact dispatch and stored TOML remain compatible.

Startup now classifies a current prefix of at most 32 records through shared
registry metadata. Operational-only complete history still enters Setup;
unknown, incomplete or cold history preserves resume without rebuilding an
index or claiming completion. J147 has 25 machine passes, no failures and 19
authenticated native pairs across six sizes, actual Setup and no-color restart.
Thirty focused checks, workspace build, risk and ten quick gates pass. See the
[operational startup assessment](../assessments/operational-startup-audit-2026-10-09.md)
for exact receipts, retained failures and limits. No model or scanner work runs.

A one-job low-usage live retry is prepared but not approved or launched. The
current operator OAuth credential remains expired and the specific allowance
question remains pending. Qualification is 53 of 109, with 56 unassigned;
the native default catalog has 98 tools. All nine broad milestones remain open.

October 9, 2026: historical Git baseline inspection distinguishes dirty current
source, dirty historical baselines and unavailable scopes from unchanged tracked
source. Full SHAs and verdict-first receipts remain readable in the transcript;
legacy metadata explicitly cannot certify complete coverage or a finding fix.
Coverage actions use Operate and cannot seed accepted Map work. Skip writes
revalidate source/history and use a ledger transaction. NUL paths and bounded
Git subprocesses replace unbounded line parsing; whole-sweep and source races
remain unqualified.

Final J148 at `/tmp/kuzushi-source-baselines-20261009/settled-tui/20261009-154657/J148`
has 22 machine passes, zero failures and 20 native text/ANSI pairs across six sizes
and no-color restart. Four scoped assistant screen judgments remain separate
from raw REVIEW_REQUIRED and human approval. The owned inert fixture has two
actual Git commits, a same-SHA edit and labeled synthetic history; it creates no
model, scanner, finding or decision work. Forty-six distinct focused checks and
the final workspace build pass. Two tools gain scoped outcome evidence, bringing
the matrix to 55 of 109 qualified and 54 unassigned. Default discovery stays at
98. Recommendation outcomes remain pending.

The screen review exposes three next TUI defects: cached Setup source facts after
drift, noisy operational error diagnostics and unrelated recovery hints, and
journey/autonomy chrome on non-Setup views before Start Map. See
[source baseline assessment](../assessments/source-baseline-integrity-2026-10-09.md)
for evidence and limits. All nine delivery milestones remain open; the specific
model-test allowance is pending. No product commit, push or inference occurred.

### Setup refreshes cached source facts on explicit reopen

October 9, 2026: explicit Setup reopening now requests fresh cached target facts
through the existing generation-checked asynchronous inspector. A pending
inspection is retained without duplication. Selected tasks, Setup cursor and
multiline composer have focused preservation evidence. No phase or discovery
work starts from this refresh.

J149 has 19 machine passes, zero failures and 12 authenticated native captures
across six sizes and no-color restart. Two actual owned commits and a same-SHA
edit demonstrate branch/revision and dirty-state replacement without restart.
Compact layouts preserve controls and draft but intentionally omit the facts
block. Fifteen distinct focused tests, workspace build and risk gate pass. See
the [Setup source refresh assessment](../assessments/setup-source-refresh-2026-10-09.md)
for exact receipts and limits. Four scoped assistant screen judgments do not
constitute operator approval. Qualification remains 55 of 109; all nine broad
milestones remain open. Automatic freshness, diagnostic noise, premature chrome,
live model validation and complete reference-quality acceptance remain pending.

### Calm operational failure reading and consistent pending Setup

October 9, 2026: shared presentation keeps journey/autonomy and screen-context
phase labels hidden while Setup is pending across utility views. The wide rail
shows Target until commitment. Structured failed/partial receipts lead with
bounded cause and recovery text; complete persisted payloads and agent failure
context remain available. Generic recovery names the actual tool's options.
Explicit draft undo retains Navigate ownership and explains how to reveal the
command line.

Final J150 has 48 machine passes, zero failures and 19 authenticated live
captures across six sizes and no-color restart. Actual dirty-tree rejection,+narrow cause reading, draft resize/undo/reveal and failure recovery have owned
native evidence. One hundred eight distinct focused tests, workspace build and
risk gate pass. See the [operational reading assessment](../assessments/operational-failure-reading-2026-10-09.md)
for retained intermediate failures and limits. Four scoped assistant judgments
do not constitute human approval. No model or scanner work starts. Qualification
stays 55 of 109; all nine broad milestones remain open. Exact cursor/selection
continuity, detailed failure-reader hierarchy, completed language labels,
automatic freshness and complete live/reference-quality acceptance remain open.


### Explicit recommendation ranking and canonical reader, October 9, 2026

The retained exact-only Compatibility recommender now defaults to free
deterministic ranking. Explicit model ranking requires the selected runtime and
Scope allowance before runtime construction, makes one tool-free query and
returns errors without model substitution or output repair. Operate/no-phase
metadata prevents suggestion generation from owning Map. Existing inventory
bounds, cancellation, partial coverage and recent-findings sampling are exposed.
Prove/Fix actions are excluded from suggestions without deleting dispatch.

The `recommendations` reader consumes canonical results, retains legacy reads,
labels older reports and loading states, and refreshes history on explicit
reopen. Deterministic `r` refresh preserves its reader/input mode. Wrapped
receipts, narrow cards and shared viewport paging make the full returned
shortlist reachable; footer actions reflect actual component availability.

Evidence: [recommendation module audit](../assessments/recommendation-module-audit-2026-10-09.md).
J151 has 34 machine passes, zero failures, 18 authenticated populated live
captures, six sizes and no-color restart. Four scoped assistant judgments stay
separate from raw REVIEW_REQUIRED and operator approval false. There are 155
distinct focused tests; workspace build, risk and all ten summary gates pass.
No provider, scanner, OAuth renewal, target execution, commit or push occurs.

Visible qualification remains 55 of 109. This hidden tool's scoped evidence
does not inflate that census or promote maturity. Live ranking, auxiliary IO,
legacy strategy approval/outcome preservation, component cursor continuity and
source applicability still need work. All nine broad milestones remain open.


### Regenerated proposals retain human review history, October 9, 2026

Recommendation regeneration preserves prior status, approval amounts,
corrections, costs and outcome/source references, then adds unapproved drafts
with separate identities. Initial legacy ids stay valid. Current generation
artifacts list only their own proposals. Existing ledger limits and schemas
remain compatible; no executor or automatic work expansion is added.

The queue refreshes on explicit reopen, sorts new drafts first and shows full
wrapped receipt fields. `strategy inspect <id>` reads one target-bound record
without approval/execution. Actual viewport paging reaches recorded costs and
result references at 40x12. Proposal approval is explicitly separate from study
and allowance approval.

Evidence: [proposal history assessment](../assessments/proposal-history-2026-10-09.md).
J152 has 34 machine passes, zero failures, 18 authenticated live captures, six
sizes and no-color restart. Three scoped assistant judgments remain separate
from raw REVIEW_REQUIRED and operator approval false. There are 123 distinct
focused tests; workspace build, risk and all ten summary gates pass. Historical outcome
metadata is labeled synthetic; generation and keep/skip decisions use the real
native interfaces. No provider, scanner, source execution, commit or push occurs.

Qualification remains 55 of 109. Live provider behavior, large-queue retention,
source applicability and complete investigation/reference-quality acceptance
remain open. All nine broad milestones stay unchecked.


### Report choices survive restart with explicit repair, October 9, 2026

The Report restart gap from J121 is repaired. Format, per-format destinations,
completeness and provenance detail persist in a bounded operator-owned store
keyed by canonical target. Target-local files cannot steer them. Restoring
choices never restores study/approval authority, history scope or receipts,
and never exports. S saves explicitly; valid choices also save on Enter export.
Damaged bytes survive export and can be replaced explicitly through S.

Evidence: [report choice recovery](../assessments/report-choice-recovery-2026-10-09.md).
J153 has 26 machine passes, zero failures and 20 authenticated live captures,
six sizes, no-color restarts, actual narrow control reading, native empty export
and explicit repair. Four scoped assistant judgments remain separate from raw
REVIEW_REQUIRED and operator approval false. There are 203 distinct tests;
workspace build, risk and all ten summary gates pass. No model, scanner, source
execution, commit or push occurs.

Visible qualification stays 55 of 109. Multi-session preference behavior, IO
latency, live-model investigation and full TUI/reference acceptance remain open.
All nine broad delivery milestones stay unchecked.

### Readable frozen settings and exact JSON, October 9, 2026

The observed J121 JSON-first review friction is addressed with Source tabs for
Overview, Inputs, Settings and JSON. Readable labels and current descriptor help
accompany frozen values; defaults never replace missing or historical data.
Legacy execution fields remain inspectable without promoting target execution,
reproducer or patch actions. Presentation never rewrites their values or changes
Core dispatch, approvals, job creation, model policy or artifact schemas.

Evidence: [readable study settings](../assessments/readable-study-settings-2026-10-09.md).
Sequential J154 has 24 machine passes, zero failures and 55 authenticated live
captures; J137 has 36 passes, zero failures and 58 captures. Both cover six sizes
and no-color restart on the same native build. Narrow paging checks all 24
recorded J154 values and keys; J137 retains its 25 keys and engine bindings.
Three scoped assistant judgments per journey remain separate from raw
REVIEW_REQUIRED and operator approval false. Thirty-seven distinct focused
tests, the workspace build and risk gate pass. No provider, scanner, OAuth
renewal, target execution, product commit or push occurs.

Qualification stays 55 of 109. Complex-value reading, field search, full input
continuity, platform/reference-quality acceptance and the complete live
investigation remain open. All nine broad milestones stay unchecked.

The final ten-gate repository summary passes. Its dirty/drift flag includes
initial dirty source and does not prove concurrent edits. Final documentation
contract checks follow the evidence update.


### Consistent Review reads during external updates, October 9, 2026

The J121 multi-query ledger refresh race is addressed with one SQLite read
snapshot around shared finding pages and complete shell projections. Nested
readers join it. The recorded watermark remains authoritative; external commits
are available on later reads. Cursor and source/subject decision validation are
unchanged. Missing data and permanent failures remain honest errors. There is
no repeated consistency-repair loop or additional discovery work.

Evidence: [concurrent Review snapshot](../assessments/concurrent-review-snapshot-2026-10-09.md).
J155 has 24 machine passes, zero failures and 23 authenticated live captures,
six sizes, narrow decision paging and no-color recovery. Its labeled synthetic
ledger retains 833 observations after 33 actual external writes and exactly one
explicit human decision on an unchanged original id. Four scoped assistant
judgments remain separate from raw REVIEW_REQUIRED and operator approval false.
There are 271 distinct focused passing tests; workspace build and risk pass.
No model, scanner, target execution, product commit or push occurs.

Qualification stays 55 of 109. Filesystem races, long-reader/WAL resource bounds,
live-provider acceptance and complete reference-quality acceptance remain open.
All nine broad delivery milestones stay unchecked.

The final ten-gate repository summary passes on this checkpoint. Dirty/drift
metadata includes initial dirty source and does not prove concurrent edits.
Final documentation contract checks follow the evidence update.


### One inventory for context sampling and readable inspection receipts, October 9, 2026

Context preparation now derives sample membership from its bounded inventory,
retains loose root files, validates sample aliases from 1 through 2000, and
preserves prior snapshots when cancellation is observed before or after that
inventory. The Context reader distinguishes tracked enumeration, sampling,
omissions and partial inspection from freshness. Long values and recovery
commands wrap; Page Up/Down use the actual body height rather than skipping
rows in narrow terminals. Provenance and manifest IO remain separate work.

Native J156 has 19 machine passes, zero failures and 29 authenticated captures
across six sizes and no-color restart. Twelve finite narrow pages expose every
receipt value and recovery command. There are 540 distinct focused passing
tests, workspace build and a passing risk proxy for 583 changed code files.
Regeneration recovery now requires an explicit exact-context check before Map,
without another synthesis request or active-context mutation. See the
[context inventory assessment](../assessments/context-inventory-preparation-2026-10-09.md)
for retained failures, final evidence and limits. Raw REVIEW_REQUIRED and
operator approval false remain explicit. Tool qualification stays 55 of 109;
all nine broad milestones remain open. No live model or product commit runs.

All ten repository summary gates pass. Final documentation checks follow this
evidence update; dirty/drift metadata includes the initial dirty worktree.

### Context copies retain investigation spending, October 9, 2026

The shared Map reader recovers accounting through at most 64 explicit
immutable copy origins, preserving the selected context and latest durable
consumption. Missing or damaged known history fails explicitly. Regeneration
can be checked, accepted as Map and followed by a separately approved study
without resetting spending or changing the globally active context.

Native J157 has 32 machine passes, no failures and 27 authenticated captures
across six sizes and no-color restart. It retains one intercepted request,
five total calls and two protected Review calls across exact checking, Map
acceptance, three-job approval and restart. Damaged origin receipts block
continuation; exact restoration recovers the same accounting. No discovery
job, live model request or target-source execution runs. There are 533 distinct
focused passing tests, workspace build and a passing risk proxy for 585 changed
code files. See the [context copy accounting assessment](../assessments/context-copy-accounting-2026-10-09.md)
for failed predecessors, final evidence and limits. Raw REVIEW_REQUIRED and
operator approval false remain explicit. Qualification stays 55 of 109 and
all nine broad milestones remain open.

All ten repository summary gates pass. Final documentation checks follow this
evidence update; dirty/drift metadata includes the initial dirty worktree.

### Dependency inventory updates Components and preserves readable recovery, October 10, 2026

The per-tool audit corrects `sbom-scan:scan` from Scan completion to auxiliary
Map inventory. Actual prepared dispatch needs no context snapshot, emits
declared/resolved dependencies plus edges and export formats, and creates no
findings or phase attempts. Completed reports now update matching target facts
directly; structured failures clear current package claims and preserve old
run receipts. A late target inspector cannot overwrite the completed report
within that generation. Tool-sourced Components labels freshness as unverified.

Native J158 exposed fixed ten-row paging over a two-row body and an error
banner that consumed the whole narrow document. Paging now follows the visible
body, failure text wraps before viewport slicing, and compact error notices
retain their badge and Logs route on one row. The existing view-model layer
owns the layout decision, and the footer exposes `PgUp/PgDn page`.

The final journey has 40 machine passes, 43 authenticated captures, six terminal
sizes, complete narrow version/failure paging and no-color restart. Three real
completed inventories and one failed inventory retain receipts with no model
requests, discovery jobs, source execution or workflow completion. There are
135 distinct focused passing tests and a successful workspace build. See the
[inventory audit](../assessments/sbom-inventory-audit-2026-10-10.md) for retained
failed predecessors, source/aggregate limits and separate screen judgments.
Qualification is now 56 of 109, with 53 unassigned. No maturity promotion or
module retirement follows. All nine broad milestones remain open.

All ten repository summary gates and six final documentation contract checks
pass after the view-model boundary repair. The CRAP-risk proxy covers 593
changed code files. Work remains uncommitted on main.

### License policy has bounded inspection and durable Review/report evidence, October 10, 2026

Real prepared dispatch reproduced clean-looking oversized-license results,
unbounded double traversal, findings on internal analysis artifacts and false
license presence from an uninspected symlink. The engine now derives candidates
from one bounded regular-file inventory, contains reads, retains failures and
rejects incomplete header-absence claims. Direct results use the existing shared
source guard. Actual directory-scoped SAST produces the same signals and rejects
exact-file widening; direct covered-absence parity remains an explicit gap.

J159 runs three direct scanner repetitions, saves a scripted deferral, observes
a covered empty SAST pass after a planned inert source edit, exports JSON,
retains a failed oversized-file outcome, repairs/reuses context explicitly and
restarts without color. The final run has 35 machine passes and 30 authenticated
captures across six sizes. The Review title preserves finding identity during
paging, and pending-result controls keep the paging hint visible. Six scoped
screen judgments remain separate from raw REVIEW_REQUIRED and operator approval.

There are 153 distinct focused passing tests, a successful workspace build,
a risk proxy pass for 597 changed code files and ten passing repository summary
gates. See the [license-policy audit](../assessments/license-policy-module-audit-2026-10-10.md)
for exact receipts, retained failures, heuristic/source/IO limits and remaining
parity. Qualification is now 57 of 109, with 52 unassigned. No module promotion
or retirement follows; all nine broad milestones remain open on dirty main.

### Advisory ranking honors scope and survives context reload, October 10, 2026

Prepared dispatch reproduced ignored targets, incorrect Map completion,
unimplemented fan-in silently succeeding, invalid coverage limits and schema
mutation during reads. Worklist is now auxiliary Map, honors the canonical
target, isolates child findings and rejects unsupported requests. Coverage
readers preserve initialized schema and refuse legacy/malformed stores without
migration. Baseline and finding-path materialization has explicit 10,000-row
ceilings; SQLite processing, aggregate bytes/latency and query cancellation are
still separate limits.

The worklist page wraps full paths/evidence, discloses shown/total counts and
retains degraded contributor reasons. Native review found a latest-run-dependent
restart failure and a returned cap lost on unchanged context rehydration. Saved
context now feeds the existing background reader; content-hash binding preserves
the cap and invalidates genuinely changed context. Explicit child results do
not replace or auto-open parent evidence. Restart reconstructs default context
ranking while exact earlier options remain in durable run receipts.

Final J160 at
`/tmp/kuzushi-worklist-audit-20261010/verified-reading-tui/20261010-033019/J160`
has 34 machine passes, no failures and 36 authenticated captures across six sizes
and no-color restart. Six assistant screen judgments stay separate from raw
REVIEW_REQUIRED and operator approval false; one remains partial for notice
prioritization. Real deterministic context feeds scoped CLI/shell ranking, with
explicit synthetic database repair, unchanged source hashes and zero findings,
provider reservations or study work. No scan, model request, source execution,
exploitation or patching occurs.

There are 161 distinct focused passing tests, a successful workspace build and
a passing risk proxy for 607 changed code files. See the
[worklist/coverage audit](../assessments/worklist-coverage-module-audit-2026-10-10.md)
for receipts, retained test failures and remaining limits. Qualification is now
59 of 109, with 50 unassigned. No module is promoted or retired, and all nine
broad milestones remain open. Full live-model and end-to-end investigation
acceptance remains unproven; work remains uncommitted on main.

All ten repository summary gates pass, with the receipt copied to
`/tmp/kuzushi-worklist-audit-20261010/verify-receipt.json`. Final six contract/docs
checks also pass. Dirty/drift observations include the inherited tree and this
increment; they do not prove another writer changed the workspace.

### Actual finite policy investigation and visible source refusal, October 10, 2026

J161 completes actual deterministic context preparation, native manual-context
import, explicit Map acceptance, approval of three fixed license-policy jobs,
one consolidated finding, a scripted deferral, JSON export and no-color restart.
The campaign batch controller uses one worker and one attempt per job. Frozen
context is independent of the globally active threat model. A deliberate inert
source edit is refused before any observation, work attempt or provider
reservation; restoring the exact original bytes permits the approved plan.
Final counts remain three attempts, three observations, one decision and zero
provider reservations. All call capacity remains protected for Review.

Direct phase verbs now open unresolved results for their explicit decision;
`plan <phase>` remains deliberate planning. Owned dispatcher failures retain
their original target, campaign and bounded redacted cause across refresh.
Background completion preserves focus and typing. Native review moved the full
cause ahead of jobs and kept narrow review/paging controls visible. The notice
is session state; relaunch replaces the current diagnostic log. Reports say
`none recorded for discovery` without inventing preparation or legacy history.

Final J161 has 36 machine passes, zero failures and 89 authenticated native
captures across six sizes, twenty narrow refusal pages, thirty narrow report
pages and no-color restart. Seven assistant screen judgments stay separate
from raw REVIEW_REQUIRED and operator approval false; tiny-reader comfort
remains partial. JSON and its sidecar preserve exact source/context, three
attempts, recurrence, the deferral and shared allowance. This is unversioned
owned policy metadata, with no vulnerability-quality or Git-fix claim.

There are 185 distinct focused passing tests, a successful workspace build,
a risk proxy pass for 609 changed code files and ten passing summary gates.
See the [finite native investigation assessment](../assessments/finite-policy-investigation-2026-10-10.md)
for receipts, retained failures and remaining acceptance. Qualification stays
59 of 109. All nine broad milestones remain open, including the complete live
model investigation and full reference-product experience. Work remains
uncommitted on main; no model request, credential renewal or source execution
occurs. The specific live test allowance remains pending.

### Visible Setup context import to native investigation, October 10, 2026

Setup's Map plan now offers explicit context import using the existing prepared
executor and descriptor Path option. Missing source blocks Start Map and direct
confirmation; no model or credential is needed. The plan defaults to inactive
saving, does not auto-select import, and requires import and generation to have
separate Map reviews. The shared source selector preserves inline precedence
and null fallback without reading document contents during readiness checks.

J162 enters through normal Setup and visible controls, accepts the imported Map,
approves three native policy passes, consolidates one finding, saves a scripted
deferral, exports JSON and restarts without another job or provider reservation.
It acknowledges the real unsaved-planning-choice exit warning. Durable context,
source, study and decisions survive; transient planning options remain session
choices. The global active context stays absent.

Final J162 has 43 machine passes, zero failures and 101 authenticated live
captures at all six sizes, with narrow failure/report paging and no-color
restart. Eight assistant judgments stay separate from raw REVIEW_REQUIRED and
operator approval false; compact Setup reading and tiny-reader comfort remain
partial. See the [Setup context import assessment](../assessments/setup-context-import-2026-10-10.md)
for actual receipts, retained failures and remaining limits.

There are 246 distinct focused passing tests, a successful workspace build,
a risk proxy pass for 652 changed code files and ten passing summary gates.
Qualification stays 59 of 109. All nine broad milestones remain open; no live
provider request, real credential access, source execution or product push
occurs. Work remains uncommitted on main and the specific live allowance is
still pending.

### Complete Setup inspection and compact readiness, October 10, 2026

An actual Ratatui-buffer check reproduced the compact Setup defect that
projection-only checks missed. Short overviews now keep Start Map and readiness
rows visible. Tab opens the complete selected-row document with pinned identity,
ordinary paging and the actual planned-work summary. Return, resize and per-row
reading positions preserve selection and the composer. Enter in inspection
starts nothing; paste returns to the composer with its normal retained blocks.
Plain output keeps the full document. No runtime or persisted contract changes.

J163 verifies inspection before any native tool run or campaign plan, then
completes visible import, accepted Map, three approved policy passes, one
consolidated signal-only finding, scripted deferral, JSON export and no-color
restart. The pre-work receipt has zero observations, attempts, decisions and
provider reservations with unchanged source. Final counts stay three attempts,
three observations, one decision and zero provider reservations.

Final J163 has 48 machine passes, zero failures and 118 authenticated live
captures across six viewports, full detail/refusal/report paging and restart.
Nine separate assistant judgments retain raw REVIEW_REQUIRED and operator
approval false; compact Setup reading is qualified while the cramped campaign
reader remains partial. See the [Setup reading assessment](../assessments/setup-reading-2026-10-10.md)
for exact receipts and remaining limits.

Ninety-six distinct focused TUI tests, the workspace build, the risk proxy for
658 changed code files and all ten summary gates pass. Qualification remains
59 of 109 and all nine broad milestones stay open. No live-model request,
credential renewal or source execution occurs. Work stays uncommitted on main;
the specific live allowance remains pending.

### Compact Campaign recovery and matching paging, October 10, 2026

Short Campaign navigation now gives the recovery/job document the full frame.
At 40x12, the native refusal has six body rows instead of one. Keyboard paging
and selected-job positioning share the rendered area; composer/palette return
retains the draft and reading position. Questions, confirmations and study
editors keep priority. Native review caught and corrected compact controls
inside normal-height chrome; plain output remains exhaustive.

Final J164 has 58 machine passes, zero failures and 125 authenticated live
captures across six sizes, full failure/report reading and no-color compact
restart. Its real native investigation imports context, accepts Map, refuses
inert source drift before work, executes exactly three approved policy jobs,
consolidates one signal-only finding, records a scripted deferral and exports
JSON plus its sidecar. Restart keeps three attempts, three observations, one
decision and zero provider reservations. No live model, real credential, source
execution or product push occurs.

There are 149 distinct focused passing TUI checks and a successful workspace
build. Nine assistant screen judgments qualify this owned workflow; one remains
partial because the tiny completed-study overview clips worker/plan-summary
labels. Raw REVIEW_REQUIRED and operator approval false stay distinct. See the
[Campaign reading assessment](../assessments/campaign-reading-2026-10-10.md)
for receipts, retained failures and remaining acceptance. Qualification stays
59 of 109, all nine broad milestones remain open and the specific live allowance
remains pending. Work remains uncommitted on main.

All ten final repository summary gates pass, including the risk proxy for 659
changed code files. The receipt is retained at
`/tmp/kuzushi-campaign-reading-20261010/verify-receipt.json`. The working tree
is intentionally dirty; this receipt does not attest to a clean committed
snapshot or full cross-platform acceptance.

### Complete Campaign overview and plan details, October 10, 2026

Campaign identity, worker configuration, spend and dispatcher state now wrap
before pagination, with grouped fields when the joined summary would overflow.
Policy, limits, incomplete cost, empty occurrence guidance and the complete
action list remain readable. Summary rendering has one focused presentation
owner. Shared Unicode section rules use terminal columns. Existing snapshot,
dispatch, context, allowance and persisted contracts remain unchanged.

J165 has 62 machine passes, zero failures and 144 authenticated live text/ANSI
captures at all six sizes, compact summary/report reading and no-color restart.
The real owned policy investigation accepts imported context, refuses source
drift before work, then executes exactly three approved one-attempt jobs with
one worker. Three observations consolidate into one signal-only finding, with
a scripted deferral and JSON/sidecar export. Restart preserves those records
and zero provider reservations. Eleven assistant screen judgments qualify this
owned workflow while raw REVIEW_REQUIRED and operator approval false remain
distinct. The compact-summary clipping gap from J164 is addressed.

Seventy-four distinct focused tests, the workspace build, the risk proxy for
662 changed code files and all ten summary gates pass. See the
[Campaign overview assessment](../assessments/campaign-overview-2026-10-10.md)
for receipts, retained failures and remaining acceptance. Tool qualification
stays 59 of 109; all nine broad milestones and full live-model acceptance stay
open. No model request, credential renewal, source execution or product push
occurs. The specific live allowance remains pending and work stays uncommitted
on main.

### Finite planning audit and protected capacity, October 10, 2026

Four Campaign tools now have explicit evidence in all nine audit dimensions
for their scoped planning, approval and inspection paths. Native dispatch
drafts three policy jobs and a separate inactive one-job context plan, binds
the exact reviewed plan, and refuses missing approval, unknown options, stale
revision, wrong digest, invalid limits and source drift. No job or provider
request starts. The allowance receipt now shows capacity available for context,
scopes, scans and lessons after protecting Review/Report, using one pure domain
calculation. Serialized formats and call admission remain unchanged.

Final J166 has 20 machine passes, zero failures and 21 authenticated live
text/ANSI captures at all six sizes, compact transcript reading and no-color
restart. All three assistant judgments qualify this owned workflow separately
from raw REVIEW_REQUIRED and operator approval false. Exact allowance, source,
absent queues and zero observations/reservations/attempts/decisions survive.
Approved planning resumes a pending Map page without publishing accepted Map;
the journey explicitly reopens Setup. Initial fixture/isolation and startup
assumption failures remain retained.

Seventy-eight distinct focused Core checks, the workspace build, the risk proxy
for 665 changed code files and all ten summary gates pass. One existing legacy
context-study test stays explicitly ignored. See the
[allowance controls assessment](../assessments/allowance-controls-module-audit-2026-10-10.md)
for receipts, failures and remaining acceptance. Qualification stays 59 of 109
with 50 unassigned; no maturity promotion or retirement occurs. All nine broad
milestones and live-model quality remain open. The specific live allowance
remains pending and work stays uncommitted on main.

### Recorded Fleet observations and honest presence comparison, October 10, 2026

Fleet now retains bounded observation history beside its compatible current
finding corpus. A same-identity/two-SHA regression proves and repairs prior
history loss. Selected-target revision comparison reports neutral base-only,
head-only or both presence for uncertain source-proximity groups, with fix status
unassessed. Row or byte overflow refuses comparison without truncation. Skipped
targets produce a partial ingestion with explicit causes. Current queries show
actual records, and all five tools are operational auxiliary actions that cannot
complete Map.

Owned native dispatch and J167 exercise all five tools, invalid inputs, legacy
history recovery, partial ingestion, compact paging and no-color restart. There
are 26 machine passes, zero failures and 30 authenticated captures across six
sizes. Three assistant judgments remain distinct from raw REVIEW_REQUIRED and
operator approval false. Four labeled synthetic observations, three current
findings and zero decisions/provider reservations/work attempts survive. No
actual Git-fix or model-quality claim follows.

Twenty-one distinct focused tests, the workspace build, a 180-tuple policy
review, the risk proxy for 672 changed code files and all ten repository summary
gates pass. See the
[Fleet history assessment](../assessments/fleet-history-module-audit-2026-10-10.md)
for receipts, retained failures and remaining acceptance. Evidence is assigned
to 64 of 109 tools with 45 unassigned; maturity is unchanged. All nine broad
milestones remain open. Global Fleet size, cancellation and concurrency still
need qualification. The specific live allowance remains pending; work stays
uncommitted on main.


### Stored architecture claims and bounded reader recovery, October 10, 2026

`x-ray:read` now declares its target, requires explicit target/workspace consent
and cannot publish a Map phase result. All four stored artifacts have an 8 MiB
per-file limit; oversized SVG, invalid UTF-8, missing and unsafe files refuse
without repair. Reads expose recorded tiers/counts separately from unassessed
source freshness, graph semantics and unknown original generation spend/model/
runtime/context. The current reader has no provider requests. One target path
and grouped filenames improve compact reading while retaining full JSON refs.

Final J168 has 20 machine passes, zero failures and 27 authenticated captures
at six sizes, compact paging, explicit missing-file restoration and no-color
restart. Three assistant judgments remain distinct from raw REVIEW_REQUIRED
and operator approval false. Owned manually supplied reports/source stay
unchanged, with zero observations, decisions, reservations, work attempts and
accepted Map baselines. No live generation quality claim follows.

Twenty-four focused tests, workspace build, the risk proxy for 679 changed
code files and all ten repository summary gates pass. See the
[stored architecture assessment](../assessments/stored-architecture-reader-2026-10-10.md)
for receipts and limits. Evidence is assigned to 65 of 109 catalog entries with
44 unassigned, including seven explicitly excluded reproduction/patch actions.
Those excluded entries are not required implementations. Maturity is unchanged.
Versioned investigation briefs remain missing; legacy `aim` remains compatible
metadata without allowance authority. All nine broad milestones and full live
acceptance remain open. The specific live allowance is pending; work stays
uncommitted on main.

### Immutable goal editor and frozen plan/report history, October 10, 2026

The study form's visible Goal and priorities row now opens a multiline editor
with previous/proposed review, preserved unsaved text and explicit revision
selection. `campaign:brief` adds version 1 target-local immutable operator
intent using the existing content store and workspace state helpers. Stale
saves refuse. Optional declared `briefRef` binds plain, scope, matrix and
context-generation plans; their jobs and scanner/model inputs do not change.
Discovery reports retain the frozen text after the current head changes.

Final J169 has 24 machine passes, zero failures and 27 authenticated native
captures across six sizes, complete compact review paging and no-color restart.
Three assistant judgments remain separate from raw REVIEW_REQUIRED and operator
approval false. Actual saves preserve Unicode and both revisions; an offline
approved three-job plan remains hash-identical with no queues, observations,
decisions, provider reservations or work attempts. Native old-goal JSON export
is separately recorded on the retained second journey's owned target.

There are 221 distinct focused passing Rust checks, with one existing native
matrix fixture explicitly ignored. The workspace build, all ten repository
summary gates and the risk proxy for 690 changed code files pass. The quick
receipt records its CI/platform omissions and dirty/drift state.

See the [investigation brief assessment](../assessments/investigation-brief-2026-10-10.md)
for exact results, retained fixture failures and remaining limits. The reviewed
policy inventory adds one operational tuple, with no prior policy changes.
Scoped evidence is now assigned to 66 of 110 operator tools; 44 remain
unassigned, including seven excluded reproduction/patch actions.

This supplies the versioned operator-intent interface missing at the stored
architecture checkpoint. Model-guided priorities, interrupted-publication
recovery, native scope/matrix goal qualification and the complete live journey
remain open. No module promotion, retirement, provider request, credential
renewal, source execution, commit or push occurs. All nine broad milestones
and full reference-product TUI acceptance remain open on main.

### Explicit scope inclusion and preserved exclusions, October 10, 2026

Whole-repository selection previously cleared recorded exclusions even though
its TUI promised to retain them. It now changes division while keeping omitted
paths and reasons. The additive `include-path` edit and visible inclusion form
remove one exact recorded rule, preserve other rules and require new acceptance.
Unknown paths keep the form and create no revision. Literal leading/trailing
path spaces are preserved and the final native fixture exercises this case.
Existing approved jobs stay
bound to their original accepted scope.

Final J170 has 34 machine passes, zero failures and 30 authenticated captures
at six sizes, actual narrow file paging and no-color restart. Three assistant
judgments stay separate from raw REVIEW_REQUIRED and operator approval false.
Accepted revision 3 compiles an inactive three-job plan over two files. Explicit
inclusion needs acceptance at revision 5 before a separate three-job plan can
include the third file. The first plan remains byte-identical and its native
pending JSON report retains the original exclusion. All source stays unchanged;
observations, decisions, provider reservations, work attempts and queues remain
absent. Inventory limitations remain visible and acknowledged.

There are 77 distinct passing focused Rust checks, a successful workspace
build, all ten passing summary gates and a risk proxy pass for 693 changed
code files. The [scope exclusion assessment](../assessments/scope-exclusion-recovery-2026-10-10.md)
records exact verification results, retained red/driver failures and limits.
The existing `pack:scopes` matrix dimensions now describe actual scoped outcomes.
Evidence assignment remains 66 of 110 tools, with 44 unassigned including seven
excluded reproduction/patch actions. No module promotion or retirement occurs.
Real model proposal usefulness, scanner qualification, complete monorepo/TUI
acceptance and all nine broad milestones remain open on uncommitted main.

### Explicit goal guidance for approved context work, October 10, 2026

Versioned goals now have a separate opt-in model use. Context generation defaults
it off; operators choose an exact revision, enable guidance and review the fixed
plan/allowance. `campaign:context-study useBriefGuidance=true` binds declared
`threat-model:build operatorBriefRef` into the repository or file-group job.
Shared dispatch requires approved fixed work and allowance. The engine receives
all reviewed text as priorities/questions, separate from source evidence, and
stamps actual reference/byte-count provenance. Saving/selecting goals still
creates no model request or scanner/finding changes.

Repository and scoped executors with stub providers consume revision 1 after
head revision 2, preserve source scope and active context, and account for their
single reserved request. Native J171 prepares one fixed job, freezes the selected
194-byte multiline goal and keeps it readable at six sizes, with actual narrow
paging and no-color restart. Its 25 machine passes, zero failures, 27 captures
and three separate assistant judgments retain raw REVIEW_REQUIRED/operator
approval false. Native source/plan remain unchanged with zero jobs, reservations,
attempts, observations, decisions or model manifests.

There are 205 distinct passing focused Rust checks and one explicitly ignored
native fixture export. The workspace build, all ten summary gates and the risk
proxy for 698 changed code files pass. See the
[goal-guided context assessment](../assessments/goal-guided-context-2026-10-10.md)
for exact verification, retained failures and limits. Evidence remains assigned
to 66 of 110 tools, including unchanged excluded-action accounting. No maturity
promotion, retirement, credential renewal, paid model request, source execution,
exploit/reproducer/patch work, commit or push occurs. Real prompt influence,
usefulness, complete monorepo/live investigation, all nine broad milestones and
full reference-product TUI acceptance remain open on main.

### Recorded context goals and matrix omission, October 10, 2026

Context reads now authenticate recorded goal references without claiming
producer model use. Study and history readers show exact text and qualification
before the document; missing guidance preserves the context and never reads the
current goal. Reports retain per-case receipts from frozen references, with
distinct explicit-omission and unbound-history states.

A real matrix export test exposed root-context omission being rejected as a
scope change. New cases carry an optional comparison receipt authenticated at
shared approval. Original condition keys, inputs and old plans stay unchanged.
Other condition guards remain active; non-root/stale lineages receive no root
projection. Constructor migration is documented.

Final J172 has 34 machine passes, zero failures and 46 authenticated captures.
Six-size history/report reading, actual compact paging, study summary/raw views,
missing-reference recovery, export and no-color restart retain goal revision 1
after head revision 2. Five scoped assistant judgments remain separate from
raw REVIEW_REQUIRED and operator approval false. Six jobs stay unstarted;
source, context object, active manifest and plan remain unchanged. No provider
reservation, work attempt, finding observation or decision is created.

There are 69 distinct passing focused Rust checks, one existing ignored fixture,
a successful workspace build, all ten passing summary gates and a risk proxy
pass for 704 changed code files. The
[context goal assessment](../assessments/context-goal-reading-2026-10-10.md)
records exact evidence, retained failures and limitations. Evidence assignment
stays 66 of 110 tools, including seven excluded actions among 44 unassigned.
No maturity promotion or retirement occurs. Real-provider validation, scoped
omission, complete monorepo/TUI acceptance and all nine broad milestones remain
open. The live allowance is pending and work remains uncommitted on main.

### Bounded secret inspection and fresh live-test draft, October 10, 2026

The individual secret scanner audit found recursive unbudgeted collection and
completed standalone envelopes despite gaps or cap truncation. Shared scanner
logic now uses iterative cancellable collection, 100,000-entry and 512 MiB
content ceilings, conservative opened-file reservations, disclosed exclusions
and partial receipts retaining observations. Canonical options expose the new
limits. Existing exact-file Scan routing and context-free direct execution are
verified without crediting DAG metadata as dependency ordering.

Final J173 has 12 machine passes, zero failures and 22 authenticated captures.
The full transcript reader works across six sizes; actual compact paging reaches
inspection limits and gaps. Three explicit native scans retain four observations
over two signal-only findings. One human false-positive reason, JSON export and
no-color restart preserve source and accounting. Four scoped assistant judgments
remain separate from raw REVIEW_REQUIRED and operator approval false.

Thirty-nine distinct Core checks, workspace build, all ten summary gates and
the risk proxy for 715 changed code files pass. The
[secret module assessment](../assessments/secret-module-audit-2026-10-10.md)
records receipts, retained failures, interface and source-race limits. Evidence
assignment is now 67 of 110 tools; 43 remain unassigned including seven excluded
actions. No maturity promotion, retirement, source execution, commit or push
occurs. All nine broad milestones remain open.

The default OAuth credential remains expired and the old retry has no approved
allowance. A fresh current-source/configuration draft prepares one tool-free
GPT-6 Luna/low lesson job over owned labeled synthetic source. Proposed allowance
is two calls with one protected Review call and one Learning call. Requested
output tokens are not enforceable as a ceiling; dollars remain unknown. Exact
renewal/launch approval is pending. Preparation makes no provider request and
changes no operator model configuration.

### Shared native limits and approved live synthesis, October 10, 2026

The operator supplied standing approval for the discussed implementation,
authentication, bounded model tests and normal Git updates. Stored OAuth refresh
failed, browser login renewed authentication, and the exact prepared one-job
lesson retry completed once. Durable accounting records one committed request,
zero unresolved reservations and one protected Review call remaining. GPT-6
Luna used low reasoning. The draft retains the synthetic source limitation and
remains unaccepted; source and operator configuration are unchanged. Output
and dollar ceilings are not claimed. See the
[live lesson assessment](../assessments/live-lesson-retry-2026-10-10.md).

Four canonical SAST options now freeze secret entry, content, file and finding
limits. Unused settings fail during shared preparation. One scanner shares its
allowances across roots, records original limits and cumulative consumption,
and exposes the same receipt through JSON and terminal output. Tests cover
atomic accounting and concurrent entry refusal. Existing public constructors
and native defaults remain available.

Native J174 exposed and corrected all-partial study handoff: persisted partial
receipts now permit explicit partial Scan acceptance, while retry-exhausted jobs
remain failed and complete-pass counts stay zero. Final J174 has 24 machine
passes, zero failures and 44 authenticated captures. Six-size Settings and
actual compact paging precede approval. Three fixed partial attempts retain
three observations, an explicit fixture false-positive decision, selected-study
export and no-color restart with zero provider requests. Assistant judgments
remain separate from raw REVIEW_REQUIRED and operator approval false.

The [settings assessment](../assessments/secret-settings-parity-2026-10-10.md)
records 76 distinct focused Rust checks, build/risk evidence and retained
failures. The batch-filtered list still omits incomplete observations; direct
finding access works, and fixing that list is next. The registry remains 110
tools with evidence assigned to 67; no module is promoted or retired. All nine
broad milestones and complete real-model/reference-quality acceptance remain
open. The newer remote Map keyboard fix is being integrated after preserving
this checkpoint on main.
