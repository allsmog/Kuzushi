# TUI integration recovery

The broader TUI check exposed two input ownership defects. Catalog refresh
could consume `r` while a prerequisite prompt was waiting. Review also offered
`G` for both the final row and the groups reader. Prerequisite prompts now own
their choice keys before contextual navigation. Review uses `g` for the first
row, `End` for the final row, and `G` for groups. The footer prioritizes these
controls, and other phase pages retain their existing navigation.

Old integration fixtures also assumed that supporting `context:build` output
completed Map, Ask immediately dispatched an unapproved agent, `full` bypassed
Setup, and Scan opened the generic picker. Those expectations now follow the
implemented workflow. Accepted-context fixtures import a real context artifact;
the journey test stores observations and a human decision in the ledger. Phase
navigation still starts no work. Plain Review checks the persisted decision and
its session association as well as its updated receipt text.

Validation:

- 57 focused tests passed, covering Map selection, context isolation, scan
  membership, plain decisions, Ask planning, Setup, navigation and footer keys.
- The locked workspace build and all ten quick summary gates passed. The risk
  gate covered 434 changed code files relative to `origin/main`.
- After the footer refinements, 32 focused input/navigation tests and two
  renderer tests passed. These overlap the earlier 57-test run and are not
  additional unique coverage.
- The final isolated native build includes the shorter filter label and physical
  End-key classification. Its SHA-256 is
  `1030c7b8e65c16a126854fe050331581a4de4072d4d9cd8f4bdbbcacc6cca49a`.
- J215 recorded 39 machine passes, zero failures and 32 captures across six
  sizes and no-color restart. It performed one intercepted provider request,
  zero live requests, and preserved the accepted context and finding decisions.
  Three raw human judgments remain open. The assistant capture review is
  separate and records `operatorApproved: false`.
- J223 recorded 22 machine passes, zero failures and 16 captures across six
  sizes and no-color restart. Its assertions check both `End last` and
  `G groups` at 120 columns and wait for actual group rows. Three human judgments
  remain open. The separate assistant review records `operatorApproved: false`.
  The owned fixture retained three observations, zero decisions, zero provider
  requests and unchanged source. Target source was never executed.

Evidence is under `/tmp/kuzushi-tui-integration-20261012`. The J215 run is
`question-tui/20261012-203339/J215`. The first J223 run is retained under
`navigation-tui/20261012-204151/J223`: row and group navigation passed, but its
completion assertion incorrectly expected a log message on the main view. The
corrected journey inspects Logs after the deterministic prerequisite completes.
The final run is `navigation-footer-tui/20261012-211829/J223`. Intermediate
receipts remain available, including a 20-pass run that did not check visible
footer controls and a later run that exposed the missing groups hint.

An additional presentation issue remains: the deterministic Map prerequisite
run starts with generic `calling model` activity text, although its completion
receipt correctly states that no model call occurred. The native fixture
confirms zero provider reservations. Correcting that initial activity label is
separate remaining work; the recorded zero-call result does not justify it.

Capture review also identified compact-footer discovery work. At 80 and 60
columns, both row-end and group shortcuts disappear from the footer; at 40
columns, groups remains visible while row-end does not. `/keys` stays available.
After restart, a pending Map result replaces the Review footer with its own
actions. The keys still work, but the local navigation is harder to discover.

The shared build cache disappeared during a disk-space failure. Validation
recovered using an isolated build directory with debug information and
incremental compilation disabled. No unrelated cache was intentionally removed.

Final formatter and direct local risk/docs checks are recorded separately. The
package-manager invocations could not fetch their pinned version for signature
verification; the same checked-in Node scripts were run directly without changing
package-manager security settings. The copy lint covered the changed navigation
labels: no positioning, banned-word, jargon, typography or honesty findings.
The skill's Liminal-specific product vocabulary does not apply to Kuzushi.

The verification receipt is dirty, drifted during execution, remains unsigned,
and predates the final footer adjustment. Final targeted checks and native
navigation evidence are recorded separately. This is a focused integration
increment. The full TUI suite has not passed: the earlier broad attempt was
incomplete and included a compatibility proof-fixture failure outside this
scope. No claim is made that the full delivery plan or reference-product parity
is complete. The live provider allowance remains exhausted at six requests.

## Navigation follow-up

The three gaps above now have implementation changes. Explicit Review navigation
no longer inherits result keys from an unresolved Map attempt. Derived navigation
can still recover an unresolved result, preserving the existing acceptance path.
Compact idle Review uses two rows for filter, detail, group and last-row controls.
Paged ledgers retain their next/previous controls as the priority, and active work
retains cancellation controls. Prepared tool activity uses the registry's resolved
runtime requirement, so deterministic Map starts with `running tool`.

Five targeted regressions and the wider 78-test footer/result-control suite passed.
The native follow-up at `navigation-followup-tui/20261012-215206/J223` records 40
machine passes, zero failures and three open human judgments. Its 16 captures
cover all six sizes and no-color restart. The assistant reviewed compact layouts,
the deterministic activity receipt, restored Review and actual group rows in a
separate record with `operatorApproved: false`. The fixture records no provider
requests, no decisions, unchanged source and no source execution.

That intermediate native run used SHA-256
`17191029e436e4dfa76a88e1f69c69299eb50f1b65467966fbe6b0176d44a5a1`.
The final run, `navigation-final-tui/20261012-220725/J223`, uses SHA-256
`c74dff513fd3a127d5d815660265c20dd867320f40d1745349f7c54d99bbfa36`.
It records 48 machine passes, zero failures and 20 captures. It additionally
pages forward/back at 40x12 and clears the filter to restore ordinary navigation.
Three human judgments remain open, with a separate assistant capture review.
The cancellation guard passed 42 focused checks; the final pagination and
navigation run passed 20 tests. These runs overlap and must not be summed as
unique coverage. Native build, formatter and the 434-file risk gate passed.

The broader TUI run finished on the preceding build: 4,263 passed, 27 failed,
eight ignored and one filtered out in 1,110.69 seconds. Full output is
`tui-supported-regression.log`; the failure index is
`tui-supported-regression-summary.json`. Its known compatibility
proof-fixture failure was explicitly excluded. The process-group test failed
inside the restricted sandbox and passed when rerun with permission to inspect
its own temporary child through `ps`. Its pagination failure prompted the now
verified guard. Other failures remain in legacy dispatch expectations, phase
navigation, renderer snapshots and pane-boundary checks. The boundary check found
14 unaudited panic sites in context-generation, context-history, context-matrix,
study-config and source-review presentation. These require implementation review;
adding them to an allowlist is not the proposed resolution. This does not
establish a passing full TUI suite.

The next focused repair is the 14 pane panic sites identified by
`boundary_lints::tests::pane_facing_code_stays_free_of_unaudited_panic_sites`.
Then inspect the in-scope failed dispatch fixtures against prepared allowance
admission, and reconcile obsolete Ask/Scan and renderer expectations with actual
behavior. The raw run also includes failures for excluded proof/patch paths;
those remain outside implementation scope. Keep their failure evidence rather
than silently treating the complete suite as passing.

## Pane recovery and context regeneration

The 14 presentation panic sites are removed without adding lint exceptions.
Renderers and summaries receive already checked state rather than looking it up
again. Missing guidance editors preserve saved input across typing, paste and
save attempts, and Escape returns to the plan. Missing study readers show a
recovery message instead of an indefinite loading state. Malformed comparison
payloads remain visible as invalid data; they cannot claim unchanged text. The
source-review reason reader also tolerates an invalid selection without choosing
a substitute verdict or recording a decision.

The focused pane, context-generation, regeneration, matrix, history and
source-review run passed 69 tests, including the pane-boundary lint. New recovery
tests cover six terminal sizes and plain output. The native build and formatter
passed; the risk gate passed for 437 changed code files. No additional live
provider allowance was used.

J107 at `pane-state-tui/20261012-222516/J107` recorded 45 machine passes, zero
failures and 36 captures. Its binary SHA-256 is
`aab685268c56c642dac8c886599ce4da71a81f80da763ec93fe806eb7e61ea8c`.
The six-size and no-color restart run preserves multiline guidance, freezes one
context job, requires separate plan/allowance approval and launch, compares an
inactive generated revision with its exact parent, and recovers that result
without repeating work. The fixture records one intercepted request, zero live
requests, unchanged original contexts and source, no source execution and zero
discovery jobs started. The generated text is explicitly labeled synthetic.

The assistant reviewed 16 captures separately. Seven human judgments remain
open and `operatorApproved` remains false. The result reader still repeats some
preparation guidance after completion, a remaining copy and hierarchy issue.
These checks do not establish complete workflow acceptance or reference-product
parity.

Three obsolete test expectations now follow the current workflow: inline Ask
requires accepted context, accepting an Ask proposal opens its unapproved
question form, and `/scan` opens a finite study instead of the generic picker.
The question and navigation run passed eight tests. The fixtures retain checks
that no worker starts, the question text and context reference survive, and no
prepared receipt is fabricated. The Scan test also checks three passes, one
worker, one attempt and no allowance approval. These changes affect tests only;
they do not weaken runtime admission.

The final Scan-default recheck, locked workspace build, formatter, architecture,
model-policy, private-context and documentation gates passed. The risk gate
still passes for 437 changed code files, and its 15 helper tests pass. Detailed
results are in `pane-state-checks.json` and `pane-final-local-gates.json` under
the evidence root. Changes are staged on main without a commit or push.

Remaining broad-suite work includes the in-scope prepared dispatch fixtures,
historical navigation fixtures and renderer expectations. Excluded proof and
patch execution failures remain recorded and outside implementation scope.
The full suite has not been rerun or declared passing. The native run predates
only the test-fixture changes above, with no subsequent production changes.

## Prepared dispatch and refusal recovery

The direct Map and Review test failures had two fixture causes: neither supplied
an approved allowance, and both used old bridges that waited for stdin EOF
instead of acknowledging request admission. The compatibility fixtures now use
explicit four-call allowances with two protected Review calls and the actual
stdio admission client to reserve and settle synthetic requests. Their adapter
scripts live outside the repository being inspected, so Map no longer mistakes
its test adapter for an application entry point. These tests exercise direct-tool
compatibility, not fixed campaign qualification or live model quality.

Prepared model-backed tools now start with `preparing model work`, avoiding a
model-call claim before allowance admission. A refusal test verifies that the
bridge never starts. Nine focused tests passed, including successful Map artifact
creation and persisted Review classification with settled accounting. The
admission client tests also passed with no external requests.

The first native J224 run recorded 11 machine passes and no failures, but review
of its captures found real gaps. The blocked result was incorrectly reported as
contradictory, and the restart assertion matched the originating Review page
while the replay command was still a draft. That run is preserved at
`prepared-dispatch-tui/20261012-224550/J224` with an assistant review that does not
accept it as a completed replay check.

Result hydration now accepts canonical blocked, canceled and interrupted
statuses, retains older failed-envelope compatibility, and rejects mismatched
outcomes. Tests cover the status cross-product and load an actual persisted
refusal through authenticated hydration. Seven Core and six TUI checks passed;
these overlap earlier focused runs. Blocked continuation copy directs the
operator to the stated requirement instead of assuming an autonomy restriction.
J224 now requires the actual replay screen and exercises compact log expansion
and paging. An intermediate run's case-insensitive `REPLAY` assertion also
matched `inspect replay` on the originating page. That run remains recorded as
insufficient; the final assertion requires the distinct `── REPLAY` heading.

The final sequential J224 at `refusal-final-tui/20261012-225736/J224` recorded
17 machine passes, zero failures and 12 captures across six terminal sizes,
including no-color restart. Its native binary SHA-256 is
`db8c9e66810c6d2672cf5610e87649bd338d1daf8b6d344f6c9e484cb1ca39cd`.
The actual Replay capture restores the same blocked run with its authenticated
result. Fixture checks preserve three observations, zero human decisions,
unchanged source and zero provider requests. Source was not executed.

Assistant capture review confirms readable expanded logs at 40x12 and result
recovery after restart. The default 40x12 log shows only two transcript rows;
expansion and paging are needed to read the refusal. Repeated refusal text and
technical receipt details still crowd the result card. These hierarchy and
discoverability gaps remain open, as do three human visual judgments;
`operatorApproved` remains false.

The final receipt and hydration run passed 20 Core tests. Nine admission-client
tests, the locked workspace build and the CRAP-risk gate passed, with the gate
covering 441 changed code files. These checks supplement the overlapping focused
runs above; they are not a complete suite pass or reference-product parity.
The six-call live-provider allowance remains exhausted, with no additional
live requests in this increment.

## Result readability and compact Review

The shared result renderer now folds warning/error text that exactly repeats
the displayed summary, as it already did for preview text. Distinct messages
remain visible; stored diagnostics, counts and artifacts are unchanged. The
phase card combines its two Replay disclosures into one row while retaining
every source key. Short Review screens use the compact result summary so the
selected finding stays visible. Wider screens retain the expanded result.

The first resize run at `result-card-tui/20261012-231357/J224` captured cleared
frames immediately after resize. Its failed evidence is retained. Waiting for
the rendered heading recovered every size, but the next run's 30 passing
machine checks still hid a layout defect: the result crowded out findings at
60x20 and 80x24. That observation led to the compact Review budget and explicit
selected-finding assertions, rather than accepting the machine result alone.

Final sequential J224 at `result-card-keyboard-tui/20261012-232336/J224` records
34 machine passes, zero failures and 18 captures. It covers six sizes, opens
Replay directly from the 40x12 result, reads the expanded compact log, and
restores the same blocked run after a no-color restart. Three observations,
zero decisions, unchanged source and zero provider requests are preserved.
The native binary SHA-256 is
`2561146fa3df5d025544f82b386e4d9dbe64877b065d96b19d0c399381cf4482`.

Focused checks passed: 12 Core presentation tests, 33 phase-result tests,
15 final header tests, two Review navigation tests and six failure-snapshot
checks. The six stored failure snapshots were compared and reviewed before
replacement, retaining their recovery actions and unknown-cost disclosures.
The locked workspace build, narrow formatter and risk gate passed; the risk
gate covers 445 changed code files. Changed copy passed the scoped register
review. No additional live allowance was used.

Four human visual judgments remain open. Compact Replay initially spends its
limited reading area on run metadata; paging is needed for the underlying
reason. Notice repetition, technical identifiers and the prompt's generic
navigation hint still need refinement. These results establish this recovery
increment, not full workflow acceptance or reference-product parity. The
broader regression backlog remains open.

## Outcome-first Replay and input ownership

Replay now moves the typed terminal outcome ahead of run identifiers and stream
metadata. The original cell is rendered once in the summary; all remaining
diagnostics, artifacts and timeline rows remain reachable. At 40x12, the initial
page now shows the blocked status and the beginning of its reason. Paging tests
retain the full text, Unicode and path spacing across the complete document.

The result prompt and footer reuse the dispatcher's current-page result check.
They name result actions while those actions own Navigate mode, preserve draft
clearing and configured bindings, and leave another phase's result out of the
current page's hint. An unresolved result retains its existing Escape priority
over notices; no input-dispatch behavior was changed.

Focused checks passed: 11 Replay/Trace reader tests, 29 phase-control tests,
30 keybinding tests and 11 prompt tests. The locked workspace build, formatter,
architecture, model-safety, private-context and risk checks passed. The risk
gate covers 447 changed code files. The initial new notice test expected the
wrong owner; its corrected version now presses Escape and verifies the existing
result-navigation behavior.

Sequential J224 at `replay-priority-tui/20261012-233902/J224` records 36 machine
passes, zero failures and 18 captures, including six sizes and no-color restart.
The 40x12 Open capture shows `Outcome · blocked` before metadata, and the prompt
and footer show the matching result controls. Fixture checks preserve three
observations, zero decisions, unchanged source and zero provider requests.
The native binary SHA-256 is
`87623f370f48eb6381858affb580332ceaabea7c694597c612121854696c27e3`.

Four human judgments remain open. Long reasons still need paging on the smallest
terminal, and notices can repeat information already on the result card. Broader
regression and full-flow qualification remain open. This increment does not
establish reference-product parity or consume additional live allowance.

## Offline Cargo audit and accurate resource preview, October 13

The stale shell-dispatch test expected a clean scan from a target with no
lockfile. Its replacement proves failed work, an authenticated failure receipt,
an empty ledger and no scanner invocation. A second test runs an owned offline
adapter through shell dispatch and checks stdin capture, isolated working
directory, offline arguments, the persisted signal and inspection limits. The
first negative fixture used an absent executable and correctly stopped at option
validation; the corrected fixture uses a valid adapter that must remain uncalled.

The native walkthrough exposed two misleading messages. Frozen single-condition
native discovery now shows zero model requests using the recorded plan and
shared runtime requirement. Local compute and scanner service costs remain
unestimated, and protected Review capacity remains reserved. Missing models and
unfrozen work never imply zero requests. The Report handoff says that review
decisions are recorded, without treating a deferred finding as non-actionable.
The changed copy passes the scoped register review.

Twenty-eight focused checks pass: two shell dispatch, six resource, 19 allowance
review and one journey destination check. The locked workspace build, formatting,
architecture, model-safety, private-context and risk gates pass. Risk checks
cover 447 changed code files. An initial size-gate failure was fixed by separating
the native projection from historical usage reading.

Final sequential J219 is
`cargo-native-paged-tui/20261013-000341/J219` under the evidence root. It records
48 machine passes, zero failures and 33 captures across six viewport sizes,
with no-color restart. Its binary SHA-256 is
`b724dc2b98c20747c8dbe74a933fec2870da8f9dd4a54efb326bb381b581fc46`.
Installed cargo-audit 0.22.2 uses a copied offline database containing 1327
authenticated source files. Three fixed jobs produce three observations and
one consolidated dependency signal. The manual deferred decision survives JSON
export and restart. Source and database hashes remain unchanged; provider
reservations remain zero; application source is never executed.

The preceding 42-pass baseline remains in `cargo-dispatch-tui`. A subsequent
43-pass, three-failure run remains in `cargo-native-final-tui`: its assertions
assumed all approval terms fit on the last page and matched a sentence across a
terminal wrap. J219 now reads both approval pages and checks the visible wrapped
text. No failed evidence was replaced.

Four human judgments remain open. Assistant review covers the missing-input
receipt, both approval pages, compact reports and restored Review. The smallest
Report requires paging; long identifiers, duplicate notices and stale workspace
chrome after fixture setup remain visible. Advisory database identity is still
not pinned by production. Native scope sets and matrices retain their existing
resource projections. Broader regressions, source applicability and complete
product/reference qualification remain open. No live request was added and no
broad milestone closes.

## Overlay ownership and current controls, October 13

Five renderer regression cases had stale expectations: targetless chrome,
experimental Go scanner wording, the suggestions title, explicit context-model
keys and the header retained beneath overlays. The overlay test now compares the
actual origin header and presses Escape, checking both the held draft and cursor.
That stronger assertion exposed a real defect: Theme Picker let the composer
consume Escape and clear its draft before closing. Theme now handles its close
key first, and the footer advertises that owner in both input modes.

Options also appeared as generic scrolling in the complete keymap, omitting
selection, editing and filter controls. Its keymap now consumes the same controls
as the Options footer, including the open field editor. The test opens the editor
through the advertised Enter action. These changes do not start work or change
stored tool options.

Fifty-seven focused tests pass: six aligned renderer checks, four keymap tests,
31 footer tests, the three-overlay return check, five keymap-reader tests and ten
option-browser tests. The locked workspace build, formatting, architecture,
model-safety, private-context and risk gates pass. Risk covers 449 changed code
files. The initial new keymap test was placed outside its test module; its compile
failure is retained and the test now lives with the existing cases.

Final sequential J222 is
`surface-controls-final-tui/20261013-002929/J222` under the evidence root. It has
48 machine passes, zero failures and 28 capture sets, covering six sizes and
no-color restart. The binary SHA-256 is
`6a5cbd23e20b9908b885961b14d70cc9ee982bdf4d07d2085d8a23f4ce83ad8c`.
The native flow opens Options help through the command palette, returns from
Theme to Logs with the held draft visible, preserves a canceled field draft,
and restores settings browsing after restart. The owned source remains unchanged;
no scanner, provider call, finding or run is produced.

Two failed native attempts remain preserved. Generic command entry first left
Options for Tools before opening Keymap. The next attempt used the internal
`theme-picker` variant name as a command; it was correctly rejected, while a weak
title match matched other content. The final journey uses the canonical `theme`
command, checks its specific theme-source text and checks the actual Logs origin.
The shared journey runner was not edited.

Four human visual judgments remain open. The native and unit checks establish
these control and recovery paths, not full product or reference parity. The
broader suite still needs supported-dispatch and canonical phase-snapshot work;
these focused passes do not replace that verification. No live allowance was
consumed and no broad delivery milestone closes.

## Scan admission and persistence fixtures, October 13

The old direct generic Scan test assumed model work could start without an
investigation allowance. Its shell bridge also predated the provider-admission
handshake and lived inside the target tree. The replacement uses separate owned
target and adapter directories, inert documentation, deterministic context through
shared prepared dispatch, explicit cached-context reuse and an approved fixture
allowance. The bridge returns one clearly labeled synthetic observation and has
no network fallback. No production scanner behavior changes in this increment.

The positive check requires an authenticated completed receipt, one durable raw
observation with its evidence and confidence preserved, exactly one settled
fixture request, zero unresolved reservations and both protected Review requests
remaining. Negative Scan and Review checks require a blocked authenticated
receipt, an untouched bridge marker and no findings. A fourth check covers honest
pre-admission activity wording. All four focused tests pass. These are admission
and persistence checks; they do not qualify detection quality or scoped discovery.

Final sequential J225 is
`scan-refusal-final-tui/20261013-004933/J225` under the evidence root. It records
28 machine passes, zero failures, 14 capture sets and three open human judgments.
The native binary is unchanged from the preceding increment, with SHA-256
`6a5cbd23e20b9908b885961b14d70cc9ee982bdf4d07d2085d8a23f4ce83ad8c`.
Its six-size journey checks the cached-context prompt, Scan's recorded engine
outcomes, Replay access and paging to the complete refusal at 40x12, existing
observations and no-color restart. The same blocked job survives restart with
three observations, zero decisions, zero provider requests and unchanged inert
source. The target is unversioned; this journey does not qualify SHA transitions.

The first native attempt omitted cached-context reuse. The second expected the
Review result-card title on Scan, which uses recorded engine outcomes. Both
failed captures remain preserved. The corrected journey passed before the final
run added a compact Replay paging assertion. Initial unit failures likewise
remain recorded: prerequisite approval was required, and persisted finding text
correctly included evidence and confidence beyond the synthetic title. The final
assertions retain those contracts rather than bypassing them.

The locked workspace build, narrow formatting, Python syntax, architecture,
model-safety, private-context and risk checks pass. The risk gate covers 449
changed code files. Checked-in verification scripts were invoked
directly; package-manager signature verification was not bypassed. No live
allowance was consumed. Broader supported regressions, phase snapshots, human
visual review and full reference parity remain open. No broad milestone closes.

## Source history and compact phase controls, October 13

Native source-history review exposed a compact-layout defect: a ready Map could
supply its DFD navigation hint and abbreviated footer while the operator was
reading Review at 40x12. The shared compact Map predicate now requires the active
page to be Map. Review retains its paging, return-to-list and prompt controls;
Scan retains its own controls. A regression starts with an accepted Map and
changes pages, so it exercises the artifact state that the targetless prompt
test missed. The first new test used an imported but unaccepted Map and correctly
failed its readiness assertion; the final test reuses the accepted Map fixture.

The older history-navigation test also used context indexing as a selectable
legacy phase result. It now records a labeled unavailable historical fixture
tool, preserving the contract that unknown historical tools remain readable
while context indexing stays supporting evidence. Failed legacy records do not
redirect the supported journey or start retries. No legacy executor is invoked.

Fifty distinct focused tests pass: eight investigation-navigation tests, six
decision-source projection tests, seven source-hydration tests, eleven prompt
tests and eighteen chrome-layout tests. The locked workspace build, formatting,
Python syntax, architecture, model-safety, private-context and risk gates pass.
The risk gate covers 449 changed code files.

Final sequential J144 is
`source-controls-final-tui/20261013-011453/J144` under the evidence root. It has
42 machine passes, zero failures, 35 live capture sets and six open human
judgments. The rebuilt binary SHA-256 is
`bc14a4301c0625fc55d77224818a1c1ac0983d257e104c3653a491116be5a762`.
The six-size journey includes bounded compact paging, local JSON/SARIF/Markdown
export and no-color restart. The corrected compact footer names Review's actual
controls and no longer advertises Enter DFD.

Four fixed offline static scans of an owned documentation example retain two
real commit identities, clean and dirty states, and distinct captured content
at the same SHA. The later missing observation preserves the finding and the
human deferral, with an explicit absence-does-not-establish-a-fix message.
Exactly three raw observations and two human decisions remain after export and
restart; provider requests are zero and target source is never executed. The
product repository's commit history is unchanged. Scratch Git commits exist
only inside the owned fixture.

Retained failed journeys document two fixture problems. The first expected the
old SELECTED FINDING title rather than the current identity and return control.
The next reached export but its Python read-only SQLite connection could not
open the WAL database before sidecars existed. The verifier now opens only an
existing database with SQL query-only enabled. It does not use immutable reads,
which could omit current WAL data, and its observation/decision counts remain
unchanged. Compact source-history checks now inspect all ten captured pages
instead of assuming the later commit appears on one fixed page.

This verifies recorded source history and the tested recovery path. It does
not establish that an absent finding is fixed, that historical decisions apply
to the current checkout, or that repository coverage is complete. Full live
qualification, remaining supported regressions, phase snapshots and reference
TUI parity remain open. Raw REVIEW_REQUIRED remains unchanged.

## Complete offline investigation and allowance resume, October 13

The complete journey found a real resume defect. After an operator increased
the shared allowance, the TUI appended `--resume` to `campaign batch`. That
controller rejects the flag and already owns plan checks and resumption. The TUI now
uses its exact controller contract, preserving the original jobs and attempts.
Other fixed study dispatchers retain their explicit resume behavior. A focused
regression constructs the actual launch arguments from a parked scan batch.

An expected allowance stop also appeared as a generic dispatcher failure. The
notice now states the completed and parked work and offers partial reporting or
review of the remaining plan and allowance. This projection requires matching
recorded queue reasons and the dispatcher's terminal explanation. An old parked
queue cannot hide a new source or execution error; a regression protects that
distinction. Reading the notice approves no work.

Source review had a separate labeling error: a successfully authenticated
frozen context object with no supplemental text appeared unavailable in the
overview. The overview now agrees with the exact-options view. Explicit
omission, legacy live selection and malformed references remain distinct.
Missing or tampered objects still fail authentication before a receipt can be
presented. No live context is substituted.

The canonical rendering fixture retained its fresh-Setup return flag after
being placed on a completed phase page. Clearing that test-only flag restores
the intended engagement chrome. All 30 canonical snapshots now compare
successfully; only four Review snapshots changed, adding the selected finding
identity to the header. A separate 18-snapshot test covers the supported
Map/Scan/Review subset. The 120 phase/size/profile buffers and 30 plain
projections also pass. Legacy phase readers were rendered without executing
their tools or changing their implementations.

Forty-six distinct focused checks pass: ten source-detail tests, six context
authentication tests, five rendering contracts, nineteen campaign tests and
six dispatcher-notice tests. The initial campaign run passed eighteen tests;
its process-group test required OS permission for inspecting an owned child.
That test passed when rerun with that permission. The locked workspace build,
formatting, architecture, model-safety, private-context and risk gates pass.
The final risk gate covers 453 changed code files.

Final sequential J121 is
`complete-flow-notice-tui/20261013-020432/J121` under the evidence root. It records
86 machine passes, zero failures, 71 authenticated live capture sets and
thirteen open human judgments. The native binary SHA-256 is
`f7dd8ba37be469163901094436aef468ac77c37313f167840277720d07c876b0`.
Its companion analysis binaries are included in the recorded bundle manifest.

The journey starts from fresh Setup, executes two deterministic preparation
jobs and one context job, accepts the generated Map, then approves three fresh
discovery passes. All passes bind the same immutable context and options. Two
passes complete under a five-call shared allowance, with two Review calls
protected. A specific six-call revision retains spending and resumes only the
original third pass. Exactly four intercepted requests, four raw observations,
two consolidated findings and three human decision records remain after
partial export, final export and no-color restart. There are zero unresolved
reservations and two protected Review calls remain. Provider responses are
fully intercepted, with no live network fallback or returned tool calls.
Target source is unchanged and never executed.

The FP decision survives a later missed observation. A rediscovered observation
retains its previous deferral and requests reassessment because its recorded
dirty source identity does not establish repository stability. The fixture
explicitly borrows a local commit identity without matching that commit's tree;
it makes no clean-source or fixed-finding claim. The earlier J144 receipts cover
actual distinct fixture commits. Global active context is unchanged.

Retained attempts identify stale Map and allowance row selections, obsolete
source-view navigation, missing companion executables in the isolated bundle,
the verifier's SQLite WAL access problem, and the real rejected resume flag.
The verifier now uses query-only SQL on an existing database and waits for a
resumed job to leave its old parked state. No live journey or protected runner
was edited. An earlier 84-check complete run remains recorded before the
allowance notice improvement. The initial snapshot candidate set and failed
assertions remain available alongside the final comparisons.

This establishes the tested offline workflow and recovery behavior. It does
not qualify live discovery quality, every module, complete repository coverage
or reference-product visual parity. Compact Report still requires paging;
historical run-cost detail includes unavailable or invalid records, and dollar
completeness is not claimed. All thirteen operator judgments remain open.
Raw status stays REVIEW_REQUIRED and operatorApproved stays false. Live usage
is unchanged at the previously exhausted six-request allowance. Product work
remains staged on main, without a commit or push.

## Context output ownership and Report cost records, October 13

Inspection of the completed journey traced its unreadable cost record to a
directory containing only `threat-model-output`. The context input parsers
generated an unrelated UUID for that directory even though execution already
had a canonical run identity. Run history correctly reported missing metadata.

The model-backed and deterministic parsers now share an output-path resolver
that uses the producing run's identity. The source-only prepared-dispatch
regression creates a real context artifact and verifies that history contains
exactly its one metadata-backed run. Explicit output paths and their alias
retain priority. Untraced library callers retain their historical generated
paths. Existing missing or malformed history remains visible.

Report now separates missing metadata from unreadable or invalid records.
Known zero, incomplete usage and unavailable cost remain separate. Missing and
invalid record counts appear when present, reducing empty error labels in the
ordinary report. Parent and child costs are still never summed into an
unsupported dollar total.

The artifact contract checker now follows both parsers through the shared
resolver and requires the canonical run identity and path helper. Two Node
tests exercise the actual sources and detect parser bypasses or detached
output resolution. Four Rust tests cover both parsers, overrides, untraced
compatibility and shared prepared dispatch. Five Report tests cover cost and
metadata categories, overlapping costs and invalid money. Initial test
failures exposed incorrect expectations about the response field and macOS
path canonicalization; those logs remain in the evidence root.

The locked workspace build, formatting, focused Biome checks, architecture,
model-safety, private-context, documentation and risk gates pass. The contract
checker was split after its first risk run exceeded the logical-line limit.
The final risk gate covers 457 changed code files. Two documentation phrases
from the previous increment were also corrected to pass the wording gate.

Final sequential J121 is `context-output-tui/20261013-022717/J121` under the
evidence root. It records 89 machine passes, zero failures, 72 authenticated
live capture sets across six sizes and no-color restart. Its native SHA-256 is
`e17b068e0af289788ffadbf97aa03451b1e051eed55e0f6ca06a937040b1cdd8`.
Every one of the 23 run directories contains metadata. The context output is
under its actual context job, and Report has no missing or unreadable record
warning. Its remaining incomplete and unavailable cost records are disclosed.

The same finite allowance stop, specific revision and original-job resume
still complete. Four intercepted requests produce four raw observations and
two consolidated findings. Three human decision records, zero unresolved
reservations and two protected Review calls remain after restart. Target
source and global active context are unchanged. No live provider request or
target-source execution occurred.

The thirteen operator judgments remain open. Raw REVIEW_REQUIRED is retained,
and operatorApproved remains false. This closes the observed output-ownership
defect; it does not establish complete coverage, live-model quality, full
module qualification or reference-product parity. Work remains staged on main,
without a commit or push.
