# Proof-Loop Playbook

Status: handoff/playbook.
Date: 2026-07-07.
Scope: Kuzushi work in this repo, mined from local coding-agent session summaries plus the successful HTB Last Resort debugging pattern.

This document defines the definitive operating principles to carry into future Kuzushi sessions. It is intentionally practical: every principle has a trigger, a required proof, an artifact to leave behind, and the dead end it prevents.

## North-Star Flag

The flag for Kuzushi is not a green build, a cleaner registry, or a polished audit. Those are receipts.

The flag is:

```text
Kuzushi reliably helps an operator discover, understand, prove, and act on real vulnerabilities through AI-assisted analysis and a trustworthy TUI.
```

Every proof loop should improve at least one part of that sentence:

- discovery recall: the right files and vulnerable sites are routed into context,
- proof quality: confirmed, likely, unverified, dismissed, and false-positive states are honest,
- false-positive control: safe decoys and dropped candidates are measured,
- TUI comprehension: the operator can see what is happening, why it matters, and what is proven,
- operator actionability: findings can be reproduced, triaged, patched, exported, or handed off,
- reproducible reporting: run artifacts, traces, and reports can be checked after the fact.

The small falsifiable ladder to this flag is:

```text
Can it route the right files?
Can it identify the exact vulnerable site?
Can it distinguish proof from a guess?
Can the TUI show the operator why to trust or reject it?
Can the operator reproduce, export, or act on it?
Can a fixture, contract script, snapshot, or eval gate catch regression?
```

## Problem Decomposition

Kuzushi's big problem is not "run AI over code." The hard problem is getting from a large, noisy codebase to a finding an operator can trust and act on. That decomposes into falsifiable hypotheses that must compose end to end.

### Hypothesis K1: Routing Finds The Right Context

Statement:

If Kuzushi routes the right files, functions, obligations, and prior deterministic scanner output into the review context, AI recall improves before reasoning even starts.

Falsifiers:

- A benchmark case contains the vulnerable file but the prepared context omits it.
- The file is included but the vulnerable function/site is absent from the slice.
- Deterministic signals such as Semgrep, CPG, LSP, recon, or prior scans exist but do not affect routing.

Proof artifacts:

- obligation ledger,
- routed-file/site-context metrics,
- eval fixture with expected vulnerable site,
- dropped-candidate log for missed or non-promoted signals.

Composes into:

Better discovery recall. Without this, later AI reasoning is guessing from the wrong context.

### Hypothesis K2: Bounded Reasoning Separates Real Bugs From Noise

Statement:

If the model reasons over bounded, vulnerability-relevant slices and tool evidence, it can separate real vulnerabilities from safe decoys and unsupported claims.

Falsifiers:

- A safe decoy is promoted as confirmed.
- A true vulnerable site is routed but not recognized.
- The model produces a plausible finding with no reproduction, trace, or corroborating evidence.

Proof artifacts:

- safe decoy fixtures,
- false-proof-rate gate,
- confirmed/proven-on-target metric,
- dropped-candidates review.

Composes into:

Proof quality and false-positive control. Without this, Kuzushi becomes a confident report generator instead of a vulnerability discovery tool.

### Hypothesis K3: Proof State Is A First-Class Product Axis

Statement:

If proof state is modeled and rendered separately from severity, an operator can prioritize confirmed exploitable findings over high-severity guesses.

Falsifiers:

- A CVSS-high unverified finding outranks a confirmed exploitable finding without explanation.
- Workbench list and detail views disagree about confirmation state.
- Export/report output drops proof state.

Proof artifacts:

- finding model proof-state projection,
- Workbench list/detail snapshot,
- sort/filter tests for confidence,
- export/report fixture showing the same proof vocabulary.

Composes into:

Operator trust. Without this, the TUI hides the most important distinction: "we know" vs "we suspect."

### Hypothesis K4: The TUI Makes Vulnerability Work Operable

Statement:

If the TUI shows status, evidence, proof state, key actions, and next steps honestly, an operator can move from discovery to triage, verification, patching, export, or handoff without losing context.

Falsifiers:

- A visible glyph, chip, footer, or action does not match the real state.
- A keybinding silently no-ops.
- The operator cannot tell which work is active, ambient, failed, or complete.
- A finding is visible but not actionable.

Proof artifacts:

- Workbench snapshots,
- key-handler tests,
- actionability tests for open, verify, patch, export, mark FP, and handoff,
- plain-output parity where relevant.

Composes into:

TUI comprehension and operator actionability. Without this, real findings still die at the interface.

### Hypothesis K5: Reports And Run Artifacts Preserve The Proof

Statement:

If traces, run artifacts, exported reports, and compatibility docs preserve the same proof state and evidence chain, the work remains reproducible after the live session ends.

Falsifiers:

- A finding is confirmed in the TUI but exported as an undifferentiated issue.
- Trace numbering or append semantics overclaim ordering.
- A run cannot be replayed or audited after completion.
- Public docs advertise behavior the code no longer has.

Proof artifacts:

- trace/replay tests,
- report/export fixtures,
- docs/contract scripts,
- run artifact replay smoke.

Composes into:

Reproducible reporting. Without this, Kuzushi may catch a vuln once but fail to hand it to a human process.

### Composition Rule

The flag only appears when a story crosses the whole chain:

```text
input target -> routed vulnerable site -> real finding -> honest proof state -> comprehensible TUI -> operator action/export -> reproducible artifact
```

Each future work item should name which hypothesis it is testing and which downstream hypothesis it unlocks.

## Frontend And Pipeline Subproblems

The two highest-risk areas for Kuzushi are the TUI and the vulnerability data pipeline. Treat them as separate proof surfaces, but never validate either in isolation for long. The flag requires the pipeline to produce trustworthy state and the TUI to make that state operable.

### TUI Subproblems

#### K-FE-01: Entry State

Question:

Can an operator open the TUI and immediately tell which target/run/session they are looking at?

Small falsifier:

Start the TUI against a known fixture run and verify the header, active target, run status, and current mode match the underlying run metadata.

Evidence:

- Workbench snapshot,
- fixture run metadata,
- focused TUI test.

#### K-FE-02: Finding List Truth

Question:

Does every row in the finding list reflect the real finding model, not stale cache or display-only state?

Small falsifier:

Seed findings with different severity, confidence, proof state, owner, and status; verify the list renders the same distinctions and sort order as the model.

Evidence:

- list snapshot,
- sort/filter unit test,
- FindingStore fixture.

#### K-FE-03: Proof-State Visibility

Question:

Can the operator visually distinguish confirmed, likely, unverified, dismissed, and false-positive findings before opening details?

Small falsifier:

Load one finding per proof state and verify the visible chips/glyphs/text do not collapse them into severity-only ranking.

Evidence:

- Workbench row snapshot,
- proof-state projection test.

#### K-FE-04: Detail Pane Evidence

Question:

Does opening a finding show why it exists?

Small falsifier:

Open a routed finding and verify the detail pane shows source file, sink/site, reasoning summary, scanner/model evidence, reproduction status, and next available action.

Evidence:

- detail snapshot,
- fixture with expected evidence fields.

#### K-FE-05: Action Wiring

Question:

Do visible actions actually mutate the backend state or run the intended command?

Small falsifier:

Trigger verify, patch, export, mark false-positive, dismiss, and handoff actions from the TUI and assert the resulting store/event/export state changes.

Evidence:

- key-handler tests,
- before/after store event,
- exported report diff.

#### K-FE-06: Disabled And Error States

Question:

Does the TUI prevent impossible actions and explain failed ones?

Small falsifier:

Render an unverified finding without reproduction data and ensure unavailable actions are disabled or routed to a clear next step; then simulate a failing backend command and verify the error is visible.

Evidence:

- disabled-state snapshot,
- failing-command test.

#### K-FE-07: Live Progress Truth

Question:

Can the operator tell what work is active, queued, complete, failed, or ambient?

Small falsifier:

Inject lifecycle events for routing, model review, verification, and export; verify the footer/status panels change without inventing progress.

Evidence:

- lifecycle event fixture,
- TUI status snapshot,
- event-to-view projection test.

#### K-FE-08: Navigation And Focus

Question:

Can an operator move through targets, findings, evidence, actions, and logs without losing context?

Small falsifier:

Run a keyboard-only smoke over list navigation, detail opening, action menu, search/filter, and back/escape behavior.

Evidence:

- keybinding test,
- terminal capture or snapshot.

#### K-FE-09: Plain Output Parity

Question:

Does non-TUI output preserve the same core truth as the TUI?

Small falsifier:

Compare a TUI finding view with JSON/plain/report output and verify proof state, evidence, and actionability are not dropped.

Evidence:

- JSON/report fixture,
- parity assertion.

#### K-FE-10: Regression Harness

Question:

Will a future UI change catch state drift before it reaches an operator?

Small falsifier:

Change a fixture proof state or action availability and confirm a focused TUI snapshot/test fails.

Evidence:

- `cargo test -p kuzushi-tui workbench -- --nocapture`,
- fixture diff.

### Vulnerability Pipeline Subproblems

#### K-DP-01: Target Intake

Question:

Does Kuzushi know what target it is analyzing?

Small falsifier:

Point Kuzushi at a fixture repo and verify language, package, entrypoint, manifest, and scan scope are captured before any model review starts.

Evidence:

- target manifest,
- intake smoke.

#### K-DP-02: Deterministic Signal Capture

Question:

Are Semgrep, CPG, LSP, recon, prior scans, and other deterministic signals captured with provenance?

Small falsifier:

Run a fixture with known deterministic hits and verify each signal appears in the obligation ledger or routing input with source and timestamp.

Evidence:

- obligation ledger,
- scanner-output fixture.

#### K-DP-03: Routing Slice Formation

Question:

Does routing include the vulnerable file, vulnerable function, and relevant adjacent context without flooding the model?

Small falsifier:

Use a known vulnerable fixture and assert the final slice contains the vulnerable site and excludes irrelevant bulk.

Evidence:

- routed slice artifact,
- expected-site assertion.

#### K-DP-04: Dropped Candidate Accounting

Question:

Do we know what the pipeline chose not to promote?

Small falsifier:

Feed mixed true positives, safe decoys, and low-signal candidates; verify dropped candidates are logged with reasons.

Evidence:

- dropped-candidate log,
- decoy fixture.

#### K-DP-05: Model Review Contract

Question:

Does the model receive bounded evidence and return structured claims instead of prose-only findings?

Small falsifier:

Run a model-review fixture and validate the output schema includes site, class, evidence, confidence, proof status, and reproduction needs.

Evidence:

- review JSON fixture,
- schema validation.

#### K-DP-06: Finding Normalization

Question:

Do duplicate or variant findings collapse into one stable operator object?

Small falsifier:

Emit the same bug from Semgrep, model review, and manual verification and assert the store merges them without losing provenance.

Evidence:

- FindingStore fixture,
- dedup test.

#### K-DP-07: Proof-State Transition

Question:

Can a finding move honestly from unverified to likely to confirmed or dismissed?

Small falsifier:

Apply reproduction success, reproduction failure, manual dismissal, and false-positive marking events; verify the final state and history are both preserved.

Evidence:

- event-log fixture,
- state-transition test.

#### K-DP-08: Persistence And Replay

Question:

Can a run be closed and reopened without losing the evidence chain?

Small falsifier:

Write findings and events, reopen the store, and replay into the same TUI/report state.

Evidence:

- event-log replay test,
- reopened store snapshot.

#### K-DP-09: TUI Subscription Boundary

Question:

Does the TUI update from real store/runtime state rather than its own invented view model?

Small falsifier:

Mutate a finding through the store and assert the TUI updates proof state, action availability, and counts from the emitted event.

Evidence:

- store-to-TUI projection test,
- cache invalidation test.

#### K-DP-10: Export And Handoff

Question:

Can a human reproduce or act on the result outside the live Kuzushi session?

Small falsifier:

Export a confirmed finding and verify the report includes target, vulnerable site, proof, reproduction, evidence, state, and next action.

Evidence:

- report fixture,
- export contract test.

#### K-DP-11: Eval Gate

Question:

Does the pipeline catch regressions in discovery recall and false-positive control?

Small falsifier:

Run a small benchmark pack with known true bugs and known decoys; require routed-site recall and false-proof rate to stay within threshold.

Evidence:

- eval scoreboard,
- fixture pack,
- regression gate.

### Atomic Wiring Ledger

Use this ledger when a session feels too broad. Each row should be independently falsifiable.

#### TUI Atoms

| ID | Atomic problem | Small falsifier |
| --- | --- | --- |
| K-FE-A01 | The active target label comes from run metadata. | Rename fixture target; header changes without editing UI code. |
| K-FE-A02 | The active run/session id is visible or inspectable. | Load two runs; UI cannot confuse which one is active. |
| K-FE-A03 | Empty state is truthful. | Empty store says no findings, not scan complete unless complete event exists. |
| K-FE-A04 | Loading state is distinct from empty state. | Delay store load; UI shows loading, not no findings. |
| K-FE-A05 | Failed load has a visible error. | Corrupt fixture store; UI reports load failure. |
| K-FE-A06 | Finding row id is stable. | Reorder findings; selection remains on same finding id. |
| K-FE-A07 | Severity label maps from model enum. | Change severity in fixture; row updates exactly once. |
| K-FE-A08 | Proof-state label maps from model enum. | Change proof state in fixture; chip/text updates exactly once. |
| K-FE-A09 | Status label maps from workflow state. | Mark dismissed; row leaves active bucket. |
| K-FE-A10 | Confidence is not implied by severity. | High-severity unverified finding stays visibly unverified. |
| K-FE-A11 | Confirmed proof outranks equivalent guesses according to one ranking policy. | Sort fixture with confirmed medium and guessed high; order matches the shared ranking policy source. |
| K-FE-A12 | Filter count matches filtered rows. | Apply proof-state filter; visible count equals rows. |
| K-FE-A13 | Search uses finding text and source fields. | Search for sink filename; expected finding remains. |
| K-FE-A14 | Detail pane opens from selected row id. | Select second finding; details do not show first finding. |
| K-FE-A15 | Source location is clickable or copyable. | Fixture has file/line; action exposes that exact location. |
| K-FE-A16 | Evidence list preserves provenance labels. | Scanner/model/manual evidence are visually distinct. |
| K-FE-A17 | Reproduction status is explicit. | Finding without repro is not shown as proven. |
| K-FE-A18 | Verify action is enabled only when inputs exist. | Missing repro command disables verify or routes to next step. |
| K-FE-A19 | Patch action is enabled only when patch path exists. | No patch candidate means no fake patch action. |
| K-FE-A20 | Export action writes the current finding state. | Export after marking FP includes FP state. |
| K-FE-A21 | Mark false-positive writes a store event. | Trigger action; event log gains one FP event. |
| K-FE-A22 | Dismiss writes a different event than false-positive. | Trigger dismiss; exported history does not say FP. |
| K-FE-A23 | Action failure is visible. | Force backend command failure; UI shows the failure. |
| K-FE-A24 | Keybindings call the same command path as buttons. | Key action and menu action produce same event. |
| K-FE-A25 | Focus returns after modal/action close. | Close action menu; selected finding still focused. |
| K-FE-A26 | Footer progress reads lifecycle events. | Emit review-start/review-done; footer changes accordingly. |
| K-FE-A27 | Ambient work does not look complete. | Emit background task; UI marks ambient/active, not done. |
| K-FE-A28 | Stale cache invalidates on store event. | Mutate store; UI row changes without restart. |
| K-FE-A29 | Plain output and TUI share vocabulary. | Same fixture renders same proof-state names in both outputs. |
| K-FE-A30 | Snapshot fixture can fail on a visual truth regression. | Break proof-state mapping; TUI snapshot/test fails. |

#### Pipeline Atoms

| ID | Atomic problem | Small falsifier |
| --- | --- | --- |
| K-DP-A01 | Target root is canonicalized. | Pass relative path; manifest stores canonical target root. |
| K-DP-A02 | Ignored paths are excluded before routing. | Add vuln-looking file under ignored path; it is not routed. |
| K-DP-A03 | Language detection is persisted. | Fixture language appears in manifest and downstream run metadata. |
| K-DP-A04 | Package/build metadata is captured when present. | Add package file; manifest records it. |
| K-DP-A05 | Scanner invocation is recorded. | Run Semgrep/CPG/LSP wrapper; command/version appears in artifact. |
| K-DP-A06 | Scanner findings keep source provenance. | Scanner hit includes tool, rule, file, line, timestamp. |
| K-DP-A07 | Prior scan imports are not treated as fresh proof. | Imported finding is tagged imported/stale until revalidated. |
| K-DP-A08 | Obligation ledger has stable ids. | Rerun fixture; same obligation gets same logical id. |
| K-DP-A09 | Routing slice includes vulnerable file. | Known vuln fixture fails if file omitted. |
| K-DP-A10 | Routing slice includes vulnerable function/site. | Known vuln fixture fails if only file-level context exists. |
| K-DP-A11 | Routing slice includes relevant caller/callee where needed. | Interprocedural fixture fails if adjacent function missing. |
| K-DP-A12 | Routing slice has a max-size guard. | Oversized target truncates with reason, not silent overflow. |
| K-DP-A13 | Dropped candidates keep reason codes. | Decoy dropped without reason fails ledger check. |
| K-DP-A14 | Model prompt receives structured evidence. | Fixture prompt contains site/evidence/provenance fields. |
| K-DP-A15 | Model output is validated against the output schema. | Missing site/proof field rejects the finding. |
| K-DP-A16 | Unsupported claims stay unverified. | Model says exploitable without proof; state remains unverified/likely. |
| K-DP-A17 | Safe decoy cannot become confirmed. | Decoy fixture promoted to confirmed fails gate. |
| K-DP-A18 | Duplicate findings merge by stable key. | Same file/sink/class from two tools becomes one finding. |
| K-DP-A19 | Merge preserves all evidence sources. | Deduped finding still lists both scanner and model evidence. |
| K-DP-A20 | FindingStore append writes exactly one event per mutation. | Mark FP once; event log has one mutation. |
| K-DP-A21 | Store reopen reconstructs current state. | Write events, reopen, compare state object. |
| K-DP-A22 | Proof-state transitions are monotonic where required. | Confirmed finding cannot silently revert to guessed without event. |
| K-DP-A23 | Verification success records command/output hash. | Successful repro stores proof artifact pointer/hash. |
| K-DP-A24 | Verification failure records failure, not dismissal. | Failed repro keeps finding active with failure history. |
| K-DP-A25 | TUI cache reads emitted events. | Emit proof change; workbench projection updates. |
| K-DP-A26 | Export reads store state, not stale UI state. | Mutate store then export; export reflects mutation. |
| K-DP-A27 | Report includes reproduction or reason absent. | Confirmed finding without repro detail fails export contract. |
| K-DP-A28 | Eval pack separates recall from false-proof rate. | Recall pass cannot hide decoy promotion. |
| K-DP-A29 | External model review is logged as advisory. | Fable/Claude note cannot become code truth without local proof. |
| K-DP-A30 | Regression gate is runnable in a small command. | Future session can run one focused command and get pass/fail. |

### Seam Contract And Critical Path

The frontend and pipeline ledgers are useful only if they share one contract. A green TUI fixture and a green pipeline fixture are insufficient if they use different ids, enums, event names, or proof-state rules.

#### K-SEAM-01: Shared Finding Contract

Question:

Is there one source of truth for the operator-facing finding object?

Small falsifier:

Rename or add a `Finding` field, proof-state enum, severity enum, evidence field, reproduction field, or action-availability field in the shared contract and verify both the pipeline code and TUI code fail or update together.

Evidence:

- shared contract/module path,
- compile or schema failure on drift,
- TUI and pipeline tests importing the same contract.

#### K-SEAM-02: Shared Fixture

Question:

Do the frontend and pipeline tests use the same canonical fixture, not parallel lookalikes?

Small falsifier:

Change one fixture finding id, proof state, evidence label, or action availability and verify the pipeline projection and TUI snapshot both observe the same change.

Evidence:

- canonical fixture path,
- store projection assertion,
- Workbench snapshot or TUI assertion.

#### K-SEAM-03: Join-Key Integrity

Question:

Does the id the operator selects in the TUI equal the id the store mutates?

Small falsifier:

Seed two similar findings, select the second in the TUI, trigger a mutation, and verify only the second finding id changes in the event log and export.

Evidence:

- selected id assertion,
- event-log mutation,
- export diff.

#### K-SEAM-04: Event Ordering And Gap Recovery

Question:

Can the TUI recover from out-of-order, replayed, missed, or reconnect-delivered events without inventing state?

Small falsifier:

Replay lifecycle/proof events out of order or with a missing sequence number and verify the TUI either reconciles from the store snapshot or shows a recoverable sync error.

Evidence:

- event sequence fixture,
- reconnect/replay test,
- visible sync state.

#### K-SEAM-05: Half-Written Run Recovery

Question:

What does the operator see if Kuzushi crashes or is interrupted mid-scan, mid-review, or mid-verification?

Small falsifier:

Stop a run after partial target intake, partial finding write, and partial verification write; reopen and verify the TUI shows partial/incomplete state without treating it as complete proof.

Evidence:

- interrupted-run fixture,
- reopened store state,
- Workbench partial-state snapshot.

#### K-SEAM-06: Confirmed Proof Gate

Question:

Is `confirmed` unreachable without a machine-checkable proof artifact?

Small falsifier:

Try to mark a model-only finding as confirmed without a reproduction command, external verifier result, proof artifact pointer, or output hash; the transition must fail or remain non-confirmed.

Evidence:

- proof-state transition test,
- proof artifact schema,
- export showing proof artifact or explicit absence.

#### K-SEAM-07: Ranking Policy Source

Question:

Does the list, detail view, export, and tests read one ranking policy?

Small falsifier:

Change the ranking policy source and verify TUI ordering, plain output ordering, and report ordering change together.

Evidence:

- ranking policy path,
- list/report parity test.

#### K-SEAM-08: Cancel And Resume Contract

Question:

Can long-running scan, verify, patch, or export work be canceled or resumed without lying about state?

Small falsifier:

Start a long action, cancel or interrupt it, reopen the run, and verify state is canceled/partial/retryable rather than complete or silently lost.

Evidence:

- lifecycle event fixture,
- resumed run smoke,
- TUI status assertion.

### Critical Path Order

Future sessions should move in this order unless there is a specific reason not to:

1. Define or inspect the shared `Finding` contract.
2. Create or update the canonical fixture.
3. Prove the pipeline can produce truthful store state and events from that fixture.
4. Prove the TUI renders that same fixture through the shared contract.
5. Prove one mutation crosses the seam from TUI action to store event to export.
6. Add per-side regression harnesses only after the seam is green.

Do not implement a TUI action against invented state. Do not implement a pipeline field without naming the TUI/export surface that consumes it.

### Kuzushi Wiring Rule

Every frontend item should name the pipeline field or event it renders. Every pipeline item should name the frontend or export surface where the operator sees it.

The smallest end-to-end proof is:

```text
fixture target -> deterministic signal -> routed vulnerable site -> structured finding -> proof-state event -> TUI row/detail/action -> export/report
```

## Why This Exists

The Last Resort session succeeded because the work was forced into small runtime proofs:

- "What is the quick test?"
- "Test it in its tiny chunk."
- "Where are we not confident?"
- "What would prove this specific assumption?"

The earlier Last Resort sessions failed when broad structural theories replaced route-specific evidence. Kuzushi has the same risk, but in product/architecture form: broad audits, long loops, external model reviews, stale docs, and large refactors can feel like progress while hiding untested assumptions.

The goal here is to make future Kuzushi work proof-shaped by default, but always in service of the north-star flag above. A tidy invariant that does not improve vulnerability discovery, proof, operator trust, or actionability is only local maintenance.

## Sources Mined

Agent session summaries reviewed (from the local agent-CLI memory directory,
`~/<agent-cli-home>/memories/rollout_summaries/`):

- `2026-05-29T12-41-12-dYla-delete_claude_cli_subprocess_runtime_langgraph_dispatch.md`
- `2026-05-29T12-42-11-JtYT-no_runtime_claude_cli_guard_eval_exception.md`
- `2026-06-01T13-36-26-m281-kuzushi_oauth_*_testing_and_doctor_interpretation.md`
- `2026-06-01T13-56-31-cuns-process_overload_diagnosis_and_stop_batch_scan.md`
- `2026-06-11T21-06-54-QrG6-anthropic_loop_boris_loop_goal_research.md`
- `2026-06-12T03-12-33-6uC4-kuzushi_discovery_architecture_end_to_end.md`
- `2026-06-24T02-01-16-Ppgx-claude_loop_24h_caffeinate_audit_hooks.md`
- `2026-07-03T23-15-47-5LPL-surface_cut_audit_implementation_and_contract_update.md`
- `2026-07-03T23-17-33-MCCA-product_vision_audit_review_and_stale_claim_fixes.md`
- `2026-07-04T02-50-15-4fs9-trace_ordering_liveness_doc_fix.md`
- `2026-07-07T13-57-47-RPz8-kuzushi_audit_remediation_main_push.md`

Repo handoff/progress files checked:

- `AGENTS.md`
- `docs/devex/new-contributor-map.md`
- `progress/kuzushi-whitebox-static.progress.md`
- `progress/kuzushi-overnight-polish.progress.md`
- `docs/plans/product-flow-prd.md`
- `docs/architecture/kuzushi-boundaries.md`
- `docs/api-compatibility.md`
- `backend-runtime-architecture.md`

## Definitive Principles

### 1. Claim Ledger Before Roadmap

Definition:

Every audit sentence, architecture suggestion, external-model recommendation, or user-reported concern must first become a claim with a local evidence status. Do this before treating it as a roadmap item.

Trigger:

- The user pastes an audit.
- A doc says something is missing, wired, unsafe, stale, or "structurally" true.
- An external reviewer gives architecture advice.
- A previous session summary claims a blocker or invariant.

Required proof:

Create a small ledger before changing code:

```text
Claim | Current evidence | Smallest falsifier | Confidence | Owner files | Gate
```

Use repo search first:

```bash
rg -n "<claim keyword>|<tool name>|<module id>|<old command>" .
git status --short
```

Acceptance artifact:

- A short table in the progress note, audit doc, or PR body.
- If the work is larger than one turn, create or update a `progress/*.progress.md` entry.

Prevents:

- Treating stale audit prose as current truth.
- Repeating Last Resort's mistake of turning route-specific facts into global facts.
- Broad fixes based on unverified "probably missing" claims.

Evidence from Kuzushi sessions:

- Product-vision audit review succeeded because stale claims about `recon:import`, patch review, `kz`, and `src/copilot/print.ts` were checked against current code before edits.
- Surface-cut audit succeeded because it separated clean cuts from folds and quarantines instead of deleting everything marked "hidden."

### 2. Tiny Falsifier First

Definition:

Before implementing the full solution, run the smallest test that could disprove the key assumption.

Trigger:

- A task depends on an assumption like "this path is current," "this event cannot strand liveness," "this tool is exact-invokable," "this warning is non-blocking," or "this loop is alive."

Required proof:

Ask and answer:

```text
What one command would make this claim false?
```

Examples:

```bash
pnpm dev -- doctor --target .
cargo test -p kuzushi-core modules::registry::tests
node scripts/check-deferred-surface-contract.mjs
cargo test -p kuzushi-tui trace_receiver_stays_installed_while_other_work_is_running
pgrep -lf "semgrep|kuzushi --plain scan"
```

Acceptance artifact:

- Record the command, result, and why it was the falsifier.
- Do not record only "tests passed"; name the assumption the test was checking.

Prevents:

- Big speculative implementation passes.
- External-model advice becoming untested work.
- "It launched" being mistaken for "it works."

Evidence from Kuzushi sessions:

- OAuth/agent-CLI work used `doctor` and `auth ping` style checks to separate expected warnings from blockers.
- Trace/liveness fix became precise after the user challenged exact doc claims about ordering and disconnect behavior.

### 3. Current-State Truth Sweep

Definition:

Before editing docs, public surfaces, registries, or architecture notes, establish what the repo currently does.

Trigger:

- Docs/audits mention commands, tools, modules, visible catalog rows, runtime behavior, or public product claims.
- Work involves `README.md`, `docs/api-compatibility.md`, `RELEASING.md`, module registry, CLI help, or examples.

Required proof:

For public command truth:

```bash
cargo run -q -p kuzushi-cli -- --help
cargo run -q -p kuzushi-cli -- scan --help
cargo run -q -p kuzushi-cli -- doctor --help
pnpm check:docs
```

For module/tool truth:

```bash
cargo test -p kuzushi-core modules
cargo test -p kuzushi-core modules::registry::tests
node scripts/check-deferred-surface-contract.mjs
node scripts/check-port-contract.mjs
```

For exact stale docs:

```bash
rg -n "<old command>|<old tool>|<old claim>" README.md docs examples .github
```

Acceptance artifact:

- A "current truth" section in the progress note or doc change.
- Public docs updated only after this sweep.

Prevents:

- Docs becoming aspirational.
- Legacy TypeScript/Ink-era examples leaking into current Rust guidance.
- Breaking exact-name compatibility when only catalog visibility should change.

Evidence from Kuzushi sessions:

- Overnight polish succeeded by first building a CLI truth baseline.
- Surface-cut implementation succeeded by updating registry, docs, release notes, and contract scripts together.

### 4. One Risk Cluster Per Change

Definition:

A work unit should fix one risk cluster at a time: trace numbering, liveness disconnects, registry visibility, patch review, auth/OAuth, packaging, docs drift, etc. Do not mix unrelated clusters unless one blocks verification.

Trigger:

- The task starts from a long audit.
- The code touches more than one bounded context.
- A verification command fails in an unrelated area.

Required proof:

Before editing, name the cluster:

```text
Cluster: <trace ordering | background liveness | registry surface | docs truth | packaging alias | model safety>
Files expected: <short list>
Focused gate: <command>
Out-of-scope: <explicitly ignored dirty files/failures>
```

Acceptance artifact:

- One commit-sized slice or one progress entry per cluster.
- If an unrelated compile blocker is fixed, call it out as unrelated and keep the fix narrow.

Prevents:

- Broad remediation drift.
- Accidental refactors while fixing an audit item.
- Losing track of which test proves which claim.

Evidence from Kuzushi sessions:

- The July 7 audit remediation was useful but broad; the summary itself says future audit fixes should be split into smaller batches per issue cluster.
- The surface-cut audit was cleaner because it had explicit buckets: clean cut, fold, quarantine, product decision.

### 5. Acceptance Gate Must Match The Claim

Definition:

The verification command should prove the specific behavior being changed, not merely show the repo still builds.

Trigger:

- Any implementation claim that can be checked with a focused test, contract script, fixture eval, or command-output check.

Required proof:

Choose the narrowest strong gate first, then widen only if needed:

```bash
cargo test -p kuzushi-core modules::registry::tests
cargo test -p kuzushi-core review_decision -- --nocapture
cargo test -p kuzushi-core triage -- --nocapture
cargo test -p kuzushi-tui workbench -- --nocapture
cargo test -p kuzushi-tui --test snapshots -- --nocapture
pnpm eval:kuzushi-whitebox-static
pnpm quality:crap-risk
pnpm check:docs
pnpm verify:pack
```

Acceptance artifact:

Record:

```text
Gate | Claim proved | Result | Residual risk
```

Prevents:

- "Cargo check passed" being used to prove product behavior.
- "Eval ran" being used to prove a new contract unless the fixture covers the contract.
- A broad final suite hiding the fact that the important assertion was never tested.

Evidence from Kuzushi sessions:

- Whitebox-static succeeded because every story had a deterministic story gate and a final full suite.
- Discovery architecture succeeded because it added metrics and `eval:gate`, not just architecture prose.

### 6. External Reviewer Output Is Input, Not Authority

Definition:

Fable/Claude/external reviewer output may propose hypotheses, architecture, or tests. It is not accepted until a local repo proof supports it.

Trigger:

- The user asks for fable/Claude/another model.
- A reviewer claims a bottleneck, architecture direction, or "world-class" change.
- A reviewer says something is impossible or structurally blocked.

Required proof:

Translate the reviewer result into local claims:

```text
Reviewer says | Repo claim | Local falsifier | Gate | Decision
```

Constrain reviewer prompts:

- Ask for the artifact shape.
- Ask for assumptions.
- Ask for falsifiers.
- Keep runtime/plugin guardrails explicit.

Acceptance artifact:

- A claim ledger that cites the reviewer output but resolves each claim with local evidence.
- No hidden `claude -p` or external CLI calls in runtime/plugin paths.

Prevents:

- Architecture drift.
- Long speculative branches.
- Reintroducing forbidden runtime behavior.

Evidence from Kuzushi sessions:

- Discovery architecture worked because fable's routing-miss vs reasoning-miss framing became concrete artifacts, eval metrics, and gates.
- Runtime guardrail sessions correctly allowed `claude -p` in eval/test but blocked it from runtime/plugin paths with a regression test.

### 7. Loop Supervision Requires Live Evidence

Definition:

A loop is not "running" until process state, sleep protection, and fresh output are all verified. A loop is not "done" until it runs its terminal audit/fix hook or writes a completion artifact.

Trigger:

- Long-running Claude/agent-CLI loops.
- Overnight work.
- Any "run every 30 minutes" or "/loop" task.

Required proof:

For each loop:

```text
script path
pid
caffeinate pid or equivalent sleep guard
fresh log timestamp
current state: running | sleeping | done | failed
completion marker
terminal audit command
```

Example checks:

```bash
ps -o pid,ppid,pgid,etime,command -p <pid>,<caffeinate_pid>
tail -n 40 <loop-log>
pgrep -fl "<exact script path>"
```

Acceptance artifact:

- A loop status table in the progress note.
- A final audit section when the loop exits.

Prevents:

- Mistaking launch for persistence.
- Stale logs being read as current progress.
- Loops consuming resources without end-state verification.

Evidence from Kuzushi sessions:

- The 24h loop session only became trustworthy after exact PIDs, `caffeinate` children, and fresh log timestamps were checked.
- Earlier launch methods were unreliable; the summary recommends exact script-path/PID/log verification.

### 8. Resource Envelope Before Heavy Work

Definition:

Heavy scans, evals, CPG generation, fuzzers, and loops need an explicit resource envelope and stop condition before launch.

Trigger:

- `semgrep`, `joern`, CodeQL, fuzzing, batch scans, multi-agent loops, or target-wide scans.
- The machine already has high load or a dirty long-running workspace.

Required proof:

Before launch:

```text
expected process tree
max runtime
max output/log path
stop command
what "healthy running" looks like
what "kill it" looks like
```

During diagnosis:

```bash
uptime
top -l 1 -n 25 -stats pid,command,cpu,mem,time,state,threads
ps aux -r | head -25
ps -o pid,ppid,pgid,user,stat,%cpu,%mem,rss,etime,time,command -p <pids>
df -h /
```

Acceptance artifact:

- Resource envelope in the progress note.
- If stopped, record process group and verification that it is gone.

Prevents:

- Semgrep/Joern overload.
- Huge logs or core dumps.
- Killing the wrong process.

Evidence from Kuzushi sessions:

- The overload session correctly identified the scan chain and killed the process group, not only the hot worker PID.
- Last Resort also reinforced this: heavy probes and cores had to be cleaned after the PoC was copied locally.

## Workflow Templates

### Template A: Audit Remediation

Use when the user pastes a long audit and asks to fix it.

```text
1. Read the audit.
2. Build a claim ledger.
3. Classify each item:
   - current bug
   - stale claim
   - product decision
   - compatibility fold
   - clean cut
   - needs separate design
4. Pick one risk cluster.
5. Name the focused gate.
6. Edit only that cluster.
7. Run the focused gate.
8. Update docs/contracts if the public surface changed.
9. Record remaining clusters.
```

Default gates:

```bash
git status --short
rg -n "<claim keywords>" .
cargo test -p kuzushi-core modules::registry::tests
node scripts/check-deferred-surface-contract.mjs
node scripts/check-port-contract.mjs
pnpm check:docs
```

Do not:

- Delete hidden tools just because an audit calls them hidden.
- Trust a stale assessment without current repo search.
- Mix unrelated lifecycle, persistence, registry, and UI refactors in one unbounded pass.

### Template B: Discovery / Architecture / Feature Build

Use when a reviewer or user asks for a "world-class" or end-to-end architecture change.

```text
1. State the vulnerability-discovery or operator-trust outcome.
2. State the bottleneck hypothesis.
3. Convert the architecture into artifacts.
4. Define measurable acceptance.
5. Add deterministic fixtures before broad runtime behavior.
6. Wire one thin end-to-end path.
7. Add a gate that can run without the model/network if possible.
8. Only then widen.
```

Good artifacts:

- vulnerable fixture or benchmark case
- ledger JSON
- fixture repo
- scoreboard JSON
- contract script
- schema
- static eval
- TUI snapshot or screenshot for operator comprehension
- generated report with known expected states

Good gates:

```bash
pnpm eval:kuzushi-whitebox-static
npm run eval:gate -- --scoreboard <scoreboard> <thresholds>
cargo test -p kuzushi-core <feature-filter>
cargo test -p kuzushi-tui workbench -- --nocapture
cargo test -p kuzushi-tui --test snapshots -- --nocapture
pnpm quality:crap-risk
```

Do not:

- Ship only a spec.
- Let external reviewer prose become acceptance criteria.
- Add hidden runtime model paths to make a demo work.
- Count a "found issue" as success unless the vulnerable site, proof state, and operator-facing action path are all named.

### Template C: Public Surface / Docs Truth

Use for README, commands, module docs, release notes, registry visibility, and examples.

```text
1. Run current command help.
2. Search stale command names.
3. Identify source of truth.
4. Update docs and code together.
5. Run docs and contract checks.
6. Record exact-only compatibility names.
```

Default commands:

```bash
cargo run -q -p kuzushi-cli -- --help
cargo run -q -p kuzushi-cli -- scan --help
cargo run -q -p kuzushi-cli -- findings --help
cargo run -q -p kuzushi-cli -- doctor --help
pnpm check:docs
node scripts/check-port-contract.mjs
```

Do not:

- Claim a command exists because a historical doc says so.
- Change a public tool name without `RELEASING.md` and compatibility docs.
- Document `depends_on` or DAG metadata as execution behavior unless the executor consumes it.

### Template D: Runtime / Model / External CLI Guardrail

Use for LangGraph, model runtime, OAuth, Claude/agent-CLI integration, or plugin behavior.

```text
1. Search for direct CLI spawns and runtime dependencies.
2. Classify allowed contexts:
   - runtime/plugin: blocked
   - eval/test: allowed when explicit
   - docs: allowed as historical or user-facing instructions
3. Add or run guardrail tests.
4. Verify packaging if dependencies changed.
```

Default commands:

```bash
rg -n "claude -p|spawn\\(|exec\\(|@anthropic-ai/claude-agent-sdk|LangGraph" .
node --test test/no-runtime-claude-cli.test.mjs
node scripts/check-model-safety.mjs
pnpm verify:pack
pnpm check:docs
```

Do not:

- Add hidden CLI subprocesses under runtime/plugin paths.
- Add hardcoded model fallbacks.
- Treat OAuth warning output as a hard failure without checking `doctor` summary and intended auth mode.

### Template E: Trace / Persistence / Liveness Correctness

Use for run artifacts, trace ordering, terminal events, receiver teardown, and background workers.

```text
1. State the exact ordering/liveness claim.
2. Locate number assignment, durable append, foreground delivery, and receiver teardown.
3. Add a delayed or disconnect test that fails before the fix.
4. Fix under the narrowest shared boundary.
5. Update architecture docs to match the implementation, not the intent.
```

Default target areas:

- `crates/kuzushi-core/src/run_artifacts/`
- `crates/kuzushi-tui/src/app/background_events/`
- `crates/kuzushi-tui/src/app/scan/`
- `crates/kuzushi-tui/src/app/tool_runner/`

Good tests:

- delayed builder does not reserve a trace number
- multiple handles share monotonic sequence
- receiver disconnect synthesizes terminal failure
- trace receiver stays installed while other work is active

Do not:

- Say "cannot interleave" unless numbering and append are protected at the relevant boundary.
- Say "never lost" when foreground delivery is best-effort after durable append.
- Leave zombie liveness possible when a sender disconnects without a terminal event.

### Template F: Long Loop / Overnight Work

Use for `/loop`, custom shell loops, repeated agents, and overnight tasks.

```text
1. Define the loop goal as a measurable state.
2. Define the loop interval and max duration.
3. Define the stop condition.
4. Define the terminal audit.
5. Launch detached only if needed.
6. Verify live state with process + sleep guard + fresh logs.
7. Record the status table.
```

Loop status table:

```text
Loop | Script | PID | Sleep guard | Last log timestamp | State | Completion marker | Terminal audit
```

Do not:

- Rely on `nohup` returning successfully.
- Trust stale logs.
- Let loops write unbounded output.
- Let loops finish without one final audit/fix attempt.

## Definitive Confidence Levels

Use these labels in progress docs and handoffs.

### Proven

Meaning:

The exact behavior has a focused test, command, or artifact that would fail if the claim regressed.

Required:

- exact command recorded
- output/result summarized
- owner files named
- residual risk stated

Example:

```text
Proven: hidden android-apk phase tools remain exact-invokable but catalog-hidden.
Gate: cargo test -p kuzushi-core modules::registry::tests.
```

### Current Repo Fact

Meaning:

Search/read evidence shows the repo currently does something, but no regression test specifically protects it yet.

Required:

- `rg`/file references
- note if test coverage is missing

Example:

```text
Current repo fact: recon:import has descriptor, registry dispatch, adapters, and tests.
```

### Hypothesis

Meaning:

Plausible claim from audit/reviewer/reasoning, not yet checked.

Required:

- smallest falsifier named
- no implementation based solely on it

Example:

```text
Hypothesis: a new eval metric separates routing misses from reasoning misses.
Falsifier: fixture where target file is routed but exact vulnerable site is not.
```

### Stale Or Superseded

Meaning:

The claim was true in a previous session or doc snapshot but is not true now.

Required:

- current evidence
- doc/progress update if user-facing

Example:

```text
Stale: patch review is only a footer promise.
Current evidence: apply/reject/regen exists in TUI and runtime.
```

### Blocked

Meaning:

Same blocker reproduced after at least three attempts or a required external state is unavailable.

Required:

- attempts listed
- exact missing input/state
- safe next step

Do not use "blocked" for hard, slow, or uncertain work that still has a tiny falsifier available.

## Pickup Checklist For Future Sessions

Start here when resuming Kuzushi work:

```bash
git status --short --branch
sed -n '1,220p' AGENTS.md
sed -n '1,180p' docs/devex/new-contributor-map.md
find progress -maxdepth 1 -type f -name '*.progress.md' -print | sort
```

Then choose the matching workflow:

- Long audit: Template A.
- Discovery, proof, TUI trust, or big architecture: Template B.
- Public docs/commands: Template C.
- Runtime/model/OAuth/external CLI: Template D.
- Trace/persistence/liveness: Template E.
- Overnight loops: Template F.

Before broad implementation, write:

```text
Claim:
Smallest falsifier:
Focused gate:
Expected files:
Out-of-scope dirty state:
```

After implementation, leave:

```text
What changed:
What proved it:
What remains uncertain:
What not to repeat:
```

## One Concrete Continuation

The cleanest next use of this playbook is a vuln-discovery proof ledger for one real or fixture-backed vulnerability story.

Run:

```bash
cd ~/vibe-code/kuzushi
git status --short --branch
sed -n '1,220p' AGENTS.md
rg -n "proof|verification|confirmed|unverified|FindingStore|Workbench|eval:gate|routing recall|reasoning recall|export" crates docs scripts eval progress
```

Then create a small ledger:

```text
Vuln story | Input/fixture | Routed files | Vulnerable site | Proof state | TUI surface | Operator action | Gate | Disposition
```

Likely target areas:

```text
eval fixtures and scoreboard gates
crates/kuzushi-core proof / verification / FindingStore paths
crates/kuzushi-tui Workbench findings list and details pane
report/export code paths
docs/plans/product-flow-prd.md W0 proof markers
```

Do not start with a broad UI or architecture sweep. Classify first:

- caught and proven end-to-end,
- routed but site missed,
- site found but proof state unclear,
- proof exists but TUI hides or misleads it,
- TUI shows it but operator cannot act/export,
- fixture-only and not representative,
- stale/superseded claim,
- safe implementation cluster.

That gives the next code slice without losing the actual flag: real vulnerabilities caught, proven, understood, and made actionable.

## The Short Version

The durable lesson from Last Resort is not "be more careful." It is:

```text
Do not advance the theory until the smallest proof for the current claim has run.
```

For Kuzushi, that means every session should produce one of:

- a measured improvement in vulnerability discovery, proof quality, TUI trust, or operator actionability,
- a tested code change,
- a corrected current-state doc,
- a deterministic eval/gate,
- a resource-bounded loop with terminal audit,
- or a clear claim ledger showing what remains unproven.

Anything else is probably drift away from the flag.
