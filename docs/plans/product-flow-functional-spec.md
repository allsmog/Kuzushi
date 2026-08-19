# Functional spec — Kuzushi Cockpit Spine

**Status:** implementation contract
**Date:** 2026-07-13
**Scope:** Rust/Ratatui shell, shared presentation DTOs, remediation persistence,
export metadata, and plain/headless parity.
**Supersedes:** the 2026-07-03 draft's Aim/Hunt/Confirm control-room proposal,
legacy Workbench composition, and duplicate Activity behavior.

## 1. Compatibility boundary

The cutover preserves:

- existing `.kuzushi` paths and legacy run/finding/proof/patch artifacts;
- the run trace schema and chain -> plan -> steer queue order;
- shared `prepare_dispatch_input` and
  `dispatch_prepared_input_with_runtime` authorization-bound policy;
- explicit target consent and context-sensitive `Ctrl+C`/`Ctrl+D`: immediate
  idle exit, active-work cancellation without exit, and safe waiting while
  cancellation is pending;
- existing export formats and no-silent-fallback semantics.

The canonical domain is `WorkflowPhase::{Map,Scan,Review,Prove,Fix}` and
`ToolPhase::{Map,Scan,Review,Prove,Fix,Operate}`. Deprecated `hunt` and
`confirm` inputs load as Scan and Prove for one major release, while new
descriptors, query output, config, and artifacts serialize only `scan`,
`review`, and `prove`. Setup, Report, Run Focus, contextual-surface route state,
patch lifecycle records, remediation export metadata, and `patch:reverify`
remain outside page-selection truth. Report is an exit, not a sixth phase.

Each requirement below is behavioral. Layout detail follows
[`terminal-cockpit-reference.md`](../design/terminal-cockpit-reference.md) and
[`product-flow-design-spec.md`](../design/product-flow-design-spec.md).

## 2. Routing and state truth

### FR-ROUTE-1 One cockpit spine

**Behavior:** the shell routes `Target -> Setup -> Map -> Scan -> Review ->
Prove -> Fix -> Report`, allowing foreground Run Focus from workflow phases and
returning to them afterward. `workbench` opens the page derived from workspace reality;
`findings` and `open <id>` open Review; `next` opens the current phase planner;
`report` opens Report.

**Acceptance:** opening Review, Prove, Fix, Report, or a visualization does not
change the reality-derived `WorkflowPhase`. An existing hydrated target resumes
its derived page; a fresh or switched target enters Setup.

### FR-ROUTE-2 Phase-native pages are unconditional

**Behavior:** Map/Scan/Review/Prove/Fix render their phase-native composition at all
supported sizes. The shell does not fall back to the legacy whole-screen
four-pane Workbench. DFD, terrain, heatmap, attack tree, attack path, replay,
and trace are contextual decks.

**Acceptance:** render tests for each persisted phase select exactly its public
page label, while opening and closing a visualization leaves the phase unchanged.

### FR-ROUTE-3 Journey chrome is honest

**Behavior:** phase rail and autonomy chrome are absent in Target and Setup and
present only after `Start Map` commits an engagement. All journey counts derive
from the unfiltered durable ledger.

**Acceptance:** Setup snapshots contain no phase rail; filters change visible
Review rows but not journey counts or phase.

## 3. Target and Setup

### FR-SETUP-1 Target consent is explicit

**Behavior:** highlighting a target requests facts but does not activate it.
`Enter` activates; `Esc` chooses targetless capability browsing. Cwd is never an
implicit fallback.

**States:** candidate facts are `pending`, `ready`, or `error`, tagged with a
generation. Results from an older generation are discarded.

**Acceptance:** rapid cursor movement followed by reversed completion shows the
currently selected candidate's absolute path, repository facts, revision,
languages/build systems, nested scope, and prior artifact state. Targetless Esc
opens Capabilities without journey chrome.

### FR-SETUP-2 Setup is one readiness model

**Behavior:** Setup renders, in order, Target, Map plan, Model, Credentials,
Prompt, Budget, and `Start Map`. `Enter` edits one row and returns without
resetting plan selection, cursor, scroll, prompt draft, or other readiness data.

**Acceptance:** edit each row in turn and assert previously chosen values remain.
At `40x12`, `60x20`, and `120x36`, all row identities and the first blocker are
reachable.

### FR-SETUP-3 Readiness is plan-aware

**Behavior:** a nonempty deterministic/runtime-free plan can start without a
model or credential. Model-backed tasks require an explicitly selected,
runtime-compatible model and an API-key, stored-OAuth, or session credential.
Missing CLIs/options/prompts block only tasks that require them.

**Acceptance:** keyless deterministic Map starts; selecting a model-backed task
moves Setup to blocked until its exact model and credential are ready. No other
provider/model/runtime is substituted.

### FR-SETUP-4 Model selection uses stable identity

**Behavior:** configured selection resolves to stable model id and then to its
position in the reordered visible catalog. Highlight and `Enter` refer to the
same id.

**Acceptance:** model-catalog permutation/filter tests preserve the selected id
and commit the highlighted id across every order.

### FR-SETUP-5 Budget vocabulary is precise

**Behavior:** unset budget is `NOT ENFORCED`. A set budget must be finite,
positive, and no greater than the configured hard ceiling.

**Acceptance:** unset, zero, negative, NaN-like invalid text, valid positive,
and over-ceiling inputs produce the corresponding readiness state and message.

## 4. Run Focus

### FR-RUN-1 One authoritative projection

**Behavior:** `RunFocusModel` owns run/sequence id, planned task rows, current
task, one event/output window, health/stall state, cost, queue depth, origin,
and terminal receipt. Planned/DAG task ids are the checklist authority.

**Acceptance:** context builds, scans, prerequisite chains, planned tools, and
steered tools use the same model. No output contains duplicate CURRENT/ACTIONS/
heartbeat projections or a context-specific checklist parser.

### FR-RUN-2 Geometry is width-driven and shared

**Behavior:** width `>=78` is side-by-side with Steps 32% clamped 28-40 and
Output at least 48; width `50-77` stacks with Steps capped at 40% body height;
width `<50` or body height `<14` shows one Tab-switchable viewport. Height alone
does not stack a wide screen.

**Acceptance:** pure rectangle tests cover `40x12`, `60x20`, `80x24`, `96x89`,
`120x36`, and `160x48`. At `96x89`, Steps and Output start on the same row and
there is no generic prompt or blank canyon. Hit testing and scrolling use those
same rectangles.

### FR-RUN-3 Run Focus owns input

**Behavior:** foreground Run Focus starts in Navigate mode and reserves no
generic prompt row. `s` opens an inline editor accepting only `run <tool> ...`;
invalid input remains with an inline error, `Enter` queues valid input, and
`Esc` closes. `b` backgrounds without cancellation.

**Acceptance:** printable keys do not enter a hidden prompt; invalid steer text
does not enter the queue; a valid command enters the existing steer queue;
background leaves the job running.

### FR-RUN-4 Origin restoration is exact

**Behavior:** foreground launch captures view, page/pane, input mode, scroll,
pinned finding, and auto-return ownership. The final success, failure, or cancel
restores that state and displays one receipt with outcome, run count, duration,
cost, changed findings/artifacts, and next action.

**Acceptance:** origin tests cover every phase, Prompt/Navigate, nonzero scroll,
and a pinned finding. Prerequisite chain, plan, and steer completions retain
their ordering and create one final receipt. Manual inspection and background
ownership never auto-return or hijack focus.

### FR-RUN-5 Output work is viewport bounded

**Behavior:** the retained event ring is windowed before formatting and output
rows are built once per frame. Plain mode uses the same model and serializes
Steps then Output.

**Acceptance:** formatting counters scale with visible rows, not retained event
count; framed and plain state vocabulary agrees.

### FR-RUN-6 Operator questions are root-shell interactions

**Behavior:** only the root interactive shell agent loop exposes
`request_user_input`. A run may make at most three question calls and eight
model steps. The reliable question event carries one to three contract-checked
questions and a one-shot response channel; Run Focus owns its input, background
questions appear as `WAITING INPUT` without stealing focus, stale-generation
answers are ignored, and headless execution returns `INTERACTION_REQUIRED`.
Credential questions route to Setup/Auth and never return credential text to
the model. Persistence retains ids, predefined labels, resolution, and a
freeform-present flag, never raw freeform text.

**Acceptance:** delivery, timeout, cancellation, background/resume, stale
answers, direct numeric selection, Other, credential routing, privacy
redaction, and headless refusal are covered by unit and live tmux tests.

### FR-RUN-7 Proposal results are canonical run artifacts

**Behavior:** planner and threat-proposal workers write canonical `input.json`,
`result.json`, trace/events, and terminal `summary.json` before exposing a
reviewable proposal. Phase attempts retain origin, attempt id, every run ref,
target snapshot, outcome, lineage/derivation, receipt metadata, rerun
specification, typed actions, and recommended next action. Restart projection
reconstructs the same result card. Discarding a proposal or attempt never
deletes its run evidence.

**Acceptance:** restart tests recover planner/threat payloads and every typed
result action from disk; injected persistence failure refuses to offer the
proposal as durable; regenerate replays the exact recorded input.

## 5. Durable phase projections

### FR-MAP-1 Map never reads live Activity

**Behavior:** Map shows target context, source inventory, grouped attack
surface, hot modules, threat/DFD status, harness/material readiness, and artifact
freshness exclusively from durable projections.

**Acceptance:** seed retained Activity from an unrelated run and assert Map is
unchanged. Empty artifacts show one actionable hint.

### FR-SCAN-1 Scan is durable attempt truth

**Behavior:** Scan is a resting projection, never a live-progress screen. It
shows the current target/revision scope and engine plan, the selected attempt,
typed per-engine `complete | partial | skipped | failed` outcomes, actual
finding/artifact deltas, duration, cost, freshness, canonical run references,
and one next action. A completed attempt advances only after selection; a
partial attempt additionally requires acknowledgement; failed, canceled, and
stale attempts never count. Imported findings materialize an imported Scan
attempt. A selected zero-finding Scan offers Report without inventing empty
Review, Prove, or Fix work.

**Acceptance:** tests distinguish never-scanned from clean, partial from
acknowledged partial, stale from current revision, and imported from bare
in-memory findings. At `40x12`, mode, reality, scope, outcome, engine count,
finding delta, and NEXT remain visible.

### FR-REVIEW-1 Review rows disclose authority

**Behavior:** each finding row has authority marker, severity, canonical proof
mini-meter, unique source count, confidence, and human decision when present.
Shell ordering remains confidence-first with severity tie-break.

**Acceptance:** every projected row contains all fields; human decisions survive
reruns; list and detail resolve the same stable finding.

### FR-SELECTION-1 Filtered pins are safe

**Behavior:** when a pinned finding is outside the active projection, Review,
Prove, and Fix name it, name the active filter, and expose `reveal in queue`.
Verify, suppress, patch, and apply target the explicitly displayed finding.

**Acceptance:** filter out a pinned finding, invoke each action, and assert no
hidden or cursor-adjacent finding receives it. Revealing removes the ambiguity.

### FR-PROVE-1 Proof hierarchy survives compaction

**Behavior:** identity, STATUS, and NEXT appear before evidence. Wide mode shows
Evidence and Proof Ladder side by side with replay afterward. Compact mode keeps
identity, status, next, proof meter, sources, and stale-proof warning before
metadata.

**Acceptance:** narrow snapshots retain every priority atom. Replay uses
`verification_run_id`; proof from an older observation is labeled stale.

### FR-FIX-1 Fix is a lifecycle

**Behavior:** Fix projects Draft available, Staged, Applied/reverify required,
Reverify running, Verified, Still vulnerable, Not rediscovered, Inconclusive,
Failed, Interrupted, and Changed since apply. Apply remains on Fix with
Remediation focused and shows paths, diff hash, application id, and exact `v`.

**Acceptance:** state tests render each lifecycle state. A successful synthesis
without apply remains Draft. A successful apply remains visible after pending
patch state is cleared.

## 6. Remediation persistence and re-verification

### FR-PATCH-1 Lifecycle events are append-only

**Behavior:** `PatchLifecycleRecorded` stores application id, target identity,
stable finding id/fingerprint, patch run id, diff hash, optional base commit,
relative paths with before/after hashes, actor/timestamps, reverify run id,
state, and detail. A current projection is keyed by application id.

**Acceptance:** multiple events remain queryable in order while current returns
the latest. Old databases migrate additively and replay. Historical sound patch
results become Draft, not Applied.

### FR-PATCH-2 `patch:reverify` is descriptor-backed

**Behavior:** the headless tool requires `applicationId`, explicit workspace,
and the original detector's tool/input. It passes through the shared registry
boundary and refuses attribution when touched-file hashes changed.

**Acceptance:** unknown application, target mismatch, changed hashes, missing
original input, and unavailable original detector are explicit outcomes. The
tool never substitutes a detector, model, runtime, provider, or target.

### FR-PATCH-3 Outcome labels are evidence-limited

**Behavior:** deterministic successful absence -> Verified; rediscovery ->
Still vulnerable; nondeterministic absence -> Not rediscovered; unavailable
comparison -> Inconclusive; cancellation/process loss -> Interrupted. Only
Verified promotes patch status to Verified; Still vulnerable records that
status; inconclusive outcomes preserve the earlier sound result.

**Acceptance:** focused tests cover every outcome and corresponding patch-result
projection.

## 7. Report and export

### FR-REPORT-1 All formats are present and ordered

**Behavior:** Report lists SARIF, Markdown bundle, JSONL, JSON, CSV, with default
paths `report.sarif`, `report/`, `findings.jsonl`, `findings.json`, and
`findings.csv`. Completeness starts All and `c` cycles All/Open/Complete.

**Acceptance:** route-state tests assert order, paths, cycle, and path editing.

### FR-REPORT-2 Export remains on Report

**Behavior:** Report reuses the export application service. Success and failure
remain on Report with format, count, completeness, absolute path/error,
timestamp, Retry, Back to Fix, and Reveal Destination.

**Acceptance:** both terminal outcomes preserve Report selection and edited
path. Retry repeats the same request unless the operator edits it.

### FR-REPORT-3 Reveal is explicit and argument-safe

**Behavior:** only `o` invokes `open -R`, `xdg-open <parent>`, or `explorer
/select,`; arguments are passed without shell interpolation. Unavailable support
becomes an inline Report error.

**Acceptance:** adapter tests inspect exact program/argument vectors for each
platform and malicious-looking path characters remain one argument.

### FR-REPORT-4 Remediation metadata is additive

**Behavior:** JSON/JSONL/Markdown, SARIF properties, and flattened CSV columns
include application id, patch run id, state, reverify outcome/run id, diff hash,
and touched paths when available. Records without lifecycle data remain valid.

**Acceptance:** fixtures round-trip old records and assert new metadata in all
five formats.

## 8. Contextual surfaces and visualizations

### FR-CONTEXT-1 Context does not replace workflow

**Behavior:** Help, Controls, and Capabilities are modal. Jobs, Replay, Trace,
DFD, terrain, heatmap, attack tree, and attack path are scrollable full-frame
decks. The first open captures the workflow origin and input mode.

**Acceptance:** open each surface from each phase, then `Esc`; the exact view,
page/pane, scroll, pinned finding, and Prompt/Navigate mode return.

### FR-CONTEXT-2 Context is non-nesting

**Behavior:** opening surface B from contextual surface A replaces A but retains
the original workflow origin. `Esc` restores that original origin in one step.

**Acceptance:** Help -> Trace -> DFD -> Esc returns to the original workflow
screen, not Trace or Help.

### FR-CONTEXT-3 Auto-open cannot steal background focus

**Behavior:** foreground `ui.auto_open_viz` restores workflow origin, then opens
the relevant real-data deck. Background completion emits a receipt/notice only.

**Acceptance:** foreground artifact completion opens the mapped content-bearing
deck; zero-result completion does not open an empty deck; background completion
does not change the view.

## 9. Plain and accessibility contract

### FR-PLAIN-1 Shared DTOs define vocabulary

**Behavior:** Setup, Run Focus, Map/Scan/Review/Prove/Fix, receipts, contextual
summaries, and Report flatten from the same DTOs used by Ratatui. Menus are
noninteractive and name exact equivalent commands.

**Acceptance:** parity tests compare state words, identities, outcomes, and
commands across framed/plain renderings.

### FR-PLAIN-2 Meaning survives terminal capability

**Behavior:** truecolor, ANSI-256, no-color, and plain modes retain selected,
severity, proof, failure, lifecycle, and next-action meaning via markers and
text. DFD/terrain/heatmap/attack-tree/attack-path plain output uses real model
data or an explicit empty hint.

**Acceptance:** render matrix covers every canonical size and color profile with
no clipped priority atoms or decorative sample evidence.

## 10. Integration acceptance journeys

The required journeys are:

1. target consent -> keyless deterministic Setup -> Start Map -> Run Focus ->
   Map receipt -> selected Map -> Scan;
2. model-backed Map plan blocked until exact compatible model/credential;
3. foreground success, failure, and cancellation restore exact origin;
4. `s` steer queues valid `run ...`, while `b` backgrounds and restores;
5. Map ignores unrelated retained live activity;
6. filtered pinned finding remains disclosed and safely targeted;
7. Draft -> Apply -> Reverify exercises all outcome labels and staleness;
8. Report success/error, retry, completeness, path edit, and explicit reveal;
9. Help/Jobs/Replay/Trace/DFD/terrain/heatmap/attack-tree decks restore the
   exact origin;
10. live TTY Map -> Scan -> operator question -> background -> Jobs waiting ->
    Activity resume -> accepted result -> Review -> Prove -> Fix/Report, using
    literal xterm BackTab and alternate-screen capture.

Required gates remain `cargo fmt --all -- --check`, workspace check/tests,
onboarding BDD, TUI parity, Clippy with warnings denied for core/TUI, CRAP-risk,
architecture, model-safety, docs, package verification, and `git diff --check`.

## 11. Locked product defaults

- Setup gates model/credentials according to the selected plan.
- Scan is a durable phase; Run Focus remains transient and promptless.
- Page selection never mutates phase reality, autonomy, model, permissions, or evidence.
- Every foreground terminal outcome returns to origin with a receipt.
- One canonical cockpit ships; no legacy UI feature flag remains.
- Report includes all five formats and defaults to All.
- Background work never auto-navigates.
- A nondeterministic detector's absence is `Not rediscovered`, not `Fixed`.
- No target, model, runtime, provider, CLI, prompt, or detector fallback is
  introduced.
