# Design spec — Cockpit Spine product flow

**Status:** canonical design for the shipped cutover
**Supersedes:** the earlier four-phase cutover, steering-gate mockups, and
legacy whole-screen Workbench/Activity compositions. The current product has
five durable workflow phases plus a Report exit.

## 1. Product promise

Kuzushi is an operator cockpit for turning a target into durable security
evidence and remediation truth. The interface makes a strict distinction
between:

- **durable truth:** target facts, artifacts, findings, proof, patch lifecycle,
  and export receipts;
- **live work:** one foreground Run Focus presentation;
- **context:** help, operational decks, and visualizations that return exactly
  where the operator came from.

The resulting spine is:

```text
Target -> Setup -> Map <-> Run Focus -> Scan <-> Run Focus
       -> Review -> Prove <-> Run Focus -> Fix <-> Run Focus -> Report
```

The canonical persisted phases are `Map`, `Scan`, `Review`, `Prove`, and
`Fix`. Report is an exit surface. Viewing Scan, Review, Prove, Fix, Report, or
a visualization never advances phase reality. The selected page is interaction
state; current reality is derived from durable target/revision evidence,
accepted attempts, review dispositions, proof, and remediation lifecycle.

## 2. Navigation model

### 2.1 Primary routes

| Intent | Route |
| --- | --- |
| Bare interactive launch | Target consent |
| Fresh or switched explicit target | Setup |
| Existing hydrated engagement | Reality-derived phase page |
| `workbench` | Reality-derived phase page |
| `findings`, `open <id>` | Review, with the finding disclosed |
| `next`, `continue` | Planner for the reality-derived phase |
| `report` | Report exit |
| `/setup` | Aggregate Setup |
| `jobs`, replay, trace, visualization | Contextual full-frame deck |
| help, controls, capabilities | Contextual modal |

The route model captures selection and interaction state, not merely a view
enum. Run Focus and contextual surfaces can therefore restore the exact phase
page, pane, cursor, filter, scroll, pinned finding, and input mode.

`Shift+Tab` cycles `Map -> Scan -> Review -> Prove -> Fix` from Prompt or
Navigate mode without changing the shared draft or cursor. Navigate-mode
`1..5` selects a page directly. If the selected page and reality differ, both
are named (`VIEW SCAN · REALITY REVIEW`). `Tab` retains completion or
pane-forward ownership; `]` additionally moves forward and `[` moves backward.
Modal editors, pickers, questions, and Run Focus receive keys first.

### 2.2 Persistence versus presentation

Durable pages consume application/presentation projections. They do not inspect
live Activity state or reconstruct storage policy in the renderer. Run Focus
owns ephemeral execution state. Contextual decks consume durable artifacts or
read-only run artifacts and do not become workflow pages.

## 3. First-contact flow

### 3.1 Target consent

The first screen makes scope consent explicit. Highlighting a candidate shows
facts but performs no activation. `Enter` activates; `Esc` browses capabilities
without a target. Cwd is only a candidate row and is never silently chosen.

Candidate inspection is asynchronous. Results are generation-stamped so quick
cursor movement cannot show facts from an old selection. The screen presents:

- absolute path and repository kind;
- revision, branch, and dirty state;
- detected languages and build systems;
- nested scope;
- prior Kuzushi engagement/artifact status.

The transition after activation depends on truth: fresh/switched targets open
Setup, while existing engagements resume the page derived from artifacts and
the finding ledger.

### 3.2 Aggregate Setup

Setup is a readiness ledger, not a sequence of disconnected pickers:

```text
Target
Map plan
Model
Credentials
Prompt
Budget
Start Map
```

The currently selected row has the only action accent. `Enter` opens its editor
and all editors return to Setup without losing any other draft. Target facts,
model selection, credential presence, prompt readiness, plan dependencies, CLI
availability, required options, and budget validation converge into one
`SetupReadinessModel`.

The Map plan controls requirements. A deterministic/runtime-free plan is
explicitly keyless. A model-backed plan blocks on an explicit compatible model
and the credentials for that provider. No provider, model, target, CLI,
runtime, detector, or prompt fallback is invented. The selected model is keyed
by stable id, so filtering or catalog reorder cannot make highlight and Enter
disagree.

Before `Start Map`, journey and autonomy chrome is hidden. This prevents an
uncommitted target/setup draft from looking like an engagement in progress.

## 4. Live execution flow

### 4.1 Foreground launch

Every foreground workflow run captures its exact `RunFocusOrigin` before
opening Run Focus. The run screen is built from one authoritative model:

- run and sequence identity;
- planned/DAG task identities and states;
- current task;
- one retained output window;
- health/stall state and last progress age;
- cost and queue depth;
- origin and terminal receipt.

There is no generic prompt on this screen. Input starts in Navigate mode. `s`
opens a steer editor that accepts only `run <tool> ...`; it reuses the existing
steer queue. `b` backgrounds work without canceling it.

### 4.2 Responsive composition

| Body geometry | Composition |
| --- | --- |
| width `>=78` | Steps left, Output right, same top row; Steps 32%, clamped 28-40; Output at least 48 |
| width `50-77` | Vertical stack; Steps content-height capped at 40% |
| width `<50` or body height `<14` | One viewport; `Tab` switches Steps/Output |

Terminal height does not force a wide layout to stack. Rendering, scrolling,
and hit-testing use the same rectangles. Events are windowed before formatting
and output rows are built once per frame. Plain output serializes Steps and
then Output from the same model.

### 4.3 Completion and receipts

Sequence precedence stays `prerequisite chain -> plan -> steer`. Intermediate
receipts accumulate while more sequence work remains. The final terminal event
restores the captured origin and presents one receipt containing origin phase,
attempt id, all run references, outcome, duration, cost, changed findings and
artifacts, interaction count, exact rerun input, typed actions, and one next
action.

This applies to success, failure, and cancellation. Manual Run Focus inspection
does not claim auto-return ownership. Background work reports completion but
never steals focus. A background request restores the origin immediately.

The receipt is backed by append-only `PhaseAttemptCompleted` and
`PhaseAttemptDispositionRecorded` records, so it survives restart. Selecting a
completed attempt, or explicitly acknowledging and selecting a partial one,
causes reality to be re-derived. Dismiss or Discard retains every canonical run
artifact. An unresolved foreground attempt blocks a second bare intent from the
same page, while navigation and explicit commands remain available.

### 4.4 Operator questions

Only the root interactive shell agent loop may request up to three structured
questions at a time. Run Focus owns the question card: arrows or `j`/`k` select,
numbers choose directly, left/right changes question, `Tab` opens Other,
`Enter` submits, `Esc` leaves Other or cancels, and `b` backgrounds. A
background question never steals focus and appears in Jobs as `WAITING INPUT`.
Delivery uses a reliable worker-to-UI event plus a one-shot response channel;
cancellation, timeout, and stale job generations are checked before an answer
is accepted.

Each run is capped at three question calls and eight model steps. Run artifacts
store question ids, predefined labels, resolution, and whether freeform was
supplied, never the raw freeform text. Credential requests route to Setup/Auth.
Headless execution has no question tool and returns the structured
`INTERACTION_REQUIRED` refusal rather than reading stdin or choosing silently.

### 4.5 Durable-page adaptive composition

Map, Scan, Review, Prove, and Fix share one semantic presentation policy.
Content occupancy and selection decide whether the page is `Sparse`,
`MasterDetail`, or `Dense`; an explicit `Z` deck is `Focused`, and a foreground
question or unresolved result is `Guided`. Automatic Dense presentation is
capped at three populated surfaces. Missing or unavailable artifacts remain
truthful rows inside the primary surface instead of receiving blank panes.

The policy is calculated from the exact body rectangle left after header,
attention card, and chrome allocation. Its visible surface order and
rectangles are also the keyboard, scroll, zoom, and mouse contract. Resizing or
temporarily entering Guided mode may use a visible fallback focus without
overwriting the operator's stored semantic focus.

## 5. Durable work screens

### 5.1 Map — know the target

Map projects durable artifact truth only:

- target/revision context and source inventory;
- grouped attack surface and hot modules;
- threat-model and DFD readiness;
- harness/material readiness;
- artifact age/freshness.

Map never reads a retained Activity session. An empty projection gives one
specific action. DFD, terrain, and heatmap remain available as contextual decks
rather than displacing Map with a legacy multi-pane screen.

### 5.2 Scan — collect candidate observations

Scan is a durable resting surface, never live progress. It projects the scope
and selected engine plan, the accepted attempt for the current target and
revision, per-engine `complete | partial | skipped | failed` outcomes, finding
and artifact deltas, failures, duration, cost, freshness, canonical run
references, and one specific next action. Source shows scope and plan, Center
shows engine coverage, Findings shows the candidate delta, and Details shows
the selected engine, run, or failure. At `40x12` these collapse into one summary
that retains mode, reality, scope, outcome, engine count, finding delta, and
NEXT.

A completed selected Scan advances reality. A partial result requires explicit
acknowledgement; failed, canceled, or stale results do not count. Imported
findings create an imported Scan attempt. An accepted zero-finding attempt
makes Review, Prove, and Fix not applicable and offers Report.

Shell-originated `sast:scan` is discovery-only. Explicit full-pipeline CLI
calls preflight their highest requested phase before any scanner side effect
and record nested Scan, Review, Prove, and Fix stages separately.

### 5.3 Review — decide what matters

Review combines the confidence-first findings queue and selected detail. Each
visible row includes authority marker, severity, canonical proof mini-meter,
unique source count, confidence, and any human decision. Group headings are not
selectable findings; every action resolves through the projected visible row.

Selection safety is explicit. If a pinned finding is filtered out, the screen
continues to name that finding, says which filter excluded it, and offers
`reveal in queue`. Verify, suppress, patch, and apply cannot target an invisible
implicit selection.

Every current-generation finding needs a terminal durable review disposition.
Triage and classification never count as proof. An all-rejected review offers
Report while preserving the review ledger.

### 5.4 Prove — make evidence legible

The hierarchy is fixed:

1. finding identity;
2. `STATUS`;
3. the single shared `NEXT` strip;
4. evidence and Proof Ladder;
5. replay/provenance.

Wide screens place Evidence and Proof Ladder side by side. Compact screens keep
identity, status, next, proof meter, sources, and stale-proof warning before
metadata. Replay always uses the verification run. Evidence carried from an
earlier observation is labeled stale and requests revalidation.

Only real terminal verification or an explicit human deferral satisfies an
actionable finding. Prose may invoke a verifier, but prose itself cannot become
proof. If no proof-backed actionable finding remains, the next destination is
Report rather than an empty Fix traversal.

### 5.5 Fix — preserve remediation truth

Fix displays an attributable lifecycle:

```text
Draft available
Staged for approval
Applied; re-verification required
Re-verification running
Verified | Still vulnerable | Not rediscovered | Inconclusive
Failed | Interrupted
Changed since apply
```

Synthesis/worktree validation alone creates a draft; it does not imply apply.
After apply, the screen stays on Fix with Remediation focused and shows touched
paths, diff hash, application id, and the exact `v` action. Re-verification uses
the original detector/tool input against the explicit workspace. Changed
touched-file hashes refuse attribution. Only deterministic successful absence
is `Verified`; nondeterministic absence is `Not rediscovered`.

Apply is available only for a `SOUND` candidate whose persisted generation
commit, target identity, originating run, detector tool/run, and detector-input
digest still match. Apply intent and application id are persisted before files
change. Re-verification replays that bound detector; missing legacy provenance
is `Inconclusive` and requires regeneration. Selecting a result never applies
it and moving to Report never implies Apply.

## 6. Report exit

Report exposes every existing format in fixed order:

1. SARIF — `report.sarif`
2. Markdown bundle — `report/`
3. JSONL — `findings.jsonl`
4. JSON — `findings.json`
5. CSV — `findings.csv`

Completeness defaults to All; `c` cycles All, Open, Complete. The destination
is editable before export and target-relative paths resolve to an absolute
destination at execution. The existing export application service performs the
write.

Success and error both remain on Report. The receipt includes format, count,
completeness, absolute path or error, and timestamp, with Retry, Back to Fix,
and Reveal Destination actions. `o` is the explicit consent required to invoke
the platform file browser. An unavailable adapter becomes an inline error.
Exported findings include additive remediation identity, application state,
re-verification result/run, diff hash, and touched paths.

## 7. Contextual surfaces and DFD visibility

The cockpit keeps every existing analysis visualization. It changes ownership:

| Surface | Presentation | Source of truth |
| --- | --- | --- |
| Help, Controls, Capabilities | modal | shell/application model |
| Jobs | full-frame deck | live job hub plus run summaries |
| Replay, Trace | full-frame deck | `.kuzushi/v3/runs/<id>/` |
| DFD | full-frame visualization deck | persisted threat model |
| Terrain, heatmap | full-frame visualization deck | module risk/findings |
| Attack tree | full-frame visualization deck | exploit chains |
| Attack path | full-frame visualization deck | source-to-sink flows |

There is one non-nesting contextual route. The first contextual open captures
the workflow origin and input mode. Opening another overlay/deck replaces the
current contextual surface while preserving that first origin. `Esc` restores
the exact origin. Empty visualization models show one truthful guidance line,
never dummy nodes or evidence.

Foreground artifact completion may auto-open the relevant visualization only
after workflow-origin restoration. Background completion posts a receipt and
does not navigate.

## 8. Interaction grammar

- Prompt mode owns printable input on durable pages.
- Navigate mode owns view keys.
- The one-row composer names and colors the selected mode: `◇ MAP ›` teal,
  `▦ SCAN ›` gold, `▣ REVIEW ›` blue, `◎ PROVE ›` violet, and `◆ FIX ›`
  magenta. Accents apply only to mode chrome; semantic warning, failure,
  severity, proof, and success colors do not change.
- Known commands, slash commands, and explicit `run <tool>` parse before
  Workbench prose. Remaining prose becomes phase intent for the selected page
  and must pass planner, descriptor, option, autonomy, authorization, and
  no-silent-fallback boundaries. Missing prerequisites are explained rather
  than silently selecting another phase, tool, model, or runtime.
- Setup and Target own their local input and suppress generic prompt chrome.
- Run Focus owns Navigate input and its compact steer editor.
- `Esc` leaves a modal/editor/deck for its captured origin before applying any
  broader navigation meaning.
- `Shift+Tab` cycles all five pages from Prompt or Navigate mode. `Tab` keeps
  completion/pane-forward behavior; `]` and `[` are explicit next/previous pane
  keys.
- Home-scoped runtime keybindings may replace these defaults or explicitly
  unbind an action. Two-stroke chords time out after one second, question and
  modal contexts retain first ownership, and invalid reloads keep the previous
  complete map instead of partially applying it.
- `j`/`k` and arrows move the active list or viewport; scroll state is route
  state and survives contextual excursions.
- Advertised actions either act or display an inline explanation.
- Phase page selection is quiet UI state: cycling or direct selection does not
  append transcript lines or imply durable progress.

## 9. Plain and headless parity

Setup, Run Focus, phase models, receipts, and Report have one presentation DTO
each. Plain rendering flattens them in reading order without changing state
names. Interactive-only menus list their exact command equivalents.

The headless `patch:reverify` tool requires `applicationId` in its descriptor.
It passes through the shared registry preparation/dispatch boundary and never
substitutes another detector, model, runtime, provider, or workspace. Existing
scan/shell/run target consent, output, and run artifact contracts remain intact.

## 10. Visual acceptance

The mandatory viewport matrix is `40x12`, `60x20`, `80x24`, `96x89`,
`120x36`, and `160x48`, under truecolor, ANSI-256, no-color, and plain modes.

Critical assertions:

- at `96x89`, Run Focus Steps and Output start on the same row;
- Run Focus has no generic prompt and no artificial blank canyon;
- narrow Prove preserves identity, STATUS, NEXT, proof, sources, and stale state;
- `40x12` Scan preserves mode, reality, scope, outcome, engine count, finding
  delta, and NEXT;
- literal xterm `ESC[Z` cycles all five pages without changing draft/cursor;
- selection remains visible without color;
- DFD and every visualization has a real-data or explicit-empty projection;
- every contextual `Esc` restores the exact originating phase/page/pane, scroll,
  finding, and input mode;
- report export success and failure never navigate away from Report.
