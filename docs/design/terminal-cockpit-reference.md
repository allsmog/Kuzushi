# Kuzushi terminal cockpit reference

**Status:** canonical Cockpit Spine contract
**Supersedes:** the legacy four-pane Workbench and Activity composition notes in
earlier revisions of this document. Historical mockups remain useful as visual
references, but they do not define navigation or state ownership.

## 1. The cockpit spine

The operator follows one durable workflow:

```text
Target -> Setup -> Map <-> Run Focus -> Scan <-> Run Focus
       -> Review -> Prove <-> Run Focus -> Fix <-> Run Focus -> Report
```

The persisted workflow enum is `Map -> Scan -> Review -> Prove -> Fix`; Report
is an exit surface, not a sixth persisted phase. The current phase is always
derived from current-target/current-revision artifacts, selected attempts,
finding review dispositions, proof, and remediation state. Opening a screen
never forges progress.

Every screen answers, in order:

1. What target and durable phase am I looking at?
2. What is true now?
3. What can I do next?
4. What evidence or artifact supports that statement?

Only one selection or action region owns the accent. Severity, proof, failure,
and lifecycle colors remain semantic. All meaning also has a word or glyph so
no-color and high-contrast terminals retain the contract.

## 2. Global frame and input ownership

After Setup commits an engagement, durable workflow screens render:

```text
Kuzushi · <target> · <LIVE?> · <reality-derived phase>
Map   Scan   Review   Prove   Fix
----------------------------------------------------------------
<screen body>
----------------------------------------------------------------
◇ MAP › <shared composer draft>       <contextual controls and one NEXT action>
```

- `LIVE` means work is actually running; it is never inferred from the page.
- The phase rail is hidden before `Start Map` commits the engagement.
- Prompt and Navigate modes remain explicit on durable screens.
- `Shift+Tab` cycles all five pages in either mode without changing the shared
  composer draft or cursor; Navigate-mode `1..5` selects directly.
- `Tab` retains completion/pane-forward ownership; `]` also advances a pane and
  `[` moves back. Pickers, editors, questions, and Run Focus own keys first.
- Selected mode and reality are named separately when they differ, for example
  `VIEW SCAN · REALITY REVIEW`. Page selection changes no durable state.
- Foreground Run Focus owns all input and reserves no generic prompt row.
- TTY and plain rendering consume the same presentation models. Plain output
  serializes the reading order and prints exact command equivalents for any
  noninteractive action.

## 3. Target

Target selection is an explicit consent gate. The selected row shows facts;
`Enter` activates it. `Esc` opts into targetless capability browsing. The shell
never substitutes the current working directory.

```text
TARGET · CHOOSE SCOPE

> kuzushi-api
  /work/kuzushi-api
  git · main@8fd22ac · dirty
  Rust, TypeScript · Cargo, pnpm · nested scopes: 2

Enter activate target    Esc browse without a target
```

Candidate facts load asynchronously and are generation-stamped. A stale
response from a previously highlighted candidate must not replace the current
row. Facts include absolute path, repository kind, revision/branch/dirty state,
languages, build systems, nested scope, and prior Kuzushi artifacts.

Fresh or switched targets continue to Setup. A hydrated engagement resumes its
reality-derived phase page. `/setup` explicitly reopens Setup.

## 4. Setup

Setup is one aggregate readiness screen. Its rows are ordered by dependency:
Target, Map plan, Model, Credentials, Prompt, Budget, then `Start Map`.

```text
SETUP · READY THE MAP RUN
One readiness check. Model and credentials are required only by the selected plan.

  Target         CONFIRMED       /work/kuzushi-api
> Map plan       READY           2 selected · 2 deterministic · 0 model-backed
  Model          NOT NEEDED      deterministic/runtime-free plan
  Credentials    NOT NEEDED      no selected task requires a provider
  Prompt         BUILT IN        no selected task requires an edit
  Budget         NOT ENFORCED    set a positive cap or continue without one
  Start Map      READY           commit this Map plan and open Run Focus

READY · 2 Map task(s) · Enter Start Map to commit
```

`Enter` edits the selected row and returns to Setup with the cursor, scroll,
selected plan, prompt draft, and other readiness choices intact. A model is
resolved by stable model identity; a reordered or filtered visible catalog may
not change what the highlighted row selects.

Readiness is plan-aware:

- A nonempty deterministic/runtime-free plan can run without a model.
- Model-backed tasks require an explicitly selected compatible model and a real
  API-key, stored-OAuth, or session credential.
- Missing CLIs, options, or prompts block only affected tasks.
- An unset budget reads `NOT ENFORCED`; a set budget must be positive and no
  greater than the hard ceiling.
- `Start Map` moves focus to the first blocker and explains it when blocked.

Setup has no journey or autonomy chrome because the engagement does not exist
until `Start Map` succeeds.

## 5. Run Focus

Run Focus is the only foreground-run presentation. One `RunFocusModel` owns the
run/sequence identity, authoritative planned task rows, current task, output
window, health/stall state, cost, queue depth, origin, and terminal receipt.
There are no duplicate `CURRENT`, `ACTIONS`, heartbeat, or context-specific
checklist projections.

### Geometry

The renderer, scrolling, and hit-testing use the same pure rectangles:

- Usable width `>= 78`: Steps left and Output right, beginning on the same row.
  Steps is 32% of width, clamped to 28-40 columns; Output gets at least 48.
- Width `50-77`: vertical stack. Steps is content-sized and capped at 40% of
  the body; Output receives the remainder.
- Width `< 50`, or body height `< 14`: one focused viewport. `Tab` switches
  Steps and Output.
- Height alone never makes a wide screen stack.

Canonical wide frame (the origin label keeps its mode accent):

```text
RUN FOCUS · MAP · sequence 1/2 · LIVE · $0.00 · queued 1
----------------------------------------------------------------
STEPS                         | OUTPUT · context:build
> ... Gather repo context    | inventory: 143 files
  o   Map entry points       | language: Rust
                              | wrote .kuzushi/context-snapshot.json
----------------------------------------------------------------
s steer    b background    Tab focus    Ctrl+C cancel
```

The default input mode is Navigate. `s` opens a compact inline steer editor.
Only `run <tool> ...` is accepted: invalid text remains as an inline error,
`Enter` queues a valid command through the existing steer queue, and `Esc`
closes the editor. `b` backgrounds without cancellation.

Before a foreground launch, the shell captures `RunFocusOrigin`: view,
phase/page/pane selection, input mode, scroll state, pinned finding, and
auto-return ownership. Prerequisite chains, plan tasks, and steer work retain
the order `chain -> plan -> steer`. Intermediate results accumulate; after the
final success, failure, or cancellation, the exact origin is restored with one
receipt:

```text
SUCCESS · 2 runs · 18.4s · $0.03
changed: context snapshot, entry points · findings +3/-0
NEXT review the new findings
```

Manual Run Focus inspection and background-owned work never auto-return or
steal focus. Background completion posts a notice/receipt only.

The completion receipt also retains the attempt id, origin phase, every run
reference, interaction count, rerun input, typed actions, and recommended next
destination. It is persisted as reference-only phase-attempt and disposition
events, so restart does not lose the result card. Selecting a partial result
requires acknowledgement. Dismiss or Discard never deletes canonical evidence;
an unresolved foreground result blocks another bare intent from that page.

### Operator question card

Only a root interactive-shell agent run may request a structured choice. The
card owns input while foregrounded: arrows or `j`/`k` select, numbers choose,
left/right changes question, `Tab` opens Other, `Enter` submits, `Esc` exits
Other or cancels, and `b` backgrounds. Jobs labels a backgrounded request
`WAITING INPUT`; reopening Activity restores it without focus theft.

The worker/UI handoff is reliable and cancellation- and generation-aware.
Question ids, predefined labels, resolution, and the presence of freeform are
recorded, but raw freeform text is never persisted. Modules, subagents,
bridge-owned loops, and headless execution do not receive this UI capability.

## 6. Durable phase pages

### Adaptive presentation policy

Durable phase truth chooses the visible composition; terminal size only limits
what can fit. The shared presentation plan uses five densities:

- `Sparse`: one primary narrative with missing, blocked, stale, and next-action
  states rendered as rows rather than empty panes;
- `MasterDetail`: a primary task surface plus meaningful selected detail;
- `Dense`: at most three independently useful populated surfaces;
- `Focused`: one operator-selected `Z` deck;
- `Guided`: a foreground question or unresolved result owns attention while
  the phase body becomes a quiet summary.

Rendering, focus order, scrolling, zoom, and mouse hit-testing consume the same
semantic surface rectangles after the phase header, question/result card, and
lower chrome have reserved their rows. A hidden stored focus may receive a
temporary visible fallback during resize or Guided mode, but the stored focus
is retained so widening or dismissing the card restores it. Missing artifact
guidance never creates an empty bordered region, and width alone never enables
Dense mode.

### Map

Map is a projection of durable target artifacts, never live Activity state. It
shows target context, source inventory, grouped attack surface, hot modules,
threat-model/DFD status, harness/material readiness, and freshness. An unrelated
retained run cannot appear as Map truth.

```text
MAP · TARGET CONTEXT                    ARTIFACTS
Rust · Cargo · main@8fd22ac             context      fresh
143 sources · 11 entry points           attack map  fresh

ATTACK SURFACE                          MATERIALS
request boundary      7 routes          threat/DFD  ready
storage boundary      3 stores          harness     ready

NEXT open Review · d DFD · t terrain · h heatmap
```

Missing artifacts render one actionable hint. DFDs and other visual material
are still first-class: they open as contextual visualization decks (§8), while
Map remains the durable summary.

### Scan

Scan is a resting projection, never live progress. It shows the selected
current-target/current-revision attempt, scope and engine plan, per-engine
`complete | partial | skipped | failed` outcomes, finding and artifact deltas,
failures, duration, cost, freshness, canonical run references, and one NEXT.

```text
VIEW SCAN · REALITY SCAN             ATTEMPT scan-... · COMPLETE
scope src/ · 3 engines               +8 findings · 2 artifacts

ENGINE COVERAGE                      SELECTED RUN
semgrep       complete               run scan-semgrep-...
secrets       complete               0 failures · 18.4s · $0.03
agentic-sast  skipped                NEXT use & review
```

At `40x12`, the panes collapse into one combined summary without dropping
mode, reality, scope, outcome, engine count, finding delta, or NEXT. A partial
attempt advances only after explicit acknowledgement; failed, canceled, and
stale attempts do not. A selected clean attempt offers Report and marks empty
downstream phases not applicable. Imported findings appear as an imported Scan
attempt. Legacy scan records are labeled `legacy inferred` rather than
rewritten.

### Review

Review is a findings queue plus selected detail. Every row includes authority
marker, severity, canonical proof mini-meter, unique source count, confidence,
and human decision when present. Confidence-first ordering remains the shell
contract.

```text
REVIEW · 8 NEED ACTION                 SELECTED · F-0007
> ? HIGH  [oo..] 2 src  84%            SSRF in webhook resolver
  + MED   [ooo.] 3 src  91%            source: scanner + agent
  ! LOW   [o...] 1 src  human defer     NEXT v prove this finding
```

If a pinned finding is excluded by the active filter, Review, Prove, and Fix
show its exact identity, the active filter, and a `reveal in queue` action.
Verify, suppress, patch, and apply always target the explicitly displayed
finding, never a hidden selection.

### Prove

Identity, `STATUS`, and the single shared `NEXT` strip precede evidence. Wide
mode places Evidence and Proof Ladder side by side, then replay/provenance.
Compact mode retains identity, status, next action, proof meter, sources, and
stale-proof warning before metadata.

```text
PROVE · F-0007 · SSRF
STATUS candidate · proof [oo..] · 2 sources
NEXT v verify with the originating detector
----------------------------------------------------------------
EVIDENCE                         | PROOF LADDER
webhook.ts:47                    | static      complete
request URL reaches fetch()      | runtime     missing
----------------------------------------------------------------
REPLAY · verification run verify-...
```

Proof replay uses the persisted verification run, not the discovery scan. A
proof attached to an earlier observation is visibly stale and requests
revalidation.

Triage is Review truth, never proof. Every review-actionable current-generation
finding requires real terminal verification or explicit human deferral before
Prove is complete.

### Fix

Fix renders the remediation lifecycle rather than a transient pending patch:

```text
Draft available -> Staged for approval -> Applied; re-verification required
-> Re-verification running
-> Verified | Still vulnerable | Not rediscovered | Inconclusive
   | Failed | Interrupted
```

`Changed since apply` is a distinct state when touched-file hashes no longer
match. A successful apply remains on Fix with Remediation focused and displays
touched paths, diff hash, application identity, and the exact `v`
re-verification action. Only deterministic verified absence is `Verified`;
nondeterministic absence is `Not rediscovered`.

Lifecycle receipts are append-only and attributable to the stable finding,
patch run, application id, target, diff, touched-file hashes, actor, and
re-verification run. Historical sound patch synthesis is `Draft available`,
never fabricated as applied.

Apply additionally requires a `SOUND` candidate with matching generation
commit, target identity, originating run, detector tool/run, and detector-input
digest. Intent and application identity are recorded before mutation. Missing
legacy provenance makes detector-bound re-verification `Inconclusive` and asks
for regeneration. Selecting a patch never applies it.

## 7. Report

Report is the dedicated exit route from Fix. Formats are ordered SARIF,
Markdown bundle, JSONL, JSON, CSV. Completeness defaults to `All`; `c` cycles
`All -> Open -> Complete`.

```text
REPORT · EXPORT EXIT

> SARIF             report.sarif
  Markdown bundle   report/
  JSONL             findings.jsonl
  JSON              findings.json
  CSV               findings.csv

completeness  ALL
destination   report.sarif
Enter Export · e Edit path · c Completeness · Esc Back to Fix
```

Paths are target-relative until export and can be edited. Success and failure
remain on Report and display format, finding count, completeness, absolute path
or error, and timestamp. The receipt offers Retry, Back to Fix, and `o Reveal
Destination`. Reveal occurs only after the explicit `o`; unavailable platform
support becomes an inline error. Exports include additive remediation metadata.

## 8. Contextual surfaces and visualizations

Help, Controls, and Capabilities are modal contextual surfaces. Jobs, Replay,
Trace, DFD, entry-point inventory, terrain, heatmap, attack tree, and
attack-path visualizations are scrollable full-frame decks. These screens do
not replace the workflow route.

One non-nesting contextual route captures the original workflow view and its
input mode. Opening a second contextual surface replaces the first while
retaining the original origin. `Esc` always restores that exact origin,
including page/pane, scroll, selected or pinned finding, and input mode.

The visualization gallery remains real-data only:

- terrain: severity-weighted risk by hot module;
- DFD: persisted threat-model data-flow graph;
- entry points: every persisted ingress in a trust-zone-grouped selectable list
  with a selected detail pane and Enter-to-DFD navigation;
- components: detected languages/build systems plus an SBOM tree that keeps
  declared manifest constraints distinct from resolved lockfile versions;
- heatmap: per-module finding risk;
- attack tree: persisted exploit chains;
- attack path: source-to-sink taint stages;
- Trace/Replay: shared run artifacts.

Missing data produces one guidance line, never sample evidence. Foreground
auto-open restores the workflow origin before opening the relevant deck.
Background completion never navigates.

## 9. Responsive and plain acceptance matrix

The canonical render sizes are `40x12`, `60x20`, `80x24`, `96x89`, `120x36`,
and `160x48`, each under truecolor, ANSI-256, no-color, and plain output.

At `96x89`, Run Focus Steps and Output begin on the same row; no prompt row or
blank canyon separates them. At narrow sizes, Prove retains identity, STATUS,
NEXT, proof, sources, and stale-proof state. All selections use a non-color
marker and full selection band. Formatting occurs only after the retained event
ring is windowed, so off-screen history is not rebuilt per frame.

The one-row composer tokens are `◇ MAP ›` (teal), `▦ SCAN ›` (gold),
`▣ REVIEW ›` (blue), `◎ PROVE ›` (violet), and `◆ FIX ›` (magenta), with
phase-specific placeholders. ANSI, high-contrast, and no-color modes retain the
glyph and label; severity, warning, failure, proof, and success keep their
semantic palette. Literal xterm BackTab (`ESC[Z`) must wrap all five pages and
preserve draft/cursor.

Operator-owned keybinding overrides may replace the default BackTab mapping,
define a two-stroke chord, or explicitly unbind an action. Footer and keymap
chrome must project the active mapping, question/modal contexts keep first key
ownership, and an invalid hot reload leaves the prior map intact.
