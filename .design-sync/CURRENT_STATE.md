# Current Kuzushi TUI surface map

This file gives Claude Design the current composition model. It is descriptive,
not aspirational.

| Product surface | Current renderer family | Design-sync component | Important states |
| --- | --- | --- | --- |
| Target selection | onboarding line view | `RouteScreen` | candidates, loading profile, targetless browsing |
| Setup | aggregate readiness | `SetupScreen` | ready, blocked, model/credential required, budget edit |
| Map | phase cockpit | `PhaseCockpit phase="map"` | resting, live context signal, returned Plan |
| Scan | phase cockpit | `PhaseCockpit phase="scan"` | no receipt, accepted receipt, partial/degraded, returned Plan |
| Review | phase cockpit | `PhaseCockpit phase="review"` | empty queue, list/detail, filters, returned Plan |
| Prove | phase cockpit | `PhaseCockpit phase="prove"` | evidence, proof ladder, deferred/failed, returned Plan |
| Fix | phase cockpit | `PhaseCockpit phase="fix"` | draft, staged, applied, reverified, returned Plan |
| Report | line-oriented exit | `RouteScreen` | preview, export receipt, incomplete/degraded |
| Activity / planner / tools | full-frame activity | `RunFocus` | live, waiting, complete, partial, failed, canceled, interrupted |
| Phase intent proposal | conditional lower card | `PlanningCard` | returned proposal, toggled change, unsupported item |
| Questions and gates | typed attention input | `AttentionCard` | question, confirmation, credential, approval |
| Runs / Jobs / Replay / Trace / Diff | run-history utilities | `RouteScreen` | empty, live+recent, stale, terminal receipts, long trace |
| Catalog / Recommend / Module / Tools / Options | capability utilities | `RouteScreen` | no target, recommended, expert inventory, option detail |
| Findings aliases and detail | Review routes to cockpit | `PhaseCockpit phase="review"` | unfiltered truth, filtered projection, pinned conflict |
| Threat / editors / prompts / tune / actors / strategy | line/editor utilities | `RouteScreen` | ready, editing, blocked, queued |
| Context / project / workspace / KB | workspace utilities | `RouteScreen` | absent, loading, ready, stale, malformed |
| Health / Auth / Config / Permissions / Cost / Logs | system utilities | `RouteScreen` | ready, missing, degraded, long content |
| Help / Quickstart / palette / pickers / dialogs | overlays and onboarding | `RouteScreen`, `AttentionCard` | empty query, filtered, selected, dismissed |
| Scene / visualizations | contextual artifact deck | `RouteScreen` | backed artifact, empty guidance, TTY-only fallback |
| Agent chat/history/story compatibility | line/chat compatibility | `RouteScreen` | empty, streaming, historical |
| Boot / update / interruption / failure / quit | system/recovery | `RouteScreen`, `AttentionCard` | ready, degraded, retry, handoff, confirmation |

## Current navigation and input behavior

- Prompt mode owns printable input. `F2` enters Navigate mode; `Esc` returns to
  Prompt mode.
- `Ctrl+G` opens the command palette. Contextual utilities restore their exact
  workflow origin on `Esc`.
- `next` opens the current phase planner. Explicit `phase map|scan|review|prove|fix`
  selects a phase without forging journey progress.
- A bare intent in a phase composer starts the constrained planner in Run Focus.
  Its returned proposal is reviewed in the lower Plan card.
- Run Focus `b` backgrounds work without cancellation. A completion restores
  the captured workflow origin when that run owns the foreground.
- Attention gates own the input surface until answered; they are not transcript
  lines that can scroll away.

## Current responsive ownership

The viewport changes composition, not domain truth:

- compact: one primary surface and shortened context;
- standard: two panes for the phase's strongest relationship;
- wide: a third useful pane or expanded evidence/detail;
- Run Focus: focused/one pane below 50 columns, stacked between 50 and 77,
  side-by-side at 78 and above;
- footer hints wrap rather than silently dropping active bindings.

All sizes preserve the bottom phase composer and conditional Plan proposal
workflow.
