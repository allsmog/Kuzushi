# TUI UX remediation — implementation and acceptance ledger

Baseline: `a59e1433321bf2f110c8f1bef93a6ba6167a42fc`.
Initial integrated source: `969593df0e6f01aa465acf59bde2537567b288b2`.
Related: issue #172 and PR #269.

This ledger separates a code change from completed release acceptance. It does
not assert that every requested item is implemented or that native, visual,
provider, performance, or platform checks have passed. Exact executable results
belong in the PR verification receipt.

## Implemented interaction changes

### Result ownership

Result keys and the associated mouse-attention check follow the active
Workbench page. An unresolved attempt on another page cannot own these inputs.
Visiting the owning page restores its existing actions. Default and configured
result shortcuts also refuse a nonempty composer. Prompt semantics, result
policies, and durable disposition writes remain unchanged.

This is phase-local ownership, not the full proposed painted-frame/focused
attempt-generation protocol. That stronger protocol remains an explicit gap;
this implementation must not be described as providing it.

### Entry-point browsing

In Navigate mode on the entry-point browser, `/` opens a dedicated local search
editor and `C` clears the query. Enter or Escape finishes editing without
submitting a command. Queries match all whitespace-separated terms, ignoring
case, across name/kind/recorded path/disposition. `path:`, `kind:`, and `state:`
restrict a term to its field. Hyphenated `state:extracted-only` and
`state:model-only` match the corresponding disposition labels. Search text is
bounded to 512 characters; pasted controls are discarded and whitespace is
normalized rather than executed.

Filtering creates a cached presentation projection. Canonical evidence counts,
receipts, and source records are unchanged. Disposition groups are counted for
the visible rows. Selection is bound to an entry identity once the operator
navigates or searches; a removed identity does not silently activate another
row. A no-match state is distinct from missing or unreadable source evidence.
Target activation clears the query, selection binding, and search cache.

The default browser header is compact. Full provenance remains in the selected
entry's scrollable detail instead of consuming the default reading area.
The existing missing model-receipt vocabulary has not been completely redesigned.

### Map

Available source-derived entry points or component inventory can make Map's
gallery useful before a threat model exists. The existing workflow-prerequisite
predicate remains separate and unchanged: inspecting an artifact does not
accept an attempt or advance the journey. When no modeled Summary is available,
the gallery shows a local-inventory summary, explicit catalog freshness, and
component counts. The model-backed Summary is retained when available.

Plain Map output retains worklist information. The existing status-card sizing
fix is preserved rather than duplicated. Full small-terminal and transition
captures are still required.

### Verification plans and Setup

Static-only investigation goals no longer promise runtime reproduction or
refreshing stale runtime proof. The card explicitly says it will not produce or
refresh a runtime witness. Local reproduction retains its original runtime
goals. This changes the plan presentation, not verification execution or proof
promotion rules.

Compact Setup includes revision and dirty-state facts rather than omitting the
entire fact block. The already-merged #267 task/support-run disclosure and its
follow-up fixes are retained.

### Report

A successful export offers another export and Reveal rather than Retry. Failed
exports retain Retry but cannot reveal a destination as if it had been written
successfully. Editing the next export format/completeness/path preserves the
last export receipt as historical context.

Canonical preview/export snapshot equivalence is not implemented by these
changes. The existing preview uses the loaded finding projection; it must not
be advertised as a newly verified complete export corpus.

### Routine checks

The quick repository verification plan now executes the unfiltered native
`kuzushi-tui` library test suite, in addition to compilation. Its contract test
pins the exact Cargo arguments. A skipped draft workflow or a timed-out build is
not a passing native-test receipt.

## Traceability to the requested 26 acceptance items

| Item | Current implementation disposition | Required outstanding acceptance |
| --- | --- | --- |
| 1 | Phase-local result ownership implemented; full explicit focused-result target not implemented | Live visible/off-page ownership and cross-phase inspection |
| 2 | Existing commit-time policies retained; painted attempt/generation stamp not added | Race and duplicate-event protocol implementation and tests |
| 3 | Off-page keyboard/mouse interception fixed; local search/paste editor added | Remapped keys, mouse geometry, all modal and help paths |
| 4 | Existing foreground/background restoration preserved | Deterministic async-event interleavings and real-terminal test |
| 5 | Existing result policy preserved | Complete outcome/acceptance copy and action-policy unification |
| 6 | Already present in baseline through #267 and follow-ups | Actual task/support-run count reconciliation matrix |
| 7 | Compact revision/dirty facts added | Actual 60x20/80x24 preflight captures and start revalidation |
| 8 | Read-only artifact-first Map implemented | Keyless first-run and model-backed gallery journeys |
| 9 | Existing freshness and readiness semantics retained | Mixed-generation, corrupt-artifact, and target-switch cases |
| 10 | Existing status-card bound retained; gallery availability changed | Wrapped-content layout and transition matrix |
| 11 | Bounded case-insensitive fielded local search implemented | Live query editing, keymap discoverability, and large catalog |
| 12 | Filtered activation and stable selected identity implemented | Hydration/reorder/removal integration cases |
| 13 | Default provenance header compacted; details retained | Remaining missing-model receipt wording and visual review |
| 14 | Boundary-aware runtime goals and static-only disclosure implemented | Static/empirical plan-to-command integration |
| 15 | Existing shared drafted-command/model ladder retained | J31 and effective-configuration execution checks |
| 16 | Existing proof/deferral/verification policies retained | Model, runtime, stale, split, blocked and degraded matrix |
| 17 | Existing visible-Review versus pinned-Prove/Fix distinction retained | Cross-phase subject identity and generation regression |
| 18 | Existing patch lifecycle and approval services retained | Disposable-target draft/reject/apply/reverify matrix |
| 19 | Existing refusal/restart behavior retained; export draft receipt preserved | Failure injection and restart journeys |
| 20 | Outcome-specific export actions and historical receipt implemented | Success, failure, repeated Enter and changed-draft cases |
| 21 | Not implemented: authoritative prepared export snapshot | Core-owned preview/write equivalence and six-format comparison |
| 22 | Failed-export Reveal blocked; shared writer unchanged | Filesystem/overwrite/interruption/platform-path matrix |
| 23 | Native TUI tests added to routine quick plan | Required-check administration, zero-test protection, executed green run |
| 24 | Focused regressions added; existing BDD harness retained | Single-key live journeys and deterministic scheduler extension |
| 25 | Cached search projection added | Measured release-build latency, idle CPU and memory budgets |
| 26 | Public CLI/MCP/storage/provider contracts unchanged by intent | Full packaging, platform, plain-output and controlled-provider checks |

## Required release evidence

Run the exact integrated candidate through the native suite and relevant
existing journeys, including J1/J2/J3, J5/J7/J8/J9, J12/J14/J15/J16/J17,
J25/J31/J49/J53. Match artifacts to the binary SHA and target source identity.
Record machine assertions separately from human REVIEW items.

Render at 60x20, 80x24, 120x36 and 160x48; probe 40x12, 96x89 and layout
threshold boundaries. An off-screen string assertion is not proof that a
critical fact remains visible in the rendered viewport.

Use isolated homes and disposable targets. Verify no target source changes in
navigation journeys, and exactly approved changes in patch journeys. Preserve
canonical evidence and public machine-readable fields. Real provider/OAuth
integration requires deliberately authorized credentials and cannot be
substituted by keyless fixture success.

The PR remains draft until its outstanding implementation and verification
items have explicit, evidenced dispositions. Reverting the source commits
requires no persisted-schema migration; it must not delete target evidence.
