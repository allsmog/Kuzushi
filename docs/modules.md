# Kuzushi modules

Windows MCP file capabilities bind an opening content digest and verify the
returned bytes against it before accepting reads or copies. Verification uses
bounded streaming passes and restores the retained file cursor. Timestamp and
file-ID metadata alone do not authorize reuse of changed content.

This document describes the module surfaces implemented by the current Rust
product. Kuzushi has two authoring paths:

- First-party capabilities are Rust descriptors plus Rust executors registered
  in `ModuleRegistry`.
- Third-party local capabilities are single-file JavaScript workers using the
  brokered Kuzushi Worker Protocol (KWP).

There is no TypeScript authoring SDK and the npm package does not export
`kuzushi/modules` or `kuzushi/testing`. The published package contains the
public schemas, native launcher, and Node support files used by the Rust
product.

Companion docs: [`mcp-server-requirements.md`](./mcp-server-requirements.md)
for MCP-bridged modules; [`api-compatibility.md`](./api-compatibility.md)
for legacy aliases and route compatibility; [`module-maturity.md`](./module-maturity.md)
for Core, Labs, and Compatibility discovery policy;
[`devex/06-module-sdk-assessment.md`](./devex/06-module-sdk-assessment.md)
for the historical SDK audit that shaped the current surface.

## Guided source investigation

The guided shell follows **Map → Scan → Review → Report**. Review completion is
based on durable decisions, including explicit deferral; it does not require
proof execution or patch work. Report can also be opened before completion and
exports the selected completeness policy without changing any finding verdict.

Workbench navigation offers `1` Map, `2` Scan, `3` Review, and `r` Report in
Navigate mode. `Shift+Tab` and next-page navigation from Review open Report;
`Esc` returns to the same page, finding, focus, zoom, scroll and input draft.
The Report shortcut is configurable as `workbench.report`. Draft text owns
ordinary letter keys. The Review planner's right arrow also opens Report.

The persisted five-value `WorkflowPhase` enum, legacy names, historical receipts,
and explicit compatibility commands remain readable. Their presence does not
add Prove/Fix steps to the guided journey. An unresolved historical Prove/Fix
attempt cannot redirect that journey. Report is a separate descriptor surface;
`BuildReport` is retained as a saved-plan identifier but is no longer offered as
a Fix planning task. No public module executor is removed.

Standalone Map artifacts remain readable, including partial deterministic
diagrams, but do not accept themselves or advance the phase rail. A completed
Map attempt needs explicit selection; partial work needs acknowledgement.
Existing completed scan history retains its pre-ledger compatibility reading
path. Browsing or restarting with artifacts alone records no acceptance.

`campaign:context-map threatModelRef=<exact reference>` reviews an existing
revision through its authenticated producing run. It requires current source
and preserves completed or partial outcomes; it never regenerates context,
changes the active model or selects a Map attempt. It is an alternative to
the context-campaign handoff, which still requires both campaign identifier and
plan digest. Missing, changed or damaged source evidence remains inspectable
but cannot satisfy current Map acceptance. Re-importing verified context can
create a new source-bound receipt without a model request.

## Report surface

`report:build`, `report:sarif` and `workspace:export-findings` declare
`phase: report`, a catalog and dispatch
surface separate from the persisted Map/Scan/Review/Prove/Fix workflow. Reports
export existing evidence at any autonomy posture and never advance a workflow
phase. File exports retain descriptor authorization. The Report phase permits
read, workspace-write and target-write effects; repository-execute and
external-action descriptors are rejected. Phase metadata never schedules work.

`workspace:export-findings` accepts optional `campaignId` (`campaign_id` alias).
The CLI equivalent is `kuzushi export --campaign-id <id>`. This selects the
study's authenticated parent and engine observations, including retained partial
attempts, instead of unrelated workspace history. Safe identity projection is
shared with Review, so recurring observations retain their evidence as one
finding without folding different weak identities together.

Every format includes a companion version-1 investigation receipt. It records
planned/completed/failed/pending work, occurrence, raw observation run references,
source SHA and content identity, accepted context, configuration/prompt digests,
human review counts and current shared investigation allowance. JSON, JSONL and
SARIF embed it too; Markdown links it and hashes it in the bundle manifest. CSV
and external scanner files preserve their existing rows. Omission of `campaignId`
retains the existing workspace-history export. Completeness filters describe
human review, not repository coverage. Unknown dollar totals remain unknown.

Reporting authenticates saved work and historical approval without granting
execution authority, resetting reservations or starting follow-up work. The
receipt discloses missing inventory/engine coverage and prompt/context omissions.
It references raw observations rather than bundling every historical artifact.
Human decisions are not yet bound to a source revision, and a missing observation
never proves a fix. Old campaigns without allowance history disclose that absence.

## Bounded shard proposals

`pack:scopes` is the source-bound review foundation for logical discovery
boundaries. Its descriptor exposes `create`, `read`, `edit`, `accept`, and
`files` operations. It uses bounded repository inventory and makes no model
requests. `create` keeps the whole repository together unless given an explicit
draft. It does not install a shard manifest, start jobs, or advance Map.

Each edit creates an immutable revision linked from the existing strategy
proposal queue. A saved reference identifies the proposal, revision, and
content digest. Coverage reports exact totals with previews of at most 128
files; `files` provides bounded pages for the remainder. Loose root files,
overlaps, exclusions, context-only shared membership, and inventory limits
remain visible. Invalid paths, more than eight primary scopes, stale references,
source drift, or damaged saved data fail explicitly.

`identityOmissions` separately reports included files absent from the authenticated
content tree, including files beyond its per-file size limit. Those memberships
cannot be accepted by acknowledging partial inventory. Explicitly exclude them
or reduce the scope first. The source identity and inventory have separate
limits; inventory inspection byte counts do not measure content hashing work.

Acceptance refuses uncovered inventoried files and requires acknowledgements
of inventory limitations, duplicate discovery, and exclusions. It approves
boundaries only. Future study compilation must consume
`load_accepted_scan_scope_proposal`, which checks committed acceptance and current
source, rather than trusting a raw historical artifact. Editing a newer draft
does not invalidate an earlier committed acceptance used by an approved plan.
An acceptance orphaned by failed queue publication cannot be consumed. History
verification checks immutable predecessor links with a 4096-revision read bound.
Ordinary strategy approval cannot accept scope boundaries. The shell scope editor is available through `scopes`. The optional model
proposal and fixed scoped study compiler remain pending;
this tool is not evidence that the monorepo workflow is complete.

Scoped `sast:scan` preparation checks repository-relative membership without
following symlinks. Native adapters currently require directory scopes; a file
selection fails before scanner preflight instead of expanding to its parent.
`offense-review` and `systems-hunt` currently require whole-repository discovery.
`taint-iris-next` accepts one directory per scoped job, with any `targetSubdir`
matching that selection. Unsupported memberships require an explicit new draft;
workers cannot enlarge them. Explicit agentic include patterns cannot override
`paths`, and empty patterns no longer disable the derived selection.

These checks also run before study publication and again before pipeline work.
The shared native runner rejects outside-root and parent-traversal finding paths.
Directory-root dispatch is not proof of every scanner's complete coverage or
model-tool access isolation. Per-engine evidence and remaining limitations are
in [the discovery scope audit](./assessments/discovery-scope-2026-10-05.md).

Native SAST observations remain usable when an engine reports incomplete
coverage. The run is `partial`, with per-engine reasons in Scan and original
messages in authenticated `native-coverage.json` and `data.nativeCoverage`.
Coverage schema version 2 records engine, selected scope, findings count,
reported errors and execution disposition. The updated reader also accepts old
schema-1 rows, defaulting their execution disposition while preserving gaps. A separate engine with no reported error keeps its own
completed outcome; this does not certify complete repository coverage. Partial
absence cannot resolve earlier findings. The operator must explicitly
acknowledge a partial attempt before using it for the guided journey.

For a selected Semgrep task, `semgrepConfig` declares rule files or selectors
and `semgrepBinary` declares the executable through shared prepared dispatch.
Use absolute local rule paths when scanning directory scopes. Local rules
avoid remote rule selection but do not disable every executable network feature.
Neither option enables Semgrep when it is absent from the approved task list.
Legacy public scan helpers still return a coverage error after persisting
observations. The native SAST runner also retains earlier observations that passed scope checks
when a later native engine fails or cancellation stops the fixed plan. Coverage records
all approved engine/scope jobs with their explicit execution disposition,
including jobs never started. The findings ledger keeps failed, canceled or
interrupted status with its retained count; these runs cannot reconcile absent
findings. The authenticated terminal result carries the recorded Scan phase
stages, native coverage and retained count. A failed or canceled attempt remains
unselected, with inspection and separately initiated recovery actions. This
contract does not retain unreturned output from the failing engine or certify
storage-failure recovery, standalone abort retention or provider context
isolation.

Standalone `semgrep:scan` and `codeql:scan` also preserve reported omissions
through a `partial` envelope and findings lifecycle. Both use the shared source
snapshot guard, so current-source workflow selection can authenticate the
source present before discovery. A changed source keeps the output for review
without claiming it is current. Recorded partial summaries include a bounded
omission preview; full messages stay in the authenticated result. Their DAG
prerequisites remain metadata unless a caller explicitly consumes them.
Dedicated evidence and limits are in
[the native coverage audit](./assessments/native-partial-coverage-2026-10-05.md).

`pack:suggest-shards` uses one repository inventory and proposes at most eight
scopes. It keeps small repositories whole and retains a parent when splitting
would omit loose files. The result adds `inventoryComplete`,
`inventoryPartialReason`, `maxProposedScopes`, and `inspection`; `inspection`
records enumeration mode, resource limits, omitted paths, and prefix-only file
inspection. A Git-index inventory covers tracked working copies, not untracked
files. A partial inventory cannot establish full repository coverage.

`signals.entrypoints` counts inventory-derived entry points. Candidate IDs have
a stable path digest suffix. Existing saved manifests are not changed by
generating a draft. Explicit `emitScopes` keeps its existing scope-tree output,
but refuses partial inventory; emitted child scopes inherit parent context and
threat-model sections. No proposal launches a scan or performs model calls.

## Source-bound model Scan results

The registered `agentic-sast:scan`, `carlini-threat-hunt:run`, and
`offense-review:threat-hunt` paths attach `data.snapshotHash` and `data.treeHash`
from an indexed source snapshot captured before execution. A second source check
after execution marks the output partial if the source changed or cannot be
verified; the saved result and recorded spend remain available. These fields
come from the Rust adapter, not the model. Existing phase acceptance checks
authenticate the snapshot and require it to match the current source.

Agentic SAST, the offensive threat hunt, and every built-in that persists
through the shared tool-findings path (native scanners such as `secret-scan`,
`dep-hygiene`, `semgrep`, `codeql`, IaC, APK, chains, and plugin adapters) emit
typed finding deltas after the finding store commits, including a zero delta
for a clean run. Counts distinguish newly added fingerprints from existing
fingerprints seen again. A phase can infer a clean Scan from zero deltas only
when every referenced run supplied a finding observation; otherwise the phase
receipt's watermark records the gap and the shell labels the count
`findings unmeasured` (or `partly unmeasured`) instead of a measured `+0`. Older runs without
source receipts remain inspectable and require a new run before acceptance on
an unversioned or dirty target; their historical records are not rewritten.

## Audit remediation contracts

Shell composer and form fields share grapheme-aware cursor movement and deletion.
Their renderers retain whole graphemes and measure terminal cells; vertical field
navigation preserves display columns. This changes shell presentation only.
Collapsed pastes have tracked spans and undoable whole-block edits. Ctrl+Y opens
a read-only preview with expand/remove/cancel controls; Ctrl+_ restores paste
edits. Preview captures keys, pointer events and pasted input until it closes.
The terminal inbox admits at most 256 events and 4 MiB of event data, with a
1 MiB limit per accepted paste. Replaceable resize, pointer-move and focus states
coalesce only between ordered actions. Keys and pastes wait for capacity instead
of being dropped. Background wakes remain deliverable while input is saturated;
the shell records queue pressure once and joins the reader during shutdown.
Payloads stay in memory and are expanded exactly when the draft is submitted;
marker text typed by an operator never resolves to a hidden payload.

Semantic response reuse requires a closed-world tool policy and a runtime
attestation binding effective backend settings and implementation revisions.
Adapters without `semantic_cache_identity` execute live; the current external
LangGraph bridge does not attest its installed dependency closure. Generation
settings participate in versioned keys; credentials and diagnostics do not.
The cache applies global `operator.semantic_cache` byte/entry quotas inside an
immediate transaction. `SemanticCache::maintain()` reports bounded eviction and
legacy-cleanup progress. Interrupted cleanup retries its unfinished shard on the
next pass; successful-prune timestamps are recorded only after pending work ends.
Model lifecycle producers must persist `ModelCallStarted` before provider
dispatch. The writer reserves completion space, rejects starts beyond its eight
in-flight slots, and commits model receipts synchronously. Normal log exhaustion
does not erase completed usage/cost or permit a healthy terminal outcome.

MCP servers validate arguments against registered schemas before dispatch. Clients
must handle invalid-argument, capacity, cancellation and shutdown responses.
CPG callers must select regex or literal query semantics and check coverage,
truncation and approximate-position metadata. Unsupported depth limits fail.
The core `cpg_taint_paths` adapter enforces its advertised `maxPaths` range
(1–25, default 10); invalid values are errors, never silent clamps.
Structural queries reject ambiguous file or method identities and return
candidates. `cpg.definitions` returns a language-scoped selector such as
`cpp:method:<digest>` for subsequent queries, including shared headers indexed
by multiple language graphs. Bare selectors remain valid when unambiguous.
Queries reject absent files explicitly. Reaching definitions require exact AST membership at the requested line;
they cannot use the approximate nearest-preceding method from `cpg.method_at`.
Slice depth is an integer in 0–32, checked before graph work.

Persisted findings retain their original primary coordinates alongside grounding.
Source-independent evidence has an explicit kind; a code citation must identify
real source lines. Static verification accepts substantive verdicts only with
source-checked source/sink or control/reachability citations. Consensus receipts retain
individual assessments and label raw confidence as uncalibrated.

Resumable tool loops journal intent before a handler runs and refuse to replay an
unresolved intent automatically. Checkpoint IO/size/ownership failures are errors;
known paid work remains recorded even when a later turn fails. Module authors must
not interpret unresolved spend as zero or an inconclusive static review as an
empirical proof. See [migration notes](../RELEASING.md#audit-remediation-compatibility)
and the [itemized ledger](quality/audit-remediation-2026-09-30.md).

Loop and stage checkpoint codecs enforce 512 records, 1 MiB per encoded record,
8 MiB in total and the JSON nesting limit. Stage payload writers use the same
8 MiB budget before publishing an artifact. Staged tools return `resumeHealth`
and retain a bounded `resume-health.json` receipt when storage permits. Recovery
durability is separate from execution status: degradation preserves the last
durable recovery point, warns once per operation/failure class and stops further
checkpoint advancement until the next dispatch. An absent or stale receipt during a disk
failure must not be interpreted as healthy recovery; live diagnostics and result
metadata carry the in-memory state.

## Sources of truth

Use these in descending order when documentation and code disagree:

1. `schemas/module.manifest.schema.json` for the published compatibility
   manifest shape.
2. Rust descriptor and registry types under
   `crates/kuzushi-core/src/modules/` for live product behavior.
3. `scripts/kuzushi-dynamic-module-host.mjs` and
   `crates/kuzushi-core/src/modules/dynamic_loader.rs` for the dynamic worker
   protocol.
4. `examples/kwp/agentic-fuzz/` for an executable local-worker example.

Changing a public schema or persisted `.kuzushi` contract requires a migration
section in `RELEASING.md`, documentation, and focused compatibility tests.

## Rust built-ins

A live built-in is a `BuiltinModule` with `ToolDescriptor` values and a Rust
executor mapping. The descriptor is the policy surface; the executor consumes
already prepared canonical input.

Important locations:

- `crates/kuzushi-descriptor/src/` — tool metadata, `OptionSpec`, prompts,
  phase, effect, approval, and runtime/workspace requirements.
- `crates/kuzushi-core/src/modules/builtins/with_v2_builtins/` — registration,
  lookup, execution, DAG metadata, and output normalization.
- `crates/kuzushi-core/src/modules/registry/` — registry facade and dynamic
  module installation.
- `crates/kuzushi-core/src/modules/options/` — stored-option merging,
  validation, coercion, defaults, aliases, and unknown-key rejection.
- `crates/kuzushi-core/src/modules/application/sast_scan/` — umbrella scan
  orchestration and continuation stages.

### Dispatch contract

CLI scan, shell, and headless run must converge on the authorization-bound
registry path:

1. `ModuleRegistry::prepare_dispatch_input(...)` merges and validates options,
   normalizes paths, applies declared prompt defaults, binds any repository
   execution input, and returns an opaque `PreparedToolInput`.
2. The launching mode adds any required explicit or interactive authorization.
3. It dispatches with `dispatch_prepared_input_with_runtime(...)` or
   `dispatch_prepared_input_observed_with_runtime(...)` when lifecycle
   observation is required.

The raw `dispatch_prepared_tool_with_runtime(name, Value, ...)` method remains a
compatibility boundary. It deliberately re-runs preparation and should not be
the model for new callers. Direct executor calls from a mode-specific path are
not allowed.

### Map result source identity

`entry-points:extract` and `module-recommender:recommend` return additive
`data.snapshotHash` and `data.treeHash` fields from the shared registered
workspace snapshot. They capture that identity before source-sensitive work
and check the current tree before returning success. Existing catalog provenance
and recommendation payloads remain intact. Source hashing uses the existing
index bounds and emits progress during collection.

These receipts let a completed Map attempt authenticate all referenced runs
against the same source. The shell's Use/Continue controls respect the shared
ledger's source-reuse decision and refresh it before accepting a result. Missing
or changed source identity requires a fresh run; historical receipts are never
backfilled with a newly computed hash. Tool names, options, and manifest schemas
are unchanged.

`threat-model:import` also returns the normalized, verification-stamped
`data.document` and an authenticated indexed `data.snapshot` receipt. Import
uses the existing snapshot index limits: 200,000 indexed files and 1 GiB total,
with files larger than 64 MiB excluded by the shared index policy. These are
source-identity limits, separate from repository inventory inspection limits.
Import can now hit the indexed snapshot ceiling before its earlier hash-only
ceiling. It reports that failure rather than substituting a weaker receipt.

Map reads context from authenticated results of its recorded runs. Exact
references authenticate the immutable object and must agree with any recorded
document. Historical documents without a revision remain readable from their
authenticated run. Missing or damaged evidence never substitutes the globally
active model. New `campaign:study` drafts inherit the current accepted Map
revision unless `scanInput` explicitly selects or omits context. An accepted
Map from changed source requires a current acceptance or an explicit selection.
With no accepted Map history, the existing active-context default remains.

### Review result source identity and current observations

Deep Review distinguishes supported positive/negative assessments from unresolved
reachability. Its model analysis accepts `triggerable: true|false|null`; null
produces `needs_review` at any confidence. A missing caller or empty reference
search alone does not refute a finding. An `implausible_trigger` refutation
without an inspected `first_link` remains unresolved. Existing Boolean analysis
JSON and persisted triage records remain readable; Rust `VulnAnalysis` callers
use `Option<bool>` for this field. Explicit retriage records new decisions while
preserving historical outcomes.

`triage:run` captures the required workspace's source identity before Review
and returns additive `data.snapshotHash` and `data.treeHash` fields. A source
change during classification makes the result partial while preserving its
classifications and observed spend. Historical attempts without source identity
require a fresh run; they are not backfilled.

Policy-aware findings lists present the latest observation in each permitted
identity group, retaining its source and evidence history. The public emitted
generation reader remains exhaustive and severity-sorted. Review records with
no identity apply only to their exact finding row, including a row that itself
has a durable identity. Shared identity records retain their declared scope.
Human decisions outrank automated decisions; recency resolves decisions by the
same kind of author. This does not enable automatic identity reconciliation.

### Rust surface extraction compatibility

Rust inventory and attack-surface extraction share a source projection that
excludes direct `#[cfg(test)]` scopes, `#[test]` functions and inner
`#![cfg(test)]` scopes before ranking and model grounding. Production code in
the same file retains its original line numbers. This is not a reachability
proof: compound cfg expressions, unknown macros and cross-file test-module
ownership remain unclassified. Current Rust rows carry
`metadata.sourcePolicy = "rust-test-scopes-v1"`; the marker is included in
catalog payload digests but does not change surface IDs. New model runs refuse
older Rust context/catalog rows with a `context:build` then
`entry-points:extract` recovery message. Existing historical models remain
readable and are not silently regenerated.

### Verification modes

Static verification distinguishes supported positive and negative assessments
from uncertainty. `data.exploitable` (and its verification/proof copies) is
nullable: true supports the claimed path, false requires cited defeating
evidence, and null leaves the assessment inconclusive. Incomplete or unsupported
responses and panels without a strict majority return `status: partial`, retain
cost and source provenance, and cannot replace accepted proof. A gate with
incomplete evidence continues to the configured verifier. A split panel stays
inconclusive unless the explicitly configured tie-break resolves it. No model
or runtime is substituted. Historical receipts keep their original content.

`verify:finding` keeps the declared `mode=model|empirical` option. Model mode
requires the explicitly selected model runtime. Empirical mode uses the shared
registry to delegate the canonical finding reference to `verify:exploit`; it does
not create a model runtime. Headless invocation binds explicit authorization to
that prepared operation. The shell requests a fresh confirmation for execution.

Local reproduction currently supports Linux with bubblewrap. Discovering the
binary is only a prerequisite: execution still checks sandbox startup, supported
language/trigger construction and source provenance. Unsupported backends record
`NotAttempted`. The Prove card shows availability before drafting, omits model
controls for empirical mode, and keeps unavailable execution from being drafted.
Selecting a completed empirical receipt validates its finding, run, generation
and durable proof snapshot; runtime evidence additionally requires current source
identity. A not-attempted receipt never becomes runtime proof. Historical receipts
missing those binding fields remain inspectable and require a rerun before
selection; they are not rewritten.

### Source evidence for model-backed Map

The default `threat-model:build` sources are `context`, `source-code`, and
`threat-model`. `source-code` supplies actual source lines to single and staged
synthesis, gap filling, and refinement. Each supplied line has a workspace-relative
file/line reference; the projection records its scope, target-tree identity,
raw-file hashes, and omitted files/lines. Source text remains untrusted input,
and a cited line does not establish a confirmed vulnerability.

`maxSourceBytes` bounds each source projection (default 200,000 bytes), and
`contextLimit` limits selected code files (default 200, maximum 2,000). Code
collection prioritizes selected surface locations, then distributes files across
components. Small files are included completely when the budget permits; larger
files supply whole lines nearest the selected locations. Explicit read ceilings
are 2 MiB per source file and 16 MiB total after inventory collection. Oversized,
binary, non-UTF-8, and budget-omitted code is disclosed. Rust code uses the test-scope
projection described above. Target drift or an incomplete inventory stops the
build with recovery guidance.

### Single-pipeline coverage: gap fill and the coverage floor

When a single-pipeline `threat-model:build` leaves grounded entry points
uncovered and budget remains, it makes one bounded gap-fill call. This is the
same repair the staged pipeline and refine use. `coverage.gapFillMethod`
records what happened:
- `none-needed`: coverage already held.
- `stride-llm`: gap fill ran.
- `budget-exhausted`: no budget was left for the call.
- `gap-fill-failed`: the call failed. The model is kept and the gaps stay
  parked and disclosed.

The build is then refused, and nothing is persisted, if it still covers less
than `minCoverage` of the grounded entry points (declared option, 0–1, default
`0.5`). The error names covered/considered and the remedies. Pass
`minCoverage: 0` to keep a low-coverage model deliberately.

### Confirmed findings as threat-model variant patterns

`threat-model:build mode=refine` reads the workspace findings ledger, including
when the calling mode supplied no findings store. It attaches each newly
confirmed finding (an automated true positive, or a `confirmed`/`to_fix` review
decision) to the threat that covers its file, and it records a bounded
`variantPatterns[]` entry on that threat. The entry is deterministic and
grounded in the repository: `findingRef`, `title`, `cwe` (from the finding, or
the threat's single related CWE), `location`, the first call-site line (taken
from the finding's detection evidence, or else read from the file; imports and
function declarations never count as call sites), and that line's distinctive
identifiers as `keywords`. A threat keeps at most eight patterns, one per
finding. The revision records `provenance.refineDelta.variantPatterns`.

Later scans use the active model's patterns. taint-iris-next adds each pattern's
leading keywords to the matching CWE's structural queries and cites the source
location as a ranking reason. The agentic-SAST threat-model digest lists the
patterns as proven call sites whose siblings the agent should look for.

`sast:scan` exposes `threatModelFeedback=off|refine` (default `off`). With
`refine`, the scan dispatches `threat-model:build mode=refine` after triage,
through the shared registry and with the configured model. The scan reports the
outcome under `data.threatModelFeedback`. A refused refine, for example when no
model exists yet, becomes a scan warning and does not fail the scan.

An explicit `sources` list remains authoritative. Use `sources=none` to omit
source artifacts, or the prior `context,threat-model` list to retain its older
behavior. `contextMode=off` excludes the default source bundle; an explicit
`sources=source-code` still requests code. Enabled code collection requires
`maxSourceBytes >= 1024`. `seedMode=fresh` drops the prior model while keeping
code. The shared registry applies these options in every supported launch mode.

### Adding a built-in tool

1. Choose a stable kebab-case module id and a tool name in
   `<module-id>:<action>` form.
2. Add a `ToolDescriptor` with an honest description, `headless` value, journey
   phase, effect, approval policy, runtime/workspace/findings requirements, and
   complete `OptionSpec` list.
3. Add the executor and register it atomically with the module.
4. Consume canonical prepared option names in the executor. Do not parse a
   second CLI/TUI/env-only input surface.
5. Add focused descriptor, preparation, executor, and mode-parity tests.
6. Document the operator-visible tool in this guide or `docs/OPERATOR.md` /
   `docs/assessments/mode-parity.md` as appropriate.

`hidden: true` is reserved for internal nodes that must not appear in operator
or model tool lists. `headless: false` means `kuzushi run` must reject the tool.
DAG `depends_on` metadata does not schedule work unless the owning executor
explicitly consumes it.

### Options and prompts

`OptionSpec` is the canonical user-input surface. It owns type coercion,
defaults, choices, integer bounds, path semantics, aliases, and deprecated
aliases. Unknown keys fail at preparation.

Prompt-aware tools declare both prompt metadata and its canonical option. When
that option is unset and an explicit workspace is available, dispatch
preparation may load:

```text
<target>/.kuzushi/prompts/<module-id>/<verb>.md
```

Explicit tool input takes precedence. A mode must not add its own undisclosed
prompt search path. The `sast:scan` umbrella forwards its declared triage and
verification prompt values to the corresponding stages.

### Runtime and model selection

Descriptor-backed agent tools use `resolve_tool_model`; adapters that have
already parsed an explicit inline model use `resolve_explicit_model`. Once
execution policy is resolved, missing or incompatible runtime/model selection
is an error. A tool must not add a literal default model, a provider fallback
chain, or a target-local model override.

### Provider-call allowances

`AgentRuntime::with_allowance_binding` accepts host-approved investigation,
revision, run, work and model attribution. The bundled LangGraph runtime uses
the durable allowance ledger before each underlying provider attempt. This
includes internal model turns and transport retries; the admitted model disables
hidden SDK retries. The tracing wrapper forwards the binding and retains the
normal model-call lifecycle. Adapters that do not implement the contract refuse
binding rather than running without accounting.

The optional bridge channel is `providerAdmission: "stdio-v1"`. The host sends
one newline-terminated request, keeps stdin for admission replies, and reads
framed `provider_admission` messages from stdout. A version-1 hello precedes
reservations. The host mints each request identity, persists it before granting
transport, and acknowledges its receipt after settlement. A missing hello stops
the bridge after ten seconds. Cancellation or broken receipt exchange retains
the reservation. Missing dollar usage is unknown, even when a call failed.
Neither this channel nor the existing retrospective dollar stop guarantees a
strict dollar ceiling.

Approved campaigns with call-bound jobs and no dollar ceiling may continue when
prices or dollar receipts are unknown. Every job must have authenticated finite work
approval; the shared runtime still reserves each request and retains unresolved
reservations. A campaign, dispatcher job or plan job dollar ceiling continues to
require usable dollar evidence. Unknown totals stay unavailable rather than zero.
The campaign's cost notice does not itself imply that dispatch has halted.

Current SAST Scan receipts are read from their authenticated, call-correlated
result artifact. A changed result or damaged lifecycle fails that read rather
than falling back to a sidecar. Summary-only legacy receipts remain readable.
Accepted parent runs keep their identity; their recorded engine membership
connects observations to the guided Review queue. The Scan page aggregates all
parent receipts, keeping distinct ledger findings separate from added/updated
changes and retaining each engine outcome. A missing receipt is disclosed.

Source-bound executor errors retain the host's pre-execution snapshot through
shared observed failure settlement. Failed, canceled and interrupted results
may therefore carry additive `data.snapshotHash` and `data.treeHash` fields.
This records attempted source, not successful discovery or coverage. Source
drift still blocks current-target selection, and changed result artifacts fail
authentication. No new snapshot is captured after failure to make old work
look current. Partial Scan selection requires explicit acknowledgement.

The scan-batch controller records an unselected Scan phase result from its
authenticated attempt receipts. Completed and partial work retain their run
references; a batch with no executed attempt cannot claim a Scan result.
Repeated controller finalization reuses the same phase attempt, including
recovery after its typed receipt was saved before the compatibility history.
Changed source blocks selection as current coverage and retains the observations
for historical inspection. Accepting the result is an explicit shell action.
Campaign refresh reloads this phase history without selecting it or taking focus.

Agentic scan context includes bounded Map architecture, data flows, trust
boundaries and open questions even when no threats were proposed. Each section
uses at most twelve elements and caps textual fields at 200 characters; omitted
elements and truncated fields are disclosed in the supplied digest. The exact
accepted revision remains the input authority. These derived claims remain
untrusted guidance and do not establish finding verdicts.

This is an opt-in dispatch contract under implementation. Eligible built-ins
declare `allowanceRef` as a JSON option containing `schemaVersion: 1`,
`investigationId`, the approved `revision`, and `workId`. Shared prepared
dispatch checks the reference and selected model before runtime preflight.
The tool descriptor supplies its work category; input cannot label discovery
as review to spend the protected allocation. Governance fields are removed
before engine parsing or model prompting, while the prepared operation retains
their identity. Nested tools inherit the bound runtime and cannot replace it.

Normalized results add a host-owned top-level `allowanceRef` only when shared
prepared dispatch bound that reference. Engine-supplied values are replaced or
removed; payload `data` is unchanged. This is provenance, not approval of more
work. The call-correlated recorded result authenticates it. Legacy results
without this field stay readable, with accounting unrecorded.

A new `campaign:study` with no explicit `investigationId` retains the current
accepted Map's recorded investigation when available. Exact context selection
and accounting are independent: explicitly omitting or changing scan context
does not reset recorded spending. `load_accepted_map_allowance` authenticates
Map history and source content, then reads the latest accounting revision.
Missing accounting or damaged evidence fails implicit continuation. An explicit
`investigationId` overrides this default using that investigation's ledger;
plan approval remains required. Setup uses authenticated selected Map history
to retain spending when preparing a replacement Map after source changes.
`load_selected_map_history_allowance` permits this financial recovery without
allowing historical context to satisfy current-source discovery.

`campaign:approve-allowance` requires explicit operator authorization and exact
model, total-call, protected-review and expected-revision values. Approval
preserves previous commitments and starts no jobs. `campaign:allowance` reads
the durable state without initializing a ledger. Neither tool requires provider
credentials. The shell opens a full-frame review of the exact terms. Page Up /
Page Down scroll the document at every supported terminal size; approval is
available on its final page. Escape cancels and preserves the composer and
navigation origin. Plain output includes the complete terms.

`campaign:study` drafts an immutable discovery batch using the existing campaign
compiler. It starts no children. The optional `campaignId`,
`campaignPlanSha256`, `campaignJobs` and `maxJobAttempts` approval options bind
that exact batch to the allowance. Each child receives its host-selected work
reference; shared dispatch verifies prepared input, source identity and config
before atomically consuming a job attempt. Cancellation and restart do not
refund attempts. Quota failures count against the finite attempt limit. The
combined shell review uses the same paged disclosure, including the complete
plan digest, job count and attempt limit. Resizing reflows the terms and
rechecks whether the final page is visible before allowing approval.
The approval/snapshot contract adds optional `workPlan` and the spend database
adds `investigation_work_attempts`; legacy records omit this field.

`campaign:context-study` drafts one `threat-model:build` job in the same campaign
format and ledger. It requires `investigationId` and `contextInput`; an optional
`campaignId` names the new immutable draft. Shared preparation freezes the
selected model, source identity, config and generation options. This initial
action is repository-wide, source-only, fresh, single-stage and non-activating.
It requires one attempt; regeneration needs a new draft and explicit approval.
Provider turns and retries within that attempt still consume the shared call
allowance. The existing campaign dispatcher executes the approved job. Context
calls cannot consume protected Review/Report calls. A subsequent scan study uses
the same investigation id and a revised work approval, retaining prior consumption.

The shell exposes this flow through `g` in the study context picker. Generated
revisions remain immutable drafts; `a` on the completed campaign reopens review,
and Enter reads its exact run-associated revision before selection. A completion
without usable context remains available as a job outcome. Legacy context actions,
review and learning still need guided allowance integration before every model
action is bound automatically.

The completed context result also offers `m Review Map`. Its shared
`campaign:context-map` tool accepts the `campaignId` and `expectedPlanSha256`
pair for this origin, or an exact `threatModelRef` for an existing revision.
The executor rejects missing, incomplete or combined origins through shared
prepared dispatch; ordinary required-option flags do not express this choice.
It checks the frozen source identity, every completed job and its recorded tool
call, then authenticates the exact generated revision against the recorded
result. It creates or reopens one durable Map attempt without selecting it.
Repeated review preserves the attempt identity; discarded results cannot be
recreated. A foreground completion presents Map for explicit acceptance.
Background completion preserves navigation and typing ownership. Changed source
requires inspecting the historical context or preparing a separately approved
draft. The handoff starts no job or model request and changes no allowance.

An explicit historical context choice, including omission, may draft new work
against current source while retaining authenticated investigation spending.
The new finite plan still requires its own approval. Ordinary continuation
without that explicit choice requires current accepted Map evidence. Missing
historical accounting remains an error rather than creating a fresh allowance.

Generated builds declare the immutable context object as their artifact, including
inactive drafts. The compatibility `data.threatModelPath` still names the active
mirror, which may not exist for an inactive build. Consume the authenticated
`modelRef` or declared artifacts for the generated result.
Recovery treats planned and running generation as pending. Failed, parked,
partial and unrecognized states require inspecting their recorded outcome.
A completed generation needs exactly one authenticated immutable revision
associated with its run. A missing manifest, missing revision, ambiguous match
or unreadable document cannot be interpreted as another pending launch.
Setup routes a model-backed Map plan through this study instead of starting its
legacy planning queue. Optional `preparationJobs` freezes at most one
`context:build` and one `entry-points:extract`, including their canonical inputs.
They must remain deterministic and bound to the same repository. All jobs run
in the reviewed order with one worker and one attempt each. The context engine
still owns its own source grounding; this does not introduce DAG dependency
execution or imply that every preparation artifact is required by synthesis.
Preparation failures remain individual campaign outcomes. Other Map combinations
and conflicting context options produce an explicit unsupported-plan error;
they are never silently removed or substituted. These restrictions apply to the
guided study, preserving direct public tool compatibility.

An allowance reference does not approve additional jobs, retries beyond the
approved limits, or a new context experiment. Existing unbound bridge calls
keep their public contract. Dynamic adapters are not certified by these
built-in descriptor changes.

### Recorded threat-model selection

Supported discovery and triage tools declare the advanced JSON option
`threatModelRef`, with compatibility alias `threat_model_ref`. A reference
contains `modelId`, `revisionId` and `sha256`; explicit `null` omits threat-model
context. With no option, legacy direct calls still select the active model.
Campaign compilation records the selected revision or omission in each scan
input and preserves a caller's explicit selection.

`threat-model:read` also declares this option. An explicit reference returns the
exact authenticated document in `data.document`, its identity in `data.modelRef`,
and `data.resolvedFrom = "exact-context"`. Explicit omission returns null document
and reference. Scope, output-directory and methodology overrides are rejected in
this mode so the preview cannot differ from the selected scanner document.
Unbound reads retain their existing persistent/scoped behavior. The study TUI
uses this shared path to inspect revisions before accepting one for a plan.
Its `v` diagram reader derives the existing DFD view model from the authenticated
document returned by that read, retaining the selected revision's grounding
status. Component, flow and boundary inspection cannot activate context or
dispatch generation. Linked source evidence is readable in full, and plain
output includes all elements with the exact context identity. Selecting the
revision for a study remains a separate action in the context browser.

Bound readers authenticate that immutable object without changing the active
pointer. Missing objects, invalid references and digest mismatches fail without
falling back to a different model. Agentic SAST, Carlini, taint planning, static
ranking and standard/deep triage consume the selected context in their relevant
prompt or artifact paths. Supported whitebox MCP attachments point to the same
object; the threat-model server checks its digest on each query. Explicit
omission removes that attachment. Model context guides inspection and impact
assessment; it never establishes a finding verdict.

Shared tool-run startup copies an explicit revision or omission into the
summary's threat-model provenance before execution. Terminal updates retain
that initial selection. Existing historical summaries are not repaired merely
by reading them; their scan input remains the recorded selection when the old
summary captured the active model instead.

This binds threat-model context only. Auxiliary context snapshots, other
knowledge artifacts, attachments and reviewed lessons still need the complete
immutable context-bundle contract. Descriptor option changes can require a new
explicitly approved plan when checking an older frozen equivalence key.

## Dynamic KWP modules

Local KWP modules are self-contained `.mjs` files. They export a plain module
object; they do not import Kuzushi helpers.

```js
export default {
  id: "example",
  displayName: "Example",
  category: "internal",
  description: "Read a workspace file through the KWP broker.",
  tools: [
    {
      name: "example:inspect",
      description: "Inspect one workspace-relative text file.",
      headless: true,
      runtimeRequirement: "never",
      phase: "map",
      effect: "read",
      approval: "none",
      workspaceRequirement: "required",
      options: [
        {
          name: "path",
          type: "path",
          pathSemantics: "workspace-read",
          description: "Workspace-relative file to read.",
          required: true,
        },
      ],
      async execute(input, ctx) {
        const text = await ctx.fs.readText("workspace", input.path);
        return {
          status: "completed",
          output: `Read ${input.path}`,
          data: { bytes: new TextEncoder().encode(text).byteLength },
        };
      },
    },
  ],
};
```

The default export, named `module` export, or imported object itself may be the
module. A tool may expose `execute(input, ctx)` or the compatibility spelling
`run(input, ctx)`.

### Module descriptor

| Field | Requirement | Meaning |
| --- | --- | --- |
| `id` | required | Kebab-case module id; every tool name must start with `<id>:`. |
| `displayName` / `name` | optional | Operator-facing name. `displayName` is preferred. |
| `category` / `kind` | optional | Module grouping; defaults to `internal`. |
| `description` | optional | Operator-facing summary. |
| `hidden` | unsupported | Dynamic modules must remain operator-visible; `true` is rejected. |
| `tools` | required | Array of tool descriptors. |

The host rejects unsupported module lifecycle fields (`init`, `ready`,
`dispose`, `requires`, `knowledge`, and `events`) rather than pretending to run
them.

### Tool descriptor

| Field | Requirement | Meaning |
| --- | --- | --- |
| `name` | required | Globally unique `<module-id>:<action>` name. |
| `description` | optional | Operator/model-facing summary. |
| `headless` | required | Whether `kuzushi run` may invoke the tool. |
| `runtimeRequirement` | optional | `never` or `always`; defaults to `never`. |
| `phase` | required for effectful tools | `map`, `scan`, `review`, `prove`, `fix`, `report`, or `operate`. Deprecated `hunt` and `confirm` inputs normalize to `scan` and `prove`. |
| `effect` | required | `read`, `workspace-write`, `target-write`, `repository-execute`, or `external-action`. |
| `approval` | required | `none` or `explicit`. Target writes, repository execution, and external actions require `explicit`. |
| `workspaceRequirement` | required | `optional` or `required`. |
| `hidden` | unsupported | Dynamic tools must remain operator-visible; `true` is rejected. |
| `options` / `inputSchema` | optional | Canonical descriptor options or the restricted schema form below. |
| `prompts` | optional | Declared editable prompt boundaries tied to named options. |

Dynamic policy has no permissive defaults for `headless`, `effect`, `approval`,
or `workspaceRequirement`. Registration is atomic, duplicate tool names and
aliases fail, and a dynamic module cannot replace an active or retired built-in
id. Unsupported tool lifecycle/DAG fields (`init`, `dag`, `runLifecycle`) fail
during description.

### Dynamic options

Explicit options support these types:

```text
string | bool | int | float | path | enum | string-list | json
```

Common fields are `name`, `type`, `description`, `required`, `default`,
`choices`, `aliases`, `deprecatedAliases`, `advanced`, and `evasion`. Integer
options may add inclusive `minimum` and `maximum` bounds.

Every `path` option must declare one of these semantics:

```text
workspace-read | state-write | target-write |
external-read | external-write | executable
```

The host uses those semantics during canonical path preparation and
authorization. It never guesses whether an unlabeled path may read, write, or
execute.

As an alternative, `inputSchema` may describe a closed top-level object. It
must set `additionalProperties: false`. Supported property shapes are strings,
booleans, integers, numbers, string enums, arrays of strings, and unconstrained
JSON objects. Supported property metadata is `description`, `default`, `enum`,
`items`, and integer `minimum`/`maximum`. Unsupported keywords fail during
description. Use explicit `options` whenever path semantics or richer option
metadata is required.

### Declared prompts

A prompt entry declares `role`, `verb`, `optionKey`, and `defaultContent`.
`moduleId` defaults to the current module and must match it. `optionKey` must
name an option on the same tool. `contextNote` is optional. This declaration is
what authorizes the shared prompt override behavior; adding an ad hoc JSON key
does not.

### Worker context and grants

Approved local workers execute from an operator-owned read-only snapshot with a
stripped environment. Ambient filesystem, network, process, secret, or MCP
authority is not inherited. Privileged work goes through grant-checked handles:

| Handle | Purpose |
| --- | --- |
| `ctx.fs` | Read/write approved `workspace`, `module-data`, or read-only `input` scopes. |
| `ctx.runtime` | Query the host-selected runtime within the approved model/cost budget. |
| `ctx.net` | Fetch approved hosts with request and byte quotas. |
| `ctx.mcp` | Call an operator-mounted, explicitly aliased MCP tool. |
| `ctx.fuzz` | Run an approved host-mounted fuzz engine. |
| `ctx.findings` | Persist bounded, allowed-severity findings. |
| `ctx.artifacts` | Record bounded artifact references. |
| `ctx.bus` | Publish to approved topic patterns. |

The local-worker context also carries host-provided `cwd`, a bounded `config`
projection, KWP metadata, `invocationId`, `runId`, and an abort `signal`.
Treat these as invocation data, not ambient authority. Compatibility package
execution may project additional target/tool identity; local modules must not
depend on that wider shape.

The approval grant is deny-by-default and is stored with the module digest in
`kuzushi.lock`. Current grant families are `fs`, `net`, `runtime`, `bus`,
`findings`, `artifacts`, `mcp`, and `fuzz`. Direct Node-worker `exec` grants are
not supported. See `examples/kwp/agentic-fuzz/grant.example.toml` for a complete
working subset and `crates/kuzushi-core/src/worker_protocol.rs` for the exact
serialized fields and quotas.

Every broker request carries a host-issued invocation id and epoch. Missing,
mismatched, stale, post-cancellation, or post-settlement authority is rejected.
Cancellation and watchdog expiry stop the worker process group and discard
stale results.

### Runtime queries

Set `runtimeRequirement: "always"` before calling `ctx.runtime.query(...)`.
The host owns model and cwd selection. A worker may provide the prompt and
supported query controls, but it may not inject custom tools, a fallback model,
host-owned runtime options, or permission callbacks. Unsupported fields fail
explicitly.

Runtime-free tools receive an unavailable-runtime handle so accidental use is
an error rather than a silent fallback.

### Results

A tool returns JSON-serializable data. The common result envelope uses
`status`, `output`, and optional `data`, `artifacts`, and `findings`. Shared Rust
dispatch normalizes the output and owns lifecycle/cost recording. Worker-returned
`costUsd` is not trusted as authoritative accounting.

Finding identity remains host-owned at this boundary. A KWP
`findings.create` payload must omit `fingerprint`, `dedupKey`, and
`sourceSignature`; the broker rejects those canonical-identity overrides.
Workers may send `actorFingerprint` when they need to retain a producer-side
observation id as non-authoritative provenance.

## Approval, loading, and audit

Local file/path modules must be approved before Kuzushi describes or executes
their code. Approval binds the exact file digest, normalized descriptor hash,
grant, version, and optional signature chain in `kuzushi.lock`.

```sh
kuzushi kwp approve file:///abs/path/to/example.mjs \
  --grant /abs/path/to/grant.toml

kuzushi --target /abs/workspace \
  --load file:///abs/path/to/example.mjs \
  run example:inspect --input '{"path":"README.md"}'
```

Headless dynamic invocation requires an explicit global `--target`; an inline
path option cannot establish the trust root. A changed file or descriptor must
be approved again. A revoked or changed approval is rejected before execution.

Local v0.1 workers are single-file bundles. Kuzushi snapshots the approved
bytes, makes the snapshot read-only, and starts the Node worker over versioned
JSON-RPC stdio. Descriptor probing and execution both use the sandboxed host.
Module stdout is redirected to tagged stderr so it cannot corrupt protocol
output.

Workspace-backed runs record broker decisions and invocation lifecycle in:

```text
<target>/.kuzushi/v3/runs/<run-id>/kwp-audit.jsonl
<target>/.kuzushi/v3/runs/<run-id>/kwp-bus.jsonl
```

Verify the hash-linked audit chain with:

```sh
kuzushi kwp audit --target /abs/workspace --run-id <run-id> --json
```

An empty `signatureChain` represents local operator approval. Non-empty entries
use `ed25519:v1:<key-id>:<base64-signature>` and must verify against
operator-owned signing keys.

### Specifiers and mode support

| Specifier | Behavior |
| --- | --- |
| `builtin:<id>` | Rust built-in lookup. |
| `file://<absolute-entry>` or local path | Approved, digest-bound single-file KWP worker. |
| `package:<npm-name>` | Trusted compatibility path; must appear in operator `trusted_modules`. |
| `mcp:<server-spec>` | Not a dynamic module load path; use the native MCP controls below. |

Only shell and `kuzushi run` consume `--load`. `kuzushi scan` and unrelated
commands reject the flag instead of ignoring it or treating a dynamic tool as a
scan engine.

`package:` is a compatibility trust path, not a way to bypass local-file
approval. Local-looking, relative, absolute, or colon-bearing package names are
rejected.

## Published manifest schema

`schemas/module.manifest.schema.json` remains a public compatibility metadata
contract for package/file ecosystems that need `module.manifest.json`. It
describes identity, display metadata, version, entry, optional host-version
compatibility, requirements, and config metadata.

The manifest is not the authorization record for a local KWP worker:

- `kuzushi.lock` binds executable bytes, descriptor, and broker grants.
- The live worker export supplies the executable module/tool descriptor.
- The native and Node sides negotiate the worker protocol and exact host package
  version at startup.

Do not infer filesystem, network, runtime, model, MCP, or process authority from
manifest `requires` or `configSchema` fields.

## MCP servers

MCP servers are native agent tools, not dynamic module specifiers. Inspect and
serve them with:

```sh
kuzushi mcp health <backend>
kuzushi mcp serve <backend>
```

The bridge's legacy forced fallback attaches tree-sitter, CPG, and CodeQL. A
normal agent-tool request uses an artifact-gated attachment plan and can select
other shipped servers, including context, entry-points, threat-model,
threat-intel, x-ray, and findings. Do not treat the three-server fallback as the
complete inventory.

The CodeQL MCP keeps an in-process result memo for dependency-free local query
selectors. A memo hit skips `codeql database analyze`, but every request still
performs full content authentication of the database tree, so memo-hit latency
remains proportional to database size. Pack selectors bypass the memo, and
local queries with imports are rejected because their dependency closure cannot
be authenticated. First use of a database revision copies the authenticated
tree into operator-owned session storage; analysis and prewarm run only on
OS-sandboxed snapshot paths.

For descriptor-backed agent tools, MCP and bridge controls are ordinary tool
options such as `mcpToolTimeoutMs`, `bridgeVerbose`, and `bridgeLogPath`. The
adapter compatibility/debug switch `KUZUSHI_AGENT_MCPS` may force MCP
attachment, but it is not a product-option substitute.

## Testing

Built-ins should have focused Rust tests for descriptor shape, option
preparation, authorization, executor behavior, output normalization, and each
intentional mode asymmetry.

Dynamic modules should be tested at two levels:

1. Import the `.mjs` file directly in a Node test and exercise pure helper/tool
   behavior with deliberately small fake broker handles.
2. Approve and load the real file through `ModuleRegistry`, then invoke it
   through canonical dispatch. This catches descriptor normalization, grant,
   sandbox, handshake, path, cancellation, and output-contract failures that a
   direct unit test cannot.

There is no `kuzushi/testing` mock package. Keep any test doubles local to the
module and model only handles the test actually uses.

## Troubleshooting

- **Tool name does not start with the module id** — rename it to
  `<module-id>:<action>`.
- **Missing policy field** — declare `headless`, `effect`, `approval`, and
  `workspaceRequirement`; add a concrete phase for effectful tools.
- **Path option has no semantics** — add the exact `pathSemantics` value rather
  than coercing the input to a generic string.
- **Unknown input key** — add a descriptor option or remove the key. Dynamic
  schemas must set `additionalProperties: false`.
- **Module is not approved / digest changed** — rerun `kuzushi kwp approve`
  after reviewing the exact bytes and grant.
- **Package module is not trusted** — add the exact `package:` specifier to
  operator-owned `trusted_modules`; do not use that list for local files.
- **Runtime unavailable** — configure a compatible operator-selected runtime
  and declare `runtimeRequirement: "always"`.
- **Broker capability denied** — update the operator-reviewed grant only if the
  module genuinely needs that capability; do not add an ambient fallback.
- **Protocol or host version mismatch** — use the Node host shipped with the
  same Kuzushi package/native binary revision.
- **`--load` rejected** — invoke the approved tool from shell or `kuzushi run`;
  scan and unrelated commands do not load dynamic modules.


### Trace expansion results and recovery

`trace:expand` may complete with zero new steps. Its canonical run result still
retains `openQuestions` and `evidenceDeltas`, and the Trace reader recovers them
through the result reference recorded for that exact tool call. A completed
empty question list replaces the previous list. Older static-evidence steps
remain readable; a missing source identity is disclosed rather than treated as
current. Recovery errors are explicit.

New expansions attach `data.snapshotHash` and `data.treeHash` from the shared
source-snapshot boundary. A source change during execution makes the result
partial. The reader distinguishes the last expansion's source status from the
accumulated history of recorded steps.

Trace uses the shared monetary result contract: `costUsd` means an exact
provider receipt. Incomplete metering uses `observedCostUsd` together with
`providerSpendUnresolved: true`, mirrored in the envelope and object-shaped
`data`. Zero dollars alone does not establish whether a model call occurred.
The retired Trace-only `costUsdExact` field is no longer emitted; see the
migration note in `RELEASING.md`.

After successful terminal persistence, the shell refreshes the Trace reader
from that verified history while the same target is active. The immediate
completion view therefore includes the saved run and source receipt. Failed
writes and completions for another target do not replace the current evidence.
Informational and successful completion notices clear on Escape while allowing
the reader or editor to handle the key. Warning and error notices retain their
explicit dismissal action; the banner reflects the current key ownership.

Final run receipts retain an actionable error raised during the current run
instead of replacing it with an informational summary. Current warnings are
retained unless the terminal outcome is a failure, which must be shown as an
error. Older alerts do not hide a new completion. Without a current alert,
failed, partial and blocked receipts disclose their severity and point to
`/activity` for details; the complete receipt remains recorded.

Replay and run Trace wrap their displayed rows before scrolling, preserving
styles, Unicode and path spacing. Page Up/Down uses the visible reader height;
scrolling back from the end or after resizing clamps against the current
document. Their Escape hint names return to the prior surface, or dismissal
while an alert owns the key. Existing authenticated and bounded result
projections remain the source of the displayed content.


Run Focus Output uses its rendered pane dimensions for scroll limits and page movement, including wrapped text and overflow disclosures. After `g` goes to the top or repeated upward scrolling reaches it, `j` moves down immediately. `G` resumes following the tail; `k` leaves it. The Output footer names the current Ctrl+C action and does not call a finished run live. Short Run Focus screens prioritize status, the complete run id, and reading space. Their footer keeps primary navigation and the current interrupt action, with the effective command-palette binding followed by `keys` for the complete control map. Steer editors, pending cancellation and operator questions keep their existing controls.

Long notice banners are bounded previews: dismissal remains visible and overflow names the command-palette route to `logs`, where the complete recorded message can be read. Logs pages and scroll bounds use the actual wrapped document and visible body; `G` follows new output and upward scrolling releases the tail. Short Logs screens use a compact header.

The `keys` control map places the originating view's controls first, wraps full key labels and descriptions, and pages using its visible document area. Compact screens omit unused composer space; the title shows the current line range. Closing it restores the originating view. Trace and Investigation name Escape as dismissal while an error owns the key; after dismissal, they name the back action again.

### Supporting evidence and phase results

The Rust descriptor field `phase_result` separates result ownership from the
phase used for authorization. Its default is `true`. Tools such as `trace:expand`
use `without_phase_result()` to save supporting evidence without producing a
selectable Map/Scan/Review/Prove/Fix result. Their declared phase, effect,
approval, runtime and option policies continue to apply.

Shell preparation and receipt projection use the resolved descriptor. Shared
workflow persistence and recovery recognize the built-in opt-outs: a Trace run
cannot replace a pending verification or be accepted as a proof set. Existing
Trace run artifacts and raw workflow events remain available as history; they
are excluded from active phase selection. Unknown historical tool identities
retain the existing checks and are never silently removed. See `RELEASING.md`
for the Rust descriptor migration.

Revision comparison reads the complete recorded Git SHA and available indexed
content hashes from run artifacts. CLI JSON adds `baseSource`, `compareSource`
and `absenceCoverage`; the shell wraps values without removing hash characters.
Missing legacy hashes remain unknown. Covered but absent findings are separate
from work that was not reassessed. Neither a nondeterministic miss nor a missing
snapshot establishes a fix.

Comparison also reads each run's recorded `scan-input.json`, adding
`baseContext`, `compareContext` and `contextComparison` to CLI JSON. The shell
shows full model/revision/digest references separately from source identity.
Changed context is labeled as changed scan conditions. Unavailable historical
context cannot be equated with an explicit omission or the currently active
model. These comparisons do not adjudicate a fix for a revision or branch.

`sast:scan` writes a per-run `findings.json` array of discovery observations
before optional post-processing. Reports and comparisons can read that saved
array without querying the later state of the findings ledger. The result
records the indexed starting `treeHash` and `snapshotHash`; a changed or
unverifiable source makes it partial while retaining its evidence and spend.
Index identity is bounded and does not prove complete repository coverage.
Earlier runs without snapshots or content identities remain unknown.

### Finding observation gaps

`findings:list` accepts `state: ["not_observed"]` through the shared prepared
input path. The shell equivalent is `findings filter state:not_observed`; CLI findings
also accepts `--state not_observed`. A gap identifies the last observed run and
the completed comparison run when the ledger has eligible scanner and scope
evidence. Unknown historical references remain explicitly unknown.

An observation gap preserves the human verdict. It does not close an open
finding or establish that a confirmed finding was fixed. Re-observation clears
the current gap; review and suppression changes preserve the separate scan
history. Review detail and workspace exports carry this distinction. Full
revision-specific fix assessment remains separate, unfinished work.

Review's Enter action opens finding details within Review. When a gap contains
both run references, **compare scans** opens Sources & context for that exact
pair: `v` in Navigate mode, or `Esc` then `v` from an empty Prompt. The control
uses the configurable `workbench.compare_observations` key binding. Escape
returns to the same finding, filter, zoom and reading position. A composer
draft owns typing; the comparison action does not overwrite it.

The detail leads with the effective saved decision and source evidence.
Other decisions remain in history, including newer automated decisions that
do not override a human verdict. Comparison reports source and context
differences without claiming that absence proves remediation.


### Interactive scope review

`scopes` opens the current repository's saved scope draft, or offers an explicit
inventory action when none exists. Arrow keys choose a boundary or coverage row;
Enter opens its action menu, `f` reads a bounded file page, and PgUp/PgDn read
long detail. The menu exposes rename, split, merge, scope/path exclusions,
boundary questions, shared discovery, whole repository and exact acceptance.
Forms preserve the shell composer and use Tab/Shift+Tab between fields, newline
path lists and F2 to save. Failed edits retain the form. Acceptance has separate
inventory, overlap and exclusion acknowledgements and starts no scans.

The surface shows recorded source identities; edits and acceptance recheck
current source. A saved accepted revision is historical evidence, not an assertion
that the current checkout still matches it. Restart reopens the saved draft
without approval or discovery work. `exclude-path` adds a literal inventoried
file/directory exclusion with a reason through the same prepared option contract.
An accepted discovery boundary exposes `p` and **Plan selected scope**. This
opens the existing study form with its exact `scanScopeRef`, preserving the
operator's engine choices. Back returns to the scope selection and reading
position. The default remains three passes and one worker. Other boundaries
remain unplanned. Preparing the draft runs source authentication in a cancellable
worker; opening the form makes no model requests and starts no jobs.

The study's **Discovery engines** row opens a local selection draft. Arrows
choose an engine, Space or Enter toggles it, `a` applies the choices, and Esc
cancels. The first explicit choice replaces automatic selection deliberately.
Unsupported engines remain visible with a scope-specific explanation; unknown
saved engines can be removed. PgUp/PgDn reads details with a visible line range,
including at 40x12. Plain output retains every engine and the selected detail.

When earlier `paths` filters conflict with an accepted scope, the picker lists
them and offers `x` to clear them in the local draft. Esc restores the original
study. Applying the repair writes an explicit empty filter list for this study,
preserves global settings and requires a new plan before approval or execution.

Applying changed choices invalidates only the study plan. Source and context
references, custom scan options, investigation identity, allowance and consumption
remain intact. Global tool settings are unchanged. Applying identical choices
retains the existing plan. Saved task-input order is preserved, and removed/readded
engines move to the end of that input. Execution retains existing orchestration
ordering. The capability preview
does not inspect source or certify dependency availability, useful findings,
credentials or spending approval. Preparation authenticates source, and dispatch
enforces dependency, runtime and allowance requirements. Useful output still
requires functional evidence.

`sast:scan` accepts `scanScopeRef` as a workflow-owned JSON option:
`{"proposal":{"proposalId":"...","revision":3,"recordHash":"..."},"scopeId":"repository"}`.
It cannot be combined with `paths`. Only committed accepted revisions with
current content and Git revision can be consumed. Exact membership comes from
the authenticated inventory, including literal loose files and exclusions,
rather than the 128-file preview. Scope identity contributes to batch equivalence.

Secret scanning and Semgrep currently implement exact file discovery. Semgrep
passes literal files in groups of at most 64 and checks its file-coverage receipt.
Missing receipts, unscanned files, skipped binary/oversized secret inputs and
interrupted batches remain incomplete. Unsupported engines fail before work;
they require an explicitly reviewed whole-repository job. Existing `paths`
directory behavior and public `ScanRunOptions` remain unchanged. Native adapters
do not consume the resolver's inherited context-file list.

This increment supports one selected scope per existing homogeneous study.
Multi-scope scheduling, scoped model sessions, inherited scanner context,
AI division and complete resource estimates remain incomplete.


Source identity and blob indexing now share an iterative source walk. It excludes
symlinks and generated paths, checks canonical repository containment and
repeated directory visits, and refuses more than 1,000,000 examined entries,
including directories and ignored entries. This is an additional safety bound;
the identity/file universes and content hash format stay unchanged for targets
within the bounds. Identity retains 1,000,000-file/16-GiB ceilings and blob
indexing retains 200,000-file/1-GiB ceilings. Per-file content remains capped at
64 MiB; oversized files remain excluded and included identity gaps still block
scope acceptance. Inventory retains its separate 100,000-entry/512-MiB/256-KiB
inspection limits. A source walk that stops produces no complete identity.

Source-bound tools check cancellation between traversal steps and 64-KiB read
chunks. Scope inventory, mutable scope review, exact reads, file paging and
latest-head lookup use cancellable lock acquisition. `pack:scopes` adds
`operation=latest`, which returns `data.review` as an exact saved review or null
when no scope proposal exists. Opening and refreshing the shell surface dispatch
that lookup in a background worker. Cancellation preserves saved revisions and
requires explicit retry. It cannot interrupt an operating-system filesystem call
already blocked inside the kernel; cross-platform and very-large-repository
performance remain separate acceptance work.


### Historical resource evidence

The study form's **Usage evidence** row selects a completed SAST run explicitly.
Provider-request evidence remains usable when subscription OAuth cannot supply
a dollar price. Observed counts include internal turns, repairs and retries.
Missing legacy accounting stays unavailable; unresolved requests remain committed.
`campaign:allowance runId` exposes the same admitted-run counts through shared
prepared dispatch without starting work or changing the ledger.

`campaign:study baselineRunId` records the choice as optional
`resourceBaselineRunId` plan metadata. It does not enter scan options. The
authenticated pointer survives restart. Selecting a different basis requires a
new plan and separate approval, preserving limits and spending. A missing or
corrupted basis remains unavailable instead of becoming zero cost.

Future projections require identical recorded source, context, scan options,
model and runtime conditions, completed engine work and settled request evidence.
The preview multiplies one historical scan's observations by the full planned
maximum starts and labels the uncertainty. It compares projected requests with
proposed capacity after existing commitments and protected Review calls. A
shortfall offers explicit work or allowance revision. Actual usage can differ;
the estimate has no enforced upper bound and never increases the allowance.

Historical choices load through the shared background view reader. The selector
uses the most recent 100 run records, disclosing the limit; it reads detailed
usage only for the selected run. A baseline named by an authenticated plan can
be older than this window. Loading, failure, refresh and restart preserve that
choice, the draft and existing spending. Background results never take focus.
The shared cache retains at most 32 named usage reads. A cold or stale history
index can still rebuild from canonical metadata in the background; the choice
window does not limit that rebuild.

### Rejected context diagnosis

`threat-model:build` and its generation aliases expose `saveRejectedOutput`.
Direct calls leave retention disabled when the option is absent. Newly prepared
context studies freeze it as enabled unless explicitly disabled. The context
form displays the disclosure and lets `s` change the draft before preparation.
Changing a frozen choice requires a new, separately approved plan.

Single-synthesis build rejection after its existing one-repair contract may
publish `rejected-context-output.txt` in the owning run. The bounded diagnostic
is at most 24 KiB, plus its final newline. It can contain source or sensitive
model text and is owner-readable on Unix. Ordinary failure text remains redacted;
authentication and transport failures do not produce this diagnostic. Staged,
deterministic and refinement paths reject enabled retention until supported.

The failed context form offers `d` only when the owning job has published the
diagnostic. Explicit inspection checks frozen input, contained paths, file size
and the content object before reading. The full-frame reader labels the output
unaccepted, escapes terminal control characters and shows source/model/run
provenance. PgUp/PgDn reads it; `d` or Esc restores the previous view and scroll.
Other workflow actions remain inert while reading. Inspection never accepts
context, changes its active revision, starts work or spends allowance. Historical
plans without the flag cannot read a file injected under the diagnostic name.

### Optional AI scope proposals

`pack:suggest-scopes` reads an authenticated existing scope inventory and returns
an unaccepted immutable revision. Its descriptor requires `proposalRef` and an
approved `allowanceRef`. `threatModelRef` selects one immutable context revision
or explicitly omits context. `priorities`, `model`, `thinkingLevel` and requested
`maxOutputTokens` flow through shared prepared dispatch. The OAuth adapter may
not enforce output-token limits, so approval discloses uncertain usage.

The executor sends bounded inventory and architecture data in one model turn,
with no tools, delegation, output repair or follow-up scans. Paths, dependencies,
counts, overlaps and residual coverage are checked against the saved inventory.
Operator exclusions remain intact. Source drift or a concurrent draft edit
rejects publication while retaining the request expense.

Shell scope review offers **Suggest scan scopes with AI**. The multiline priority
editor leads to the existing fixed-plan and allowance review. Context, scope and
scan acceptance stay separate. `campaign:context-study generationTool=pack:suggest-scopes`
provides the same one-job path for headless use. A later accepted-scope scan study
retains the proposal's investigation accounting and requires its own work approval.
Missing or mismatched generation receipts fail instead of resetting spending.


### Source framework extraction and partial Map evidence

Python HTTP routes use conservative source receiver bindings for Flask, FastAPI
and Sanic shared decorators. Unknown factories and ambiguous bindings retain
route evidence without a guessed framework. Bindings are memoized per inspected
file. Current rows carry `metadata.sourcePolicy=python-http-receivers-v1`; cached
context or entry-point rows without it request `context:build` followed by
`entry-points:extract` before new grounding. This is an extraction-policy change,
independent of source revision. Historical accepted context stays unchanged.

The deterministic Map remains partial and limited to artifact review. Diagram,
Summary and plain reading preserve that qualification. Entry-point details use
the catalog framework and cannot inherit a contradictory model annotation.
