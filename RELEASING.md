# Releasing Kuzushi

The canonical changelog lives in [CHANGELOG.md](./CHANGELOG.md). Update it as
part of every release commit.

## Export compatibility notes

- Allowance approval and inspection receipts now state the calls available for
  context, scope, scans and lessons after protecting Review/Report capacity.
  The value uses the shared snapshot domain calculation. This adds a public
  `AllowanceSnapshot::non_review_remaining` helper and additive receipt text;
  serialized allowance formats, approval limits and admission remain unchanged.
  Available call capacity does not approve additional work or a dollar ceiling.

- Campaign overview wraps the complete campaign identity, worker configuration,
  reported cost, limit explanations and action list before paging. Narrow
  layouts group summary fields; wide layouts retain a compact summary when it
  fits. Empty occurrence guidance wraps too. Shared section dividers measure
  Unicode terminal columns. The summary has one presentation owner; approved
  work, dispatch, spending and persisted formats retain their contracts.

- Campaign navigation uses the full frame at 18 rows or fewer, with pinned
  recovery and action controls. Paging and selected-job positioning use the
  same actual reader area. Composer and palette controls use the configured
  key labels; returning preserves the draft and reading position. Questions,
  confirmations and study editors keep priority. Taller layouts, plain output,
  approved jobs, spending and persisted formats retain their existing contracts.

- Setup adds a read-only `Tab` detail reader with paging, per-row reading
  position and `Tab`/`Esc` return. `Enter` in this reader starts no work.
  Paste returns to the existing composer and retains the normal paste-block
  behavior. Short overviews keep Start Map visible and expose complete row
  explanations through the reader. Plain output includes the same complete
  text. The additive internal editor state is `SetupEditor::Details`; no
  tool option, phase, context, approval or persisted schema changes.

- Setup's Map plan adds an explicit `Import context document` action using
  `threat-model:import`. It is never preselected, needs no model, and presets
  the existing `activate` option to false for an inactive revision. Explicit
  option edits still control activation. The Context import row opens its
  declared Path option. A missing document source blocks Start Map and direct
  plan confirmation; file contents are checked during execution. Import and
  generation require separate Map reviews. Existing CLI/run defaults, inline
  document precedence, option names and stored context formats are unchanged.
  The additive planning identity is `PlanningTaskId::ImportThreatModel`.

- Direct Map, Scan and Review verbs open a pending durable result for its
  explicit decision. They no longer open a new planner over that result;
  `plan <phase>` remains the deliberate planning action. No result is selected
  or accepted by navigation alone. Persisted phase formats are unchanged.

- An owned campaign dispatcher failure now retains its bounded, redacted log
  explanation in the shell. Refresh and campaign selection preserve the cause
  for its original target and campaign; background completion keeps focus and
  the composer intact. Missing or unreadable logs remain explicit errors. The
  notice is session state, while `logs/dispatcher.log` retains the current
  launch's diagnostic until the next launch replaces it. Successful relaunch
  clears the earlier notice. The complete cause precedes the job table and
  failure controls keep review and paging visible in narrow terminals. No job,
  source, allowance or persisted queue format is changed.

- Investigation report captions say `none recorded for discovery` when the
  frozen discovery model field is absent. They do not infer that preparation
  or review used no model, or certify model history omitted by a legacy
  receipt. Structured model fields and existing report formats are unchanged.

- `worklist:rank` is auxiliary Map work with `phase_result: false`. Reprepare
  frozen work whose descriptor binding changed; existing plans and receipts
  are not rewritten. Its declared `target` now selects the actual canonical
  workspace, with isolated read-only child finding history. Results add
  `target` and `sourceFreshnessVerified: false` while retaining worklist fields.
  Unsupported true requests for `includeFanIn` and its aliases fail explicitly.
  Default false remains compatible. The TUI wraps full evidence, shows capped
  totals, preserves target ownership and reads saved context after restart.

- `coverage:recommend` rejects limits outside 1 through 500 rather than silently
  defaulting invalid values. Results add `recommendationTotal`, `target`,
  `sourceMeaning` and `sourceFreshnessVerified: false`. Coverage readers never
  initialize or migrate existing databases; restore an initialized backup or
  migrate version 0 explicitly before reading it. Schema version 1 and baseline
  formats are unchanged. Reads refuse more than 10,000 materialized baseline or
  current finding-path rows. Returned row bounds do not cap SQLite processing
  or total latency. Writable producers retain explicit initialization.

- License scanning now uses bounded candidate membership and ignores its own
  `.kuzushi` analysis artifacts. Traversal above 100,000 entries, 50,000 files
  or 64 directory levels fails. License-file read failures retain their causes;
  an incomplete 64 KiB header prefix cannot manufacture a missing-header
  finding. Existing rule ids, fingerprints, option aliases and report fields
  remain compatible. Direct results add shared `snapshotHash`/`treeHash`
  source references and can become partial when source verification fails.
  Source capture and verification perform separate IO. Existing historical
  findings are retained; no disappearance alone establishes a fix. Direct
  execution still lacks SAST's composite coverage receipt. Directory-scoped
  SAST execution remains the supported coverage path; exact-file scopes fail
  instead of silently widening.

- `sbom-scan:scan` now declares Map with `phase_result: false`; dependency
  inventory cannot complete Map or Scan. Its tool name, input options,
  runtime-free execution and output formats remain compatible. Reprepare frozen
  work if its descriptor binding changed. Existing accepted plans and historical
  phase receipts are not rewritten. SBOM errors now retain their underlying
  cause, including size-limit failures. The shell Components projection consumes
  completed results, clears current package claims on structured failures and
  keeps recovery guidance reachable. Internal presentation fields add no
  persisted schema. Reports still have no authenticated source revision.
  Gallery Page Up and Page Down now use the visible document body rather than
  a fixed ten-row jump. Failure text wraps before page selection; no report
  content or tool input is changed by this reading correction.
  Compact galleries retain an error badge and Logs link without reserving a
  three-row preview that could hide the entire document body.

- Map readers now retain recorded investigation accounting across explicit
  immutable context copies when the current producing run has no allowance
  reference. Recovery authenticates up to 64 `sourceRevisionId` links and their
  producing results. Damaged, missing or excessive known history now refuses
  implicit continuation instead of silently starting unbound spending. Restore
  the original receipt/history and reopen the form. Legacy roots without an
  accounting origin stay readable and unbound. Current run references take
  precedence. JSON, descriptors, existing approvals and plan digests remain
  unchanged; no approval transfers to newly prepared work.

- Context sample limits now reject negative, zero, non-integer and above-2000
  values instead of silently substituting or clipping them. Review saved
  `sampleLimit`, `limit` or `sample_limit` options explicitly before retrying.
  Both context actions retain their names, aliases and default of 200.
  Sampling uses recorded inventory membership, with depth-then-path ordering;
  Git tracked enumeration can therefore differ from older filesystem samples.
  `fileIndex.enumeration` and `fileIndex.sampleOrder` are additive. Existing
  snapshots stay readable and disclose unknown extent when inspection metadata
  is unavailable. Rust `ContextSnapshotView` literals must initialize the new
  `inspection` field, using `None` for legacy or unavailable receipts. Reprepare
  frozen work when its descriptor binding changed; accepted plans are not
  rewritten automatically.
  Context values now wrap and page steps follow the actual visible body;
  stored inputs and plain projections are unchanged.

- Regeneration campaign results remain inactive context drafts and cannot
  directly create a Map checkpoint. Compare the draft, save an exact checked
  revision with `threat-model:verify`, then review the checked reference with
  `campaign:context-map`. Existing draft objects and run receipts stay readable;
  recovery does not repeat synthesis or transfer acceptance to another revision.

- Finding pages and full shell Review projections now read related ledger
  queries in one SQLite snapshot. Concurrent commits remain available to the
  next read; page cursors and manual decisions retain their original evidence
  bindings. `FindingStore::with_projection_snapshot` is additive, synchronous
  and connection-owned. Nested readers join the caller's transaction. It
  freezes database reads from the first query, does not freeze filesystem
  artifacts and is not a write-authorization gate. Public JSON and tool inputs
  remain unchanged. Long reads may retain WAL history until the snapshot closes.

- The study's Source and context surface adds a readable Settings view before
  the complete JSON view. Frozen values remain authoritative; help comes from
  current tool descriptors and unknown historical keys remain visible.
  Legacy execution fields remain inspectable together without promoting
  execution, reproducer or patch actions. Their values are never rewritten.
  Tab/Shift+Tab retain independent positions for Overview, Inputs, Settings
  and JSON. Plain output includes the same content. This is presentation only;
  prepared inputs, plan digests, approvals, execution and artifact schemas do
  not change. The former Options tab is labeled JSON.

- Report presentation choices are saved in the operator-owned
  `.kuzushi/v3/report-choices/<canonical-target-hash>.json` namespace, schema 1.
  `S` saves format, per-format destinations, completeness and provenance detail;
  valid choices also save on explicit export. Restart restores those choices
  without restoring work approval, study selection, history scope or export
  receipts. Target-local files cannot steer them. Malformed choices remain
  visible; export preserves the damaged file and explicit `S` replaces it with
  the reviewed current values. CLI export defaults and public tool inputs stay
  unchanged. Store reads/writes are bounded to 32 KiB and destinations to 4096
  bytes each. Unknown schema versions and foreign targets are rejected.

- Recommendation regeneration preserves existing strategy proposal records.
  First-generation legacy ids remain readable; later identity collisions get
  a `-draft-<uuid>` suffix. Use the ids returned by the current `strategy.json`
  artifact or queue rather than assuming a legacy id always names the newest
  suggestion. Reviewed proposals never transfer status, approved amounts or
  results to a new generation. Identical unreviewed drafts in the same named
  run may be reused; unnamed runs create separate drafts. JSON fields and
  ledger paths remain compatible, including the existing 4 MiB write limit.
  Workspace corrections are applied before assigning the new identity.
  `strategy inspect <id>` adds a read-only, target-bound detail reader.

- `module-recommender:recommend` now defaults to deterministic ranking even
  when a model is configured. Explicit `useModelRanking=true` requires an
  approved `allowanceRef` before runtime construction. Ranking uses one
  tool-free request through the shared account; errors and invalid output do
  not trigger deterministic substitution or output repair. Requested output
  tokens are not a strict charge ceiling when the adapter cannot enforce them.
  The retained Compatibility tool uses Operate, InputAware runtime policy and
  no phase result. Reprepare saved work whose descriptor binding changed.
  Inventory and findings sampling receipts are additive; clipped inspection
  returns partial work. Reports remain in canonical `result.json`. The shell
  `recommendations` reader also reads legacy snapshots, discloses earlier
  reports after newer activity, and offers explicit deterministic refresh.
  `recommend` continues to open the phase-native capability catalog.

- Pending Setup hides journey/autonomy chips and screen-context phase labels
  across utility views. The wide identity rail uses Target until commitment;
  durable workflow reality remains available separately. Structured failed and
  partial results now use bounded transcript receipts with a detail action.
  Curated output, persisted payloads and failure context remain compatible.
  Generic recovery names the failed tool's options and recorded failure details;
  study-specific guidance is retained. Restoring a draft in Navigate mode logs
  how to return to the command line without changing input ownership.

- Explicitly reopening Setup refreshes previously cached target facts through
  the existing asynchronous, generation-checked inspector. Pending inspection
  is retained without duplication. This creates no investigation work and does
  not establish continuous source freshness. Stored formats remain unchanged.

- Coverage history inspection (`coverage:baselines`, `coverage:sweep`,
  `coverage:recommend`) now uses Operate with no phase result. It cannot create
  an accepted Map. Tool names, inputs, baseline rows and the SQLite schema remain
  compatible; reprepare frozen work whose descriptor binding changed. Sweep
  adds the `source-unverified` verdict with `dirty-working-tree`, `dirty-baseline`
  or `scope-unavailable` reasons. Consumers must handle unknown verdicts
  conservatively. Root appears in `unbaselinedScopes` when no baseline exists.
  Baselines and sweep add `scopeCoverageVerified: false`; sweep also adds
  `findingFixVerified: false`. These records cannot certify complete coverage
  or a finding fix. Skip writes recheck source/history and use a ledger
  transaction. Git subprocesses have time/output limits and NUL-separated paths.

- Operational inspection (`config:show`, `router:show`, `workspace:status`,
  `threat-model:methodologies`) and legacy `engagement:aim` now use Operate and
  cannot own a Map result. The harness action is Compatibility in default tool
  discovery; exact dispatch and its existing TOML/input formats remain intact.
  Its result adds `data.compatibility` with explicit unenforced-budget and
  unapproved-work flags and the `campaign:study` replacement. Existing historical
  receipts are retained; reprepare any frozen operation whose descriptor changed.
  Configuration and routing retain their structured data and add readable values.
  Startup uses a current 32-entry history prefix to distinguish operational-only
  history from an investigation. Cold, incomplete or unclassified history
  preserves resume behavior without rebuilding or claiming phase completion.

- `findings:ground` adds bounded candidate/source-read options, per-citation
  inspection data, canonical target/Git facts and a qualified coverage receipt.
  Existing checked/count/revision fields remain readable. Additional candidates,
  unavailable sources, cancellation and audit failures return partial results.
  Audit identity includes source and revision; original observations and verdicts
  remain unchanged. Existing audits remain as history. Grounding is auxiliary
  and cannot replace a Review result. Cached import citations remain historical.

- Completed ledger imports replay without inserting or re-grounding observations.
  Failed/running imports retain recovery behavior. Import JSON, aliases and run-id
  formats remain compatible. Import now uses Review and `phase_result: false`;
  retained Map history is unchanged. Explicit TargetWrite authorization remains.
  Imported ids cannot establish local Map/Scan completion. Reprepare saved work
  whose frozen descriptor binding no longer matches.

- Study comparison input collection is now iterative and bounded. Each
  comparison capture shares a 100,000-entry and 512 MiB read limit across
  executable files, CPG cache files, prompt overrides and house rules. Engine
  files are limited to 128 MiB; overrides keep their existing 16 MiB file
  limit. A 30-second deadline is checked between reads. Source inventory and
  managed CodeQL database authentication retain their separate checks. Limit,
  symlink or changed-file failures refuse a complete comparison identity.
  Existing sorted content digests are preserved for supported input trees.
  Explicit `semgrepBinary` now binds that executable's content, so affected
  older plans must be prepared and approved again before execution. Existing
  plan formats remain readable; no stored artifact migration is needed.
  Automatic SAST selection limits the standalone Cargo advisory version probe
  to two seconds and 64 KiB per output stream. Missing dependencies retain
  disclosed optional skips; failed or timed-out probes refuse preparation.
  Filtered automatic selection avoids probing a disabled Cargo advisory task.

- Findings page cursors now bind the matching finding content, decisions,
  aliases and relevant source-run facts. Unrelated run bookkeeping can advance
  the disclosed watermark without invalidating the next headless page. Changed
  findings, decisions, suppression state, query, target or relevant source-run
  facts still require reloading the first page. The existing cursor envelope
  stays version 1; cursors created before this change require a first-page
  reload. The before/after consistency check during a read remains in place.
  `findings:list` adds a `suppressed` boolean to each JSON row. It describes
  current lifecycle state separately from the human decision and the retained
  `proof_confidence` compatibility field. Review displays `suppressed` for that
  state instead of implying a human dismissal. Existing consumers can ignore
  the additive field.

- Suppression actions now declare their required findings store. `suppress:list`
  declares `workspace-write` because it reconciles expired or removed rules in
  the ledger, and respects the Review autonomy ceiling. `suppress:remove` requires
  `id` during shared preparation; `ruleId` and `rule_id` are declared aliases.
  The three suppression actions and `findings:dismiss` are auxiliary results.
  They cannot replace a selected phase result or the implicit report source.
  Report source selection honors the existing `phase_result` descriptor field
  through the dispatch registry. Explicit `report:build runId=...` remains
  available for auxiliary runs. Tool names, rule files and event formats remain
  compatible; no data migration is needed.

- `threat-model:build` adds optional `scanScopeRef` and `inheritedContextRef`
  for one approved inactive context synthesis over accepted file membership.
  Existing directory and repository builds keep their behavior. Group builds
  use the shared context-study campaign, accounting and revision store; they
  create no discovery work or global context changes. Generated documents add
  `provenance.scopeContext.receipt` with bounded source and inheritance evidence.
  Selected-text regeneration reuses this exact group instead of widening it.
  `campaign:context-study` adds optional `scopeStudyOrigin` and its version 1
  return draft. JSON readers can ignore the new field. Rust callers constructing
  `ContextStudyReceipt` literals must set `scope_study_origin: None` unless
  supplying a validated `ScopeStudyOriginV1`. This metadata grants no work
  approval; existing plan kinds and receipts remain readable.

- Scope studies add a TUI context association browser using the existing
  `scopeCases[].threatModelRef` contract. Missing references inherit common
  context; explicit null omits it; exact references override it. Inactive edits,
  inspection and selection preserve global context and sibling associations.
  Association changes require a newly frozen plan and separate approval,
  retaining the investigation allowance. No artifact migration is needed.

- `campaign:study` adds optional `scopeProposalRef` and `scopeCases` (with snake
  aliases) for one finite study over explicitly selected accepted boundaries.
  It emits `kind: scope-study`, uses the existing campaign dispatcher and durable
  allowance, and freezes at most 100 jobs across one to nine scope cases.
  Cases inherit a frozen common context or select an explicit immutable override
  or omission. Context matrices and historical baseline experiments remain
  separate actions. Workers cannot append sibling or follow-up jobs.
  `InvestigationReportDocument` adds `ScopeStudy`; Rust exhaustive consumers must
  handle the variant. `ScopeStudyReceipt`, its metadata, and scoped occurrence
  receipts are additive. Recurrence denominators stay inside each boundary.
  Older executors that do not understand this plan kind must refuse execution.
  Existing single-scope batch and context-matrix formats remain unchanged.
  In the TUI, Space marks accepted discovery boundaries and p plans the marked
  set; Back preserves selection. Every change requires a new plan and approval.

- Standard agentic discovery now accepts `scanScopeRef` through the shared
  prepared dispatcher. It requires `mcps=false`, the standard strategy, and no
  include/exclude filters. The selected runtime must acknowledge the exact
  accepted discovery/context file union before execution and in the executing
  response. No model or runtime fallback is introduced. Membership is bounded
  to 100,000 literal files and 8 MiB serialized data. `AgentToolPolicy` adds
  optional `readScope`; Rust literals add `read_scope: None`.
  `AgentToolPolicyReceipt` adds optional `readScopeSha256`; literals add
  `read_scope_sha256: None`. `AgenticSastReport` adds optional `scope` and
  default-empty `outOfScopeObservations`; legacy literals add `scope: None`
  and `out_of_scope_observations: Vec::new()`. Old JSON remains readable.
  Observations outside discovery stay in canonical run results and never
  become findings for that scoped job. Study engine selection offers an
  explicit draft-only file-tool choice. Existing plans require regeneration
  and approval after their descriptor contract changes.

- Standard agentic preparation now walks iteratively with a shared 100,000-entry
  limit and a conservative 512 MiB read allowance. `maxInventoryFiles` and
  `maxBytesPerFile` are declared on both SAST surfaces; defaults remain 80 and
  2048. The byte option limits snippets before decoding. Binary inspection can
  read up to `max(4096, maxBytesPerFile) + 1` bytes per candidate. Failed and
  binary-looking reads retain their conservative reservations.
  `AgenticSastReport` adds optional `inventoryCoverage`; Rust literal consumers
  must add `inventory_coverage: None` for legacy reports. Missing legacy receipts
  remain unknown. Preparation limits and omissions propagate into prompts,
  canonical results, Scan engine details and expanded investigation reports.
  These receipts describe preparation, never complete repository coverage.
  Unstarted studies need regeneration and explicit approval after descriptor
  defaults change; historical completed studies stay readable. Compatibility
  snippet consumers now fail honestly at walk/read limits when they cannot
  retain a partial receipt. Runtime and model selection are unchanged.

- Trend history readers retain at most 90 valid snapshots from the final
  1 MiB, oldest first within that recent window. Larger requested limits are
  clamped; partial and malformed lines are skipped. History remains append-only,
  and campaign spending totals still come from campaign receipts. The displayed
  sparkline is labeled as recent history. Status adds `historyWindow` with the
  read and row limits. False-positive trends remain unavailable when a snapshot
  has no decisions. The compact text label groups count, rate and spending;
  `history_reading_lines` exposes those same groups for narrow readers.

- Tool descriptors add optional `discoveryMaturity` and default-false
  `costDataProjection`. Older descriptors keep their serialized identity when
  neither is set. `ModuleMaturity` is now shared by the descriptor crate; the
  existing Core export remains a compatibility shim. Rust struct-literal
  consumers must add `discovery_maturity: None` and `cost_data_projection: false`.
  Tool tiers may restrict Core modules but cannot promote a Labs or Compatibility
  owner. Exact dispatch and `--all` remain available. The local dynamic host
  preserves and validates `discoveryMaturity`.

- `campaign:plan` and `campaign:coverage` are Compatibility tools. Use
  `campaign:study` and the investigation Report for accepted scopes. Status and
  coverage are operational actions; status retains its trend-history write,
  while coverage is a reader. `ToolClassification` adds `Operate` for declared
  workspace/target operations; external actions and repository execution remain
  unclassified in that phase. Rust exhaustive matches must handle the new
  variant. Operational runs no longer displace analysis in implicit reports.

- Historical coverage adds `excludedJobs`, `coverageMeaning` and `limitations`.
  `CoverageReport` Rust literals must add `excluded_jobs: 0`. Non-discovery,
  unclassified and modern non-shard jobs no longer populate legacy cells. Old
  cell names remain job-progress values, never a current-source coverage claim.

- Runtime-free status projects historical spending under its existing `data`
  fields. Shared dispatch adds `dataCostScope: projection` from the resolved
  descriptor and removes module-supplied markers. Current execution cost is
  parsed from envelope fields in that case; historical values stay unchanged.
  Model-backed tools cannot declare this scope. Missing current cost remains
  unavailable, and an operational read cannot add old spend to its own run.
  This declaration is supported by Rust descriptors only. The local KWP host
  rejects `costDataProjection`: worker cost claims are sanitized and current
  execution charges remain owned by the broker.

- Discovery plans add `scanContextRef` schema 1 to pin the agentic adapter's
  supplemental Map text in an authenticated, target-bound content object. The
  64 KiB limit includes metadata. Empty snapshots remain empty across retries
  and resumed passes; explicit null omits supplementation. Other adapters do
  not consume this text. Plan equivalence adds optional
  `supportingContextSha256`. Old receipts without it remain readable; existing
  unstarted plans need explicit preparation and approval after descriptor
  changes. Historical inspection permits source drift, while execution refuses
  it. `StudyPlanReceipt` and `ContextMatrixReceipt` add optional
  `supportingContext` for the authenticated text shown before approval. Rust
  consumers constructing either receipt must add `supporting_context: None`.

- `findings:lesson-generate` adds one tool-free model synthesis request under
  the investigation's Learning allowance. `campaign:context-study` can freeze
  its exact human confirmation and observation as one job. Approval and launch
  remain separate. Invalid output, changed confirmation and cancellation do not
  save a draft or start repair requests. Lesson acceptance remains human-owned.

- Finding exports add an optional `lessons` array with exact current lesson
  references, text, origin, generation receipt, review state and context
  eligibility. JSON and JSONL preserve it; SARIF uses `kuzushiLessons` result
  properties and Markdown bundles retain indented JSON records. CSV and the
  compatibility findings format disclose `lessons` in omitted fields. Existing
  finding verdicts remain unchanged. Older export readers may ignore the new
  field. Rust consumers constructing `WorkspaceFindingExportRecord` literals
  must add `lessons: Vec::new()` or use its existing `Default` implementation.
  Reports containing lesson records cannot supply automatic artifact context,
  including reports saved at custom paths. Reuse still requires explicit exact
  accepted references.

- Reviewed lessons add immutable `finding-lesson-v1` diagnostic records to the
  existing finding audit ledger. `findings:lessons`, `findings:lesson-save` and
  `findings:lesson-review` preserve finding ids, observations and decisions.
  Exact `lessonRef` values contain lesson id, revision and content digest.
  Editing produces a new draft revision. `threat-model:reuse-lessons` creates
  an inactive immutable context copy with up to eight explicitly selected
  accepted snapshots. Empty selection removes lessons from the copy.
  Older binaries ignore this audit namespace and cannot validate lesson
  retirement in saved context. Upgrade readers, writers and scanners together
  before using contexts containing `reviewedLessons`. Existing contexts without
  this field keep their current reader contract.

- Tool descriptors add optional `allowance_category`, serialized only when
  present. Existing descriptors keep their previous serialized shape and
  phase-based accounting. An explicit learning category charges learning work
  rather than protected finding-review calls. This metadata adds no requests,
  allowance approval, fallback or automatic lesson generation.

- Unstarted parked scan trials now contribute to pending work instead of
  failure counts. Their recorded state and reason remain unchanged. Explicit
  failed trials and attempted parked trials retain failure semantics. Old gate
  receipts may need explicit recomputation when their stored counts include
  unstarted parked trials; original receipts are retained.
  Model-backed prepared dispatch checks call capacity before executor entry,
  while each transport attempt still needs its own atomic reservation.
  Explicit fixed-plan launches can resume unstarted parked jobs without adding
  jobs or resetting durable allowance consumption.

- `campaign:study` adds optional `contextCases` (`context_cases`) and
  `baselineCaseId` (`baseline_case_id`). These produce the additive
  `context-matrix` campaign kind with schema-1 `contextMatrix` metadata and
  a typed `ContextMatrixReceipt`. Each case retains its own condition key;
  there is no combined recurrence denominator. Readers must select the receipt
  by campaign kind. Existing single-batch constructors remain unchanged and
  refuse matrix input. The result reader refreshes on entry, preserves exact
  plan identity, and keeps missing accounting from resetting recorded spending.
  Matrix report export uses the additive `InvestigationReportDocument` reader
  and a schema-1 `context-matrix` receipt. Single-study readers and constructors
  stay compatible. Matrix receipts retain per-case conditions and occurrence;
  they have no top-level combined equivalence key or recurrence denominator.
  CSV and external scanner row contracts stay unchanged through sidecar receipts.
  Matrix dispatch now publishes authenticated completed or partial work into
  the existing Scan journal. Results remain unselected until explicit operator
  acceptance, including acknowledgement of partial work. Recovery does not
  duplicate the attempt or execute completed jobs. Missing source identity and
  source drift keep observations available as history and block progression.

- `campaign:study` adds optional `contextBaselineRunId` for a separately approved
  context candidate. The existing version-1 scan-batch plan adds optional
  `contextExperiment` schema-1 metadata. It freezes the named completed SAST
  baseline, candidate conditions, controlled-input digest and baseline
  investigation. Only context may differ; other source, scope, options, model,
  runtime, prompt, engine and descriptor identities must match. Approval rereads
  baseline evidence. Missing accounting or partial/unverifiable work is rejected.
  Existing plans without the option remain unchanged. Candidate passes still
  share one condition key; ordinary recurrence does not combine contexts.
  `campaign:allowance` adds `target` to its read-only result so late shell reads
  cannot replace another target's allowance. Public plan/receipt constructors
  and existing context, findings and allowance storage formats stay compatible.

- `threat-model:regenerate` adds selected explanatory-text synthesis through
  shared prepared dispatch and the existing fixed context-study campaign.
  It requires an exact `threatModelRef`, one to eight editable `fields`, a
  selected model and an approved `allowanceRef`. Optional `guidance` is limited
  to 2048 bytes. Source and prompt projections are bounded. One synthesis
  request runs with tools disabled; transport retries use the same allowance.
  Invalid or partial output causes no repair request. The result is an inactive
  new lineage with its exact parent, source excerpts and model receipt under
  versioned `provenance.regeneration`. Existing source metadata, human edits,
  unselected fields and the active mirror remain intact. A final source-identity
  failure preserves the historical draft with a partial receipt and
  `sourceCurrent=false`. Existing storage and public tool inputs are unchanged.

- `threat-model:verify` adds optional `threatModelRef`. An exact-reference check
  requires the revision's recorded content hash and SHA to match the selected
  workspace, inherits that revision's scope, and saves an inactive checked
  revision when `write=true`. It preserves the active pointer and mirror.
  `write=false` returns the check without publishing. Missing identity or source
  drift stops the check, including after a store-lock wait. A final source-check
  failure returns a partial receipt. Existing unbound active/scoped checks retain
  their behavior. Stored formats and public commit APIs remain compatible.
  Exact reads add `sourceState` with a versioned status/message. They compare
  source identity using the bounded, cancellable content walker without changing
  the document. Unavailable identity stays unknown. The browser labels stored
  checks as historical and displays the source state captured at inspection.

- `threat-model:revise` is an additive, runtime-free action. It accepts an exact
  `threatModelRef`, reviewed `edits` (`pointer`, `text`) and optional copy `label`.
  It creates an inactive lineage with `sourceRevisionId`, keeps the original
  objects and active mirror, and clears the old verification stamp. Editable
  fields are overview, component description/purpose and question answers.
  Text is limited to 16 KiB per field and 64 edits per copy. Existing strings in
  `openQuestions` become question/answer objects only in the edited revision.
  The shared store now refuses objects beyond its existing 16 MiB reader limit
  before writing an unreadable object. Existing public storage formats and
  activate/restore commands remain compatible.

- Review resolution now uses immutable event sequence, with projection id for
  legacy records, instead of display timestamps. Human priority is unchanged;
  cached triage cannot manufacture a newer review. The shared resolver exposes
  `record_id()` so source readers and exports use the same exact decision.
  `reviewDecisionBasis` adds `sourceApplicability`: `latest_observation`,
  `matching_recorded_source`, `reassessment_required`, `later_source_unverified`,
  or `unrecorded_source`. Rust constructors must supply the additive field.
  `review_completion_for_findings` exposes source-qualified progress without
  changing verdicts or events. Dirty/unversioned later observations without a
  known repository identity conservatively require reassessment. Legacy
  unrecorded sources remain readable and require an explicit source-bound review
  to complete the guided current-source journey. Stored verdict export filters
  retain their compatibility semantics. No database migration is performed.

- Capability preparation now shows recovery guidance in both modal and plain
  readers. Short modals wrap it instead of clipping the options command.
  Runtime-backed selection checks the existing model/auth binding policy and
  directs incompatible configuration to `doctor`. Deterministic inputs stay
  runtime-free. No dispatch option, persisted artifact or public API changes.

- Findings page metadata adds `continuityAnchors` alongside unchanged exact
  `anchors` and snapshot-bound cursors. Rust `FindingPageMetadata` constructors
  must supply `continuity_anchors`; `Default` supplies an empty vector. Opaque
  version-one continuity values prefer the original generation, then follow
  exactly one matching identity and fingerprint within the current query.
  Variants, ambiguous matches and unsupported tokens do not become implicit
  selections. The existing descriptor-backed `anchor` option accepts both
  forms. Public generation anchors keep their previous meaning.
  Passive Review navigation uses continuity, while explicit historical pins
  and manual decisions retain exact generation and read watermark. A changed
  source requires opening the current row before recording a new decision.

- Native scanner primitives now record terminal execution before the owning
  module reconciles observation gaps. Shared `sast:scan` saves its actual Scan
  scope and engine receipt first, then reconciles only when both the receipt
  and ledger run are completed. This fixes empty-result gaps and prevents a
  positive control in a scoped scan from marking unscanned findings absent.
  Failed and partial work remains ineligible. Primitive API signatures and
  public `record_run_finished` behavior are unchanged; direct primitive callers
  that need reconciliation must first persist their real Scan receipt and then
  explicitly finalize that ledger run through `record_run_finished`.

- Review exports add nullable `reviewDecisionBasis.sourceGit` and
  `reviewDecisionBasis.laterObservation.sourceGit`. They contain recorded full
  SHA, branch and dirty state; unavailable or invalid metadata remains null.
  Export never substitutes the current checkout. Rust constructors for
  `WorkspaceReviewDecisionBasis` and `WorkspaceObservedSource` must supply
  `source_git: None` when constructing an unenriched basis. JSON, JSONL and
  SARIF gain additive fields; Markdown bundles gain explicit recorded Git rows.
  CSV columns, ledger events and database formats are unchanged.

- Review exports add `reviewDecisionBasis.sourceComparison`, with values
  `not_reobserved`, `same_cited_source`, `different_cited_source`, and `unknown`.
  It compares captured cited files. Snapshot ids alone do not establish a code
  change. `sourceChangedSinceDecision=false` does not establish unchanged source
  or a fix. The basis follows the governing verdict, including an earlier human
  decision that takes priority over a later imported assessment. Persisted events
  and CSV columns are unchanged. Rust callers constructing
  `WorkspaceReviewDecisionBasis` must supply the new comparison field.
  `read_finding_review_source` accepts an immutable observation identity and
  decision/observation watermarks; `finding_observation_identity` exposes that
  identity. `load_run_summary_without_repair` is now public for historical
  readers that must not repair stale running metadata. These readers do not
  migrate stores, change verdicts, or start work.

- Inspecting a generated context retains the completed result's navigation
  origin, options and scroll. Back restores that result; explicit context use
  proceeds to study preparation. Draft, cursor and allowance stay intact.
  Persisted artifacts and dispatch options are unchanged.

- `campaign:context-map` accepts `threatModelRef` as an alternative to the
  existing `campaignId`/`expectedPlanSha256` pair. Revision review authenticates
  the original producing run and current source, records pending Map review,
  and preserves partial status. The two input forms cannot be combined.
  Neither form starts model requests or accepts the result automatically.
  Deterministic builds now carry authenticated source snapshots. New imports
  and verification revisions retain their producing run when available;
  historical revisions stay unchanged. Invalid partial acknowledgements are
  rejected before any typed disposition is written.

- Standalone Map artifacts no longer advance the guided phase rail by
  themselves. Review and explicitly select a completed Map attempt, acknowledge
  usable partial work, or explicitly skip Map. Existing artifacts remain
  inspectable. Historical completed scan evidence keeps its pre-ledger reading
  path. No persisted artifact or disposition is rewritten by this change.

- Python HTTP surfaces add `metadata.sourcePolicy=python-http-receivers-v1`.
  Shared decorators no longer imply FastAPI: source receiver bindings determine
  known framework labels, and unresolved bindings omit the claim. Older Python
  HTTP context/catalog artifacts require explicit re-extraction before new
  grounding, even when source bytes match. Historical artifacts remain readable
  and unchanged. Corrected labels can change existing canonical surface IDs;
  regenerate context/catalog links together. Deterministic Map viewers retain
  the recorded partial, artifact-review-only qualification.

- Study usage history now loads through the shared background reader. The
  selector discloses its 100-record choice window and reads detailed usage only
  for a selected run, including older authenticated plan references. Refresh
  preserves the draft, baseline and allowance. Persisted formats are unchanged.

- `campaign:allowance` adds optional `runId` to inspect admitted historical
  provider requests independently of dollar pricing. Missing legacy evidence
  remains unavailable. The reader preserves approval, consumption and unresolved
  reservations. `campaign:study` adds optional `baselineRunId` and freezes it as
  `resourceBaselineRunId` metadata in the existing version-1 plan. It stays out
  of scanner input; changing it requires a new plan digest and approval.
  Existing plan inputs without the option keep their formats. Historical dollar
  costs remain readable, while future projections require matching recorded
  conditions and complete engine work. No estimate grants an allowance or starts
  jobs. Shared projection initialization now stamps the schema version expected
  by read-only findings consumers; readers still perform no migrations and
  writers reject newer versions before writing projection tables.

- `campaign:study` adds `resourceBaselineCampaignId` for explicit prior scope
  study or context-matrix calibration. It cannot combine with `baselineRunId`.
  Version-1 plans and scope/matrix receipts add optional `resourceEvidence`;
  older artifacts without it need no migration. Evidence binds every case to
  its frozen conditions and complete run identities. Unknown cases and prices
  keep totals unavailable. The version-1 scope return draft adds optional
  `resourceBaselineCampaignId`, preserving selection through file-group context
  work. No preview starts jobs, changes the model or grants more allowance.

- Prior-study resource selection now reads bounded history in the background
  without opening Campaign first. Entry, choice, metadata-byte and file limits
  are disclosed. Loading, failure, refresh and late completion preserve the
  current draft, selection and spending. Persisted formats are unchanged.

- `threat-model:build` and its generation aliases add optional `saveRejectedOutput`.
  It is disabled when absent and has no injected descriptor default, preserving
  older canonical inputs. Supported single-synthesis build failures may publish
  a bounded local diagnostic in their own run. It can contain source or sensitive
  model text, is owner-readable on Unix, and never becomes accepted context.
  Provider failures do not publish raw authentication or transport errors.
  Newly compiled context studies enable retention unless explicitly disabled;
  old plans without the flag remain readable and do not inspect injected files.
  Inspection authenticates frozen input and content, and never starts work.


- `pack:suggest-scopes` adds one budgeted model action over an existing inventory.
  `proposalRef` and `allowanceRef` are required; `threatModelRef` binds an immutable
  context or explicitly omits it. Generated scope revisions add optional
  `generation` provenance. Legacy revisions omit that field and keep their
  serialized hashes. Operator exclusions survive generation. Acceptance remains
  separate from generation and never authorizes scans.
  `campaign:context-study` adds `generationTool`, defaulting to the existing
  `threat-model:build`. A scope proposal uses one job with no preparation jobs.
  Accepted or edited generated scopes retain their investigation expense; missing
  accounting blocks continuation. Existing campaign kinds, job ids and public
  tools remain compatible. The request permits one model turn and no output
  repair or recursive work. Transport retries still consume the shared allowance.


- `sast:scan` adds optional `scanScopeRef` for an exact accepted scope revision
  and discovery boundary. Shell scope review supplies it through **Plan selected
  scope**; run callers may supply the structured option. It cannot accompany
  `paths`. Current exact-file adapters are secret scanning and Semgrep;
  unsupported engines fail without widening scope. Existing version-1 scan-batch
  plans repeat one selected scope and preserve the fixed job count. Scope
  references contribute to equivalence only when present, so the scope-digest
  projection for older inputs is unchanged. The public `ScanRunOptions` layout
  is preserved, and new `ScanEngine` methods have compatibility defaults.
  Semgrep file-coverage omissions are reported as partial work. The new scope
  handoff does not approve spending or launch discovery. Multi-scope plans and
  scoped model adapters are still pending.

- Scan scope review adds `pack:scopes` through the shared prepared dispatch
  boundary. Its version-1 inventory objects and immutable draft revisions live
  under `.kuzushi/v3/scan-scopes/`. The existing strategy queue gains optional
  `scopeProposalRef`; older rows without it retain their behavior. Scope rows
  cannot be accepted through generic strategy approval or launch scan jobs.
  Acceptance records exact coverage acknowledgements and requires the current
  draft, content identity, and Git revision. Historical revisions remain readable.
  Review also reports `identityOmissions`; included files absent from the content
  identity must be explicitly excluded before scope acceptance.
  The tool does not contribute a completed Map result. Existing shard manifests,
  nested scope trees, and public tool names remain unchanged. These artifacts
  are the review foundation. Visual editing and single-scope native study binding
  are available; complete monorepo study compilation is still pending.

- Standalone `semgrep:scan` and `codeql:scan` now return a canonical `partial`
  envelope and persist a `partial` findings run when the engine reports
  omissions. Their existing report fields remain unchanged. Results without
  reported omissions keep their completed envelope. These executors also use
  the existing source-binding guard, adding authenticated `snapshotHash` and
  `treeHash` before a result can support current-source workflow selection.
  Terminal readers retain a bounded omission preview beside the primary
  reason; the full reported omissions stay in the result artifact. This does
  not establish scanner precision, complete source coverage or cancellation
  retention.

- Native SAST coverage reports are additive: `data.nativeCoverage` and the
  authenticated `native-coverage.json` use schema version 2 with engine, scope,
  finding count and original reported errors. A usable native result with
  reported coverage errors persists its observations and a `partial` ledger
  run. That run does not reconcile absent findings as resolved. The public
  scalar scan helpers retain their coverage-error return after persistence;
  callers must inspect the partial run instead of treating that error as an
  empty findings store. `ScanRun` fields and existing artifact readers remain
  unchanged. Native SAST now retains earlier observations that passed scope checks
  when a later native engine fails or is canceled/interrupted. Coverage adds a defaulted
  `disposition` per fixed engine/scope job: `complete`, `failed`, `canceled`,
  `interrupted`, or `not_started`. Older schema-1 rows deserialize as complete
  execution while retaining their reported coverage gaps. No historical
  artifact is rewritten. New schema-2 receipts require readers that understand
  dispositions; old schema-1 receipts remain readable by the updated reader.
  Canceled/interrupted findings runs use the existing
  failed lifecycle event with the explicit terminal status and retained count;
  only completed runs reconcile absence. Failed/canceled terminal results
  include recorded phase stages, coverage and retained observation counts.
  Remaining jobs do not start. Persistence failure and standalone abort
  retention need separate evidence.
  `sast:scan` adds descriptor-backed `semgrepConfig` and `semgrepBinary` options
  for the selected Semgrep task. Explicit local rule files can avoid remote
  rule selectors. Use absolute local rule paths across directory scopes because
  relative rule paths resolve from the scanner's working directory. These
  options do not enable an unselected scanner.

- Scoped native scans now reject file selections instead of scanning their
  parent directory and filtering the findings afterward. Choose a directory
  explicitly and review the larger scope before retrying. Directory selections
  reject symlink components. Scanner results outside their root or containing
  parent traversal fail instead of being relabeled as in-scope findings.
  `sast:scan` and study preparation reject scoped repository-wide engines and
  unsupported taint memberships through shared prepared dispatch. Existing
  names, manifests and stored artifacts remain readable. Previously accepted
  unsupported plans can require a revised draft and approval; they are never
  enlarged during execution. This does not certify every engine's scope behavior.

- `workspace:export-findings` adds optional `campaignId` (alias `campaign_id`),
  and `kuzushi export` adds `--campaign-id`. Omission retains workspace history.
  Selecting a study exports only its authenticated attempt observations and
  adds a version-1 investigation receipt with frozen source/context/configuration,
  planned and completed work, recurrence, human review counts, coverage limits
  and shared allowance accounting. Every format writes an adjacent
  `<filename>.investigation.json`; Markdown bundles use `investigation.json`
  and include its digest in the manifest. JSON, JSONL and SARIF additionally
  embed the receipt. CSV and external scanner rows keep their existing contract.
  Preview exposes the same receipt without writing it.
  `WorkspaceExportOptions` adds optional `campaign_id` and
  `WorkspaceFindingsExport` adds optional `investigation_receipt_path`; Rust
  struct-literal callers should initialize these fields or use the builders.
  Unavailable observed dollar totals serialize as `null` in this report-only
  receipt. Canonical allowance snapshots and execution accounting are unchanged.
  Historical study approval remains reportable after a later approval without
  authorizing old work. The export descriptor now declares `phase: report`;
  names, authorization and the persisted workflow enum remain unchanged.
  Changed descriptors can invalidate frozen plan equivalence. Draft and approve
  replacement work instead of modifying an approved plan. Completed jobs do not
  establish complete repository coverage or revision-specific fix verdicts.

- `threat-model:import` adds `data.document` and `data.snapshot` without
  changing its existing reference or verification fields. Authenticating this
  receipt uses the bounded snapshot index instead of hash-only source identity;
  its 200,000-file and 1 GiB ceilings can reject a previously importable target.
  Files larger than 64 MiB remain excluded by the shared index policy. No
  historical receipt is rewritten or silently upgraded.
  New fixed study drafts default to the accepted current Map revision. Explicit
  revision choices and omission retain precedence. Source drift requires a
  fresh acceptance or an explicit context choice; without accepted Map history,
  the existing active-context default remains. Durable Map views read their
  authenticated run context and disclose unavailable evidence independently of
  the global active selection. Global editors retain their existing behavior.

- Finding presence and human review are now separate facts. Existing
  `finding-disappeared` events remain intact, but no longer derive `fixed` or
  `removed`. A confirmed finding stays confirmed; an unreviewed finding stays
  open. Legacy serialized states and filter names remain accepted. Use
  `state:not_observed` to find recorded gaps from eligible completed scanner
  comparisons; a nondeterministic miss never establishes a fix.
  `Finding` adds optional `observationGap` with event sequence/hash and the
  last-seen/compared run IDs. Missing historical run IDs stay unknown. Ledger
  reads overwrite producer-supplied gap claims; suppression changes do not
  erase a gap, and a new observation clears it. Existing events need no rewrite.
  Workspace exports add `observationGap` and `observationNote`; list-tool JSON
  uses `observation_gap` and `observation_note`. SARIF carries corresponding
  `kuzushiObservation*` properties. CSV appends five observation columns after
  existing columns. Rust struct-literal callers should initialize the optional
  fields or use `Default`. This does not introduce revision-specific fix
  adjudication; existing human decisions still lack a SHA/content binding.
  `FindingListReport` also carries an in-memory `review_decisions` map keyed by
  fingerprint; Rust callers constructing it directly should initialize an empty
  map. List output uses these persisted decisions independently of the original
  scanner triage, and adds `review_decision_author` to JSON. A recorded gap no
  longer removes a finding from the relevant corpus. Operator identity-policy
  projections hydrate the same ledger annotations as headless reads.

- Shared tool-run startup preserves an explicit threat-model reference or
  omission in `run.json`. The existing `threatModelResolvedVia` string gains
  `explicit-input` and `explicit-omission`; terminal writes retain that starting
  provenance. Historical summaries are not rewritten: older summaries may name
  the active model even when `scan-input.json` records another selection.
  `sast:scan` now writes `findings.json` as a discovery observation array before
  post-processing and declares it in `data.artifacts.findings`. Its result gains
  the existing `snapshotHash` and `treeHash` source fields; source drift makes
  the result partial while preserving observations and consumption. These are
  additive artifacts and fields, not a change to finding identity or verdicts.

- Supported discovery and triage descriptors accept `threatModelRef` (alias
  `threat_model_ref`). An explicit reference selects and authenticates that
  immutable object without changing or locking the global active model;
  explicit `null` omits threat-model context. Missing options retain legacy
  active-model behavior. Missing or corrupt selected objects fail without
  fallback. Campaign compilation preserves an explicit selection. Descriptor
  changes can invalidate frozen plan equivalence; draft and approve a new plan
  instead of modifying an approved plan. Auxiliary context is not yet frozen.
  `DeepAuditConfig` adds `threat_model_context`; Rust struct-literal callers
  should use `None` to preserve legacy behavior.

- Run comparison JSON adds `baseContext`, `compareContext` and
  `contextComparison`, derived from recorded scan input. Missing historical
  context is unknown, distinct from an explicit omission. These fields augment
  full Git SHA and indexed content identities. Neither changed context nor an
  absent observation establishes that a finding was fixed on either revision.
  The shell comparison opens on findings and their limitations. `Tab` switches
  to full source/context references when the composer is empty; typing retains
  composer completion. Each tab retains its reading position. Plain output
  includes both projections. Finding categories no longer stop after ten rows,
  and unchanged observations are available under `SEEN AGAIN`.

- Spend databases add a durable ledger identity and investigation allowance
  revision/reservation tables. Existing dollar rows and operation caps retain
  their meaning. Deposits now read current operation caps and reserve within a
  SQLite write transaction across workers. Stage failures or incomplete cost
  receipts no longer refund context-generation deposits as zero. These are
  estimated commitments, not guaranteed maximum provider charges.
  The additive `kuzushi_core::allowance` API uses version-1 approval/snapshot
  documents with explicit model, call limits, protected review and revision
  checks. `AgentRuntime::with_allowance_binding` opts a runtime into host-bound
  accounting. The bundled LangGraph bridge reserves each provider attempt,
  including internal turns and transport retries, and disables hidden SDK
  retries in this mode. Tracing preserves the binding. Other adapters reject
  binding unless they implement this contract. Supported built-in descriptors
  expose the additive JSON `allowanceRef` option. Shared prepared dispatch
  validates it and binds the runtime before preflight; nested dispatch cannot
  replace inherited accounting. Ordinary unbound calls retain their existing
  behavior. This API does not itself approve an investigation or job list.

- Prepared dispatch now owns an additive top-level result `allowanceRef`.
  It copies the validated version-1 reference, overwrites engine claims and
  removes engine-supplied references when execution was unbound. Call-correlated
  result recording authenticates this provenance. Existing results without it
  remain readable; their investigation accounting cannot be inferred.
  Ordinary scan forms and `campaign:study` with no explicit `investigationId`
  recover the current accepted Map's recorded investigation and latest durable
  consumption. Explicit context omission does not reset accounting. A new plan
  still requires approval. Missing accounting or damaged/current-source Map
  evidence blocks implicit continuation; no new allowance is substituted.
  Setup retains authenticated historical accounting when source changes require
  a replacement Map. Its new work still needs a separately approved plan.

- Finite call-bound campaigns without dollar ceilings can continue when dollar
  cost evidence is unavailable. Every job must have validated work approval;
  request reservations and protected review remain enforced. Existing dollar
  ceilings retain their evidence requirement. Unknown zero-valued cost receipts
  display as unavailable, and cost uncertainty no longer falsely implies a halt.
  Agentic context digests now include bounded architecture, flows, boundaries
  and open questions from the selected Map, including threat-free Maps. The
  twelve-element and 200-character bounds disclose omissions and truncation.

- Source-bound observed failures retain the host's start-time snapshot in
  additive `data.snapshotHash` and `data.treeHash` fields. Failed, canceled and
  interrupted status remains unchanged. This allows explicit partial Scan
  acknowledgement after an allowance refusal on unchanged source; source drift
  or tampered receipts still block reuse. Public error behavior is preserved.
  Revised study approval also displays retained calls and net discovery/review
  capacity without clearing reservations or silently changing its limits.
- Scan-batch finalization now publishes an unselected, typed Scan phase result
  for explicit acceptance. Completed and partial attempts retain their run
  references; source drift blocks current selection without deleting findings.
  Recovery reuses an interrupted typed result instead of duplicating it.
  Campaign refresh reloads externally recorded phase history without taking
  focus. Existing phase artifact contracts are reused additively.
  Campaign documents gain bounded paging across terminal sizes. Navigation-mode
  paste enters the composer without submitting and preserves the held cursor
  and draft; editor and confirmation paste ownership remains unchanged.

- `campaign:approve-allowance` records exact limits under explicit authorization;
  `campaign:allowance` reads them without creating a spend ledger. Approval is a
  Map preparation action with `phaseResult=false`, not an accepted Map or Scan.
  The shell confirmation shows the model, revision, total calls and protected
  review allocation. The paged card supports the full viewport matrix,
  including 40×12; approval is available only on the last page. No jobs start
  when an allowance is approved.

- `campaign:study` compiles the existing scan-batch format without starting
  children, with three passes and one worker by default. Its additive
  `requiresWorkApproval` marker blocks launch until exact plan approval.
  `campaign:approve-allowance` optionally accepts `campaignId`,
  `campaignPlanSha256`, `campaignJobs` and `maxJobAttempts` to bind those jobs.
  Approval/snapshot version 1 gains an optional `workPlan`; Rust struct-literal
  callers should set it to `None` for legacy allowance-only behavior. The
  additive SQLite `investigation_work_attempts` table preserves failed,
  canceled and interrupted starts. Revised approvals cannot erase consumed
  attempts or reuse their identities for changed input/source/configuration.
  The campaign dispatcher attaches allowance references automatically and
  counts quota failures against approved attempt limits. Shared dispatch
  verifies the job and atomically claims it before executor entry. These plan
  approvals currently support discovery scan batches; immutable context
  isolation and review/learning job planning remain in progress. The combined
  work/allowance receipt uses the same paged approval surface. Older campaign
  plans retain their existing launch contract.

- The shell `scan batch` action now prepares `campaign:study` through shared
  dispatch, followed by explicit allowance review and a separate job launch.
  It no longer compiles and immediately starts a legacy batch. `b` on Scan
  opens the form; `a` in Campaign reopens a saved study and its allowance.
  `campaign:study` adds optional `investigationId`, persisted in the plan;
  approval must retain that identity. This keeps spending attached to an
  investigation when a draft replaces previously approved work. Result JSON
  adds frozen `scanInput`, requested workers and any worker limitation. Existing
  plan/result fields and headless legacy batch execution remain compatible.
  Unsupported scanner names are rejected before publishing a study draft.

- `campaign:context-study` adds a finite, source-only context generation plan.
  It requires `investigationId` and `contextInput`, and accepts an optional new
  `campaignId` and `preparationJobs`. Up to one deterministic `context:build`
  and one `entry-points:extract` job may precede generation, in the reviewed
  order. The existing campaign `plan.json` gains the additive
  `kind: "context-study"` form with one frozen `threat-model:build` job. Version-1
  allowance work plans now also accept these tools and attribute their calls to
  Context, without access to protected review calls. Context studies allow one
  attempt; regeneration requires a separate plan approval. Current context is
  retained until the operator inspects and selects the generated revision.
  Setup also opens this flow for a Map plan containing threat-model generation
  and its supported preparation. Other model-backed combinations are refused
  with an explanation; existing selections are preserved. The CLI enforces
  one worker for context studies as well as their frozen attempt limits.
  The TUI opens this flow with `g` in the study context picker and recovers it
  through `campaign <id>` then `a`; exact options are available with Tab.
  Existing scan-batch and direct threat-model tool contracts remain compatible.

  Saved context plans now open a distinct result view after generation. Setup
  recovers the exact run-associated revision for inspection and keeps its
  allowance and navigation origin. Failed, parked, partial, unknown and
  completed-but-unreadable outcomes open job inspection; preparing a replacement
  remains an explicit action. Recovery keeps its public return type and now
  reports stopped or unavailable results as errors instead of pending work.
  Campaign cost summaries disclose missing receipts, and completed context
  plans offer result review. These changes require no artifact migration.

  `campaign:context-map` adds an explicit handoff into durable Map review.
  Required `campaignId` and `expectedPlanSha256` bind the reviewed plan.
  The tool authenticates completed job calls and the generated immutable object,
  refuses changed source or discarded results, and preserves one attempt across
  retries and interrupted receipt writes. It neither selects Map nor starts
  additional work. The TUI exposes `m Review Map` on completed context results;
  foreground completion presents explicit acceptance and background completion
  preserves focus. Existing phase receipts and campaign formats are retained.

  Generated context artifact lists now identify their actual immutable object.
  Inactive builds no longer advertise an unwritten active-model mirror. The
  legacy `data.threatModelPath` field retains its mirror path for compatibility;
  consumers should use `modelRef` or declared artifacts for an exact build.
  Inactive build status says that the immutable draft was saved and active
  context stayed unchanged. A failed artifact settlement retains its mandatory
  recovery notice within the lifecycle preview limit.

- `threat-model:read` adds the shared `threatModelRef` option (and
  `threat_model_ref` alias). An exact reference authenticates and returns the
  unchanged scanner document; `null` reads explicit omission. This mode rejects
  scope, output-directory and methodology overlays. Existing reads without the
  option keep their previous behavior. The study form's Source and context row
  now opens a revision browser; inspect a revision before accepting it for that
  study. Selection does not activate the workspace threat model and changing
  context requires a newly compiled and approved plan with the same accounting.
  After inspection, `v` opens that exact revision's DFD. Arrows choose elements,
  Enter reads their full details and linked evidence, and Escape restores context
  review. This is read-only; generation and study acceptance remain separate.
  The shared DFD renderer now preserves short vertical arrows and reverse flow
  direction. Existing artifact formats remain unchanged.

- Source indexing now evaluates ignored directory names relative to the selected
  workspace. Repositories beneath an ancestor named `target`, `dist`,
  `node_modules` or `bazel-*` are no longer silently hashed as empty. Recompute
  older identities from affected paths before claiming unchanged dirty content;
  previously frozen study keys may correctly require a new plan.

- Runtime failure metadata adds `allowance_refused` to `run.items.schema.json`
  and `run.failures.schema.json`. Exhaustive consumers must accept this category.
  The optional `stdio-v1` provider-admission channel requires a startup
  acknowledgement within ten seconds; missing acknowledgement never falls
  back to an unaccounted call. Legacy bridge requests without an allowance keep
  their existing protocol. Unresolved reservations persist after cancellation,
  and absent dollar receipts remain unknown. Call limits do not promise a
  strict dollar ceiling. Failure handoffs offer reporting and explicit allowance
  review instead of recommending automatic stage resumption for this category.

- Tool descriptors add the `report` phase. `report:build` and `report:sarif`
  move from `fix` to `report`; tool names, outputs, saved workflow phases and
  historical receipts retain their meaning. Consumers with exhaustive phase
  enums must accept `report`. Re-approve local KWP descriptors when changing
  their phase. Reports are available at any autonomy posture and do not advance
  the persisted workflow; explicit export authorization still applies.
  Repository execution and external actions cannot use the Report phase.

- Repository size and model recommendations no longer preselect subdivision.
  The Map planner retains whole-repository work and an explicit scope action,
  including after a failed subdivision attempt.

- Repository inventory adds an optional `inspection` receipt with enumeration
  mode, entry/byte limits, omitted paths, and files inspected only as prefixes.
  Missing receipts in older artifacts mean the inspection extent is unknown.
  Prefix inspection now marks the inventory partial. Existing inventory fields
  retain their types, and existing artifacts are not rewritten.

- `pack:suggest-shards` derives at most eight candidates from one bounded
  inventory. Small repositories and parents with loose files can remain whole.
  New drafts rank extracted entry points (`signals.entrypoints`) rather than
  substring hits. New candidate IDs include a path digest to avoid slug
  collisions; saved shard manifests and scope trees are unchanged until the
  operator explicitly replaces them. Review scope references when accepting a
  new tree. `emitScopes` refuses incomplete inventory; the draft remains for
  inspection. Child scopes inherit parent context and threat-model sections.

- The interactive cost-halt action opens a cap editor instead of doubling the
  cap. Editing and cancellation preserve the halt; a specific amount above
  observed spend must be approved to continue. Unknown proposal estimates no
  longer pass a configured budget check as zero-cost work.

### Audit remediation compatibility

- MCP method selectors now include their language graph, for example
  `cpp:method:<digest>`. This disambiguates shared headers indexed in both C
  and C++. Existing names and bare selectors remain accepted when unique.
  A structural query naming an absent file returns an explicit membership
  error. Semantic cache databases and journals reject multiple hard links
  before SQLite initialization. An oversized terminal paste reports a notice
  and leaves the shell available for further input.

- Windows bounded MCP file reads now retain an opening content digest and
  verify both returned bytes and current handle content before accepting a read
  or copy. Read identities always include a content digest on Windows. This adds
  bounded streaming reads; same-size writes and restored timestamps cannot reuse
  a stale content identity. Loop checkpoint owners explicitly unlock on drop,
  including error paths, before concurrent spawned processes finish exec.

- Shell composer and form fields move and delete by extended Unicode graphemes.
  Cursor projections and clipping use terminal display widths, including emoji
  sequences and combining accents. Existing scalar-offset view-model interfaces
  remain compatible; interior offsets snap to a complete character boundary.
- Collapsed multiline pastes are tracked editor spans. Arrows, word movement,
  Backspace and Delete cannot damage a marker. Ctrl+Y opens the adjacent block's
  read-only preview; Enter/e expands it, Delete removes it and Esc cancels.
  Ctrl+_ or Ctrl+/ restores paste edits or a cleared draft, including all payload
  bytes. Paste undo lasts until submission or intentional clearing. Completion
  waits until pasted blocks are expanded. Literal copies of marker text never
  acquire a document payload.
- The interactive terminal inbox is limited to 256 queued events and 4 MiB of
  event data. Resize, pointer-move and focus updates coalesce without crossing
  ordered input. Keys, pointer actions and accepted pastes apply backpressure;
  a paste over 1 MiB is rejected explicitly. Background wakes have a separate
  coalesced slot, and saturation produces one bounded input diagnostic.
- Semantic query keys now include generation settings and an attested runtime
  identity. Legacy keys safely miss. Runtime adapters opt in through
  `AgentRuntime::semantic_cache_identity`; unauthenticated external bridges,
  including the current LangGraph adapter, execute live. This can increase model
  spend compared with earlier cache replay. Credentials and transport diagnostics
  are excluded, and tracing/routing wrappers preserve the inner attestation.
- Semantic responses now use an indexed SQLite cache with defaults of 10,000
  entries and 64 MiB of database pages. Set `operator.semantic_cache.max_entries`
  and `max_bytes` in global config; target config cannot raise quotas. Half the
  page budget is reserved for response payload and the rest for index overhead.
  A rollback journal can temporarily add up to one database's size. Oversized
  entries and quota pressure skip caching. Legacy JSON entries safely miss and
  are reclaimed in resumable batches of at most 64 directory entries per open;
  indexed expiry also visits at most 64 entries per pass. `maintain()` reports
  reclaimed bytes, quota pressure and pending work. Lowering the byte budget below
  an existing database's size disables that cache until it is cleared; it never
  admits new writes above the new budget.
- Run-item writers reserve a bounded model completion receipt before each model
  start and preserve a terminal outcome slot. At most eight calls may be in flight
  in one run stream; a start without available receipt capacity fails before
  provider dispatch. Model start/finish emission is synchronous and durable,
  including through the ordinary `emit` API. Completed usage/cost receipts remain
  admissible after ordinary log capacity is exhausted; the run still ends degraded.
- Sandbox children receive an explicit minimal environment. Callers must grant
  required variables through `SandboxExecOptions.env`; stdin and each output
  stream are limited to 1 MiB. `output_limit_exceeded` is a new terminal outcome.
  Cancellation owns the process group/Windows Job Object and kills descendants.
- MCP tool arguments are validated against their advertised JSON Schema before
  execution. Invalid input now returns a protocol error without invoking the
  handler. The server limits concurrent requests to eight and honors cancellation
  and shutdown; clients must not depend on acceptance after shutdown.
- Loop checkpoint protocol 3 binds the executable digest and uses full request
  fingerprints. Old checkpoints are not resumed. A kernel lease excludes a second
  owner; an unfinished tool intent requires explicit effect reconciliation before
  retry. Checkpoints over 8 MiB or 512 transcript entries fail visibly. Historical
  files are not rewritten and spend from failed turns remains unresolved.
- Loop and stage checkpoints now admit at most 512 records, 1 MiB per encoded
  record and 8 MiB per checkpoint. Readers validate raw record length before
  allocating structured records and retain the JSON nesting limit. Stage payload
  publication also stops at 8 MiB, including its newline. Oversized legacy
  checkpoints require inspection instead of implicit recovery; bounded serializers
  borrow transcripts and stage receipts instead of cloning the completed history.
- Staged tools expose `resumeHealth` separately from execution success, persist
  `resume-health.json` when storage permits, and emit one warning per failure
  class and operation. The receipt names the last durable stage and source run.
  A load, payload, receipt or save failure stops checkpoint advancement for that
  dispatch while paid execution may continue; recovery retries on the next
  dispatch. A failed clear is visible. Embedders must handle the new `Result`
  returned by `StageCheckpointStore::clear`.
- Finding anchors are grounded even without evidence. `unavailable` is distinct
  from invalid source evidence; claimed coordinates are preserved. Cross-producer
  evidence is merged independently of severity. Static verification requires exact
  bounded source citations; missing or invalid citations produce an inconclusive
  result. Raw model confidence remains explicitly uncalibrated.
- Core `cpg_taint_paths.maxPaths` accepts integers from 1 through 25, with a
  default of 10. Invalid or larger values now return an explicit error instead of
  silently using a clamped value. The MCP query retains its separately advertised
  output range and discloses the engine flow cap.
- CPG structural queries now return explicit ambiguity errors for duplicate
  suffix paths, method names, start positions or language-graph matches. Use the
  canonical `selector` returned by `cpg.definitions` for overloaded methods.
  Rust query helpers now return `QueryResult`; callers must handle resolution
  errors. Reaching definitions require an unambiguous AST node at the requested
  line, so blank lines and inter-method gaps return an unavailable-membership
  error. `method_at` remains explicitly approximate. Slice depth is checked in
  the advertised 0–32 range; depth zero retains intra-method behavior.
- CPG caches use source-content and implementation identities; existing caches
  rebuild. `maxCallDepth` is rejected until the engine can enforce it. Regex and
  literal matching are explicit; limits and approximate method positions are
  disclosed in results. Queries with failed language coverage return an error.
- History uses a versioned JSON record format to preserve multiline commands;
  legacy records are imported on read. Evaluations require complete run-bound
  receipts, distinguish unjudged output, and enforce recall thresholds only when
  requested. Historical score files do not acquire provenance retroactively.
- Publication uses the `candidate` npm dist-tag. The exact-version public-install
  matrix must pass before promotion of platform tags and finally the root `latest`
  tag, followed by GitHub release visibility. Rerunning promotion verifies registry
  integrity before changing any tag. If interrupted, the root launcher remains on
  the previous version until its final tag operation; rerun the same candidate
  after correcting the failure. To roll back a completed promotion, move the root
  `latest` tag to the previously verified exact version and then restore platform
  tags; never republish different bytes under an existing version.
- Full-quality runs compare with the latest successful ancestral full run, not
  the previous commit. The initial run requires `quality_base_ref`; failures to
  resolve a baseline fail the gate rather than silently narrowing the interval.

See [the audit ledger](docs/quality/audit-remediation-2026-09-30.md) for acceptance
work that remains open; these changes are not an all-items completion claim.


- Static `verify:finding` results now use `exploitable: null` for incomplete
  evidence, unsupported language, or an unresolved panel. These outcomes have
  `status: partial` and cannot replace selected proof. Consumers must handle
  null explicitly; false means the model cites evidence defeating the claim.
  `consensus.inconclusiveVotes` and `proofVerdict: inconclusive` are additive.
  Older model responses pairing false with an explicit incomplete verdict are
  normalized to null on new execution. Historical run files and selected
  evidence are not rewritten; rerun to obtain the corrected assessment.

- `verify:finding mode=empirical` now delegates through the shared `verify:exploit`
  dispatch boundary with explicit authorization and no model runtime. The public
  input contract is unchanged. Prove discloses backend availability and validates
  empirical receipt selection against the durable proof and current source.
  Historical incomplete or stale proof receipts remain inspectable; rerun before
  selecting them. No saved receipt is rewritten.

- Session transcripts add `agent_conversation` and `agent_conversation_cleared`
  events. The public Ask checkpoint retains its target/revision/Map/policy
  receipt and incomplete-turn state. It uses the existing redaction, retention
  and persistence opt-out. Historical unbound turns are not reconstructed into
  model context. No existing transcript or target run is rewritten. Oversize
  checkpoints explicitly disable recovery for that target instead of silently
  restoring an older answer; see the bounds in [operator guidance](docs/OPERATOR.md).

- Interactive Report destinations now default to `.kuzushi/reports/` instead
  of the target source root. Explicit destinations and the shared export
  format/path contracts retain their meaning; existing files are not moved.
  Destination edits save or cancel independently of export, and each format
  keeps its chosen path for the session. Report now discloses recent run-cost
  coverage without treating campaign totals as workspace spend. No campaign
  metric, run-cost record or serialized receipt is reinterpreted or migrated.

- Registered model-backed Scan outputs add `data.snapshotHash` and
  `data.treeHash` as adapter-owned source receipts. Existing result fields keep
  their meaning. Historical runs without a verifiable source receipt remain
  available for inspection; rerun them to obtain an execution-bound receipt
  before accepting work on dirty or unversioned targets. The offensive threat
  hunt now emits the same typed added/updated finding counts as Agentic SAST.
  No stored run is retroactively rewritten.

- Model-backed `threat-model:build` now includes `source-code` in its default
  `sources` list. This supplies bounded, file/line-addressed source excerpts to
  synthesis and refinement, with hashes and explicit coverage omissions.
  Explicit source lists retain their meaning; `contextMode=off` continues to
  exclude the default bundle. Code collection requires `maxSourceBytes >= 1024`.
  See [source evidence options](docs/modules.md#source-evidence-for-model-backed-map)
  for budgets, exclusions, and how to retain the previous input selection.

- Rust surface metadata now carries `sourcePolicy: rust-test-scopes-v1`.
  Production surface IDs ignore this extraction-policy marker, preserving
  their prior identities; payload digests still authenticate it. Before a new
  model run can reuse a context or explicit entry-point catalog with older
  Rust rows, rebuild with `context:build` and `entry-points:extract`. Historical
  models are not rewritten. The source projection excludes direct `#[cfg(test)]`
  scopes, `#[test]` functions and inner `#![cfg(test)]` scopes. Compound cfg
  expressions, unknown attribute macros and cross-file test-module ownership
  remain conservative candidates, not proven production reachability.

- Markdown-bundle and machine-export `derivedSourcePresent` now means that a
  finding has explicit source-grounded static proof. A constructor-generated
  source signature or automatic occurrence row remains provenance and no
  longer promotes a zero-evidence finding from `message_only` to
  `source_linked`.
- KWP `findings.create` no longer accepts worker-supplied `fingerprint`,
  `dedupKey`, or `sourceSignature` values. Those canonical identity fields are
  host-owned; module authors should use `actorFingerprint` for a producer-side
  observation id.

## Current release status

`0.24.0-alpha.14` is the next candidate. `0.24.0-alpha.13` was a failed
release attempt and was never published; do not create or reuse its tag.
Preparing a candidate does not publish npm packages, create a GitHub Release,
or change repository visibility.

## Prerequisites

- Node.js 22 or newer (`node --version`), matching `engines.node`
- GitHub CLI authentication and push access to `github.com/allsmog/Kuzushi`
- For the later tagged release only, an npm token available to the release
  workflow as `NPM_TOKEN`

## Prepare and verify a nonpublishing candidate

Run the local gates, bump every machine-owned version source, and commit the
candidate without tagging it:

```sh
pnpm check:docs
pnpm quality:architecture
pnpm quality:model-safety
pnpm quality:crap-risk
pnpm test
cargo check --workspace
cargo test --workspace
pnpm build:native
pnpm verify:pack

node scripts/bump-release-version.mjs 0.24.0-alpha.14
pnpm check:release

git add package.json pnpm-lock.yaml npm/platform-packages Cargo.toml Cargo.lock scripts/kuzushi-dynamic-module-host.mjs CHANGELOG.md RELEASING.md
git commit -m "chore: bump version to $(node -p 'require("./package.json").version')"
```

Push the reviewed commit to `main`, then dispatch `release-candidate.yml` at
that exact commit. Supply a previous reachable release tag, or a full ancestor
commit for the first release, as the quality baseline:

```sh
candidate_sha="$(git rev-parse HEAD)"
candidate_version="$(node -p 'require("./package.json").version')"
quality_base_ref="$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || git rev-list --max-parents=0 HEAD)"

gh workflow run release-candidate.yml --ref main \
  -f expected_sha="${candidate_sha}" \
  -f expected_version="${candidate_version}" \
  -f quality_base_ref="${quality_base_ref}"
```

The candidate workflow requires `expected_sha` to equal the workflow commit,
runs reusable full CI, builds all five native targets on four native runners,
installs the exact root and matching platform tarballs on all five target
runners, and uploads one
`release-candidate-artifacts` bundle. Its `release-manifest.json` receipt binds
the source commit and version to every npm package, native archive, and source
archive with byte size, SHA-256, and npm integrity where applicable. The
workflow has read-only repository permission and no npm credential.

A later tag run rebuilds these files and repeats every candidate check. It does
not promote bytes from an earlier manual candidate run.

## Repository visibility gate

This gate governs repository visibility only. Do not make the repository public
until every item below has an operator-owned receipt. It does not gate creating
a release tag or publishing to npm; see the recorded decision below.

1. Build the all-ref history rewrite in an offline mirror from the verified
   backup bundle. Record the old-to-new map for every advertised head and tag,
   and verify topology, author/committer identity and dates, metadata-only tree
   equality, the path-scoped content allowlist, and zero private identifiers or
   prohibited attribution across every rewritten ref.
2. With separate operator authorization and while the repository is private,
   force-update every advertised head and rewritten tag. Verify the remote ref
   map exactly matches the reviewed mirror before continuing.
3. Obtain GitHub Support confirmation that immutable pull-request refs and old
   sensitive object IDs have been purged from repository storage and caches.
   Verify the named old SHAs are no longer fetchable and that the contributor
   graph cannot recover the prohibited attribution. Rewriting branch and tag
   tips alone is not sufficient.
4. Confirm the Alpha14 candidate runs at the rewritten `main` commit and its
   downloaded bundle passes `node scripts/verify-release-artifacts.mjs
   <directory> <sha> 0.24.0-alpha.14`.
5. Obtain npm unpublish or registry-support cleanup for the exact
   `kuzushi@0.24.0-alpha.10` and `kuzushi@0.24.0-alpha.12` root packages. They
   contain private identifiers. Moving `latest` to Alpha14 does not make an
   exact historical version unavailable.
6. Remove or replace the corresponding root npm tarball assets on the
   `v0.24.0-alpha.10` and `v0.24.0-alpha.12` GitHub Releases. If an asset is
   replaced, record the approved clean file's SHA-256 and verify the downloaded
   bytes against it.
7. Verify the two exact npm versions are no longer downloadable, or retain the
   registry support confirmation that provides the equivalent restriction.
   Verify each GitHub Release asset list and download before recording the gate
   complete.
8. De-register and delete every self-hosted runner and restore hosted CI
   **before** the repository becomes public. `gh api
   /repos/allsmog/Kuzushi/actions/runners --jq '.total_count'` must return `0`,
   and `.github/workflows/ci.yml` and `.github/workflows/ci-full.yml` must be
   back on `runs-on: ubuntu-latest` (flip the `hosted` input default to `true`,
   or replace the expressions outright). A self-hosted runner on a public
   repository executes code from any fork pull request on the owner's machine.
   Teardown steps are in `scripts/runner/README.md`.

This work requires separate operator authorization. The release workflow does
not delete or rewrite historical registry content.

### Recorded decision, 2026-08-28: the visibility gate does not block Alpha14

Decided by the repository owner on 2026-08-28. Items 1 through 7 above were
previously written to block the Alpha14 tag as well as public visibility. They
now block public visibility only. Item 8 was added later, with the self-hosted
runner, and has always been visibility-only.

Rationale: `0.24.0-alpha.10` and `0.24.0-alpha.12` are already published and
already carry private identifiers. Publishing a scrubbed `0.24.0-alpha.14` at
the `latest` dist-tag strictly reduces exposure, because every new install
resolves to the scrubbed package instead of a contaminated one, and it is the
prerequisite for deprecating alpha.10 and alpha.12. Withholding the tag leaves
`latest` pointing at contaminated bytes and improves nothing. The repository
stays private until this gate is complete, so the history rewrite and support
confirmations remain required work rather than cancelled work.

## Publish the tagged release

The tag-triggered workflow is the sole publishing path. Create the tag only
after the candidate gate is complete and the release commit is the current
`origin/main`. The repository visibility gate above is not a tag prerequisite:

```sh
git fetch origin main --tags
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
version="$(node -p 'require("./package.json").version')"
git tag "v${version}" "$(git rev-parse HEAD)"
git push origin "v${version}"
```

`.github/workflows/release.yml` refuses a tag that does not match the package
version or current `origin/main`. It then calls the candidate workflow, rehashes
the complete receipt, publishes all five exact-version platform packages, and
publishes the thin `kuzushi` launcher last. Every npm publish uses the `latest`
dist-tag. A matching already-published file is reused; a byte mismatch fails.
Only after npm succeeds does the workflow create the GitHub Release and run the
five-platform public-package smoke.

Do not publish from a local package build. `pnpm publish:npm:go` fails closed
because `pnpm build:native` stages only the current host.

### Native platform builds

Four runners produce the five shipped platform payloads:

| Slug           | Built on              | Installed and executed on |
| -------------- | --------------------- | ------------------------- |
| `linux-x64`    | `ubuntu-24.04`        | `ubuntu-24.04`            |
| `linux-arm64`  | `ubuntu-24.04-arm`    | `ubuntu-24.04-arm`        |
| `darwin-arm64` | `macos-14`            | `macos-14`                |
| `darwin-x64`   | `macos-14` (cross)    | `macos-15-intel`          |
| `win32-x64`    | `windows-2025`        | `windows-2025`            |

Releases use those hosted macOS images by default. Passing `hosted: false` (or
setting the `KUZUSHI_RELEASE_SELF_HOSTED` repository variable) moves every darwin
leg onto `kuzushi-mac`, the owner's self-hosted Apple silicon runner — see
[the darwin release legs](#darwin-release-legs-on-the-self-hosted-mac) below for
its prerequisites.

`darwin-x64` is cross-compiled from the Apple silicon runner with
`rustup target add x86_64-apple-darwin` followed by a second
`node scripts/build-native-runtime.mjs` under
`KUZUSHI_NATIVE_TARGET=x86_64-apple-darwin`, and uploaded as its own
`release-candidate-native-darwin-x64` artifact. Kuzushi's native dependency set
crosses cleanly — no openssl, git2, or portable-pty; the tree-sitter grammars
and bundled `libsqlite3-sys` build through `cc`, wasmtime is cranelift-only, and
reqwest uses rustls. The x64 payload is still *installed and executed* as an
Intel payload — on the hosted Intel runner by default, or through Rosetta 2 when
a release opts into the self-hosted Mac — so cross-compilation never replaces
execution evidence.

To cross-build one platform locally:

```sh
rustup target add x86_64-apple-darwin
KUZUSHI_NATIVE_TARGET=x86_64-apple-darwin node scripts/build-native-runtime.mjs
# equivalently: node scripts/build-native-runtime.mjs --target x86_64-apple-darwin
```

Cargo writes to `target/<triple>/release` (or `$CARGO_TARGET_DIR/<triple>/release`)
and staging publishes it as `native/<slug>`. Only the five supported triples in
`scripts/native-runtime-contract.mjs` are accepted; anything else is refused
rather than mapped to a guessed slug.

`node scripts/smoke-native-runtime.mjs [slug]` still refuses to execute a slug
the host cannot run. A `darwin-x64` payload may be smoked on a `darwin-arm64`
host only with an explicit `KUZUSHI_SMOKE_ALLOW_ROSETTA=1` opt-in *and* Rosetta 2
actually installed; the receipt then records the host slug, the smoked slug, and
`"translation": "rosetta"`. The same opt-in applies to
`scripts/smoke-release-tarballs.mjs`. No other host/payload pairing is ever
unlocked.

### Darwin release legs on the self-hosted Mac

Hosted macOS runners bill at 10x, and a release touches five macOS legs: the
native build, both local-tarball smokes, and both published-install smokes. All
five run on hosted `macos-14` / `macos-15-intel` by default, because keeping the
owner's Mac runner online between releases cost more than the occasional hosted
release. All five stay eligible for that runner (labels
`self-hosted, macOS, ARM64, kuzushi-mac`) when a release opts in. Linux and
Windows legs are unchanged, and `identity`, `assemble`,
`publish-npm`, and `github-release` stay pinned to `ubuntu-24.04` — they hold
`NPM_TOKEN` or `contents: write`, which must never reach a persistent machine.

**Owner prerequisites** for opting in, one time on the Mac:

```sh
softwareupdate --install-rosetta --agree-to-license   # translate the x64 payload
arch -x86_64 /usr/local/bin/brew install node@22      # an x64 Node under /usr/local
rustup target add x86_64-apple-darwin                 # the candidate re-runs this anyway
```

The x64 Node is not optional for the `darwin-x64` legs: npm gates
`@kuzushi/darwin-x64` on `process.arch === "x64"`, so an arm64 Node installs no
platform package. The workflow puts `vars.KUZUSHI_X64_NODE_PREFIX` (default
`/usr/local`) first on `PATH` and fails the leg loudly if no x64 Node is there.

**Opting in.** To run one release on the self-hosted Mac, bring the runner
online, then:

```sh
gh variable set KUZUSHI_RELEASE_SELF_HOSTED --body true
git push origin vX.Y.Z          # this release's darwin legs run on kuzushi-mac
gh variable delete KUZUSHI_RELEASE_SELF_HOSTED
```

`release.yml` forwards `hosted: ${{ vars.KUZUSHI_RELEASE_SELF_HOSTED != 'true' }}`
to both the candidate and the published smoke, so the one variable moves every
darwin leg. `workflow_dispatch` on either workflow exposes `hosted` directly
(default `true`).

Full detail, including how a translated leg proves it smoked the Intel payload,
is in [docs/quality/release-legs-self-hosted.md](./docs/quality/release-legs-self-hosted.md).

## Verify a tagged release

```sh
npm view kuzushi version
npm view kuzushi@0.24.0-alpha.14 dist.integrity
npm install -g kuzushi@0.24.0-alpha.14
kuzushi --version

gh workflow run published-release-smoke.yml -f version=0.24.0-alpha.14
```

## Surface Compatibility Migrations

### Unresolved deep-auditor assessments (unreleased)

The raw deep-auditor analysis now accepts `triggerable: null` for unresolved
reachability or impact. Existing Boolean JSON remains readable, and persisted
`TriageVerdict` values keep their existing format. Rust callers constructing
`VulnAnalysis` must use `Some(true)`, `Some(false)`, or `None` for `triggerable`
and handle the unresolved case explicitly. A false `implausible_trigger`
assessment without an inspected `first_link` now remains `needs_review`, with
the original rationale and an explanation retained. Existing stored decisions
are preserved; an operator must explicitly retriage to produce new decisions.

Before publishing a release that changes the registry surface, check
`docs/api-compatibility.md` and the deferred-surface contract. Current
compatibility folds intentionally keep old exact tool names runnable while
removing them from catalog/recommender discovery:

- `operator.keybindings` is an additive, home-scoped config surface. Empty
  binding lists mean explicit unbind; project-scoped keybinding policy is
  rejected, and invalid live edits preserve the last valid runtime map.

- shell `home`, `/home`, `/`, and `workbench` -> the selected
  Map/Scan/Review/Prove/Fix page in the Cockpit Spine, with workspace reality
  disclosed separately
- shell `findings` and `open <id>` -> Review; `report` -> the dedicated Report exit
- shell `modules` -> the contextual Capabilities overlay (`tools` is the raw inventory)
- `bounty:import-har` -> `recon:import {"tool":"har","path":"..."}`
- `bounty:import-burp` -> `recon:import {"tool":"burp-xml","path":"..."}`
- `randori:pasta` -> `threat-model:build {"methodology":"pasta"}`
- `carlini-threat-hunt:run` -> `offense-review:threat-hunt`

- `taint-iris:hunt` -> `taint-iris-next:hunt`
- `full-mode:hunt` -> `agentic-sast:scan {"strategy":"chunked"}`
- `deep-audit:run` -> `triage:run {"strategy":"deep"}`
- `classifier-gate:score` -> `triage:run {"strategy":"gate-deep"}`
- `verify:exploit` -> `verify:finding {"mode":"empirical"}`
- `shinsa:*quick-check` -> `shinsa:*scan {"depth":"quick"}`
- granular `android-apk:*` phase tools -> `android-apk:scan`

`smoke:next-step` was a hidden runtime smoke-test helper and has no migration
path.

## Map source receipt compatibility (unreleased)

`entry-points:extract` and `module-recommender:recommend` add
`data.snapshotHash` and `data.treeHash` to successful results. Both use registered
source snapshots and reject source changes detected during execution. Existing
result fields, module names, options, and the manifest contract are preserved.

Older completed Map attempts may lack a verifiable identity for one or more
referenced runs. The shell now keeps those unresolved results inspectable and
offers a fresh run instead of accepting a result that cannot advance the journey.
Already recorded dispositions remain historical records. Rerun Map against the
current source to create a usable receipt; do not backfill or rewrite old run
identities. See [the module contract](docs/modules.md#map-result-source-identity).

## Five-phase Cockpit Spine and patch-lifecycle migration (unreleased)

The interactive shell has one canonical route:
`Target → Setup → Map ↔ Run Focus → Scan ↔ Run Focus → Review → Prove ↔ Run
Focus → Fix ↔ Run Focus → Report`. The old
Target → Model → Credentials → Planning wizard, generic whole-screen
Workbench, and duplicate Activity projections are superseded presentation
contracts; no production feature flag retains them. The canonical persisted
and descriptor phases are now `map`, `scan`, `review`, `prove`, and `fix`;
Report is an exit rather than a sixth phase. For one major release, descriptor,
query, CLI-autonomy, and config inputs accept deprecated `hunt` as `scan` and
`confirm` as `prove`, emit a warning, and serialize only the canonical names.
Config may not provide an old key together with its replacement. Existing run,
finding, proof, and patch artifacts are projected in place: scan records imply
Scan, triage records imply Review, verification records imply Prove, and patch
records imply Fix, with `legacy inferred` shown when no explicit phase attempt
exists.

The shell's `sast:scan` dispatch is discovery-only (`triage=false`,
`verify=false`, `autoPatch=false`). Explicit CLI full-pipeline calls remain
available, but the registry preflights their highest requested phase before
any scanner side effect. Phase attempts and dispositions are append-only
reference records under `.kuzushi/v3/workflow/`; canonical run bundles remain
the payload source of truth and discarding a result never deletes evidence.

Storage v3 additively introduces the `PatchLifecycleRecorded` event plus
`patch_lifecycle_events` and `patch_lifecycle_current` projections keyed by
`applicationId`. The event is append-only; projection rebuild/reset replays it
through the normal v3 projector. Existing event logs remain valid, absent
lifecycle rows mean “not applied,” and historical `SOUND` `PatchResult` records
must render as `draft available / not applied`. Do not synthesize application
receipts or infer apply state while migrating an old workspace.

`patch:reverify` is a new descriptor-backed, headless tool with required
`applicationId`. It replays only the originating detector and original prepared
input in the explicit workspace, refuses changed touched-file hashes, and
never chooses a substitute target, detector, runtime, provider, or model. Only
deterministic successful absence promotes the patch to `Verified`;
nondeterministic absence is `NotRediscovered` and unavailable comparison is
`Inconclusive`.

Finding exports add an optional `remediation` object in JSON/JSONL/Markdown,
SARIF properties prefixed `kuzushiRemediation`, and these flattened CSV
columns: `remediation_application_id`, `remediation_patch_run_id`,
`remediation_application_state`, `remediation_reverify_outcome`,
`remediation_reverify_run_id`, `remediation_diff_hash`, and
`remediation_touched_paths`. Consumers must tolerate the additive fields;
records with no applied lifecycle retain their prior shape/empty CSV values.
No existing finding or export record is rewritten.

Nested project-scope trees now write schema version 2. Newly discovered
non-root scope ids keep their readable prefix and add a path-derived suffix so
two paths that normalize to the same slug cannot collide. Refresh preserves a
valid legacy id when kind and relative path still match exactly; removed or
changed scopes remain visibly stale instead of being reassigned. Consumers
must continue treating scope ids as opaque strings.

Threat models now use an additive immutable lineage/revision store under
`.kuzushi/threat-models/`. On the first writable open, a valid legacy
`.kuzushi/threat-model.json` is imported as one lineage and remains the derived
compatibility mirror of the active revision. Read-only opens never migrate.
After migration, `manifest.json` plus its content-addressed object is
authoritative; a missing/corrupt active object is an integrity error, and a
hand-edited divergent mirror requires explicit adopt or forced-discard action.
Every new run summary may add `threatModelId` and `threatModelRevisionId`
alongside the existing content SHA. Older readers may ignore those additive
fields but must not treat the mirror as an independently writable authority.

Context comparison adds `contextText`, `documentChanged`,
`changedDocumentSections` and `comparisonCoverage` to `threat-model:diff` data.
Both revision selectors also carry the immutable content SHA. Existing
structural fields remain unchanged. Readers should accept these additive fields;
bounded terminal previews preserve complete text in the structured result.
Document-section changes include metadata and do not establish semantic
equivalence or finding validity. Unique component/question ids and exact
question text match across reordered rows; ambiguous or unkeyed rows compare
by position.

The `diff`, `activate` and `restore` results add the canonical workspace path
as `data.target` for target-bound consumers. Existing structural, revision and
activation fields remain unchanged. No stored artifact migration is required.
The shell's `threats models` command now opens an immutable revision browser;
`6 MODELS` opens the same browser from the threat pages. Inspection and baseline
comparison use the existing prepared read/diff tools. Activation and restore
remain explicit workspace-management actions. Browser selection, baseline and
reader positions are session state; restart loads the saved immutable history
and current active pointer. No new tool options or authorization are introduced.

The context `activate`, `restore`, `adopt`, `revise` and `regenerate` descriptors
now declare `phase_result: false`. They manage context or create inactive copies
and cannot replace an accepted Map attempt. Tool names, options, workspace
effects and authorization remain unchanged. Existing persisted Map attempts are
retained as history; this change applies to new dispatches. Building/importing a
Map and explicitly accepting its evidence retain their existing contracts.

Adopting mirror edits now clears the document's previous verification and marks
the new revision `userEdited: true`. Original objects and verification history
remain immutable. The transaction authenticates the observed mirror digest
before withdrawing it, then uses the existing pending-mirror recovery record.
Later mirror edits refuse the commit. No manifest or activation schema changes
are required; no-op adoption still refuses without publishing a revision.

`kuzushi scan --trials N` creates a dedicated immutable `scan-batch` campaign
plan and invokes the same prepared `sast:scan` input for each logical trial.
The deprecated `--attempts` and `--samples` spellings remain input aliases for
`--trials`; dispatcher retries remain separately controlled. Batch artifacts
add equivalence, logical-trial, occurrence, and one-controller-gate metadata.
Consumers must count at most one completed observation per logical trial and
must keep failed/parked trials outside the completed denominator.

`--workers W` is additive for scan batches. Every immutable plan records the
requested/effective worker counts and the shared resource-claim decision.
Automatic or unresolved task selection stays single-worker; CodeQL database
and cpg-rs graph users name their workspace-exclusive resource and stay
single-worker. Explicit read-safe tasks may use up to eight detached campaign
children (and never more workers than trials). The controller publishes one
atomic `gate.json` after reporting/SARIF, before applying the final exit code.
Each child publishes `batch-equivalence.json` after recomputing the frozen
worktree/config/model/scope/engine key at scan consumption. The gate binds the
logical terminal state, safe-fold blocking set, and final SARIF digest, so a
later report refuses stale controller output.
Operationally incomplete dispatch remains code 1 even when completed trials
also contain a blocking finding; code 3 is reserved for an otherwise complete
batch gate failure.

Finding identity adds a conservative `basis` and descriptor-backed
`identityFold=legacy|safe|aggressive`, `identityReconcile=auto|off`, and
`modelDedupe=off|manual|auto` controls. The shipped default fold is `safe`;
file-fallback identities still require matching source signature or dedup key,
and attack-chain findings remain fingerprint-keyed. Existing findings remain
readable and derive a conservative basis when the persisted field is absent.
Run `kuzushi findings identity-audit --target <root>` before changing any
workspace policy to aggressive reconciliation or automatic model dedupe.

Review readers now include finding-local decisions on the exact observation
they address, even when that observation has a durable identity. These records
do not propagate to other generations. Policy-aware lists use the latest
observation, preserving source/evidence history, rather than choosing an older
observation for its severity or proof rank. Existing finding and decision
formats remain readable without rewriting them; the exhaustive generation
reader keeps its prior sort order. Human-over-automated review priority and
identity-fold policy are unchanged.

`triage:run` now adds source snapshot/tree hashes to its result and marks source
changes during work as partial without erasing classifications or spend.
Completed historical Review attempts lacking this receipt require an explicit
fresh run before reuse. No model, runtime, or reconciliation default changes.

Optional PromptArmor, Shinsa, Trail of Bits, and Vuln Scout packages are no
longer bundled or auto-discovered from `node_modules`. Configure an adapter
explicitly or load it as an approved KWP integration. This prevents development
dependencies from silently changing the operator and LLM discovery surfaces.
Keep those packages out of both `dependencies` and `optionalDependencies`;
`pnpm verify:pack` rejects their accidental reintroduction, including Git URL
dependencies that would make a fresh npm install depend on GitHub availability.

## Structural producer identity migration (unreleased)

`dep-hygiene`, `cargo-audit`, and `iac-scan` used to fingerprint a finding by
tool, rule, and file only. Every issue of one rule in one file therefore
landed in a single stored row: fifteen risky specifiers in one `package.json`
became one finding with `corroboration_count: 15`, and six public-ingress
blocks in one Terraform file became one finding. These producers now emit a
discriminating identity input:

- `dep-hygiene` records `symbolLocator` `<manifest>#<package>` (for example
  `package.json#neostandard`) and `cargo-audit` records
  `Cargo.lock#<crate>@<version>`. Both mint the strong `source_locator`
  identity basis, so rescans of the same dependency corroborate one identity.
- `iac-scan` keys Terraform `key = value` statements inside labeled blocks by
  their block path (for example
  `aws_security_group.alb.ingress[1].cidr_blocks`), also recorded as
  `symbolLocator`. Other IaC findings are keyed by their exact line and keep
  their existing weak `file_fallback` identity.
- `IacScanFinding` gains an optional `locator` field in tool JSON.

Existing durable identities, rows, and review decisions are not rewritten, and
no `FindingRekeyed` edge is written: a one-to-many split has no unambiguous
target, and a decision made about a merged row cannot be attributed to any one
of the issues it absorbed. On the first rescan, each distinct issue mints its
own identity (new fingerprints and the new locator make the merged identity
ineligible for exact-fingerprint or dedup-key reuse). The merged identity is
no longer observed, so the deterministic rescan reconciler marks it stale.
Re-review split findings that previously inherited a decision from the merged
row.

`sast:scan` `data.findingsCount` and `data.coreFindings` now use the same safe
identity fold as `--fail-on` and scan-scoped SARIF instead of collapsing every
observation that shares a durable identity. Weak `file_fallback` identities,
such as one secret repeated on identical lines, stay distinct per source
signature. `data.observationsCount` and the `kuzushi scan --json`
`observationsCount` field are additive; the summary line reads
`N distinct finding(s) from M observation(s)` only when the two differ.

## Run status vocabulary migration (unreleased)

The public run-artifact vocabulary additively includes `"blocked"` and
`"canceled"` in `run.json`, typed `items.jsonl`, `failures.json`, CLI status
filters, and terminal projections. `"blocked"` means policy or validation
refused the operation before execution; it must never be projected as failed,
skipped, or completed. `"canceled"` means an operator or budget cancellation
request reached cleanup. `"interrupted"` remains readable and is reserved for
watchdog escalation, process loss, and abnormal shutdown. `events.jsonl` is a
non-authoritative compatibility diagnostic, not a terminal-status ledger. No
existing artifact is rewritten, and readers that already tolerate unknown
additive status values require no data migration.

## Typed run-lifecycle cutover (unreleased)

New runs write `runs/<runId>/items.jsonl` as the sole authoritative execution
lifecycle. The former diagnostic trace stream and its compatibility reader were
removed before release. `events.jsonl` remains only for non-authoritative
run-start and recovered-interruption diagnostics; replay never reduces it.
Verify live/replay/plain/JSON projection equivalence and document the minimum
reader version. Never add lifecycle fields to the current `run.json` or
workflow-v1 wire shapes because older readers deny unknown fields.

Phase-attempt records keep their workflow-v1 shape while additively admitting
the serialized outcome `"blocked"`; workflow-v2 persists the same truth as
`RunItemStatus::Blocked`. This is emitted only for policy refusal, remains
unselectable, and is dual-written without rewriting old attempts. Older Kuzushi
binaries whose closed workflow-v1 enum predates `"blocked"` cannot read those
new lines, so upgrade every reader before sharing a target written by this
release. The minimum compatible reader version must be called out in the
release notes.

## Native dynamic-module policy migration (unreleased)

Local `file://` and path modules no longer become executable merely because
their specifier appears in `[operator].trusted_modules`. Before upgrading,
operators must run `kuzushi kwp approve <specifier> --grant <grant.toml>` for
each exact resolved bundle and retain the generated `kuzushi.lock`. Loading
rehashes the bundle, verifies its descriptor hash and optional Ed25519
signature chain, then runs it as a brokered KWP worker. Changed bundles require
fresh approval; revoked or mismatched entries fail before module code runs.
The old trusted-specifier list remains only for non-local compatibility forms.
The v0.1 KWP Node tier accepts one self-contained entry file. It requires the
permission-mode network boundary introduced in Node 25, adds a macOS network
sandbox, and requires Node 26.3.1 or newer on other platforms. Multi-file
directory bundles must remain on the legacy trusted path until a
content-addressed bundle format lands.

Trusted Node modules loaded with `--load` must now declare an explicit native
policy on every tool: `effect`, `approval`, `workspaceRequirement`, and a
concrete `phase` for effectful operations. `headless` remains mandatory.
Target-write, repository-execute, and external-action tools must use
`approval: "explicit"`. `repository-execute` is for repository-selected build
or test commands run in an isolated validation copy; it must disclose the
resolved commands before interactive dispatch.
Modules that omit this policy fail atomically during description, before any
tool is registered. This is an intentional fail-closed contract change; add
the fields described in `docs/modules.md` before upgrading an external module.

Dynamic descriptor options with `type: "path"` must now add a mandatory
`pathSemantics` value. This is a deliberate fail-closed migration: the host
does not infer whether an unlabelled path is a workspace read, Kuzushi state
write, target write, external read/write, or executable. Target-owned option
stores cannot supply model selectors or executable/external/write-capable
paths. Update modules and their tests before bumping the required Kuzushi host
version.
The native/Node bridge also performs a protocol-version and exact package
semver handshake, so custom `KUZUSHI_DYNAMIC_MODULE_HOST` implementations must
emit the documented version envelope/handshake before payloads.

The old `dispatch_prepared_tool_with_runtime(name, Value, ...)` API remains
source-compatible, but it now re-runs canonical preparation. New Rust callers
should use `prepare_dispatch_input` and
`dispatch_prepared_input_with_runtime`, which carry an opaque preparation
proof and avoid duplicate validation.

`codeql:create-db outputPath` and `cpg:build outputPath` are now confined to
the active target's `.kuzushi/` state tree. Before upgrading, move any custom
destination into `<target>/.kuzushi/`; destinations elsewhere are rejected
instead of allowing scanner subprocesses to overwrite operator or project
files.

Managed CodeQL databases now require a content-bound promotion receipt in the
operator-owned global state store. Existing target-only databases, including
legacy `.kuzushi/codeql-db` and `.codeql/db` layouts, are intentionally not
trusted after upgrade. Rebuild them with `codeql:create-db`; Kuzushi will then
bind the database contents, source commit, nested target scope, and language to
the operator receipt before any consumer can use the database.

The empirical Rust API `verify_finding` now requires an explicit
`workspace_root` argument. Custom callers must pass the same trusted target
root that owns the finding store. Rust/C finding paths are resolved below that
root with bounded, no-follow reads; absolute paths outside it, `..` traversal,
symlinks, and oversized source files now fail as infrastructure input errors.

## If a version is already published

npm does not allow republishing the same version. Choose a new version, update
the machine-owned version surfaces with the canonical bump script, and rerun the
candidate workflow. Publish only through a new immutable release tag.

## If a release tag is wrong

Do not move or force-update a release tag. Correct the problem in a new version,
pass the candidate gates again, and create a new tag for that version.

## Suppression primitive migration (unreleased)

A unified `SuppressionRule` primitive now backs all muting concepts. Notes:

- New durable store `<target>/.kuzushi/v3/suppressions.toml`. Absent file is a
  no-op, so existing workspaces are unaffected.
- The legacy `<target>/.kuzushi/v3/whitebox-suppressions.json` store is retained
  and compiled into the unified pipeline. `kuzushi suppress` now writes both.
  A later release may migrate whitebox records into `suppressions.toml` and drop
  the JSON store; no data loss in this release.
- No event-log or projection migration: the `SuppressionAdded` /
  `SuppressionExpired` / `SuppressionRemoved` event kinds and the
  `stable_findings.current_status` projection already existed. New payload fields
  are additive and ignored by old readers.
- `Finding.suppressed` is now hydrated from the projection (additive over any
  value stored in finding JSON). This lights up the pre-existing
  `status:suppressed` / `verdict:suppressed` filter tokens and the export
  `suppressed` column/SARIF `result.suppressions[]`.

## JVM Joern retirement (unreleased)

The JVM Joern integration is deleted. CPG evidence now comes from the
in-process cpg-rs engine (git-pinned `oxidized-joern` crates) — no Java, no
2 GB Joern install, no `joern-parse` subprocess.

- `kuzushi-mcp-joern` is gone; `kuzushi-mcp-cpg` replaces it (`cpg.*` tools,
  joern-compatible input schemas). `kuzushi mcp serve|health joern` is now
  `kuzushi mcp serve|health cpg`.
- The `<target>/.kuzushi/cpg.bin` artifact is obsolete. Graphs live under
  `<target>/.kuzushi/cpg-rs/<lang>.v<shape>.cpg` and build implicitly in
  seconds; `cpg:build` prebuilds them and no longer accepts `heapMb`.
- `taint-iris-next` `backend=joern` is a retired alias: it redirects to
  `backend=cpg-rs` with a warning. Rename saved configs to `cpg-rs`.
- Retired env vars (now ignored): `KUZUSHI_JOERN_BIN`, `KUZUSHI_JOERN_CPG`,
  `KUZUSHI_JOERN_TIMEOUT_SECS`, `KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS`,
  `KUZUSHI_JOERN_FLOW_SCRIPT`, `KUZUSHI_JOERN_DEBUG_LOG`, `JOERN_SERVER_URL`.
- Language coverage change: Kotlin, C#, PHP, Swift, and bytecode targets have
  no cpg-rs frontend yet and fall back to codeql/structural evidence. cpg-rs
  covers c, cpp, go, java, javascript, python, ruby, rust, scala, typescript.

## Review-session recording (unreleased)

Prospective review sessions are recorded so a later evaluation can ask whether
a trained model would have helped. All three changes are additive; a workspace
that never sets `--review-yield-shadow-model` produces none of them.

- New event kind `review-session-started`. Old readers ignore unknown kinds, so
  a log containing it replays unchanged on an earlier build; a build that has
  the kind but no `review_sessions` table simply projects nothing.
- New projection table `review_sessions`, created by
  `create_projection_schema` on every open (`create table if not exists`), so
  legacy databases gain it without a `migrate_*` step. Projection is keyed by
  `event_hash` and is replay-idempotent.
- New additive column `review_decisions.review_session_id`, added by
  `migrate_review_decision_session_column`. Deliberately **not** backfilled:
  decisions taken before sessions existed genuinely have none, and inventing a
  link would fabricate the measurement the column exists to make.
- `DecisionWrite` gains `review_session_id: Option<String>`, emitted as
  `reviewSessionId` in the `triage-decided` payload. Existing projectors read
  named keys, so old and new events coexist.
- `--review-yield-model <path>` and `--review-yield-mode <shadow|visible>` are
  an interim operator mechanism and a stopgap. They replace the earlier
  `--review-yield-shadow-model`, which was never released; there is no
  compatibility alias, because a flag that implied a mode is exactly the
  guess this pair exists to refuse. Both are shell-only, both are required
  together, and both will be replaced by a `[review_yield]` config section
  with no compatibility shim.
- `--review-yield-mode visible` adds one advisory section to the finding
  detail. It changes no ordering, no filter, no stored artifact, and no other
  displayed value; `shadow` remains silent.


## Trace cost-result migration

Consumers of `trace:expand` results should replace the legacy
`data.costUsd` + `data.costUsdExact` pair with the shared cost contract.
`costUsd` is present only for exact metering; otherwise read
`observedCostUsd` and `providerSpendUnresolved: true`. Do not interpret an
absent exact total or an observed zero as a free call. Both the top-level
result and its `data` object carry the canonical fields. Existing run
artifacts are retained unchanged.

A zero-step Trace result is a valid completed outcome. Preserve its questions
and evidence notes independently of appended step counts. New results include
source snapshot/tree identities; older results without those identities are
shown with that limitation. The reader requires a call-correlated result
receipt for complete-result recovery and reports unverifiable history rather
than silently using it as current evidence.


## Phase-result descriptor migration

`ToolDescriptor` adds `phase_result`, defaulting to `true`. The default is
omitted from serialized descriptors, preserving the identity of unchanged
tools. Rust callers using struct literals must initialize the field; descriptor
builders can use `without_phase_result()` for supporting-evidence tools.
`trace:expand` opts out. Its Prove authorization phase, workspace-write effect,
model requirement and normal JSON output remain intact.

New workflow writers reject known supporting-evidence-only attempts and their
selection. Recovery removes those attempts from the selectable phase projection
while retaining raw v1/v2 events and canonical run history. Unknown historical
tools retain existing validation and visibility. This migration does not accept,
discard, delete or rewrite old attempts and does not select another proof.
The package/file module manifest schema is unchanged.

### Revision comparison disclosure

Run comparison adds `baseSource`, `compareSource`, and `absenceCoverage` to CLI
JSON. Existing classification fields remain compatible. Source metadata includes
the complete recorded Git SHA, branch, dirty state, and available indexed-content
and snapshot hashes. Legacy hashes remain unknown; a dirty flag alone does not
identify a working tree. Hash equality does not establish complete scan coverage.

The shell and CLI use the same coverage check to separate absent findings covered
by a completed engine receipt from findings that were not reassessed. Missing or
partial receipts, missing finding snapshots, and out-of-scope paths cannot prove
absence. Nondeterministic absence never changes a finding's verdict or establishes
a fix. Existing deterministic reconciliation remains a separate compatibility
classification; this change does not add a human-confirmed fix workflow.

### Investigation briefs (unreleased)

`campaign:brief` adds bounded read/save of operator intent through the shared
prepared-dispatch boundary. It is operational, runtime-free, auxiliary and
workspace-scoped. Existing `engagement:aim` compatibility behavior is unchanged.

Accepted brief revisions use existing content-addressed blobs and immutable
target-local revision references. A small head pointer selects the current
revision for inspection. Text is limited to 8192 UTF-8 bytes; serialized
documents to 16 KiB. Saves require the current revision, acquire a cancellable
per-brief lock and refuse overwriting existing revision ordinals. Reading an
exact revision does not require changing an active threat model.

`campaign:study` and `campaign:context-study` add optional `briefRef`. Single,
scope and context-matrix plans retain the authenticated full revision in
`investigationBrief`, covered by the existing plan digest and approval. Plan
reads authenticate this metadata against the immutable object and published
reference. Later edits do not change frozen jobs. Brief selection alone inserts
no text into scanner/model prompts and changes no finding verdict.

`campaign:context-study` adds `useBriefGuidance` (default false). Explicit true
requires `briefRef` and supports inactive repository/file-group context builds.
The declared child option `threat-model:build operatorBriefRef` supplies the
exact reviewed text as priorities/questions and requires a fixed approved
investigation work item at shared dispatch. Whole text remains bounded to
8192 bytes. Context provenance adds `operatorIntent` with its actual reference,
byte count and non-evidence purpose. Source, model, scope, scan conditions and
finding decisions are unchanged. Existing receipts gain optional
`briefGuidance` only when selected; old JSON remains compatible. Rust callers
constructing `ContextStudyReceipt` must initialize the new optional field.

Study, scope and matrix report receipts add optional `investigationBrief`,
omitted when absent. Existing JSON without briefs remains unchanged. Rust
callers constructing report structs directly must initialize the new optional
field; summary struct literals additionally initialize the borrowed optional
reference. Public manifest and module naming contracts remain unchanged.

Context readers add the auxiliary `data.goalState` receipt. It authenticates a
recorded immutable goal reference and text, while retaining
`modelUseVerified=false`. This read cannot independently prove producer model
use, including for imported provenance. Missing guidance leaves the original
context readable. Reports add auxiliary `scope.contextGuidance` and matrix
`scope.caseContextGuidance` fields, with one exact context receipt per case.
No Rust report struct field, dispatch option or stored context format changes
are required. Historical unbound inputs and explicit context omission remain
distinct and never read the current active context.

New root-context matrices add optional `omissionScopeSha256` to
`FrozenContextCase`. It records the comparable discovery scope for explicit
context omission. Shared approval authenticates this projection against the
selected context's root lineage and current scope. Existing condition keys,
job inputs and single/scope-study plans are unchanged. Historical cases without
the field retain their previous comparison behavior; no frozen plan is
rewritten. A root/omission experiment without that receipt needs a new approved
matrix. Rust callers constructing `FrozenContextCase` initialize the optional
field. Scoped or stale context lineages cannot acquire a root projection.

### Bounded secret inspection (unreleased)

`secret-scan:scan` adds `maxEntries`/`max_entries` and
`maxTotalBytes`/`max_total_bytes`, defaulting and capped at 100,000 entries and
512 MiB. Traversal is iterative and cancellable. Reads are contained and reserve
their conservative upper bound, including a growth-detection byte. Finding,
entry, content and per-file caps now produce partial receipts with explicit
coverage gaps; retained findings and mid-scan observations are not discarded.
The existing Scan adapters forward those gaps and share aggregate ceilings.
The tool remains a signal detector with no credential-validation request.

`SecretScanOptions` gains `max_entries` and `max_total_bytes` fields. Rust
callers can use the existing default update syntax. `SecretScanReport` gains
optional `inspection`; direct constructors initialize it. Its additive
`SecretScanInspection` records version 1 limits, traversal count, conservative
content reservations and exclusions. Old serialized reports without this
field still deserialize. Module names, finding identities, raw observations,
manifest schema and public compatibility aliases are unchanged.

### Native secret settings in finite scans (unreleased)

`sast:scan` adds four optional limits: `secretScanMaxEntries`,
`secretScanMaxTotalBytes`, `secretScanMaxFileBytes` and
`secretScanMaxFindings`, each with a snake-case alias. Preparation rejects
these settings when secret scanning is not selected. Existing native per-file
and finding defaults remain unchanged. A prepared job now shares entry,
content-read and finding limits across its roots instead of resetting them
for each root. Separate approved passes still receive separate job limits.

The SAST result adds `data.nativeInspections` and readable inspection receipts.
Each record retains original configured limits and cumulative consumption;
missing accounting stays unavailable. Existing result fields remain intact.
`ScanEngine::inspection_receipts` has an empty compatibility default, so
existing external implementations need no change. The unit
`SecretScanScanner` constructor remains available. Its findings-only interface
now refuses an empty result with coverage gaps, consistent with the aggregate
interface's existing honest-coverage contract.

Finite studies whose every attempt is partial now produce a reviewable partial
Scan result when persisted run receipts agree. Retry-exhausted queue jobs remain
failed and completion counts remain zero. The operator must explicitly
acknowledge partial coverage before Review. Unreadable receipts cannot supply
partial acceptance. Existing selected results and raw observations are retained.

### Stored architecture reader (unreleased)

`x-ray:read` retains its report fields and four artifact references, adds a
declared `target` option and opts out of phase results. Reading stored reports
cannot create accepted Map evidence. Direct library calls without a target or
workspace now fail instead of substituting the process working directory.

All four files are contained regular artifacts with an 8 MiB limit per file;
oversized architecture SVGs now refuse the read. Markdown decoding remains
strict UTF-8. The reader does not assess graph semantics or source freshness.
Cancellation is checked before and after bundle IO; this is not a guarantee of
interruptible individual filesystem reads.

`data.readProvenance` adds explicit unknown generation spend, producer runtime,
model and context, unassessed source freshness and zero reader provider calls.
`data.costUsdExact` is false for stored-report reads. The compatible numeric
zero does not establish the original generation cost. The separate current
reader operation still reports its known zero provider cost. Original tier and
count fields remain recorded report claims, with readable labels and warnings.
No finding decision, severity or confidence is changed by a report read.

### Fleet observation history (unreleased)

Fleet ingestion adds a separate derived observation-history projection. Current
`fleet:findings` rows keep their existing schema and latest-finding behavior;
authoritative per-target findings stores and observations are unchanged. Rebuild
an older corpus with `fleet:ingest` before requesting revision comparisons. An
older corpus remains readable through `fleet:findings` but cannot establish
recorded observation history. A skipped target cannot be compared.

`fleet:diff-findings` reads only the selected target and two recorded SHAs. The
new `maxRows` option defaults to 10,000 and accepts 1 through 10,000. Larger
comparisons or more than 8 MiB of comparison payload fail without returning a
truncated comparison. Ingestion refuses an individual target with more than
10,000 observations or 8 MiB of observation payload; other readable targets can
still be ingested, with a partial outcome and explicit skipped-target warnings.
These are per-target limits, not a global Fleet resource guarantee.

Legacy JSON `lead` values `branch-delta`, `backport-gap` and `both` remain.
Entries add `presence` (`head-only`, `base-only`, `both`),
`matchBasis: source-proximity-group` and `fixStatus: unassessed`. Nearby source
locations are uncertain matches. Observation presence does not establish
introduction, repair, complete coverage or equivalence of scan conditions.
SHA-only Fleet comparisons do not distinguish dirty content or context changes;
the investigation run comparison remains the detailed provenance surface.

All five Fleet tools are operational auxiliary actions with `phase_result`
false. Their execution does not produce accepted Map evidence. Exact tool names,
public aliases, headless dispatch and the compatible `allowanceRef` input remain.
`fleet:findings` now validates its row limit as 1 through 10,000. Scorecards say
critical/high records; legacy JSON count names remain compatible and do not
represent actionability decisions.

### Guided investigation navigation

The default shell journey now stops at Review and offers Report once all ledger
findings have decisions. Normal phase navigation presents Map, Scan, Review,
and the separate Report surface; Report is reachable with Navigate `r` or
`Shift+Tab` from Review. `Esc` restores the exact origin, including a focused
finding's zoom, scroll, and composer draft. `workbench.report` supports keymap
overrides. The Review planner's right arrow uses the same Report entry.

The persisted `WorkflowPhase` enum and its legacy aliases/order are unchanged.
The added `INVESTIGATION_ORDER` defines only supported guided progression.
Historical Prove/Fix attempts remain stored and available through explicit
compatibility views but no longer redirect the default journey. `BuildReport`
is retained for saved-plan decoding and removed from offered phase tasks because
its executor declares the separate Report surface. Module/manifest and artifact
schemas are unchanged. Review queue guidance no longer suggests patch work from
a finding's proof level.


The scope edit union additionally accepts `include-path` with `path`, which
removes exactly one recorded exclusion rule. The whole-repository edit now
preserves explicit exclusions and their reasons. Integrations that intentionally
restore omitted files should use explicit inclusion and accept the resulting
revision. Older version-1 scope records remain unchanged and readable. Rust
callers with exhaustive `ScanScopeEdit` matches must handle the new variant.

The scope edit union additionally accepts `exclude-path` with `path` and `reason`.
It uses the same inventory validation and acknowledgement contract as scope
exclusion. The shell adds `scopes`; existing tool dispatch and scope artifacts
retain version 1. Scope review and acceptance do not compile or start scan jobs.


`pack:scopes operation=latest` is additive and returns `data.review` (saved review
or null). Existing operations and version-1 scope/tree/snapshot formats remain
compatible. Source hashing and blob indexing replace recursive traversal with
one guarded iterative walker and add a 1,000,000-entry ceiling. The producing and
verifying walks retain identical source membership and hash serialization.
Targets beyond a safety ceiling fail without claiming a complete identity.
Source reads use bounded cancellable chunks and aggregate byte limits apply to
actual captured bytes, including growth during a read. Public per-file identity
observer callbacks retain their existing frequency.

The shell study form adds **Discovery engines** before Source and context.
Existing keyboard automation selecting later rows must account for this new
row. The picker edits a study-local `taskMode`/`tasks` draft through the shared
scope capability check. No tool names, options or persisted formats change.
Applying identical choices keeps the saved plan; changed choices require a new
plan while retaining investigation accounting. Unsupported saved choices remain
removable, and exact source/dependency/allowance admission remains in prepared
dispatch. This surface does not establish scanner usefulness or complete the
multi-scope/model-backed monorepo workflow.

The same picker offers an explicit local repair when stored `paths` conflict
with an accepted `scanScopeRef`. `x` clears filters in the draft, `a` applies and
Esc cancels. An empty local `paths` list overrides the old stored value without
changing global settings. Applying this change invalidates the study plan while
retaining source/context identity and investigation accounting. No new option or
persisted format is introduced.

OAuth client construction now rejects expired or malformed stored expiry after
a failed refresh. Credential files keep their existing shape; the `expires`
field already required by Rust readiness checks is now enforced by the bridge.
No fallback model, provider or API-key client is selected. `maxOutputTokens`
keeps its option name and default; its description and the context planning
surface distinguish the request from an enforceable output-token ceiling.

Campaign snapshots retain an explicit dispatcher reason first. When absent,
terminal job failures may project a bounded, redacted error from the matching
run metadata. Unrelated tools and live runs cannot supply this reason, and
reading it does not repair or rewrite metadata. Finding-count reads now use the
shared bounded artifact reader and reject escaped run references. Snapshot
fields and stored queue/run formats remain compatible.

Repository-index chrome now names its artifact separately from accepted
threat-model context and retains stale/unverified states. Summary preserves
reading space in small terminals, sizes wide descriptions from wrapped content,
and pages using shared reading geometry. Session-cost copy distinguishes the
current shell's dollar cap from prior investigation usage. No persisted format
or public tool input changes accompany these presentation fixes.

### Findings page queries

`findings:list` adds descriptor-backed `cursor`, `anchor`, and `order` options.
The default order remains `ledger`; `confidence` orders the complete matching
set before selecting a page. Each returned page is capped at 500 rows. Existing
`data.count` and `data.findings` remain available, with additive `data.page`
metadata containing offset, loaded/total counts, order, ledger watermark,
next/previous cursors and parallel finding anchors. Machine offsets are zero
based; interactive ranges are one based.

Cursors are opaque, versioned continuation values bound to the target, query,
policy, ledger revision, matching identities and relevant run metadata. Reuse
the same options with a returned cursor. Changes require a fresh first-page
request rather than silent continuation. Anchors identify a finding in the
active workspace and allow an updated query to keep that finding in view.
Supplying both a cursor and anchor is an error. Existing report/artifact formats
and `FindingListReport` stay compatible; the page API is additive.

### Campaign Stop and interrupted source receipts

The Campaign deck's `K` action now requests Stop from the dispatcher launched
by this shell. It retains the child handle while supervised jobs settle and
partial work is saved. Repeated requests are bound to one dispatcher session;
old requests cannot stop a later launch. Reservations remain in the shared
allowance and incomplete provider charges stay unknown.

New SAST runs persist a call-scoped `source-start-<itemId>.json` artifact before
model work. The updated lifecycle reader accepts this specific source artifact
from its running SAST producer while retaining terminal-only rules for other
artifacts and canonical results. Interruption recovery authenticates the host's
result against the root call. Nested engine results remain absent when they
were never produced. Source reuse verifies the start reference and indexed
content-store objects; changed artifacts fail closed.

Use the updated reader for these new lifecycle records. Existing records keep
their original meaning. Historical interrupted runs without authenticated
start-source or result references are not retroactively rebound or declared
current; inspect them as historical evidence and prepare a fresh plan when
current-source acceptance is needed.

### Reversible finding relationships

`triage:dedupe` now records proposed duplicate relationships by default. It
preserves finding identities, raw observations and finding verdicts. Consumers
should use the additive `relationshipsProposed` and `relationshipIds` fields;
`linked` and `verdictsRecorded` stay zero for this path. `dryRun=true` records
neither proposals nor decisions. The explicit advanced `legacyRekey=true`
option retains the old rekey and duplicate-verdict behavior for compatibility.
Existing historical rekeys keep their meaning and are not undone by this API.

`findings:relationships` reads bounded pages. `findings:relationship` records
`accepted`, `rejected` or `removed` with a required reason and exact
`expectedRevision`. Decisions append versioned `finding-relationship-v1`
metadata through the existing audit ledger. Old readers retain these generic
audit events. Updated readers expose endpoint identities and recorded runs;
human review does not rebind a relationship to later source.

JSON, JSONL, SARIF properties and Markdown bundle manifests add relationship
metadata separately from finding verdicts. CSV columns and external scanner
exports remain compatible and declare that relationships are omitted. The TUI
`relationships` reader, also reachable with `L` from Review, offers proposal
acceptance, keeping observations separate and unlinking with a reason. Its
editor preserves the shell composer and returns failed saves to the note draft.

### Atomic relationship review batches

`findings:relationship-batch` adds a bounded operator review action for one to
fifty exact relationship objects returned by the reader. `relationships`,
`state` and a required `note` use shared prepared dispatch. Full captured
records and revisions are checked again under the existing writer lock.
Acceptance additionally requires the recorded observation endpoints to remain
current. Explicit rejection and unlinking can retain historical endpoints.

Each batch is one `diagnostic-recorded` envelope with subject
`finding-relationship-batch-v1` and versioned `details.records`. Existing
single-relationship events remain unchanged. Readers combine both namespaces;
projection replay restores the entire batch. No finding identity, observation,
verdict or phase-completion field changes.

Migration: upgrade all ledger readers and writers together before using the
new batch action. Builds without this action ignore the batch namespace and
cannot accurately review its relationships. Existing events need no rewrite;
the single-relationship tool remains supported. Keep an upgraded reader when
exporting or continuing a ledger that contains batch decisions.

The TUI uses Space to select, `*` to select the current page, `c` to clear and
`A` to review a captured selection. Pair review, the reason editor and final
confirmation have separate input ownership. A stale selection requires explicit
refresh and review; it never silently rebinds.
Pair review also opens either endpoint's exact finding generation. `G` restores
the captured selection, pair, source side, scroll and shell draft after inspection.

### Source-bound finding group reader

`findings:groups` adds bounded group and member pages over accepted duplicate
relationships. Filters and selected `runIds` apply before grouping. `groupId`
or a nonzero `offset` requires the returned string `expectedRevision`.
The revision binds the target and grouping data; unrelated read receipts do
not invalidate it. `ledgerWatermark` remains an informational receipt. Changed
observations or relationships require a fresh first page. Variants and uncertain
matches remain separate, and group count is independent from finding count.

The additive `selectedRunIds` page field records the selected parent and engine
references. Each member's `matchingRunIds` names its recorded observations in
that selection, while `runId` continues to name the displayed current ledger
observation. Run selection filters history; it does not choose a historical
source snapshot or carry a finding verdict to another revision. Older readers
can ignore these fields, and missing fields deserialize as empty lists.

The shell `groups` command and Review `G` open the existing relationship surface
in group mode. Opening a member and returning preserves its page and selection.
Existing individual Review, artifact formats and verdict contracts remain.
`generation:<positive-id>` is an additive exact observation lookup accepted by
shared finding reference services. It preserves that generation's recorded run;
ordinary fingerprint, prefix and positional alias references keep their meaning.

### Bounded pack inspection and legacy scope discovery

`pack:lint` adds descriptor options `maxWalkEntries` (default/ceiling 100000),
`maxBytesPerFile` (default/ceiling 8388608) and `maxReadBytes` (default 67108864,
ceiling 536870912). Values must be positive. Document reads and iterative
pack/target walks share their respective allowances. Symlink and unavailable
entries are omitted explicitly; failed reads retain conservative reservations.
The additive `data.coverage` receipt distinguishes complete inspection from
partial work and never asserts repository scan coverage. Missing active targets
leave shard existence/count checks partial. Schema errors still fail the tool.

Migration: ordinary pack and shard formats, option aliases and public
`lint_pack` remain unchanged. Oversized documents previously accepted by
unbounded reads now fail; split those documents or use an explicit supported
allowance. Consumers should preserve partial receipts and their limitations.
`pack:suggest-shards` is Compatibility in default discovery, with exact dispatch
and legacy optional scope materialization preserved. Modern reviewed proposals
use `pack:scopes`. Both lint and legacy suggestion retain Map classification
but no longer own phase-completion results.
