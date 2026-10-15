# Kuzushi modules

Goal relevance is an explicit operator assessment, separate from finding
validity, severity, confidence and Review completion. Open `goals [brief-id]`
in the shell, or press `G` in Review navigation. The browser covers workspace
findings and does not inherit the ordinary finding filter or selected study.
It shows the exact saved brief, fifty rows per page, a relevance filter and
the recorded observation receipt. `?` lists its controls. `1` to `4` choose
Direct, Related, Outside goal or Uncertain; `u` clears an assessment. Add a
reason, use Ctrl+S to inspect the replacement, then Enter to save.

`findings:goals` exposes the same read surface headlessly, including exact
`briefRef` reading and generation-specific history through `findingId`.
`findings:goal-assess` requires that published reference, the exact observation
`basis`, `relevance`, `reason` and `expectedRevision`. Both use prepared
dispatch and require no model. Assessments bind one finding generation and
observation, not the current checkout. Other source revisions need independent
review. `r` refreshes the same brief; `R` explicitly opens its latest saved
revision. Older assessments never carry automatically into a new brief.

Assessment reasons remain session-only until saved. Back, target switches and
brief switches retain them in the running shell; Quit discloses their presence
without printing their text. Conflicts retain the reason. Refresh and explicitly
select the assessment again to review the current revision before replacing it.
`h` reads recorded history. JSON/JSONL, SARIF, Markdown bundles and external
finding exports include the assessment history separately from finding verdicts.
CSV explicitly lists this history as omitted. Clearing records another revision;
it never deletes the history or resolves a finding.

Plan approval begins with a compact overview of the frozen workload and its
recorded execution models. Current accounting and spending limits precede scope
and context receipts. All distinct models remain visible; missing model records
are disclosed. Detailed conditions, resource estimates and exact references stay
in the same review document and in exhaustive plain output. Approval still needs
an explicit decision at the end of that document and starts no jobs. Cancellation
preserves the study's proposed limits and navigation origin.

Model-backed forms retain their own plan and recovery contracts. Back offers
Stay or Discard when question text, scope-proposal inputs, Review changes or
call limits would otherwise be lost. Unchanged Review tasks can return to their
existing queue. Discarding an embedded context-generation draft keeps the scan
study; discarding regeneration guidance returns to the same context editor.
Recorded plans, findings, human decisions and spending remain intact.

Quit names session-only model inputs, including retained Setup, workflow and
lesson drafts, without showing their text. Raw generation guidance is not a
recoverable discovery checkpoint. Preparing a plan saves its exact inputs;
allowance choices become durable through separate explicit approval. Back,
Stay and Discard make no provider request and grant no authorization.

Changed ordinary discovery-study settings and unaccepted goals use the same
private study checkpoints as context cases. Reopen `scan batch` and explicitly
choose a draft. Recovery preserves options, pass and worker counts, budget
choices, exact context and prior goal revision. Interrupted goal saves return
to review. A newer accepted revision requires reload and review before saving
the recovered text. The local checkpoint approves no work or spending. Failed
writes offer Stay or Discard; accepted artifacts and accounting remain intact.
Earlier private version-1 files remain readable with the optional `briefDraft`
field absent. Other workflow kinds retain their distinct orchestration.

Unprepared context-case studies use private local checkpoints when durable
shell recording is available. Reopen `scan batch`, select the saved draft and
press Enter to restore choices. Names and partial field cursors, baseline,
passes, immutable context references, discovery options and investigation
identity are retained. Exact context objects are checked in a background
reader and spending is read from the existing ledger. Restoring starts no jobs
and grants no allowance. Prepare a fresh plan, inspect source and context, then
approve its allowance. An unavailable spending ledger blocks approval rather
than resetting consumption. Back can leave acknowledged saved choices; Quit
distinguishes recoverable drafts, pending writes and session-only edits. Fully
acknowledged choices retain normal idle exit; reopen the study to recover them.
Version-1 `.kuzushi/v3/study-drafts` files are outside transcript and target
artifact discovery. Preparing a plan saves its work conditions; proposed call
and attempt limits remain checkpointed until matching approval saves them.
Partial numeric editors are retained too. Recovery restores choices for fresh
review and reads the existing ledger, without restoring work authorization.
Explicit case clearing resolves only the cleared choices; other drafts remain.

Manual context-copy editing has private local checkpoints when durable shell
session recording is available. They preserve text, cursor and selected field
under the operator's `.kuzushi/v3/context-drafts`; they are excluded from
transcript discovery and automatic target context. Inspect the same exact
context and open its editor to choose a saved draft. Recovery accepts no context
and approves no work or spending. Normal copy saving still uses prepared
`threat-model:revise` dispatch. The editor shows pending, saved and failed local
writes; recording-disabled editing stays session-only. Explicit discard resolves
the adopted checkpoint, while independent later edits remain recoverable.

Repository inventory preserves safe files when a tracked member becomes a
symlink, disappears, or is no longer a regular file. Its omission and partial
coverage are recorded before scope planning. On Unix, directory enumeration and
file reads remain attached to the opened repository root and refuse symlinked
components. Directory collection checks cancellation between entries. Metadata
and content inspection share an opened file and the read cannot exceed the
reserved byte prefix. The 100,000-entry, 512 MiB overall inspection and 256 KiB
per-file limits remain. Unix root replacement aborts publication. Inventory collection and
deterministic scope drafts make no model requests.

An incomplete `context:build` returns a partial receipt and its actual limitation.
It does not report a completed inventory or assume every omission was caused by
a size cap. Safe snapshot material remains inspectable. Explicit source repair
and rebuild produce a separate later receipt; prior results remain historical.
This supporting action does not complete Map or accept context automatically.

`/plan <goal>` opens a fixed workflow-proposal study. Review the goal, optional
Map/Scan/Review boundary, selected model and shared allowance before preparing,
approving and launching it. `/plan` reopens a kept session draft; durable jobs
remain in Campaign history after restart. The Labs `planner:propose` tool performs
one request with no tools, delegation or output repair. It proposes only declared
Core investigation options and actions. Missing choices remain visible questions.
Proposal spending does not authorize the proposed actions or new model work.
Action review checks the original source, target, model and capability contract.
Malformed output retains its raw response and cost as partial work. Responses
above 128 KiB disclose omitted content. The tool requires a frozen
proposalConfigSha256 and fixed allowanceRef from `campaign:context-study`, with
generationTool set to planner:propose. It cannot complete Map. Public historical
proposal readers remain supported.

Finding presence and stored scan IDs contribute review counts, not Map/Scan
completion. Legacy phase inference requires a compatible completed run receipt;
partial or auxiliary observations remain readable without advancing the guided
journey after restart. Modern phase attempts still require explicit acceptance.

Campaign Stop records operator cancellation separately from unexpected
interruption. It reaps the owned job processes, closes unfinished lifecycle
activity and retains consumed attempts and unresolved provider reservations.
Retry approval and call-allowance approval remain separate. A completed study's
Scan receipt references each trial's final successful run. Earlier canceled or
superseded attempts remain in its queue, raw findings and investigation report;
partial receipts retain every attempt reference. Report readers authenticate
either the exact final-run set or the legacy exact full-attempt set. An arbitrary
subset cannot stand in for a selected investigation.

`campaign:status` keeps `attempts` as the current retry counter and adds
`dispatches` for the recorded lifetime attempt count. Legacy or contradictory
lifetime counts are null. Resuming work does not refund consumed attempts.
Batch recurrence uses the final run of each completed logical pass; all raw
attempt observations remain available, including candidates seen in no completed
pass. Recurrence changes do not change finding verdicts or clear severity gates.
The campaign's `o observations` action explicitly selects its batch Review scope;
`batch clear` returns Review to workspace history.


`codeql:create-db` and `codeql:scan` keep exact dispatch as Labs, auxiliary Map
and Scan actions. Database creation retains explicit repository-execution
authorization and its isolated checkout. It records the source commit and
target scope; a database artifact does not complete Map. Automatic language
selection now uses the bounded repository inventory and refuses a partial
inventory until an explicit language is supplied. dbPath scanning requires a
managed database below the target's .kuzushi directory with matching source,
content identity and operator promotion receipt. Raw paths no longer bypass
those checks. Query observations remain partial and cannot complete Scan.
threads defaults to one across shared and direct engine construction; threads
and ram reject overflow instead of clamping. Selected command deadlines also
reach language resolution. RAM is a requested CLI allocation, not an OS ceiling;
whole-job authentication and work bounds remain unqualified. See the
[CodeQL module audit](assessments/codeql-module-audit-2026-10-14.md).

`android-apk:scan` retains exact dispatch as Labs, auxiliary Scan with explicit
target-write authorization. Its finite internal stages consume the selected
preparation options, including timeout and executable selectors. jadxBin,
apktoolBin, unzipBin and semgrepBin are declared paths; snake-case aliases remain.
includeLibraries reaches bundled code rules. timeoutMs is one to 86,400,000,
default 600,000, per subprocess. maxApkBytes bounds archive identity inspection
from one byte to four GiB, default 512 MiB. Successful preparation retains a
version-one inputReceipt with archive bytes and content digest; the pipeline
rechecks it after scanning. These checks do not authenticate decompiled source
or prevent concurrent output-generation races. Partial code errors and prior
observations remain visible; skipped scans cannot establish complete coverage.
Failed preparation names its cause in shared result text. Exact hidden tools
and historical receipts remain available. See the
[APK pipeline audit](assessments/android-pipeline-audit-2026-10-14.md).

`recon:nmap`, `recon:subdomain` and `recon:http-fingerprint` retain exact dispatch
as Labs, auxiliary Map actions. Explicit external-action authorization remains.
Their successful receipts are partial and retain existing observation fields,
with `sourceVerified: false` and `coverage.complete: false`. Historical names
use the existing `unknown` host state and record that liveness was not tested.
`timeoutSeconds`, alias `timeout_seconds`, now accepts one to 300 seconds and
governs both transport and the subprocess supervisor. Defaults are 60 for nmap,
20 for subdomain sources and 10 for HTTP. Several bounded processes may run in
one action; this is not a whole-operation deadline. nmap ports accept top100,
top1000 or numeric lists/ranges; domains require ASCII DNS labels. Missing
executable-path errors name the supplied path. No repository Map or Scan
checkpoint is created. Existing scope and redirect checks remain, while broad
network scope, useful live results and atomic observation recovery need further
evidence. See the
[external-recon audit](assessments/external-recon-audit-2026-10-14.md).

`threat-intel:research` and `threat-intel:harvest` are Labs, displayed as
**Look up advisories and draft catalog** and **Draft advisory catalog**.
External-action authorization is retained. Learning allowance covers nested
extraction with the same model, reasoning and limits. Harvest uses at most 32
supplied ID rows and eight unique IDs by default; exact case aliases are
deduplicated before model work. Both return partial unaccepted context and
cannot complete Map or start hunts. Research can use supplied OSV responses;
missing offline responses remain failed lookups without live fallback. A
resource limit defers the remaining explicit IDs and retains completed drafts.
See the [advisory-catalog audit](assessments/advisory-catalog-audit-2026-10-14.md).

`ndiff:extract-fix-pattern` is Labs, displayed as **Draft advisory pattern from
supplied diff**. It consumes existing supplied text or a bounded file beneath
the selected target. Learning allowance is enforced through shared dispatch,
and external-action authorization remains explicit. The request has no source
tools and inherits selected reasoning. The receipt records the full supplied
content hash, included and omitted bytes, and unaccepted status. It does not
activate context, accept a lesson, generate a patch or start discovery. An
explicit `ndiff:hunt-variants` action can consume the output under the same
investigation allowance. The whole `ndiff` module is Labs; exact dispatch and
historical receipts remain available. See the
[advisory-pattern audit](assessments/advisory-pattern-audit-2026-10-14.md).

`ndiff:hunt-variants` is Labs, displayed as **Search advisory-guided observations**.
It is auxiliary Scan work with an explicit pattern and approved Discovery
allowance. The retained DAG dependency does not extract a pattern or order
execution; the executor consumes the supplied pattern directly. Reasoning
inherits the selected runtime. Requested output tokens and model turns apply
to initial and repair queries without changing the model. Partial receipts bind
the host source snapshot and disclose unverified coverage and locations. An
empty response does not resolve earlier findings or accept reusable context.
Scope, applicability and useful output remain unqualified; see the
[advisory-search audit](assessments/advisory-search-audit-2026-10-14.md).

`offense-review:threat-hunt` is Labs and **Discover actor-guided observations**.
It retains exact dispatch and its `carlini-threat-hunt:run` compatibility alias.
Both are auxiliary Scan actions with partial coverage and independent-review
requirements. `thinkingLevel` is an optional override; omission inherits runtime
reasoning. Declared `maxOutputTokens` and `maxModelTurns` reach every query, and
the truncation retry keeps those same requested limits. Actor and repetition
bounds are explicit. A fresh repetition uses a distinct work identity; resuming
that work can reuse its staged responses. The action requires prioritized
high/critical threat context. That priority never establishes a finding verdict.
Scope isolation, whole-operation bounds, paid partial retention and useful
detection remain unqualified. See the
[actor-discovery audit](assessments/actor-discovery-audit-2026-10-14.md).

`trace:expand` is Labs, displayed as **Draft data-flow claims**. It retains exact
dispatch and legacy Prove authorization without a phase checkpoint. Source-only
follow-up work requires Discovery allowance and cannot borrow protected Review.
Review exposes the shared recorded-trace reader with `t`; paging and back keep
the Review origin and focus. Reading and command drafting start no work.
Valid responses are partial and disclose unverified references, relationships
and coverage. Trace reads exactly the authenticated last result, including an
empty result, with its source receipt. Earlier results remain in history; legacy
graph-only records disclose missing per-run source binding. An unchanged source
receipt never proves a data-flow claim or a fix. Scoped tools, immutable context
binding and useful generated hops remain unqualified. See the
[trace source-history audit](assessments/trace-source-history-audit-2026-10-13.md).

`triage:chain-hunt` is Labs, displayed as **Propose finding relationships**.
It synthesizes unreviewed hypotheses from confirmed finding metadata, retaining
member decisions and requiring independent source review. It is auxiliary Review
work with Discovery accounting and cannot borrow protected Review capacity.
Declared candidate, prior-hint, prompt-byte and output-token limits bound model
work. Exact member references are required; invented or duplicate members reject
the whole proposal. The request has no source tools and creates no follow-up jobs.
Source-version isolation, full ledger preparation limits and useful detection
remain unqualified. See the
[finding-relationship audit](assessments/finding-relationship-hypotheses-2026-10-13.md).

`variant:hunt` performs a separately approved source search from a current
confirmed finding. It is Labs and returns partial, unverified observations with
explicit coverage limits, preserving the original confirmation and requiring
independent Review. Its DAG dependency on pattern drafting is metadata; execution
does not read that draft or schedule either action automatically. Optional
thinkingLevel inherits the selected runtime. Exact dispatch remains available,
but immutable discovery scope, source authentication and useful detection remain
unqualified. See the
[related-observations audit](assessments/related-observations-audit-2026-10-13.md).

`variant:lift-pattern` is an experimental source-pattern draft from a currently
confirmed finding. Its result remains unaccepted and does not activate context
or complete Scan. Model requests use Learning allowance and preserve protected
Review. Optional `thinkingLevel`, with `thinking_level` alias, inherits runtime
reasoning when omitted. The existing signature payload remains, with additive
draft flags and bounded required fields. For reviewed future context, use
`findings:lesson-generate`, explicitly accept the lesson and select it for an
immutable context copy. Pattern usefulness and source-version isolation remain
unqualified; see the
[source-pattern audit](assessments/source-pattern-draft-audit-2026-10-13.md).

Run comparisons distinguish newly observed, seen again, not observed in covered
work and not reassessed findings. CLI and TUI retain exact source references
and disclose coverage limits. Neither absence nor a stored decision proves a
fix or permission to reuse a verdict at another revision. Review shows the
decision's original source and requires reassessment when recorded source
changes. CLI JSON adds versioned neutral observation fields while retaining
explicitly labeled legacy counters; migration details are in RELEASING.md.

Guided Scan uses the finite-study surface: `plan scan` opens it directly, and
`scan` opens it when no completed or pending Scan result needs reading. The
phase rail follows the same route. Its defaults offer three fresh passes and
one worker, with the existing canonical SAST engine and option controls.
Context is an exact revision or an explicit omission. Preparation freezes jobs;
approval reviews that plan and the shared allowance; starting jobs is a separate
action. The operator can cancel review without losing the draft, then return
to the original page. Merely opening this form does not advance durable phase
evidence. Completed Scan reading and exact individual-tool dispatch remain.

Picker phase navigation and automatic Map advancement also use finite Scan.
The Map picker retains its rows, choices and cursor while the study is open;
canceling restores its prior phase and origin. Old transient notices are cleared
on intentional entry, with their transcript records retained, so a hidden alert
cannot intercept the study's Back key.

`full [target]` and `pipeline [target]` open the same aggregate Setup as an
explicit new investigation entry. Without an argument they require the active
target; `full .` selects the current directory explicitly. Setup reviews Map
work and opens the shared finite context study for model-backed tasks. It does
not start a worker or approve an allowance. Scan follows its existing finite
study route. Opening Setup preserves the composer and leaves durable phase
evidence unchanged. Legacy wizard transition helpers remain covered by tests;
these commands no longer enter that separate wizard.

Allowance review starts with the matching frozen work receipt: repository,
workload, workers, engines, scope and context for discovery; distinct cases for
scoped/context studies; frozen observations and strategy for Review; and action
and preparation jobs for context work. Mismatched identifiers, digests or job
counts do not borrow a displayed draft's description. Mutable form values do
not replace recorded conditions. Path previews disclose clipping; exact inputs
retain membership. Spending terms, retries, protected capacity and technical
identity remain in the same paged document used by terminal and plain output.
Approval stays unavailable until its final terms are reachable.

`iac-scan:scan` reads Dockerfiles, GitHub Actions workflows and Terraform as
configuration policy signals. It never builds or executes these files. Its
iterative walk excludes symlinks and dependency, build and state directories,
and stops at 64 directory levels. The descriptor declares `maxEntries`
(`max_entries`, default and ceiling 100,000), `maxTotalBytes`
(`max_total_bytes`, default and ceiling 512 MiB), and the existing
`maxFileBytes` (`max_file_bytes`, default 512 KiB, range 1 KiB to 64 MiB).
Total content allowance has a 1 KiB minimum. Invalid limits fail preparation
instead of being silently clamped.

The additive `data.inspection` receipt records limits, entries visited, actual
bytes read and excluded material. Oversized, invalid UTF-8, unreadable,
depth-limited and truncated content produces explicit coverage gaps and a
partial result while retaining other observations. A direct run captures its
source identity and preserves workspace-relative finding paths for a selected
child directory. Source authentication performs separate IO beyond the content
inspection allowance. Signals remain `signal_only` and require owner review.

`sast:scan` declares optional `iacScanMaxEntries`, `iacScanMaxTotalBytes` and
`iacScanMaxFileBytes`, each with a snake-case alias. Preparation rejects these
options unless IaC scanning is selected. One prepared scanner shares limits
across its selected directory roots, with cumulative `data.nativeInspections`
receipts in JSON and readable shell/plain output. Exhausted capacity leaves a
root uninspected and makes the result partial. An error without an accounting
receipt holds the remaining allowance rather than reusing uncertain capacity.
Separate approved jobs receive separate limits. Exact-file scopes are refused
before discovery; directory or whole-repository scanning requires its own
explicit scope approval. No automatic scope widening or retry follows.
Producer-owned IaC fingerprints are rebound with their paths, so direct and
scoped SAST observations of the same policy signal consolidate consistently.
The additive `ScanEngine::rebind_scoped_finding` hook defaults to existing
path-only behavior for other engines. Historical split identities remain
reviewable and are not automatically merged.

Live workspace watching distinguishes Git's index caches from staged inventory.
Index cache writes preserve known membership; changes to staged paths, modes,
object ids or merge stages remain visible. The shared metadata probe uses a
two-second deadline, 16 MiB output limit and read-only Git settings outside the
TUI thread. Unavailable or limited reads retain staleness rather than claiming
the inventory is current. Source-file events and immutable context/source
comparisons remain independent. The footer prioritizes workspace staleness over
routing detail; narrow chrome retains a warning beside the autonomy ceiling.


`license-scan:scan` reads manifest declarations, repository license text and
source-header policy signals without a model or target execution. Findings
remain `signal_only` and require owner review. Options and aliases retain their
existing names. A direct run now captures source identity before execution,
attaches `snapshotHash` and `treeHash`, and uses the shared source check to retain
changed-source results as partial. These source checks perform separate IO.

One bounded regular-file inventory supplies manifests, root license files and
source-header candidates. Traversal fails above 100,000 entries, 50,000 files
or 64 directory levels. Symlinks, build directories and `.kuzushi` analysis
artifacts are excluded. Contained reads retain the 8 MiB manifest, 2 MiB license
text and 64 KiB source-header limits. An unreadable or oversized license fails
instead of becoming a clean-looking result. Header inspection uses complete
lines within the prefix: it cannot infer absence before inspecting twenty
lines, or derive an identifier from a cut-off line. A complete early identifier
remains usable before an uninspected remainder.

The existing SAST path selects this engine with `tasks: ["license-scan"]` and
records its durable Scan coverage. It supports directory scopes and rejects
exact-file scope widening. Direct tool runs retain findings and source identity;
they do not publish SAST's composite coverage receipt. A later direct empty
result therefore makes no new covered-absence claim. An explicit completed
SAST pass can record a gap while keeping observations and human decisions.
The shell prerequisite planner asks before indexing or reusing context;
headless prepared execution does not infer ordering from DAG metadata.

License recognition remains heuristic, and the header comparison uses the
first declared manifest in path order. Mixed-license monorepos need explicit
component targets and owner interpretation. Neither an empty result nor a
covered absence establishes a fix or a compliance verdict.

`sbom-scan:scan` is an auxiliary Map inventory action. It reads declared
dependencies and lockfile versions, emits dependency edges plus CycloneDX and
SPDX documents, and creates no vulnerability findings or phase checkpoint.
The `context:build` DAG dependency is display metadata; shared dispatch does
not require a prior context snapshot. The selected target is the inventory
root. This adapter does not accept an exact-file discovery scope.

The inventory walker limits traversal to 100,000 entries, 50,000 regular files
and 64 directory levels. The declared `maxFileBytes` option defaults to its
64 MiB upper limit. `maxTotalBytes` defaults to 64 MiB and can be explicitly
raised to at most 512 MiB. Each distinct dependency input is captured once
through the contained, symlink-excluding reader; digest, edge and component
parsers reuse those bytes. Captured bytes stay in memory for this operation,
so raising the allowance increases memory consumption. These limits bound
source content, not parser allocation, CPU time or all filesystem metadata IO.
Exceeding a limit fails without publishing components. Ignored and unsupported
material remains outside the dependency inventory.

Direct tool results add `data.inspection`: configured limits, reserved source
bytes, actual source bytes read, captured files/bytes, per-input content hashes
and a combined captured-input hash. Failed results retain available inspection
evidence; opening or validating the target can fail before a receipt exists.
The capture is not an atomic checkout snapshot or a Git identity. It does not
establish that source stayed unchanged after each file was captured. Existing
`scan_sbom` callers retain their signature and report fields; the additive
`scan_sbom_with_options` API exposes the inspection separately.

In the shell, a completed inventory updates Components for the matching active
target without another target inspection or a focus change. A structured
failure clears its current package claims and retains the previous canonical
run receipts. Components remains available for inspecting failures and rerun
guidance. Tool-sourced reports disclose that source freshness is unverified;
the report has no authenticated source revision. Restart collects target facts
again instead of presenting a prior report as current source evidence.
Line-based gallery pages now page by their actual visible body after the pinned
header and position row. Component failure text wraps before viewport slicing,
so narrow terminals can read the full cause and rerun action.
The footer exposes `PgUp/PgDn page` for these gallery documents.
At compact gallery heights, an error notice keeps its badge, dismissal hint
and Logs route on one row so it does not consume the document's reading area.

Map accounting survives explicit immutable context copies, including checked
regeneration drafts. A current run reference takes precedence; otherwise the
shared reader follows up to 64 `sourceRevisionId` copy links and authenticates
their objects and producing runs. It keeps the exact selected context and
ignores budget claims inside document text. Cycles, missing known origins,
changed objects, damaged runs and mismatched revisions are errors, rather than
permission to start fresh spending. Legacy roots without recorded accounting
remain unbound. The latest investigation ledger supplies consumption and
protected Review capacity; selecting context does not approve new work.
This finite read is separate from inventory limits and has no total IO latency
guarantee. Ordinary predecessor links are not copy origins.

`context:build` and the hidden compatibility action `context-lite:index` select
their file sample from one bounded repository inventory. They no longer walk
the tree again to assemble the sample. `sampleLimit` and its retained `limit`
and `sample_limit` aliases accept integers from 1 through 2000; malformed or
out-of-range values fail through shared preparation before replacing a snapshot.
The inventory preserves its 100,000-entry, 512 MiB inspection and 256 KiB per-file
inspection limits, containment checks, ignored-path rules and cancellation.
Git path acquisition has a 30-second subprocess deadline, 64 MiB stdout and
1 MiB stderr capture limits. Cancellation is polled during acquisition, before
file inspection. The parser retains at most the entry cap plus one overflow
witness so a capped inventory stays partial. A missing Git executable, a
non-repository directory or an empty index retains filesystem enumeration.
Other Git failures, capture limits and deadlines stop preparation and preserve
prior artifacts; they never expand membership through filesystem fallback.
Cancellation during acquisition returns an empty partial inventory with
`inspection.enumeration = "interrupted"` and a cancellation reason.
Source identity and manifest checks perform separate IO; these inventory limits
are not a total operation allowance or a filesystem latency guarantee.

The sample is ordered by path depth, then path, so loose root files remain
eligible before deeper files. `filesIndexed` counts the recorded inventory
membership, and additive `fileIndex.enumeration` and `fileIndex.sampleOrder`
identify its basis. Git inventory enumerates tracked files, including staged
files, and excludes untracked source. Filesystem inventory can omit ignored or
generated paths. The Context reader shows the enumeration, sample count,
inspection caps, recorded omissions and partially inspected files. Older or
malformed receipts show unknown inspection extent. Neither a complete sample
nor a current source binding establishes complete content coverage. Cancellation
observed before or immediately after inventory preserves the prior snapshot.
Context values wrap at the available width. Page Up and Page Down use the
actual body height, including lower chrome and the input surface, so narrow
terminals do not skip unread rows. Paging preserves the command draft.

Shared `findings:list` pages and the full shell Review reader use one SQLite
snapshot for their related ledger queries. Page rows, aliases, decisions,
lifecycle state, corpus counts and source-completion reads share the recorded
watermark. Concurrent writers can commit in WAL mode; later reads see their
updates. There is no repeated consistency-repair loop. Missing ledgers, invalid
filters, changed cursor bindings and other actual failures remain errors.

`FindingStore::with_projection_snapshot` is a synchronous, connection-owned
read boundary. Its first query fixes the database read point; nested readers
join an existing caller transaction without closing it. Error and panic paths
release a transaction owned by the helper. Callers must only perform reads;
the helper is not a write-policy or authorization gate. Filesystem artifacts,
source changes and policy files are not frozen. Existing source/decision
validation still applies, and long reads can retain WAL history. This is
consistency protection rather than a total IO latency guarantee.

Pack validation uses `pack:lint` through the same prepared boundary in shell
and run modes. Its positive `maxWalkEntries`, `maxBytesPerFile` and
`maxReadBytes` options bound shared local inspection. Results retain
`data.coverage`, including omitted checks and conservative failed-read
reservations. A partial result or a missing target does not establish full
inspection. Prompt destinations are checked; prompt content is not analyzed.

`pack:suggest-shards` remains exact-dispatch Compatibility for legacy campaign
drafts. Reviewed modern scope proposals use `pack:scopes`, with an optional
explicitly budgeted `pack:suggest-scopes` request. Lint and legacy drafts are
auxiliary Map results and cannot establish a Map checkpoint. Legacy
`emitScopes=true` remains an explicit option for the older nested-scope tree;
it does not accept a modern proposal or approve scan jobs.

Finite study preparation records executable and cache comparison facts before
approval. Source and context shows their recorded paths, content digests and
missing inputs. These facts establish comparison identity, not engine health,
target suitability or useful coverage. A selected `semgrepBinary` is bound to
its actual content; changed bytes refuse a frozen child's execution.

Override, executable and CPG cache inspection uses iterative traversal with a
shared 100,000-entry and 512 MiB limit per comparison capture. Engine files have
a 128 MiB limit; overrides retain 16 MiB. The 30-second deadline is checked
between reads and cannot interrupt a blocked filesystem call. Source inventory
and managed CodeQL database authentication have separate checks. Cases repeat
comparison capture; this is not a total study IO allowance or dollar guarantee.
Incomplete, changed or symlinked input refuses a complete identity rather than
publishing a partial comparison. Missing directories remain distinct from
invalid or dangling symlinks.

Automatic SAST preparation checks the standalone `cargo-audit` executable with
a two-second deadline and bounded output. A missing optional dependency can be
disclosed as skipped. An installed dependency whose check fails or stalls is a
preparation failure, with the draft retained for explicit engine selection.
Disabled Cargo advisory tasks are not probed in filtered automatic selection.

The study form retains preparation errors after the temporary banner expires.
Escape dismisses the error and preserves the draft; a new explicit preparation
clears the previous error. z read expands the selected explanation, including
a retained error. Arrows scroll the expanded document; PageUp/PageDown, Home
and End reach the full text. z or Escape returns to the same field and original
form scroll. Escape remains dismissal while an error is open. The reader adds
no jobs or approvals, and plain output uses the same selected-section content.

Source and context separates Overview, Inputs, Settings and JSON. Tab and Shift+Tab
switch these views, preserving separate form and reader positions. Overview
keeps source and context identity; Inputs labels each condition's recorded
executable facts. Settings presents each frozen key and value with a readable
label and current descriptor help, grouping regular and advanced settings.
Keys absent from the current descriptor remain visible as recorded bindings;
current defaults never replace missing or historical values. Descriptor help
does not claim that an engine is ready or that the plan is approved. Legacy
execution fields remain inspectable together without action-oriented help:
this investigation workflow offers no target execution, reproducer or patch actions.
Their recorded values remain unchanged, including historical true values;
presentation never grants approval or enforces dispatch policy. JSON
retains the complete prepared input and exact supplemental text. Null, empty
text and missing fields remain distinct. A missing legacy context-reference key is distinct from explicit null
omission. The plain form remains exhaustive across all views, while its reader
projects the selected view. View changes do not alter dispatch or approval.

`findings:list` page cursors bind the complete matching finding facts, current
decisions, ledger aliases and relevant source-run facts. Running the next listing
does not invalidate its own cursor through unrelated run bookkeeping. A changed
finding, decision, suppression state, query or source binding requires reloading
the first page. The returned watermark still identifies the observed projection;
the reader checks it again before publishing a page.

Suppression management is a Review operation over an active workspace and
findings store. `suppress:list` reconciles expired or removed rules and can
update finding state. Its descriptor therefore declares `workspace-write`,
and the shared Review ceiling applies. Adding, listing or removing a rule
preserves raw observations and independent human decisions. `suppress:remove`
requires a rule identifier; `ruleId` and `rule_id` are aliases for `id`.

These actions and individual dismissals have `phase_result: false`: completing
one cannot establish Review completion or displace the analysis run used by
implicit `report:build`. An explicit run identifier still reports their own
receipts. The source selection uses descriptors from the dispatch registry,
including auxiliary result ownership, rather than inferring it from a name.
Review labels a rule-suppressed observation as `suppressed`, keeping its human
decision and author separate. Suppression alone does not establish a human
false-positive verdict.

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

### Fleet history and revision comparisons

Fleet is an operational surface over operator-owned registered targets. Register
targets with `fleet:register`, rebuild the derived corpus with `fleet:ingest`,
then inspect `fleet:status`, `fleet:findings` or `fleet:diff-findings`. These
runtime-free tools do not complete Map or authorize additional scan work.

Current findings and recorded observation history are separate projections.
Ingestion preserves prior observations so one repeated finding can remain
visible at both recorded SHAs. Unreadable or oversized targets are explicitly
skipped; a partial ingestion cannot establish complete Fleet coverage.

Revision comparisons report base-only, head-only or both for uncertain source
proximity groups. Absence never establishes a fix. The full investigation run
comparison supplies detailed source, context and coverage provenance; the Fleet
SHA-only reader does not distinguish dirty trees or differing scan conditions.
Use a separate evidence-backed human decision for fix status.

`maxRows` on `fleet:diff-findings` and `limit` on `fleet:findings` accept 1 through
10,000. Comparisons exceeding their row allowance or 8 MiB of payload fail
without a truncated result. Ingestion also limits each target's observations to
10,000 rows and 8 MiB. Fleet-wide ingestion size and latency are not guaranteed
by these per-target bounds. An older derived corpus needs explicit ingestion to
add history; current-finding queries continue to read its existing projection.

## Report surface

`findings:groups` is a read-only Review tool over the complete matching ledger.
It groups accepted duplicates with matching recorded endpoints and leaves
variants and uncertain matches separate. The tool lists groups by default;
pass a returned `groupId` and `expectedRevision` to page its independent members.
Pages default to fifty rows and allow at most two hundred. `runIds` uses selected
Scan references, and `filter` uses the existing finding filter expression.
The TUI `groups` command or Review `G` opens the reader. Enter opens members,
then an exact observation; `G` returns to the group. `n/p` pages, `PgUp/PgDn`
reads details, `L` opens relationships and `R` refreshes changed grouping.
Finding verdicts and guided phase completion remain independent from grouping.
The returned `selectedRunIds` includes recorded parent/engine membership.
Member `matchingRunIds` discloses which selected runs observed the finding;
`runId` names the displayed current observation. Selecting an earlier run does
not select its source snapshot. Review source comparisons remain necessary
before carrying a decision forward to another revision.

Review `relationships` reads proposed duplicate, related-variant and uncertain
links independently from finding verdicts. Press `L` in Review Navigate mode
to open the selected finding's relationships. In the reader, `a` accepts, `r`
keeps observations separate and `u` unlinks; each decision needs a reason.
The note field owns keyboard input and multiline paste while preserving the
shell draft. `R` reloads, `n/p` changes pages and `PgUp/PgDn` reads details.
Recorded endpoint runs remain historical when source changes.

Shared headless tools are `findings:relationships` and
`findings:relationship id=<id> state=<accepted|rejected|removed>
note=<reason> expectedRevision=<shown revision>`.

`findings:relationship-batch` applies one operator decision to one to fifty
captured relationship objects atomically. Supply `relationships` from the
reader, `state` and a required `note`. The writer checks every captured record
and source binding before appending one batch event. Accepted grouping never
changes finding verdicts. Rejection and unlinking remain explicit and reversible.
In the relationship browser, Space selects, `*` selects the page, `c` clears
and `A` opens pair review. Choosing a decision opens the reason editor, then
Enter previews the exact confirmation. Only the final Enter records the batch.
During pair review, `[` and `]` select an endpoint and Enter opens its recorded
finding generation. `G` returns to the same pair, side, scroll and captured set.
See the batch-reader upgrade contract in [RELEASING.md](../RELEASING.md).
`triage:dedupe` proposes links
under the selected model and allowance. It does not change identities or mark
duplicates false positive by default. `dryRun` writes no proposal;
`legacyRekey=true` retains the old explicit compatibility behavior. Its
`modelDedupe=auto` callers no longer prune their review queue through those
default proposals. Remaining per-finding triage can therefore cost more than
the old identity-rekey path and stays subject to the approved allowance.

`triage:run` distinguishes classification from applying a review decision.
Storage policy can retain an existing human decision while the run records the
model's opinion with `decisionApplied=false`, `applicationStatus=not_applied`
and `stage=model-opinion`. The receipt counts these in `unappliedOpinions` and
explains that existing decisions remain authoritative. Successful classification
does not assert that an automatic decision was written. Unapplied FP opinions
cannot remove findings; real storage errors remain failures. A failed, consumed
fixed Review job stays in history and needs a new approved plan for further work.

Model-backed investigation dispatch requires an approved `allowanceRef`.
The native model adapter also requires a host allowance binding for direct
queries and tool-loop steps. `preflight_model_work_blocking` checks model and
work admission without reserving a call. Credential readiness, authentication
ping and tool-policy acknowledgement remain separate from billable work.
Standalone adapter callers must bind their approved work through
`AgentRuntime::with_allowance_binding`; they cannot use an unbound session to
bypass the shared accounting. Root session questions retain their drafts when
admission is blocked. Their operator-facing approved question-plan flow remains
under implementation; use the existing approved module plans for supported
model-backed investigation actions.
Preparing input or a draft does not approve spending. A nested executor can use
the parent's existing runtime binding after shared dispatch validates its
workspace ledger, work identity, revision, model and available capacity. Runtime
wrappers forward `AgentRuntime::allowance_binding()`; adapters that expose no
binding cannot inherit one implicitly. Provider attempts continue to reserve
through the existing adapter admission protocol. Explicit runtime-free variants,
such as `context:build enrichment=false`, remain available without an allowance.

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

JSON and JSONL include optional `provenance.sourceHistory`; SARIF uses
`kuzushiSourceHistory`, and Markdown manifest entries use `sourceHistory`.
These are recorded source summaries with first/latest run references and dates,
not a complete raw observation log. Markdown displays at most eight summaries;
the manifest retains every exported summary. CSV explicitly lists
`provenance.sourceHistory` among omitted fields, and the external scanner format
omits provenance. Report discloses the selected format's treatment before export.
Repeated runs from the same producer and signature count as one distinct source
without changing confidence or decisions. Historical summaries do not establish
that a finding still applies at a different commit.

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
Human decisions retain their recorded source basis when available; legacy
decisions disclose missing provenance. A missing observation never proves a fix.
Old campaigns without allowance history disclose that absence.

Manual decision save receipts name the recorded observation and its available
snapshot, commit and clean/dirty state. The receipt reads the exact committed
decision at its source watermark, so a later observation cannot change it.
CLI JSON adds version-1 `sourceReceipt` and
`currentCheckoutApplicability=not_assessed`; existing result fields remain.
A source-read failure after commit reports that the decision was saved and its
source receipt is unavailable. Legacy decisions without provenance stay unknown.
Saving a decision does not assess the current checkout or approve later reuse.

`findings:review-source` provides explicit `capture`, `read` and `decide`
operations with declared `finding`, `sourceRef`, `verdict` and `reason` options.
All use shared prepared dispatch and explicit operator authorization, require
the active target and findings store, and need no model. Capture stores a
version-1 immutable source identity in the existing content store. It binds the
exact finding generation and ledger read cutoff to target, snapshot, content
hash and available Git state. It follows the existing bounded source identity
walk and its exclusions. It is not a complete stored source copy or a scan.

Read authenticates an exact reference and returns its historical metadata.
Decide requires a human verdict and reason, then checks current content and Git
state before committing the source metadata with the decision in one event.
An intervening finding or decision change refuses the stale read cutoff.
Cancellation and missing, malformed, oversized or foreign references refuse
work. Neither action creates an observation, establishes a fix, approves
follow-up work or changes the selected model. `matched_before_save` describes
the pre-save comparison; later readers do not assert current applicability.

The selected finding header exposes `Y` to open source review without running
work or replacing a composer draft. `workbench.review_current_source` is the
remappable action name. The form presents the capture limits before execution,
then frozen code, source identity, explicit verdict choices, a multiline reason
and a separate save review. Enter authorizes capture or the reviewed save;
both compile into shared prepared dispatch. The raw tool result still carries
the source reference. An explicit captured-source decision is shown separately from its prior
observation, including capture time, commit and dirty state. JSON/JSONL and
SARIF exports preserve the capture, and Markdown includes it with a current
checkout caveat.

`maxCitedSourceBytes` declares a complete-file read limit from 1 to 262144 bytes.
Captured file bytes must match the recorded tree entry. Code is retained by
content hash; later reads authenticate it and never use a mutable checkout
fallback. Binary, invalid-text, missing, excluded and oversized material stays
unavailable. Legacy captures have no cited code. The form provides code/source
tabs, code and receipt paging, Unicode-aware reason editing and explicit saved
decision ids. Closing during work requests cancellation; background completion
retains the exact target and draft without moving focus. Source changes refuse
saves and preserve the reason for review.

## Bounded shard proposals

The finite Campaign reader displays scope or context-case names and pass numbers
from the recorded plan. These labels do not change job ids, state or approval.
Enter inspects the selected job's recorded inputs and outcome; q returns to its
place in the list. Up/Down selects adjacent jobs while inspecting. Paging,
resize, refresh and background completion preserve the composer draft. Active
inspection keeps Stop available and pending cancellation visible. Missing model,
context, run and charge evidence are disclosed without reading current settings
as historical facts. Plan/allowance review remains a separate action.

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

The scope Actions menu can copy a primary boundary into shared context without
changing its discovery ownership. The declared `edit` payload uses
`create-shared-context` with `scopeId` and a new `sharedScopeId`. It refuses to
replace existing shared context implicitly. `remove-shared-context` removes
the context copy after explicit dependency references are cleared. Both create
new unaccepted revisions and keep earlier plans intact. Shared discovery stays
off on creation; enabling it is a separate edit with overlap review and later
explicit job selection.

`Add discovery scope` adds exact source membership through the same `edit`
boundary. The additive `add-scope` payload contains one `scope` using the
existing proposed-scope fields. Paths must match the saved inventory; normal
path, identity, eight-scope and overlap checks still apply. The TUI prefills
uncovered paths only when the entire list fits within 32 files. Larger or
partial previews require explicit paths. Invalid edits retain the form. Esc
keeps the new-scope draft for reopening during this session; quitting warns
that it will be discarded. Saving recomputes coverage and clears acceptance.
The operator must separately accept the revision and approve its fixed work.

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
Ordinary strategy approval cannot accept scope boundaries. The shell scope
editor is available through `scopes`. Optional model proposals and finite
scoped studies use separately reviewed Campaign plans and shared allowance.
Live proposal usefulness and complete monorepo acceptance remain unproven.

Scoped `sast:scan` preparation checks repository-relative membership without
following symlinks. Semgrep accepts exact regular-file membership. Other adapters
may require directory or whole-repository scopes. An unsupported selection fails
before scanner preflight instead of expanding to its parent.
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

Study-filtered Review includes retained observations from authenticated attempts,
including partial scans. Completed-pass recurrence remains separate. An
incomplete observation can be reviewed without increasing completed-pass counts;
unavailable study receipts produce an error and hide stale list membership.

`sast:scan` exposes optional `agenticMaxModelTurns` (`agentic_max_model_turns`
alias), from 1 through 40. It requires the selected `agentic` task and reaches
that scanner as `maxModelTurns` through shared prepared dispatch. Omission keeps
the scanner's existing 20-turn default. The limit applies per query; structured
output repairs and transport retries also consume the shared investigation
allowance. It does not establish a token or dollar ceiling.

For a selected Semgrep task, `semgrepConfig` declares rule files or selectors
and `semgrepBinary` declares the executable through shared prepared dispatch.
Use absolute local rule paths when scanning directory scopes. Local rules
avoid remote rule selection but do not disable every executable network feature.
Neither option enables Semgrep when it is absent from the approved task list.
The direct Semgrep descriptor publishes its existing executable default.
It also declares `timeoutMs` (`timeout_ms` alias). The SAST umbrella declares
`semgrepTimeoutMs` (`semgrep_timeout_ms` alias) and refuses unused Semgrep
settings before execution. The default is 1800000 ms, with positive values up
to 86400000 ms. A prepared engine shares this time allowance across selected
roots and exact-file batches. The existing controlled subprocess adapter bounds
output, cancellation and deadline cleanup for the process tree. Earlier returned
batches remain available when later work fails; remaining work is incomplete.
Approval names the frozen per-job limit, and native receipts preserve the
configured allowance and elapsed time. These are subprocess limits; source
authentication and parsing after process completion remain separate. Process
cleanup and scheduling can outlast the clock deadline. No strict dollar ceiling
or complete repository-coverage claim follows from this limit. Legacy direct
`SemgrepScanner` invocations use the default deadline while preserving their
existing Rust shape. Saved descriptor-bound plans require explicit re-preparation.

Semgrep also declares `jobs` (1 through 256, default 1). The SAST option is
`semgrepJobs`; it is valid only when Semgrep is selected. This controls scanner
workers within each job, separately from study concurrency. Approval and native
receipts preserve the frozen setting. Additional runtime threads remain possible;
this is not an operating-system CPU ceiling.

Exact-file discovery packs literal paths into ordered batches of at most 1,024
files and 12,288 encoded argument bytes, including the executable and fixed
arguments. It does not expand directories or globs. An argument that cannot fit
stops remaining work with an explicit error; returned earlier batches survive as
partial results. There is no automatic subdivision or retry. Existing output
limits and the shared job deadline still apply. Receipts add `exactFileBatching`
and `configuredLimits.jobs`. Environment size and platform process limits can
still cause a subprocess error; the argument allowance is not a portability
guarantee. Legacy direct scanner methods now use one worker. Reprepare saved
descriptor-bound plans and approve their exact terms after this option change.
CodeQL retains its optional binary and adapter resolution. Selected capability
actions inspect declared executable options in the
background using canonical stored values. Missing executables are visible before
loading a command; `r` rechecks while the picker owns input. Presence does not
certify engine versions, configuration, scope coverage or useful output. Shared
Semgrep preflight rejects a Unix file without execute permissions before scanning
and preserves the exact filename, including meaningful whitespace.
Shell `set` and `setg` text/path values accept double-quoted JSON strings. For
example, `set binary "/owned/scanner path "` preserves the space inside the final
quote. Unquoted text retains its existing trimming behavior. Incomplete quoting
returns an error before changing the stored option. Structured `run --input`
JSON strings retain their existing literal values.
Shell list options also accept a complete JSON array of strings. A quoted JSON
string represents one list entry, including commas in a rule filename;
unquoted comma-separated values keep their existing behavior. Malformed arrays
and non-string entries refuse before storage. `set` and `setg` completion
distinguishes option names from values: named descriptor choices and boolean
values can complete, while free-form values remain the operator's text.
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

### Bounded native secret inspection

`secret-scan:scan` is runtime-free Scan work with a required findings store.
Shared prepared dispatch declares `maxEntries` (`max_entries`) and
`maxTotalBytes` (`max_total_bytes`) alongside the existing file/finding limits.
The traversal is iterative, lexical within enumerated candidates, cancellable
and bounded to 100,000 entries. Reads beneath the target reject symlinked file
components and reserve at most 512 MiB in aggregate. Each reservation uses the
same opened file's metadata and includes the bounded reader's extra byte.
Failed reads keep their reservations; budget exhaustion starts no further read.

Finding, entry, aggregate-read and per-file limits produce partial output with
coverage gaps. Observations already found remain available. Mid-scan
cancellation preserves observations; cancellation before/during collection
fails before discovery. The report adds optional version-1 `inspection` with
limits, conservative reservations, traversal count and exclusion lists.
Library exact-file membership reports no directory enumeration count and cannot
exceed its configured entry allowance. Both standalone and aggregate outputs
forward coverage gaps. No credential validity check or provider request occurs.

`sast:scan` declares optional `secretScanMaxEntries`, `secretScanMaxTotalBytes`,
`secretScanMaxFileBytes` and `secretScanMaxFindings`, with snake-case aliases.
They require the `secret-scan` task and are checked before dispatch or study
publication. Omitting them preserves native defaults. One prepared job shares
its entry, conservative content-read and finding allowances across all selected
roots. Each finite pass has its own frozen settings and accounting.

Accepted exact-file membership consumes the same configured limits and never
expands into excluded files. Exhausted allowances refuse further roots, retain
observations and disclose partial coverage. Additive `data.nativeInspections`
records each inspected root, original job limits, cumulative consumption and
coverage gaps. The terminal receipt projects the same records. Frozen study
Settings shows the exact canonical values with current descriptor help; these
source inspection limits are separate from provider-call or dollar accounting.

The tool's `context:build` dependency remains DAG metadata. Native direct
dispatch works without a context artifact; no dependency execution ordering is
inferred. Standalone directory inspection and accepted exact-file Scan routing
remain distinct surfaces. Source race timing, all configurations, scope parity
and complete investigation usefulness remain unqualified.

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

Standard triage reuse additionally requires the exact captured source snapshot,
complete serialized review request and a `triage_semantic_cache_identity`
attestation from the runtime. Query attestation alone does not authorize triage
reuse. The additive `AgentRuntime` method defaults to `None`, so existing
adapters remain compatible and execute live. Current external bridges do not
attest their triage path. Runtime handles and tracing preserve explicit
attestations. Failed or incomplete runs discard reuse entries for their source
snapshot; explicit retriage always bypasses reuse. The process cache retains at
most 4,096 entries. Cache hits keep zero new model cost without changing prior
decisions or raw observations.

Policy-aware findings lists present the latest observation in each permitted
identity group, retaining its source and evidence history. The public emitted
generation reader remains exhaustive and severity-sorted. Review records with
no identity apply only to their exact finding row, including a row that itself
has a durable identity. Shared identity records retain their declared scope.

An explicit `generation:<id>` opens that exact observation as a pinned reader.
It does not request a canonical list-page anchor for an older observation that
the current fold excludes. The current list page remains in place; the pinned
selection and its out-of-window disclosure remain subject to the existing
decision and source guards.
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

`taint-iris-next:finding-review` retains its exact name and now appears as Labs,
**Discover taint candidates**. It starts fresh source/sink discovery and imports
observations rather than reviewing selected ledger findings. It cannot own a
Scan checkpoint. Missing model selection remains a pre-execution block without
an incorrect exhausted-allowance classification. Model and approved allowance
requirements still apply. Cancellation is checked at stage boundaries and
before publication; interruption within backend work remains unqualified.

Saved Replay receipts retain outcome, recorded issue, cost and continuation
first. Current terminal receipts then show attention and result content before
work identifiers and routine **RUN DETAILS**. Running work and receipts with
integrity, durability, progress or delivery uncertainty retain prominent
diagnostics. This changes presentation order only; every typed row, disclosure,
artifact-authentication boundary and timeline remains available by paging.

`ndiff:fetch-cve` is runtime-free advisory metadata, retained as an exact Labs
action. Supplied records are labeled unverified, must match the requested id,
and share the declared `maxMetadataBytes` allowance with fixture metadata.
Malformed supplied objects fail before online fallback. Metadata is auxiliary
Map work and does not establish target applicability or complete Map. Existing
record and primary-link fields remain with an additive retrieval receipt.
Live retrieval and cancellation remain unqualified.

Module shorthand in the shell preserves the registered primary action. When
that action is outside Core discovery, the operator must choose an exact tool.
It does not select another remaining action or fall through to global SAST.
Exact `module:action` dispatch still uses the shared preparation boundary.
The two deterministic taint planning names retain that path as Labs and
Compatibility, without owning a Scan result. Source membership is collected
iteratively; partition advice consumes it without another traversal.

`threat-intel:apply` declares an input-aware runtime requirement. Its canonical
`dryRun=true` default reads catalog metadata without a model or child dispatch.
The same predicate governs runtime preparation and execution; `dryRun=false`
still requires an explicit runtime/model and approved accounting. The tool is
Labs and auxiliary Map. A preview does not approve the proposed hunts or become
an accepted scope study. Live catalog dispatch, large histories and cancellation
during enumeration remain unqualified. Exact dispatch stays available.

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

When an owned dispatcher exits unsuccessfully, the shell displays its latest
bounded and redacted `Error:` line from `logs/dispatcher.log`. Refresh retains
the notice for the original target and campaign; changing selection cannot
carry it into another study. Background completion preserves focus and input.
Missing, unsafe, invalid or oversized logs keep an explicit unavailable cause.
The notice lasts for the shell session and clears on successful relaunch; the
current launch's log remains on disk until the next launch replaces it. The
full cause precedes job details, with visible review and paging controls.
A failure neither changes approved
jobs nor permits new spending. Pending Map, Scan and Review results open for
their explicit decision through the phase verb; `plan <phase>` explicitly
opens planning. Navigation accepts no result and launches no work.

Setup also offers `Import context document` in its Map plan. This explicit
runtime-free action uses `threat-model:import` and its existing descriptor
options. It is excluded from automatic and model-recommended preselection.
The plan presets `activate: false`; the visible option can still be changed
explicitly. The Context import readiness row opens the Path option, preserves
the plan and composer, and distinguishes missing source input from model or
credential requirements. Source presence is checked by the same pure selector
used by the executor. File existence, JSON content, bounded reads and source
grounding are checked during execution, so a ready input is not a verified
document. Import and generation need separate Map reviews. A completed
foreground import plan presents its durable Map result for explicit acceptance;
the context can reach scans without changing the global active pointer.
Local planning options are session choices unless explicitly persisted. The
exit confirmation names that unsaved state; accepted context, study approval,
observations and exported reports have their own durable records.

Setup's `Tab` action inspects the selected readiness row without editing or
executing it. The complete document includes current state, source/check
explanations and the actual planned-work summary. Page Up/Down, arrows and
Home/End read it; Tab/Escape returns to the same row. Enter in inspection
starts no work. Reading positions survive return and resize within Setup;
explicit reopening resets them. Paste leaves inspection for the original
composer without submission and retains existing multiline paste blocks.
Short overviews use a compact row list with Start Map visible. Complete
explanations stay in the reader; plain output serializes the full document.

Campaign Navigate mode uses the full frame on terminals with at most 18 rows.
The complete job/recovery document shares its actual area with keyboard paging
and selected-job positioning. Recovery text, current actions and configured
composer/palette keys stay visible. Escape returns to the normal composer;
palette return, resize and ordinary reading preserve the draft and selection.
Pending confirmations, visible questions and study editors retain input and
rendering priority. Taller terminals keep the normal shell layout. This reader
does not launch work or change approved jobs, reservations or persisted state.

The Campaign overview preserves the complete campaign identity and groups
worker, cost and dispatcher fields when their joined summary would overflow.
Plan policy, configured limits, unresolved cost and empty occurrence guidance
wrap before pagination. The complete action list remains available through
reading. Wide layouts retain the joined summary when it fits; Unicode section
titles use actual terminal columns. This presentation uses the existing
snapshot values and does not change execution or accounting.

`campaign:allowance` and `campaign:approve-allowance` receipts explicitly show
the calls available for context, scope planning, scans and lessons after
subtracting protected Review/Report capacity. Consumed and unresolved calls
remain committed. The calculation comes from the shared allowance snapshot;
it does not change admission, approve new jobs or enforce dollar charges.
An optional `runId` with missing legacy evidence stays unavailable, even when
the current investigation has a known zero call count. Planning and approval
publish no Map result. A saved approved plan can resume its pending Map page;
that page still requires source-grounded Map work and explicit acceptance.

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

`threat-model:ask` answers one question over an exact `threatModelRef`. The
question, selected model, source identity and optional captured operator notes
are frozen through `campaign:context-study generationTool=threat-model:ask`.
One worker executes one approved job with tools disabled and one model turn;
transport retries consume the same allowance. A standalone allowance without
that fixed question job is insufficient. Context calls preserve protected
Review capacity. `maxContextBytes` defaults to 65,536 and refuses oversized
context before a request. `maxOutputTokens` is a requested output limit whose
enforcement depends on the adapter; unknown dollar consumption stays unknown.
Question answers never accept context, complete Map, or change finding decisions.
Saved completed or partial answers validate their model, question and exact
context against the frozen plan when reopened.

`campaign:review-study` drafts one `triage:run` job over 1 to 100 pending
observations. Its required `reviewInput` is prepared through the shared registry.
Selectors freeze to exact `generation:<id>` references; the effective strategy
is preserved, with one worker and one attempt. It binds an accepted Map context
revision or an explicit omission, never an unrecorded globally active context.
Source, configuration, findings and options are revalidated before the existing
`campaign:approve-allowance` approves its exact plan. Internal turns and retries
use the same investigation ledger under Review. Another attempt requires another
explicit plan; legacy standalone triage remains compatible.
New drafts also freeze recorded observation commits from bounded run metadata.
The form separates those commits from its planned Review source and calls out
a different commit. Missing, malformed and legacy metadata remain unknown;
planning and absence in later scans cannot establish a fix.
Broad finding selection freezes the exact raw generations that approval rereads.
Consolidated source history remains a separate projection. Repeated runs by the
same producer and source signature count as one distinct source, while every
run stays selectable and visible in provenance.

Selecting triage in `plan review` opens this form before credentials or dispatch.
The picker explains that no calls start; other selected work stays paused. An
unselected worker count defaults to one, while explicit choices remain visible
for validation. Active work keeps its existing queue. A completed draft returns
to the form despite paused choices; runnable continuations still hold Run Focus.
`t` edits total calls, `r` protects Review capacity, `M` chooses a model, `c`
changes context inheritance or omission, and `s` changes strategy explicitly.
`Tab` reads exact options and paging reads the complete draft. Enter prepares,
then reviews the allowance, then opens approved jobs; `L` on the campaign starts
the fixed job separately. Back retains the selected task and composer. Named
campaign review restores the plan and accounting after restart. Historical Map
spending remains relevant across source revisions, while historical context
cannot satisfy current-source acceptance. Missing prerequisites and approval
failures preserve the draft and expose their reason.

The shell exposes context generation through `g` in the study context picker. Generated
revisions remain immutable drafts; `a` on the completed campaign reopens review,
and Enter reads its exact run-associated revision before selection. A completion
without usable context remains available as a job outcome. Legacy context actions
and other model-backed review actions still need guided allowance integration before every model
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

The context browser's `p` action inspects the threat-model digest used by agentic
scans and model triage. It uses the same renderer as execution and names its
consumer limits. The full document remains available with `Tab`; fields and
items absent from the displayed digest are not included by that projection.
Item caps and truncated reviewed-lesson fields are disclosed before the text.
Source files, supporting context, prompt overrides and runtime validation are
separate. Other engines may consume different context. Reading starts no work,
changes no selection or active context and grants no spending approval.
`Home`/`End` and `PgUp`/`PgDn` navigate each context text view; `p` returns from
the scanner projection to its summary. The current projection stays named in
the pinned header while paging.

Exact `threat-model:read` results add `data.scannerContextPreview`, with
`schemaVersion: 1`, a projection kind, rendered text/hash, limits and omissions.
The text hash identifies that digest, not a complete prompt or source snapshot.
An unavailable or malformed preview produces reread guidance in the TUI.
Context documents, references, accepted plans and execution prompts are unchanged.
The omission list names truncated ordinary fields and open questions using the
same string trimming, array joining and fallback selection as execution. It
also reports the flattened pattern limit and groups matching pattern-code cuts
by exact indexes; grouped character counts apply to each named field. Fields
outside selected items and unrenderable architecture rows do not claim partial
inclusion. Some historical pattern labels remain included in full. The preview
does not impose a new prompt, token or dollar limit.

The context browser's `e` action edits a copy of the inspected exact revision.
It offers overview, component description/purpose and human question answers.
Multiline text has its own input owner. Back retains drafts and cursors within
the shell session, including leaving and reopening the study. Ctrl+S reviews
changes; Enter in the review saves. Discard requires its own confirmation.
Saving selects the new catalog row for inspection, while choosing it for a
study remains a separate `a` action. The original revision and globally active
model stay unchanged. Unsaved text is a session draft; saving is the durable
boundary. No context edit starts model work or scan jobs.

Shell and run modes share `threat-model:revise` through prepared dispatch. The
tool requires an exact `threatModelRef` and an `edits` array containing `pointer`
and `text` pairs from the editable field catalog. Arbitrary evidence, source,
scope and verification changes are refused. A different inline target cannot
redirect a write from the selected workspace. The result contains
`sourceModelRef`, the new `modelRef`, its document and `activated=false`.
Source membership and revision binding are inherited from the edited revision;
editing historical context does not make it current. New text invalidates the
old verification stamp. Model calls are never required, and a canceled store
lock wait does not publish a revision. After an uncertain save, inspect the
context catalog before retrying; the editor preserves the draft.

`threat-model:regenerate` proposes replacement explanatory text for one to eight
editable pointers in an authenticated exact context. Its declared controls are
`fields`, `guidance`, `maxSourceBytes`, `contextLimit`, `maxOutputTokens`,
`thinkingLevel`, `model` and required `allowanceRef`, alongside target and context
reference. The current shell selects one field per explicit action. CLI callers
can supply a finite field set. The existing `campaign:context-study` accepts
`generationTool=threat-model:regenerate` and freezes one job, one worker and one
attempt with no preparation jobs. Planning makes no model request. Approval and
execution remain separate actions, with durable provider reservations and
protected review capacity.

In the shell, `threats regen` opens this flow directly. Choose a saved revision
and press Enter to inspect it, then `e` to choose text and `g` to plan that
field's regeneration. The model, guidance and allowance are reviewed in the
existing context-study form. Selecting or reading a parent starts no model
work. Back restores the original screen and composer; an already-open study
draft is preserved. Inspect and compare the generated inactive copy in the
context reader. `threats apply` belongs to previously pending context changes
and does not apply a regeneration result.

The request supplies bounded source excerpts and architecture with explicit
omissions. It enables no tools, delegation, vulnerability scan or finding
verdict. Structured output must match the selected pointer set exactly. There
is no output repair loop. A successful request creates an inactive copy in a
new lineage; protected metadata, source scope, unselected human text, original
objects and active context remain unchanged. The old verification stamp is
cleared. Versioned `provenance.regeneration` retains the exact parent, supplied
source excerpts, model, run, prompt digest and selected fields. `accepted=false`
describes the saved draft; it does not substitute for human study acceptance.
Source identity is checked before generation, after store-lock waiting and
after publication. Final drift retains a partial historical result, never a
current-source claim. Recovery authenticates the saved revision and recorded
run without repeating synthesis. A separately approved new job makes a new
request; selecting a stored result does not.

A regeneration campaign cannot establish a Map checkpoint. Its result remains
an inactive draft. Compare it with its parent, then use `threat-model:verify`
with the exact reference to save a checked inactive revision. Review that
checked revision through `campaign:context-map` using its `threatModelRef`.
These separate actions do not repeat synthesis, select Map automatically or
change the active context. The shell keeps the draft selection and explains
this path if Map review is requested directly from regeneration.

In the context chooser, `d` compares editable text with its authenticated parent.
Comparison includes removed text and added question answers. It does not compare
arbitrary structure or establish context accuracy. Missing or unreadable parents
have explicit local retry/back controls. The candidate stays selected during
parent reads, paging and late completions. `a` still explicitly chooses context
for a new study plan and never activates a global model.

In the context browser, `c` checks an inspected revision and `Space` opens all
context actions. This uses the shared `threat-model:verify` descriptor with an
exact `threatModelRef`. The check authenticates the object and its recorded
content hash, SHA and scope before checking citations, links and bounded
coverage. A successful execution can still report a failed structural verdict.
It does not establish finding truth or complete repository coverage.
`write=true` saves a new inactive revision in the same lineage; `write=false`
only returns the check. Original objects, the active pointer and mirror stay
unchanged. Inspecting and selecting the saved revision for a study are separate
actions. Source drift or unknown recorded identity stops this exact check.
An inline scope override or different target is refused. The source is checked
again after any store-lock wait, immediately before publishing, and once after
completion. A final check failure leaves a partial receipt for review. Existing
unbound active/scoped verification retains its behavior. Late results preserve
selection and focus; uncertain outcomes direct the operator to Activity and the
catalog before retrying.

Exact reads preserve the scanner document and add a separate `sourceState`
receipt (`schemaVersion`, `status`, `message`). Inspection compares recorded
revision, content and dirty state using the existing bounded, cancellable source
walker. Missing identity or read failure is unknown, rather than a match.
Cancellation stops the read. The context browser displays this captured state
beside the last recorded check, including after restart. A stopped check marks
the displayed inspection uncertain until the operator reads again. Catalog
loading never establishes that a revision is missing. Source identity matching
does not establish architecture accuracy or finding truth.

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

`threat-intel:discover` and `threat-intel:list` are supporting Map actions.
Neither creates accepted context or completes Map. The candidate extractor is
Labs and returns partial coverage with a route to `sbom-scan:scan`; its exact
tool name and candidate file contract remain available. The additive coverage
object explains omitted nested manifests and potential enclosing Bazel reads.
The catalog reader inspects stored metadata without dispatching its entries.

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

Review also shows the observation behind the governing decision separately from
the latest observation. Its background reader is keyed by target, immutable
finding identity, decision watermark and displayed ledger watermark. It reads
recorded commit, branch and dirty state without repairing run metadata. Missing
or unreadable history stays explicit. A different recorded revision prompts
reassessment while retaining the human verdict. Enter or a typed `open` reveals
the detail when a narrow viewport hides it; page keys read the same document.

JSON export adds `reviewDecisionBasis.sourceComparison`: `not_reobserved`,
`same_cited_source`, `different_cited_source`, or `unknown`. The comparison uses
captured cited file path and content hash. It does not establish repository-wide
stability. Different run-scoped snapshot ids alone are insufficient. The legacy
`sourceChangedSinceDecision` flag is true only for a demonstrated cited-source
change, so false must not be interpreted as unchanged or fixed. The basis follows
the exported verdict's recorded watermark. Markdown names these limitations;
events and CSV columns are unchanged. Source-qualified fix assessment remains
unfinished. Public read helpers are described in [RELEASING.md](../RELEASING.md).

Review completion now separates a recorded verdict from applicability to later
observations. Event sequence chooses the governing decision; legacy records use
their projection id, and embedded triage supplies no new provenance. Readers and
exports use that exact record. A changed cited file, recorded commit, branch or
dirty state requires reassessment. Matching recorded clean revisions permit
reuse; missing or dirty/unversioned later identity does not. A decision on the
latest observation counts as reviewed without proving that a finding was fixed.
The reader caps cached metadata comparisons at 128 distinct runs; omitted history
remains unverified. It does not rehash dirty repositories to establish reuse.

The current-source journey, open queue and backlog keep such items available for
review while preserving earlier verdicts. Investigation report counts use the
same Core application service. JSON adds `sourceApplicability` and Markdown names
the qualification. Historical stored-verdict export filters remain compatible;
they must be read with the source qualification. Unrecorded legacy provenance
requires an explicit source-bound review for current-source progression. Full
evidence-backed fix assessment and authenticated dirty-content reuse remain open.
If the completion read fails, the shell resets both current reviewed and
confirmed counts and keeps governing terminal decisions queued for source
reassessment. Their recorded verdicts remain intact.


### Interactive scope review

Standard agentic preparation is an iterative, cancellable snippet selection.
`maxInventoryFiles` and `maxBytesPerFile` are shared descriptor options on
`sast:scan` and `agentic-sast:scan`, with defaults 80 and 2048. The latter limits
snippet bytes before decoding; binary inspection can read up to
`max(4096, maxBytesPerFile) + 1` bytes per candidate. All candidate reads share
a conservative 512 MiB allowance, and directory enumeration shares a 100,000-entry
guard. Failed and binary-looking reads retain their reservations.

Study review presents the frozen limits. Prompts and `inventoryCoverage` preserve
preparation extent; Scan and expanded Report keep qualified preparation notes
before technical identifiers. Initial snippets do not establish full repository
coverage, and later agent reads are separate.

Standard agentic discovery accepts an exact `scanScopeRef`. Discovery files and
inherited context files form a literal, authenticated read-membership list.
Preparation samples that list directly, interleaving discovery and context.
Read, list, glob and grep use this membership instead of traversing the entire
repository. Context files inform discovery but cannot supply imported findings
for the selected boundary. `outOfScopeObservations` preserves observations
outside discovery in the canonical result, with counts in Scan and Report.

Scoped execution requires the standard strategy, `mcps=false`, and no
include/exclude filters. It mounts only Read/LS/Glob/Grep. The runtime must
acknowledge `source.membership-read-only.v1` and its exact membership digest
before the first query, then acknowledge it again in the executing response.
Unsupported runtimes, malformed membership and changed source fail explicitly.
Membership is bounded to 100,000 files and 8 MiB serialized data. The model,
runtime, allowance and fixed job list do not change. In the study engine picker,
`m files` makes this explicit draft-only choice; Cancel restores the
original options, and Apply requires a new plan and approval.

Campaign combines supported investigation actions and retained shard actions.
Long job lists keep Stop, paused-work guidance and plan/allowance controls
visible outside the paged document. Keyboard job movement reveals the selected
row without changing the composer draft. Narrow readers use a compact job,
state and attempt row; inspecting the job retains its full options. Scoped jobs
display their accepted boundary identity before any legacy shard label.
Plain output retains the complete projection.
The documented Ctrl+_ draft restore action also accepts its legacy terminal
encoding, reported by Crossterm as Ctrl+7. Explicit enhanced Ctrl+_ reports
retain the same action.

`campaign:plan` and `campaign:coverage` have Compatibility discovery tiers and
are available through `tools --all` or exact dispatch. Default guidance uses
`campaign:study` and investigation Report. The compatibility matrix counts only
known Scan jobs with a legacy shard binding and reports every excluded job.
Completed cells describe historical job progress. They establish neither
repository coverage nor applicability to current source. Empty matrices do not
invent a column.

Status and coverage use Operate rather than Map. Status writes a deduplicated
trend snapshot; coverage reads existing data. Neither can replace an analysis
run when `report:build` chooses its source implicitly. Historical status spending
remains in `data`; shared dispatch marks that cost projection so run persistence
does not mistake it for the cost of the current read. Unknown current cost is
unavailable, never borrowed from a historical total.
Rust descriptors own this cost projection declaration. Local KWP modules cannot
declare `costDataProjection`; their monetary claims remain sanitized and current
execution cost comes from the broker.
Trend sparklines show a recent window of at most 90 valid snapshots read from
the last 1 MiB of history. Earlier history remains on disk; it does not enter
this window. Campaign spend totals continue to come from campaign receipts.

`scopes` opens the current repository's saved scope draft, or offers an explicit
inventory action when none exists. Arrow keys choose a boundary or coverage row;
Enter opens its action menu, `f` reads a bounded file page, and PgUp/PgDn read
long detail. The menu exposes rename, split, merge, scope/path exclusions,
explicit inclusion, boundary questions, shared discovery, whole repository and
exact acceptance. Choosing whole repository preserves recorded exclusions and
their reasons. **Include an excluded file or directory** removes one exact
exclusion rule, recomputes coverage and creates an unaccepted revision. Other
rules remain in force, including any parent directory exclusion. Unknown paths
refuse without changing membership. Existing accepted plans retain their
original scope revision.
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

Model-backed discovery and Review studies freeze `threatModelDigestRef` schema
1 alongside the exact `threatModelRef`. This separate, authenticated blob holds
the exact rendered threat-model text, including absence, disclosure limits and
omissions. Its 512 KiB serialized limit bounds storage, not tokens or dollars.
Existing input fingerprints bind the reference into every fixed job. Execution
rechecks source identity and lesson eligibility, then uses saved text without
rerendering it. Changing the active context or upgrading the renderer cannot
replace these bytes. Missing, damaged, oversized, foreign or mismatched blobs
fail explicitly. No repair loop or replacement job starts automatically.

The Context picker's scanner preview reads the matching study receipt. It
labels saved text and current or historical source state; the full immutable
document remains separate. Frozen read previews include `frozenReference` as
inspection metadata. The picker matches this object reference and the context
revision before accepting a completion; late reads cannot replace the current
plan's preview or reset its position. The reference is added to the returned
copy, so it creates no self-reference in the content object.
`threat-model:read` accepts both references for the
same historical inspection. Earlier approved model work without the new
binding requires explicit preparation and approval of a replacement, retaining
prior attempts and spending. Direct unbudgeted invocations without this option
retain compatibility rendering. Imported variant patterns remain leads that
require independent source assessment.

Finite studies also freeze `scanContextRef` schema 1. It identifies an
authenticated target-bound blob containing the exact supporting Map digest
used by `agentic-sast:scan`, with a 64 KiB serialized limit. Other engines do
not consume this supplementation. The study Context details display the frozen
text or its absence before approval. This is separate from `threatModelRef`.
Generating or editing live context cannot change an accepted pass, including
when the original supporting snapshot was empty. Malformed, stale or
unverifiable live context blocks new preparation; explicit `scanContextRef:null`
omits it. Missing, damaged, oversized or foreign frozen content fails without
substituting current context. Execution rejects source drift; historical
inspection retains the recorded text. Both homogeneous studies and context
matrices include this binding in equivalence. Direct invocations without the
option retain live supporting context selection and do not establish frozen
study conditions.

Secret scanning, Semgrep and standard agentic discovery implement exact file discovery. Semgrep
passes literal files in groups of at most 64 and checks its file-coverage receipt.
Missing receipts, unscanned files, skipped binary/oversized secret inputs and
interrupted batches remain incomplete. Unsupported engines fail before work;
they require an explicitly reviewed whole-repository job. Existing `paths`
directory behavior and public `ScanRunOptions` remain unchanged. Native adapters
do not consume the resolver's inherited context-file list.

Existing homogeneous studies support one selected scope. `campaign:study`
also accepts `scopeProposalRef` plus `scopeCases` for one explicitly selected,
finite scope study. Each case names `scopeId`, optional `passes` (defaulting to
`trials`), and optional `threatModelRef`. Omission inherits the common context;
explicit null omits it. All actual context references and supporting text are
frozen before approval. At most nine cases and 100 jobs are permitted. Context
experiments and historical baseline comparisons require separate studies.

The new `scope-study` plan reuses the existing dispatcher and shared approval.
Its job list is authenticated against every frozen scope and pass count. Model,
runtime, source and common scan options stay fixed. Source drift, altered jobs,
changed configuration and unapproved attempts fail before execution. Its Report
keeps recurrence separate for each boundary and lists unplanned siblings.
`findings batch <id>` reads per-case occurrence for both scope studies and
context matrices. JSON, JSONL, SARIF and Markdown bundle receipts preserve the
scope structure. Scope review offers Space to mark accepted discovery boundaries
and p to prepare their joint study. Marking, planning, approval and launch remain
separate actions; Back preserves the marked set. No recursive jobs are created.

Source and context opens the boundary association browser for scope studies.
Enter inspects or chooses an immutable revision for the selected boundary;
`i` restores inheritance and `o` explicitly omits context. Common context is a
separate row. Manual editing saves an inactive copy which must be inspected
before use. Selection preserves sibling overrides and the globally active
context. Changing an association invalidates the frozen plan and requires a new
approval while retaining investigation accounting. The prepared browser shows
the context actually frozen per boundary, source identity and membership.
Back retains the boundary cursor and reading position; plain output uses the
same projection. Context matrices require a separate finite study.

The boundary context picker offers `g` to draft one file-group context job.
`campaign:context-study` passes its exact `scanScopeRef` and optional
`inheritedContextRef` to `threat-model:build`. This supported path requires a
fresh, inactive, source-only single synthesis with explicit fixed-plan approval.
It reads literal discovery and shared-context members, including disjoint
paths, within the source byte and file limits. The tool-free request has one
turn; malformed output or unsupported citations create no repair request.
Its receipt records the supplied excerpts, omissions, inheritance, source,
model and run. Complete repository coverage is never claimed. Source drift
before publication keeps spending but commits no context revision.

`scopeStudyOrigin` is an optional versioned return draft in the context study.
It retains the selected boundaries, common input and local overrides through
job navigation and restart. It does not authorize discovery or add jobs.
Inspecting and selecting the generated revision changes only its intended
boundary; scanning still needs a newly prepared and approved finite plan.
Selective text regeneration of these revisions also honors their recorded
accepted file group. The Common row explicitly plans repository context.
Complete resource estimates and broader recovery acceptance remain incomplete.
Standard agentic sessions consume inherited source context, while native
adapters do not. AI division is a separate, explicitly approved one-job proposal
described below. No accepted boundary creates additional jobs automatically.


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

Scope studies and context matrices can explicitly select a prior study through
the Usage evidence picker or descriptor-owned `resourceBaselineCampaignId`.
The named prior scope study or matrix supplies per-case complete observations
only when source, context, options, model and runtime conditions match exactly.
It cannot combine with `baselineRunId`. Queue reads are bounded; named metadata
inspection is limited to 1 MiB per file and 32 MiB across the preview, followed
by existing artifact authentication. Cancellation and missing data stay explicit.

Version 1 `resourceEvidence` is additive plan metadata and an optional field in
scope/matrix receipts. Each case binds its condition digest, planned passes,
sample run identities and observed request/price ranges. Full scenarios include
maximum attempts; any unknown case or price keeps the corresponding total
unavailable. These are historical scenarios, without enforced future bounds.
Approval shows them beside exact workload and remaining capacity. Changing the
selected prior study requires a new plan digest and approval, retains spending,
and starts no jobs. Older artifacts without this field retain their behavior.
The picker loads history through the shared background reader, visiting at most
1,000 entries plus a truncation sentinel, retaining 100 choices, and inspecting
32 MiB of metadata with a 1 MiB file cap. It discloses partial history, malformed
records and unknown completion status. Choices are ordered within the inspected
set. A named selection outside the window remains available. Loading, failure,
refresh, paging and cancel preserve the draft and selection; completion never
takes focus. Plain output is exhaustive.

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

`sharedDependencies` contains exact ids declared by another primary scope or
`sharedScope`. Package names and paths cannot substitute for an undeclared id.
The optional shared scope supplies context only while `sharedDiscovery=false`;
shared code requiring discovery must also belong to a primary integration scope.
Failed scope-study reading authenticates its frozen input and published result
before displaying the recorded cause. Reading never retries the spent job.

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


### Complete findings pages

`findings:list` accepts `cursor`, `anchor`, and `order` through shared prepared
dispatch. `order=confidence` sorts the complete matching ledger before its
500-row page window. SHA, branch and run filters also run before that window,
so a match beyond the first 500 rows remains reachable. Ledger aliases travel
with the rows and retain their whole-ledger meaning.

Responses retain `data.count` and `data.findings` and add `data.page` with offset,
loaded/total counts, next/previous cursors, order, watermark and parallel anchors.
Use a returned cursor with the same options. Malformed, oversized or stale
cursors fail explicitly; the query never starts repair or follow-up work.
An anchor reloads the page containing its finding in the active workspace.

Review offers Ctrl+N and Ctrl+P in empty Navigate mode when the corresponding
page exists. The current range remains visible, including in small terminals.
Prompt-mode history and editing keep their existing ownership. External updates
try to keep the cursored finding in view; changing the query or grouping starts
fresh. Local search narrows the loaded page, while Ctrl+F prepares the global
query. Paging adds no discovery, provider requests or allowance. The underlying
query still reads the matching ledger; this change does not claim lower query
or durable-write cost.

### Explicit context candidates

`threat-model:models` and `threat-model:revisions` expose immutable history;
revisions are listed newest first. `threat-model:activate` changes the active
pointer, while `threat-model:restore` appends a new revision linked to historical
content. Exact `threatModelRef` reads remain independent of that pointer. A
divergent compatibility mirror refuses activation until its edits are adopted
or explicitly discarded through the existing force option.

`threat-model:adopt` preserves operator-authored content as a new active
revision, marks it user-edited and clears prior verification. Original objects
remain unchanged. The transaction checks the observed mirror digest before
withdrawing the mirror and uses the existing recovery record; later edits
refuse the commit. Adopting an unchanged mirror publishes nothing.

`threat-model:diff from=<revision-or-lineage> to=<revision-or-lineage>` adds
editable text comparison to its existing structural output. System overview,
component description/purpose and question answers retain complete before/after
values in `data.contextText`. Unique component/question ids and exact question
text match reordered rows; ambiguous or unkeyed rows compare by position.
Removed text remains visible. Both selectors include their content SHA.

`documentChanged` and `changedDocumentSections` disclose changes elsewhere,
including metadata, so an unchanged structural/text subset cannot establish
identical stored documents. `comparisonCoverage` identifies the compared
fields. The terminal preview shows up to eight fields, four lines per value and
240 characters per line. Structured data retains full values. Comparison never
activates a revision, modifies source or establishes finding validity.

In the shell, `threats models` or `6 MODELS` from a threat page opens saved
revision history. Arrows select an exact revision without changing the active
pointer. Enter reads its authenticated document; Tab switches between the
shared context summary and complete JSON while retaining each reading position.
PgUp/PgDn and Home/End page through the full content, including at 40x12.
`b` records a baseline and `c` compares it to the selected exact revision through
`threat-model:diff`. Full before/after values and comparison coverage remain
readable. `a` explicitly activates the selected revision; `r` restores it as
a new active revision. The receipt names the original subject even if selection
moves while the operation runs. Exact labels survive a manifest refresh.

These history actions use the shared prepared dispatcher. Read/diff/activate/
restore receipts carry the canonical target and exact revision identities;
foreign-target and changed-digest results cannot replace the requested read.
Unavailable objects remain visible errors with explicit local retry. Background
completions retain the current navigation and draft. Escape restores the prior
projection and scroll, and paste returns intact to its composer. Plain output
retains complete document data. Browsing and comparison make no model requests.
The existing `m/M` compatibility shortcut is labeled as activation. Restart
retains stored revisions and the active pointer; browser baselines and cursor
positions remain session state.

Activation, restore, adoption, manual revision copies and selective regeneration
are auxiliary context actions with `phase_result: false`. They cannot replace a
Map attempt. Explicit workspace-management commands retain their existing
authorization; building/importing and accepting Map evidence remain separate.

`campaign:study contextBaselineRunId=<run>` drafts a separate fixed candidate
study against one named completed `sast:scan` pass. Choose a different immutable
`scanInput.threatModelRef`. Exact context or explicit omission must be recorded;
an implicit active context is insufficient. The baseline needs its authentic
consumed condition receipt, prepared scan input, complete per-engine receipt
and durable investigation accounting. A changed SHA, content tree, scope,
options, model, runtime, prompts, engine or descriptor set refuses context-only
planning. This conservative comparison can also refuse an older tool revision.

The existing scan-batch plan adds optional `contextExperiment` schema-1 metadata:
baseline run/investigation, baseline and candidate condition keys and a digest
of the prepared input with only context removed. It inherits the baseline's
investigation when unspecified and rejects another investigation id. Approval
authenticates the baseline again. Candidate passes retain one identical-condition
key and fresh discovery sessions. They require their own exact plan approval;
the baseline is never rerun and workers cannot expand either plan.

In `scan batch --prior-run <run>`, select **Context comparison**, choose and
inspect the candidate in **Source and context**, then prepare and approve it.
The shell reads the existing allowance without approving or resetting it.
A failed read blocks preparation; press `r` to retry. Dismiss an error banner
with Esc first if it captures input.
After a plan is frozen, Enter on Context comparison lists its actual candidate
passes. Enter opens the existing run comparison; Esc restores the selected
pass. Missing runs remain unavailable, partial runs retain their recorded status,
and comparing starts no work or decisions. `x` clears the comparison while
preserving accounting and completed work. Restart reads the same frozen plan.

Context changes invalidate historical usage calibration. Unknown dollars stay
unknown and all provider attempts share existing call limits and protected
review capacity. Run comparison discloses both exact contexts and source
identities; a missing observation cannot establish a fix. This is a candidate
versus one historical pass, not a multi-case permutation matrix or causal metric.
See the [context experiment assessment](assessments/context-experiments-2026-10-07.md)
for execution evidence and remaining work.

### Finite context cases

The optional `campaign:study contextCases` array contains two to eight cases,
each with `id`, `label`, an exact `threatModelRef` (or explicit null omission),
and optional `passes`. Missing passes inherit `trials`. `baselineCaseId` must
name one included case. Case ids and context references must be distinct, and
the total must not exceed 100 jobs. This option cannot be combined with a
historical `contextBaselineRunId`.

The existing campaign store records a `context-matrix` plan with schema-1
`contextMatrix` metadata. Each case freezes prepared input and its own condition
key. Source, scope, model, runtime, options, prompts, engines and descriptors
must agree across cases. Approval covers the exact complete job list and shared
allowance. Reading or editing cases starts no work. In the case list, Enter
inspects the selected exact revision and Esc restores its selection. `n` edits
its display name; Back retains the unsaved field and cursor. An inspected
replacement applies only to that case and refuses duplicate exact revisions.
Names, identities, baseline roles and repetitions remain separate. Any changed
case needs a new immutable plan and approval; spending remains recorded.
Existing single-batch receipt
readers reject matrix input; use `ContextMatrixReceipt` and
`ContextMatrixOccurrenceReport` for this kind.

For a context bound to the current root lineage, new cases record optional
`omissionScopeSha256`. This permits explicit context omission to compare the
same discovery scope without changing legacy condition keys or child inputs.
Shared approval recomputes the projection. Non-root or stale lineages keep the
original scope guard. Old cases without this receipt remain readable and are
not rewritten; a root/omission experiment needs a separately approved new
matrix. Source, model, runtime, engine, prompt and option guards still apply.

The shell result reader loads recorded outcomes in the background and refreshes
on entry. Selection and pass comparison preserve their navigation origin.
Recurrence uses completed passes within the selected case. Missing observations
do not resolve findings or alter decisions. Missing accounting keeps previously
recorded consumption visible and blocks continuation until a successful read.

The matrix-aware `InvestigationReportDocument` reader rebuilds reports from the
approved frozen plan, authenticated attempt receipts, observations and decisions.
Every case retains its conditions and recurrence. Aggregate work and raw
observation counts do not combine recurrence or raise confidence. Shared
investigation consumption stays separate from parent/child cost totals. Reports
retain historical source and accepted scope limitations after source changes.

JSON, JSONL and SARIF embed the receipt; CSV and external scanner formats keep
their existing row contracts and receive a sidecar. Markdown bundles include a
receipt and per-case work summary. `report:sarif` retains its confirmed-only
selection while supporting a matrix campaign. Existing single-study APIs stay
compatible; matrix consumers select the document reader explicitly.

`report:sarif` shared dispatch selects the canonical effective confirmation
across observations of the same finding. A later observation does not erase an
earlier human decision; a later human false-positive decision reverses it. Each
result preserves decision authority and reason, its recorded source basis,
relationships, lessons and independent managed suppression state. The export
does not modify observations or decisions.

`runs[0].properties.kuzushiExport.scope` distinguishes `workspace_history` from
`investigation`. `kuzushiSourceApplicability` compares recorded observations;
`kuzushiSourceApplicabilityBasis` is `recorded_observations`, and
`kuzushiCurrentCheckoutApplicability` is `not_assessed`. Missing source evidence
stays unknown. These additive properties do not establish applicability on the
current checkout or a fix from a missing observation. The public
`ConfirmedSarifSelection` API remains compatible; callers without workspace
metadata retain selection by finding id and receive unknown source metadata.

Shared review exports also carry `reviewDecisionBasis.sourceGit` and, when
observed again, `reviewDecisionBasis.laterObservation.sourceGit`. Each contains
the full recorded `sha`, `branch` and `dirty` state, or null when unavailable,
malformed, outside this target's history or beyond the reader's 128-revision
window. These fields describe the recorded run, never the checkout at export
time. Snapshot identity and cited-file comparison remain separate. JSON, JSONL
and SARIF retain the structured fields; Markdown bundles retain them in the
manifest and display the recorded Git states with the absence of a
current-checkout assessment. CSV columns remain
unchanged; CSV and external scanner formats disclose the missing basis in their
omission metadata.

Owned, labeled fixture coverage does not certify every scanner adapter,
monorepo boundaries, live-model costs or the complete investigation workflow.

## Versioned investigation briefs

An investigation brief records operator goals, priorities and open questions
separately from source evidence. `campaign:brief` uses the shared descriptor and
dispatch path for current/exact reads and reviewed saves. It makes no model
requests and cannot complete Map, approve work, change model context or modify
finding verdicts. The default target-local id is `repository`.

Each accepted revision keeps its exact text, prior reference and target in a
bounded content-addressed object. Published revision references are immutable;
the current head is separate. Expected-revision checks and a per-brief lock
prevent lost updates. Reading an old revision does not change the current head
or active threat model. Missing, malformed, foreign or unpublished references
refuse rather than silently selecting another revision.

Optional `briefRef` on `campaign:study` and `campaign:context-study` retains the
exact authenticated revision as plan metadata. All fixed plan kinds and their
report documents preserve it. Existing digest/allowance approval covers the
metadata; edits cannot create jobs or change approved conditions. The brief
guides human planning and priorities. Scanner inputs remain unchanged by brief
selection. Optional `campaign:context-study useBriefGuidance=true` explicitly
supplies the exact selected goal to an inactive repository or file-group context
build. Its child declares `operatorBriefRef`; shared dispatch requires approved
fixed work and allowance. No goal is supplied implicitly or to other generation
tools. Whole reviewed text is bounded to 8192 bytes and is supplied without
truncation as priorities/questions, not source evidence or finding authority.
Plans authenticate the child reference against their frozen brief. Generated
context provenance records the actual reference and text byte count.

`threat-model:read` adds `data.goalState`. Recorded guidance authenticates its
immutable brief reference and exact text bytes, with `modelUseVerified=false`.
This is reference authentication only; imported context provenance does not
prove producer use. Unavailable guidance never substitutes the current head or
rewrites the context document. Exact, stored and legacy readers expose the same
inspection. Study reports add `scope.contextGuidance`; context matrices add
`scope.caseContextGuidance` keyed by case id. Scope studies keep each case's
receipt under its existing scope entry. Reports distinguish explicit omission,
unbound history and unavailable references without inspecting active context.

The study form offers ordinary multiline editing, saved/proposed review,
explicit save/use, draft retention, failed-save refresh and exact frozen-plan
disclosure. Background completion does not navigate or select a brief in a
different study. Plain output uses the same brief content and controls.
Context generation offers an explicit guidance toggle and separate frozen-goal
reader. Old receipts without `briefGuidance` retain their existing behavior.

## Stored architecture reports

`x-ray:read` reads the four existing `x-ray/` files without generation or model
requests. The shared descriptor accepts an explicit target; a direct library
call needs a target or workspace and cannot infer consent from cwd. Each file is
limited to 8 MiB, with containment and symlink checks. Missing, oversized or
invalid UTF-8 text artifacts fail without truncation or repair. SVG presence and
bounded bytes do not establish valid graph semantics.

The displayed tier and counts are parsed report claims. Source freshness,
original generation spend, producer model/runtime and context are unknown from
these legacy files. Structured `readProvenance`, `costUsdExact: false` and
warnings retain that distinction. The current reader makes zero provider
requests; the old report's generation cost must not be inferred as zero.

The reader is auxiliary Map evidence with `phase_result: false`. It cannot
accept Map, change finding verdicts or authorize additional work. Accepted
source-bound threat-model/context revisions remain the supported context path.
`x-ray:run` and its hidden alias remain exact-dispatch Labs actions. Generation
cannot complete Map and has no supported finite Map study. Target-write
authorization and Context allowance accounting are separate requirements.
Inherited Review capacity cannot fund it. Effort reaches the selected runtime;
missing provider charges display as unknown. Cancellation before a request
starts no work; cancellation after a request retains consumption and prevents
report publication. Reader qualification does not establish generation quality,
source grounding, atomic multi-file publication or scope enforcement.

The functional matrix inventories the entire operator catalog, including
excluded reproduction and vulnerability-patch actions retained for public
compatibility. Such unassigned entries are not required implementation work for
this investigation. A mode-dependent source-review tool needs separate evidence
from its excluded execution mode. No excluded implementation is changed or
executed by this scope annotation.

## Operational inspection and legacy harness metadata

`config:show`, `router:show`, `workspace:status` and
`threat-model:methodologies` inspect current metadata without a model request.
They use Operate and cannot publish a Map result. Configuration and routing
return both readable values and their existing structured data; routing does
not certify credentials or provider acceptance.

`engagement:aim` retains exact dispatch and its existing harness TOML and option
aliases as a Compatibility action. Its budget is recorded metadata, not an
enforced allowance. Result `data.compatibility` states `budgetEnforced: false`,
`workApproved: false` and `replacementTool: campaign:study`. Accepted finite
studies and explicit allowance approval remain the supported investigation path.

Startup can classify a complete current prefix of up to 32 operational-only
receipts as a fresh target requiring Setup. Cold, larger or unclassified history
keeps resume behavior and does not establish phase completion.

Explicitly reopening Setup refreshes cached active-target facts, including Git
revision and dirty state. Setup shows inspection in progress until the existing
asynchronous inspector supplies the current generation. An already pending
inspection is retained without a duplicate probe. Reopening does not start Map,
discovery or model work. Source changes while Setup remains open still require
an explicit reopen; these facts are not an atomic source snapshot.

Pending Setup keeps journey/autonomy chips and the screen-context phase label
hidden when visiting Logs, failure details, configuration or Quit. The wide rail
names the target without presenting a committed engagement. Start Map enables
the investigation presentation; reopening Setup hides it again. This does not
replace the durable workflow projection or create phase progress.

Structured failed and partial results lead with bounded status, stage, cause,
warning and recovery text. Additional error/warning counts are disclosed. The
complete payload remains in run artifacts; `failure` opens the existing detail
reader. Curated `output` text is preserved. Generic error recovery points to the
exact tool's options and recorded details, while study-specific recovery retains
its own instructions. Ctrl+_ restores cleared input without taking Navigate
mode ownership; its message names Esc as the return to the command line.

## Report choice recovery

The interactive Report surface retains operator-owned presentation choices per
canonical target directory. `S` saves the selected format, accepted destinations
for all six formats, completeness and provenance-detail preference. Explicit
export also saves valid choices. These settings are presentation state, not a
parallel tool-input or approval system; CLI export defaults do not read them.

The schema-1 files live under the operator's home `.kuzushi/v3/report-choices/`
namespace. Reads and writes are limited to 32 KiB; each destination is limited
to 4096 bytes without control characters. A changed SHA in the same directory
does not discard format/path choices, and does not carry finding decisions or
study authority with them. Target-local copies are ignored. Unknown versions,
malformed data, foreign targets and symlinked stores are explicit errors.

Opening Report restores choices once for the active target. It does not export,
select a historical study, enable workspace-history export or restore a receipt.
The selected format/filter/path remain visible before Enter exports. If saved
choices are damaged, current choices remain usable and export leaves the
damaged file untouched. `S` explicitly replaces it with the displayed values.
Editor input owns `S` while editing a path; outside the editor, both ordinary
and Shift-encoded `S` save choices. Failed persistence stays visible separately
from the export outcome. This does not establish a strict charge ceiling or
current-source applicability of historical findings.

## Generated module suggestions

Regeneration keeps existing proposal history unchanged and adds new unapproved
drafts. The initial legacy id remains stable; collisions receive a unique draft
suffix. Current run `strategy.json` lists only that generation's proposals.
Older approvals, recorded costs, corrections, source/result references and
outcomes remain with their original ids. No proposal approval increases an
investigation allowance or approves a study. The existing 4 MiB ledger limit
still fails writes without deleting history; this is not an automatic retention
policy. Exact same-run, unchanged unreviewed drafts may be reused. Reviewed rows
and unnamed runs do not reuse review authority.

Workspace corrections matching the legacy family are applied before draft
identity assignment. Version-specific corrections stay attached to that exact
proposal. Inspect the current artifact or queue to obtain the new id.
`strategy inspect <id>` reads one saved proposal without approval or execution;
`strategy` returns to the full queue. Reopening refreshes external changes.
Costs, outcome and source references wrap rather than clipping. Newest drafts
appear first within their status group. Unknown or invalid cost stays unknown,
and missing requested ids are explicit. Source/run references are recorded
metadata, not proof of current-source applicability or a verified finding fix.

`module-recommender:recommend` is retained as an exact-dispatch Compatibility
tool. The default is deterministic ranking without a model request, independent
of the configured model. It produces proposals for review, not approved jobs or
an accepted Map. Its operative phase is Operate and it has no phase result.

Explicit `useModelRanking=true` requires the selected compatible model, runtime
and an approved `allowanceRef`. Shared prepared dispatch checks the allowance
reference before runtime construction and binds Scope accounting. One tool-free
ranking request is made. Provider failures, malformed output and unsupported
picks return errors without a fallback or repair request. `maxOutputTokens`
requests 1 to 4096 output tokens, default 2048; enforcement and dollar certainty
depend on the selected adapter. Optional `thinkingLevel` overrides only the
request; omission retains runtime configuration. No model fallback is added.

Inventory uses existing cancellation, entry and byte limits. Its receipt shows
partial inspection and omitted or clipped material. Recent findings are sampled
up to 50 and do not establish complete ledger coverage. The shortlist excludes
Prove and Fix actions. These suggestions do not certify complete repository
coverage, scanner readiness or discovery scope enforcement.

Canonical run `result.json` stores the report. `recommendations` opens the shell
reader; `recommend` retains its phase-native catalog behavior. The reader finds
the latest completed or partial recommendation attempt in its bounded 100-run
history and labels an earlier report when newer activity exists. Malformed
canonical data stays visible. Existing `recommendations.json` snapshots remain
readable. Navigate-mode `r` starts explicit deterministic refresh without model
ranking or discovery. Narrow terminals use wrapped cards and normal paging.

## Historical Git baseline inspection

`coverage:baselines` lists recorded scope, phase, full commit SHA, dirty state and
run identity. `coverage:sweep` compares these historical rows with current Git
metadata. Both use shared prepared dispatch without a model. Coverage tools use
Operate with no phase result, so successful metadata inspection cannot complete
Map or authorize discovery.

A clean same-SHA baseline or an unchanged whole-repository diff can support
`current`, rendered as "tracked source unchanged". A dirty working tree, dirty
historical baseline or unavailable scope returns `source-unverified` with its
reason. A revision that Git cannot compare remains `baseline-unreachable`.
Missing root/nested baselines are reported separately. Full SHAs remain visible
in readable and structured output; each verdict precedes its baseline SHA.

These legacy records do not identify accepted context, exact dirty source content
or a verified complete discovery scope. `scopeCoverageVerified` remains false;
sweep also returns `findingFixVerified: false`. A later pass missing a finding
never changes a finding verdict through this metadata check. `.kuzushi` state is
excluded from working-tree dirtiness here; context identity requires its own
immutable receipt.

The declared `writeSkips` option and existing aliases retain explicit dispatch.
Dirty source refuses writes. A clean write rechecks the report against current
source/history, writes within a ledger transaction and rechecks source before
commit. A rejected write rolls back its skip rows. Git and SQLite are separate
systems, so this does not establish an atomic source snapshot across concurrent
external edits. Each Git subprocess has a ten-second timeout, a two-MiB stdout
limit and a 64-KiB stderr limit. These limits do not bound the entire ledger or
sweep duration. Diff/status use NUL separators and fail on invalid UTF-8 rather
than silently misclassifying a path. External diff, text conversion and fsmonitor
are disabled for these inspections.

`coverage:recommend` retains deterministic heuristic ranking from saved context,
finding paths and historical baselines. `limit` now accepts 1 through 500 and
returns both the shown recommendations and `recommendationTotal`. Results name
the canonical `target` and set `sourceFreshnessVerified: false`. Missing baseline
records do not establish that source was never scanned. Ranking is advisory and
cannot establish complete coverage, confidence, a vulnerability or a fix.

Historical Scan-phase record counts no longer generate saturation or a
gap-fill-only recommendation. Parent scans and their engines can each produce
a record, and these rows do not bind comparable context or finding yield.
The public `Saturated` reason and `all_baselines` input remain compatibility
surfaces. New recommendations ignore the latter, avoiding an unnecessary full
history read. Actual study receipts retain their completed-pass recurrence.

Coverage readers open existing SQLite databases read-only. They never initialize
or migrate schema during recommendations, baseline listing or sweep inspection.
Missing databases remain absent; schema version 0, future versions, incomplete
tables and unsafe paths fail with a repair explanation. Writable producers retain
explicit initialization. Restore an initialized backup or perform an explicit
migration before requesting reads of a legacy database. There is no guided TUI
database repair action yet.

Baseline reads refuse more than 10,000 returned rows. Recommendations read at most
10,001 current finding paths and refuse more than 10,000 instead of silently
truncating; they do not deserialize or hydrate every finding. These guards bound
materialized data. SQLite identity folding, sorting, grouping, Git inspection and
overall latency remain separate resource limits, so a returned row cap is not a
whole-workload ceiling.

### Advisory file worklist

`worklist:rank` remains a Read tool in Map, with `phase_result: false`. It can help
choose inspection order but cannot complete Map. Its declared `target` selects
the actual canonical workspace, including a child directory. Parent finding
history is not reused under a child target; an existing child finding store is
opened read-only, and a missing one is not created. The `data` object retains its
rows, citations and contributor states, adding `target` and
`sourceFreshnessVerified: false`.

`limit` accepts 1 through 500. The summary and worklist page show returned rows
against the total ranked population. `includeFanIn`, `include_fan_in` and `fanIn`
remain accepted option names, but requesting true now fails because that
contributor is unimplemented. False and the default remain supported. `deep`
remains an explicit, separate opt-in path; the default reads saved metadata and
performs no model request or implicit graph build. The current native audit does
not qualify the deep path's total traversal or cancellation limits.

The worklist gallery preserves complete paths, raw contributor values and
degradation explanations through wrapped keyboard paging. A child-target result
does not replace a parent gallery or open it as if the child result belonged
there. New captures bind to the saved context content hash, preserving the
returned cap when unchanged context is reloaded. Restart reads
the saved context asynchronously instead of requiring an attack-surface artifact
on whichever tool happened to run last. Historical run-artifact presentation
remains a compatibility source before context hydration or when context is
absent. Malformed saved context is disclosed rather than replaced. Context and source
freshness still require their own accepted provenance; these advisory readers do
not forge it. No tool implementation is removed or promoted by this change.

## Finding-page continuity

`findings:list` returns exact `page.anchors` and optional navigation values in
`page.continuityAnchors`. Both use the declared `anchor` input option. Cursors
remain bound to their original query content. A continuity value is opaque and
versioned: it prefers the exact original generation and follows a replacement
only when identity and fingerprint identify one row inside the new query.
Related variants and ambiguous generations are not selected implicitly. Missing
identity retains exact semantics; malformed or unsupported values fail without
an output-repair loop. Changing the query or identity policy resets passive
navigation as before.

Review preserves its current page, cursor, composer draft and reading position
when an observation replaces a generation. Explicit historical selections keep
their original generation and read watermark and are disclosed outside the
current list. Manual verdicts and false-positive decisions prioritize that
captured source binding. Source changes cannot silently assign a newer watermark
to an older displayed generation. Open the current row explicitly to inspect
its source before recording a current-source decision.

## Reviewed reusable lessons

The `lessons` shell reader and the prepared `findings:lessons`,
`findings:lesson-save`, `findings:lesson-review` tools use the existing finding
ledger. A new draft requires an exact generation with a human confirmation and
recorded observation watermark. It retains that generation, observation event,
source snapshot, original decision and recorded Git revision when available.
Missing Git metadata remains unrecorded. A lesson never transfers a finding
verdict to another SHA or to current source.

Every draft contains title, text, applicability and limitations. Review requires
an exact digest-bearing `lessonRef`, a reason and explicit acceptance, rejection
or retirement. The writer validates revision and origin under its existing
single-writer lock. Concurrent or stale reviews cannot overwrite a newer
revision. Editing an accepted lesson produces a new draft. A changed human
origin decision prevents acceptance and reuse; rejection and retirement remain
available. Historical revisions remain readable.

All three mutating lesson tools declare explicit approval. Headless use requires
an explicit invocation; the TUI binds its final confirmation to the exact
prepared operation. An unapproved agent tool call cannot accept or reuse a
lesson.

`threat-model:reuse-lessons` accepts an exact `threatModelRef` and zero to eight
exact accepted lesson references. It creates a separate inactive context copy;
zero references remove a previous lesson selection from that copy. The operator
inspects and selects the copy before approving scan work. Shared selected-context
readers authenticate its `reviewedLessons` against the current ledger. Changed,
retired, forged and unavailable lessons prevent scan-context loading. Exact
inspection remains available with `lessonState.usable=false` and the reason so
the operator can create a replacement copy. The active context and original
immutable objects remain unchanged.

Lesson action runs are excluded from automatic artifact context. Saved run
documents carrying reviewed lesson snapshots, and the shared reviewed-lesson
digest, are excluded too. The active compatibility mirror is indexed without
its lesson selection. This prevents general artifact search from selecting
historical lessons on the operator's behalf. Lesson generation with a model,
cross-workspace lesson transfer and lesson-aware investigation report export
remain pending. The current manual flow makes no model requests.

### Recorded evidence imports

`recon:import` reads saved Amass, httpx, nuclei, Nmap XML, Burp XML or HAR
exports. `bounty:import-har` and `bounty:import-burp` retain their exact dispatch
paths. Importing recorded hosts, notes or HTTP requests supplies evidence for
inspection; it does not scan the repository or complete its Map/Scan workflow.
HTTP request observations retain imported provenance and informational severity.

The import path is literal, including spaces at either end of a filename.
JSONL imports stop before reading when already cancelled and check cancellation
between records. A later invalid record returns a failure with its input line
and warns that earlier persisted evidence may remain. Inspect hosts, services
and notes before retrying; the operation does not roll back earlier records.
The existing 64 MiB JSONL read limit remains. These checks do not establish
cancellation during a file read/SQLite operation, capture-wide record budgets,
or complete import parity across all formats.

## Stored engine history readers

`fuzz:status` reads stored workspace markers and externally reported index
counts. It checks at most 10,000 target entries, 10,000 nonempty index rows and
64 MiB of index text. Missing roots or indexes are disclosed. Unreadable,
nonregular, linked or over-limit inputs fail explicitly; malformed rows yield
a partial receipt with their count. Cancellation is checked before inspection
and between entries and rows. Marker presence does not certify a build.

`fuzz:import` preserves its existing findings-ledger integration. Skipped
malformed rows now return partial results. Verification is an external engine
claim, with no local reproduction performed. Per-run log reads are contained
under the supplied data root. This does not add aggregate import IO limits,
interrupt an in-progress import, authenticate the original source revision or
qualify the external engine's evidence. Both readers stay Labs and declare
`phase_result: false`; stored history cannot complete a new Scan. Their exact
tool names, aliases and existing result fields remain available.
## Catalog metadata import

`taint-iris-next:import-sinks` requires `sinksPath` and imports recorded JSONL
metadata through shared prepared dispatch. Shell and run mode preserve literal
paths and public aliases. Unusable lines produce partial status and a visible
warning. Default merge refuses an unreadable saved catalog; explicitly choose
`merge=false` to replace it after inspection. Input is capped at 64 MiB and
100,000 nonempty lines; saved catalogs must fit their 8 MiB reader limit.
This runtime-free auxiliary action accepts no context or Scan result and creates
no findings. Its metadata does not establish current source or scope coverage.
