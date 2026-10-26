# Releasing Kuzushi

## Workspace-owned native source identity and phase guidance

License, dependency-policy and secret tool runs now register and verify source
identity in the selected workspace, including child-directory inspection. Child
discovery coverage stays at the child. Source identity IO is separate from
scanner read limits. Standalone secret results add the shared snapshot hashes
and source-currentness field. Existing observations and decisions are retained;
previous unverifiable workflow results require a new scan for reusable identity.

Standalone tool history no longer implies accepted Map or Scan checkpoints.
Genuine legacy scan history remains readable. When Map is missing, its next
step stays first while completed or partial later results remain available for
explicit selection. Failed recovery and stale accepted-Map guidance remain.
See [the source and guidance assessment](docs/assessments/workspace-source-guidance-2026-10-26.md).

## Rejected scope diagnostics and manual correction

`pack:suggest-scopes` adds optional `saveRejectedOutput` with alias
`save_rejected_output`. Omission preserves the earlier no-retention behavior;
there is no injected descriptor default. New `campaign:context-study` scope
plans explicitly choose retention unless the operator sets false, and include
that choice in the frozen input. Existing plans are not rewritten.

Retained `rejected-scope-output.json` has schema version 1, at most 16 KiB of
candidate text, an original byte count, completeness and a bounded failure
reason. Partial output remains readable but cannot enter the recovery action.
The file can contain sensitive text and stays separate from valid revisions.

`pack:scopes` adds `operation=recover` and optional `recoveryRef`. Together with
`draft`, these authenticate one failed campaign's retained output, current scope
head and source before saving an unaccepted revision. This starts no model
request and preserves the failed job and consumed allowance. Exclusions and
shared discovery must match the original draft.
Subsequent scope-backed study planning retains the failed producer's original
investigation and spending through authenticated run accounting, including after
acceptance or boundary edits. Missing or foreign accounting is an error, not a
new allowance.

Scope revisions add optional `correction` metadata, omitted when absent. It
records the failed output reference, model/context and corrected-draft SHA-256;
the retained artifact hash remains its existing typed content hash. Old records
remain readable without conversion. No old rejected response can be recovered
unless its text was retained. See the
[qualification](docs/assessments/rejected-scope-correction-2026-10-26.md).

Older binaries that reject unknown revision fields cannot read new correction
records. Upgrade readers before using recovery; the original revisions remain
unchanged for historical reading. This does not rewrite a saved old plan.

## Package boundaries and child-target source locations

License header checks use the nearest package declarations, including explicit
boundaries for private or undeclared packages. Parsed declarations are shared
across the license checks. Root-license recognition remains heuristic.

Normalized license, dependency-policy and secret findings from a child directory
now use paths relative to the explicit parent workspace. Retained source bytes
come from that child file. Direct and SAST directory scans converge on the same
durable finding identity, and sibling packages remain distinct. License and
dependency producer fingerprints use the workspace path. Opaque secret producer
fingerprints remain compatibility aliases. License paths retain literal Unix
backslashes. Relative inline targets and equivalent `target`/`cwd`
choices are resolved inside an explicitly selected workspace before containment
checks; its findings store and run artifacts remain at the parent.

Field names, tool names and source-snapshot formats are unchanged. Raw scanner
APIs continue to use their supplied scan root. Resolve normalized `coreFindings`
paths, ledger locations and exports against the explicit workspace. The result's
target still names the inspected subtree. Secret scanner `data.findings` retains
its engine-relative paths and legacy producer fingerprints.

Existing observations and human decisions are preserved. Earlier child-target
records can contain ambiguous locations or source captured from the parent
file. Updating does not repair that history. Rescan the intended child and
reassess affected decisions against its new source receipt. Corrected child paths
can produce different identities; review historical duplicate relationships
explicitly. A missed later finding still does not establish a fix.

## Repository index refresh and session dollars

Workspace artifact refresh now updates the optional repository-index view after
owned studies and external writers. The existing background hydration path
keeps reads bound to the active target and rejects stale target generations.
Read failures remain unavailable, with an explicit retry, rather than suggesting
that a snapshot is absent. Accepted context, investigation jobs and spending
retain their existing identities.

The global dollar chip says `session:`. Study and investigation totals retain
their own unknown-cost qualifiers and shared allowance. Structured results,
persisted artifacts and tool options retain their contracts.

## Literal whitespace in terminal evidence

Logs now wraps each message once, preserving printable path whitespace and
complete graphemes across timestamp and continuation widths. Plain output also
preserves internal spaces when wrapping long rows; repeated spaces alone no
longer cause a row to be treated as a column heading and truncated. Existing
control stripping and right-padding cleanup in plain output remain.

Long human-readable rows can therefore occupy additional lines. Structured JSON
results, source identities and persisted artifacts retain their contracts.

## Source-qualified CycloneDX references

New `sbom-scan:scan` CycloneDX documents use opaque `bom-ref` values for complete
recorded component identities. The `purl` field remains package metadata and
must not be reconstructed as a reference. Consumers must join each actual
`bom-ref`. The root reference remains `kuzushi:root`. Saved exports are preserved;
re-run inventory for corrected documents.

SPDX and CycloneDX now consume one source-qualified export graph. The shared
extraction preserves the corrected SPDX package identifiers and relationships.
Both formats omit and disclose missing or ambiguous endpoints while retaining
all canonical component records and raw edges. One combined message names the
omitted count. The additive `data.cycloneDxExport` records counts and candidate
references. Both diagnostic objects add `uniqueComponentCount`.

CycloneDX metadata retains omission details in
`kuzushi:omittedDependencyRelationships`. Its dependency compositions are
`incomplete` when an observed edge cannot be mapped and `unknown` otherwise.
Absence of outgoing evidence does not create a dependency-free leaf. Each
generated document has a fresh serial number, which identifies that document
and does not authenticate a Git revision or installed dependency resolution.
Public options, report structs and stored artifacts need no migration. See the
[verification and limits](docs/assessments/sbom-cyclonedx-source-references-2026-10-26.md).

## Source-qualified SPDX package references

New `sbom-scan:scan` SPDX exports use opaque package identifiers derived from the
complete recorded component identity: ecosystem, name, version, manifest path,
scope and package URL. Identical component records share one SPDX package.
Consumers must read each package's `SPDXID` and join relationships by that value;
do not construct the former ecosystem/name identifier. Saved historical exports
are preserved. Re-run inventory to obtain corrected exports.

Dependency endpoints resolve only within their recorded source manifest or
lockfile. Missing or ambiguous endpoints produce no guessed SPDX relationship.
The additive `data.spdxExport` records emitted counts and every omitted edge with
its source and candidate IDs. Raw `data.components` and `data.dependencies`
retain their contracts and full observations. The output summary discloses
omissions, and the standalone SPDX document retains them as annotations.

Each export now has creation and annotation timestamps, a fresh document
namespace and explicit document-to-package `DESCRIBES` relationships. The
namespace identifies the generated document, not a Git revision or an atomic
source snapshot. Version-specific relationships remain unknown when the raw
name-level graph cannot distinguish them. CycloneDX has the separate reference
and composition correction above. Full semantic and ecosystem qualification
remain open. Public tool options, report structs and stored artifacts need no
migration.

## Setup context drafts after restart

Setup now captures supplied options through shared descriptor validation before
freezing context work. Stored global runtime-role settings remain in their
operator configuration instead of becoming unknown threat-model options after
restart. Canonical aliases, explicit overrides and workspace policy checks are
preserved. Shared context-study preparation applies its finite-action defaults
before approval. This repair selects no model, allowance or additional job.

## Recorded execution status in investigation reports

Investigation attempt receipts add optional `runStatus`, read from the saved run
metadata without repair. It remains separate from `scan`, which is the engine's
phase receipt. Cancellation can be known even when no engine outcome exists.
TUI attempt history now names recorded cancellation, interruption or failure
rather than presenting those executions as missing outcomes or successful scans.
Missing or malformed run metadata remains unknown; names never imply a status.

JSON, JSONL, SARIF and Markdown investigation receipts include this additive field
when recorded; schema version 1 remains. Old receipts and unknown status values
remain readable. Consumers constructing the public Rust
`InvestigationAttemptReceipt` must initialize `run_status`, using `None` when no
recorded metadata is available. Re-export to obtain recorded statuses in new
reports. Stored historical exports are preserved.

## Current review counts across scan passes

Campaign status, the TUI trend, shared confirmed SARIF and the CLI gate now read
recorded decisions against current canonical findings. A carried confirmation
survives a new observation row; a later human FP replaces that confirmation once.
Human priority and exact-row decision scope follow the shared review resolver.
Filtering or paging the Review list does not change workspace trend totals.

Field names and legacy observation-row selection APIs remain compatible.
Previously saved trend-history points may contain observation-based counts and
are preserved. Re-run a current status or export to obtain corrected totals;
old snapshots are not rewritten. Exact zero no longer displays as a negative
spend, and unknown-spend flags remain unchanged.

## Native observation sources and exported revisions

The aggregate native scan now binds observations to the authenticated source
snapshot captured before execution and retains cited files as content-addressed
blobs. SAST reuses its existing snapshot. Standalone native orchestration captures
one snapshot before discovery. Native source retention has a 64 MiB aggregate
limit per batch. Changed source, invalid citations, cancellation or exhausted
retention leave observations unbound and disclose a source-binding limitation.
Nontext or unavailable cited files cannot receive this source binding.
This path does not reread live files to manufacture substitute source evidence.
Previously recorded observations are preserved, including unknown Git metadata.

Native coverage writers use schema version 3 and add optional `sourceBinding`.
Readers continue accepting versions 1 and 2. A source-binding limitation makes
coverage partial independently of scanner errors; it does not assert that the
scanner failed to inspect the cited file. Strict coverage consumers must accept
version 3 and distinguish these two limitations.

Workspace export provenance adds `runGit`, `observationSource` and
`relationshipSources`. The first describes the matching saved run checkout.
The second identifies the exact observation generation, run, snapshot, tree,
blob and recorded Git metadata. The third contains the distinct generations
referenced by exported relationships, including older endpoints after every
current finding has been observed again. It is not a full observation-history
export. Unknown source metadata remains null even when run metadata is known.
Neither a later checkout nor a missing later observation proves a fix.

JSON and JSONL include these fields in provenance. SARIF adds `kuzushiRunGit`,
`kuzushiObservationSource` and `kuzushiRelationshipSources`. Markdown bundle
manifests include the same camel-case fields and finding documents display their
recorded identities. CSV appends `run_git`, `observation_source` and
`relationship_sources` after all prior columns; each cell is JSON. Existing
column positions and workspace export markers remain unchanged.

Rust consumers constructing `WorkspaceRunExportContext` must initialize
`run_git`; consumers constructing `WorkspaceFindingProvenanceSummary` must also
initialize `observation_source` and `relationship_sources`, or use
`..Default::default()`. The additive `RecordedObservationSource` reader accepts
schema version 1 only. Re-export to obtain these fields; historical exports are
not rewritten or assigned missing SHAs.

Review now uses retained source for every saved observation, including the
current generation. Missing or loading retained source never substitutes current
bytes. Unsaved previews compare the entire displayed excerpt, including spacing,
before choosing live text. Retained-source captions identify saved run-checkout
metadata explicitly; they do not relabel it as authenticated observation Git
metadata. A current file preview with missing or unchecked retained source is
explicitly labeled as a current preview.

A decision carried through a durable finding identity can belong to either an
earlier or later observation than the selected generation. Review labels this
as a decision source check without asserting chronological order. Existing
conflict tokens and review authority remain unchanged. In particular, the legacy
`reappeared_after_rejection` token identifies a check against another observation;
its name alone does not establish that a scan happened after a human decision.

## Unsupported dependency metadata

`sbom-scan:scan` now fails when a `package.json` document is not an object,
when one of its four supported dependency sections is not an object, or when
a dependency lacks a supported string specification. These inputs previously
could return a completed empty inventory or dependency edges without packages.
Failure names the manifest and field, retains available byte/hash inspection,
and publishes no components, dependency edges, CycloneDX or SPDX document.

Correct the source metadata and explicitly rerun the tool. Strings, including
empty ranges, aliases, URLs, local paths and Git specifications, remain accepted.
The existing object with a string `version` is retained for compatibility.
This is shape validation, not complete package-manager validation or resolution.
Tool names, options, output schemas and existing run receipts are unchanged.
The shell clears stale package claims on failure and recollects facts on restart.

## Evidence origin classification in reports

Generic `reasoning` evidence now displays as `reasoning assertion`. Explicit
`model-claim-unscored` evidence retains its model-generated classification and
stays excluded from observed-code and capture counts, including when it carries
a filepath or capture reference. The TUI and export projections share the
findings-domain classification. Existing stored observations and human decisions
are preserved.

Workspace JSON/JSONL evidence summaries add `reasoningAssertionCount`.
Its presence identifies the corrected classification in v2 exports.
`modelGeneratedReasoningCount` and its presence flag now describe explicit model
claims; generic reasoning no longer establishes automated analysis. A record
with only generic reasoning uses evidence state `reasoning_assertion`. Treat
this state as an unverified assertion. Strict state consumers must accept the
new value. Existing v2 export markers and finding-store formats are retained.

CSV appends `reasoning_assertion_count` after all existing columns. SARIF adds
`kuzushiReasoningAssertionCount`; Markdown bundle manifests add the matching
camel-case count and their detail text shows the shared origin labels. Rust
consumers constructing `WorkspaceEvidenceExportSummary` with a struct literal
must supply `reasoning_assertion_count` or use `..Default::default()`. Historical
exports keep their recorded counts; inspect original evidence kinds before
interpreting older model-origin or observed-evidence totals.

## Literal diagram links and exact finding filters

On Unix, `findings:list` `filePaths` and shell `files:[...]` filters now keep
literal backslashes distinct from directory separators. A query for `src/a\b.rs`
no longer matches `src/a/b.rs`. Windows keeps native separator equivalence, and
leading `./` remains accepted. Existing findings and decisions are not rewritten.
Queries that relied on the former Unix alias must supply the intended recorded
path explicitly. No schema or option migration is required.

Diagram finding links and scoped planning now share lexical containment checks
and preserve the same native filename spelling. A path match can include saved
revisions; it does not establish current-source equivalence or a finding verdict.

## Bounded duplicate proposal inputs

`triage:dedupe` keeps its name, existing result fields and reversible proposal
behavior. Five additive advanced options govern ledger preparation and supplied
source: `maxLedgerObservations` (10,000), `maxLedgerBytes` (8 MiB),
`maxLedgerReadMs` (10,000), `maxJudgePromptBytes` (128 KiB) and
`maxConfirmationBytes` (256 KiB). Matching snake-case aliases are supported.

Excess ledger or metadata prompt input now refuses before inference instead of
materializing the entire history. No observation is removed or silently omitted
from that read. A successful candidate selection discloses whole-file buckets
omitted by `maxCandidates`. Confirmation source reads share one invocation-local
allowance, reject symlinks, retain literal paths and report current-file digests.
Unavailable source, missing citations or oversized confirmation prompts drop the
proposal without a confirmation request. Failed source reads conservatively
retain their allowance; unknown bytes remain unknown.

`maxCandidates` values below two now select no complete duplicate bucket; the old implicit increase to two is removed.

New JSONL imports also preserve literal file aliases in findings and evidence.
Previously imported rows are retained as recorded. Replaying a completed import
keeps its old run; it cannot recover stripped characters. If original payloads
exist, use a separately reviewed import with a distinct tool label to record
corrected observations, and review their relationships explicitly.

Ordinary ledgers need no schema migration. Existing exports and full-history
readers are unchanged. Automatic dedupe prepasses use conservative defaults;
revise these limits through a separately reviewed `triage:dedupe` action.
Previously frozen work may need a fresh plan because declared defaults are part
of prepared input. Existing approvals do not authorize revised work or spending. Malformed model output fails without an automatic repair request.


## Historical baseline read limits and timestamp ties

Coverage ledger readers now enforce an 8 MiB aggregate retained-text limit in
addition to the existing 10,000-row limit. Oversized metadata returns an explicit
error without truncating or removing history. Ordinary histories need no
migration. Existing `.kuzushi/v3/coverage.sqlite3` schema version 1, findings,
context objects, run receipts and public options are unchanged. Back up and
archive oversized derived metadata deliberately before requesting history advice;
the reader performs no automatic cleanup. Restoring a valid saved ledger restores
inspection without altering finding decisions or source.

Equal baseline timestamps now select the last stored row across modes. This
tie-breaker describes database storage order, not finer completion time, Git
ancestry or a fixed finding. See the
[history reader evidence](docs/assessments/baseline-history-selection-2026-10-24.md).

## Boundary context reading order

Boundary-context detail now leads with the association and preparation state,
including at forty columns. Full names, notices, exact context/source receipts
and guidance remain readable below. This is presentation only; public options,
stored artifacts, approvals and accounting need no migration. See the
[native evidence](docs/assessments/boundary-context-reading-2026-10-24.md).

## Authenticated partial context recovery

Generated partial context can be inspected and handed to Map when its finished
typed run, tool call, recorded input and exact immutable revision authenticate.
A failed queue entry remains failed; recovery grants no retry, call or job.
`campaign:context-map` adds `data.mapOutcome` and preserves partial outcomes
requiring explicit acknowledgment. Unauthenticated historical jobs remain
unavailable rather than receiving guessed inputs or substitute context.

Recorded grounding leads the context readers. Diagram details show quoted
direct source files, and scoped actions consume those references through the
existing validated planning boundary. Public options and stored schemas need
no migration. See the [native workflow evidence](docs/assessments/generated-partial-context-workflow-2026-10-24.md).

## Architecture input in scope proposals

Scope proposals now include the selected context's canonical `systemContext`
overview alongside the existing legacy overview, DFD and entry-point projection.
The architecture projection remains bounded to 8 KiB and the complete proposal
input to 64 KiB. Saved limitations distinguish omitted context from selected
sections omitted by size. No global active-context substitution is introduced.

Scope review puts recorded input facts before long membership and source
receipts. Drafts advertise acceptance, and multiline Map summaries keep their
paragraphs. Public options and persisted schemas are compatible; historical
proposals retain their original limits and prompt hashes. See the
[context handoff evidence](docs/assessments/scope-context-overview-2026-10-24.md).

## Context catalog phase ownership

`threat-model:models`, `threat-model:revisions` and `threat-model:diff` now declare
`phase_result: false`. Their receipts cannot bypass fresh Setup or become a
selectable Map result. Recovery excludes known catalog-only phase attempts from
the phase projection and preserves raw history. Actual context artifacts still
support investigation resume. Tool names, inputs, outputs and persisted schemas
are compatible. Frozen work bound to an older descriptor digest must be prepared
and approved again before execution; completed receipts and spending remain.
See the [startup and history evidence](docs/assessments/context-catalog-phase-2026-10-24.md).

## Report recurrence and recorded source comparison

The context matrix Report recap shares the case reader's literal location and
severity presentation. Source and allowance precede recurrence; `p` details add
complete observation references. Run comparison derives matching, differing or
unverified content notes from recorded artifacts. Missing content never becomes
known merely because Git SHAs match. Plain output preserves the same meaning.
These are presentation changes; no persisted artifact or public tool migration
is needed. See the [native Report and source comparison evidence](docs/assessments/report-source-recap-2026-10-24.md).

## Literal finding paths and context matrix evidence

Agentic and generic finding adapters preserve path whitespace. Agentic merging
and prior-identity reuse preserve case and native path semantics. Ordinary v3
producer fingerprints stay stable. New producer and structural identity keys
encode paths changed by legacy normalization with the reserved
`kuzushi-literal-path-v1:` component; real filenames beginning with that tag are
escaped too. Fingerprint and persisted artifact schemas remain unchanged.

Existing records and human decisions are not rewritten. A new observation for an
affected literal path may have a different identity. Do not automatically migrate
an old verdict, repair historical paths by guessing, or treat absence as a fix.
Inspect the exact source and record a fresh observation instead.

Matrix results now show claims and locations before exact case/source and
observation receipts. Narrow paging and End/PageUp retain all evidence; plain
output includes every case. These presentation changes need no artifact migration.
See the [native evidence and remaining display work](docs/assessments/context-matrix-evidence-2026-10-23.md).

## Bounded general context filename input

General context builds reuse the canonical bounded inventory and add
`provenance.repositoryInventory` schema 1 plus tool-data `repositoryInventory`.
The base-synthesis receipt records the exact filename list, its digest, limits
and exclusions separately from inspected source. Refine retains a historical
synthesis receipt and does not claim a new filename input. Existing contexts and
public options need no migration. Complete enumeration can include bounded
content-prefix inspections; incomplete enumeration still blocks source selection.

The explicit Map control opens an authenticated already recorded result without
another tool run, including when Activity auto-open is disabled. Background
completions retain focus ownership and Map acceptance remains explicit. See the
[general context and native workflow evidence](docs/assessments/general-context-inventory-2026-10-23.md).

## Study outcome wording and refreshed receipts

Human study summaries distinguish completed work, an optional severity cutoff
and proof. An unconfigured cutoff no longer says security is disabled. Findings
precede equivalence metadata; requested SARIF export status remains visible.
Stored gate schema, status values and exit behavior are preserved.

The in-process `FindingPageSnapshot` adds `study_gate_error`. Consumers should
surface it when an optional severity receipt cannot be authenticated. Finding
membership and its cursor remain usable; a stale assessment is not reused.
The TUI warns while retaining triage, and background refresh retains valid
receipts. Strict standalone batch reads keep rejecting invalid receipts. Existing
artifacts need no migration. See the [outcome and native recovery evidence](docs/assessments/study-outcome-clarity-2026-10-23.md).

## Investigation reader footers

Lesson, relationship, diagram, comparison, saved-result and Activity readers,
plus fixed-study views, use the existing investigation footer. Source warnings,
operator ceiling, attention, conflicts, scope, work, cancellation and allowance
remain; shell routing and notification diagnostics stay on their configuration
and diagnostic surfaces. Secondary readers retain phase orientation. Legacy
campaigns keep their existing footer. No artifact or option migration is needed.
See the [current learning and diagram evidence](docs/assessments/learning-readers-current-2026-10-23.md).

## Study reads during startup

Batch and finding-page readers distinguish an unpublished current-attempt receipt
from malformed or unauthenticated evidence. Required artifact errors add the
typed `run_artifacts::RunArtifactMissing` without changing their display text.
Study readers add `findings::BatchReceiptPending` for the bounded startup case.
Existing successful results and artifact formats remain unchanged.

The TUI preserves loaded findings and drafts while showing pending receipts. It
waits for a later store update or explicit refresh without polling the same read,
and never credits completed work without its receipts. Existing plans and saved
artifacts need no migration. See the [native recovery evidence](docs/assessments/pending-study-receipts-2026-10-23.md).

## Complete large diagrams

The TUI no longer drops nodes or flows after the first 64 valid elements of a
saved context. Existing context storage limits remain in place. Selected nodes
and boundaries bring their connected flow endpoints into the visible zone pages,
and stacked arrows preserve source-to-destination direction when selection
changes zone order. Existing artifacts, public tools and schema need no migration.
See the [scoped native investigation and open refresh defect](docs/assessments/large-dfd-investigation-2026-10-23.md).

## Local architecture corrections

`threat-model:revise` retains its exact-reference and pointer/text contract and
adds operator edits for component names, roles and trust zones, flow descriptions
and existing-component endpoints, and boundary names and descriptions. IDs,
evidence, scope and source provenance remain protected. New values must satisfy
the shared field constraints; ambiguous or unsupported endpoint IDs are not
offered. Model text regeneration keeps its narrower allowlist.

The TUI offers local role and endpoint choices, complete-value details and an
explicit apply action before review and saving. Browsing, paste and Ctrl+S in a
choice view cannot apply a value or start work. Names use one-line input. Saving
still creates a separate inactive context, with explicit inspection and study
selection afterward. Existing context and checkpoint artifacts need no migration.
Reprepare unstarted revision-edit jobs when their recorded descriptor differs.

## Generated context roles and operator Report choices

New model-generated DFD nodes require a recognized `process`, `external-entity`
or `data-store` role before compatibility normalization. Known spelling aliases
remain accepted. Missing or unsupported roles fail acceptance; legacy imports
and saved contexts retain their existing readers. This validates role vocabulary,
not architecture or finding verdicts. Reprepare unstarted jobs whose descriptor
digest changes with the clarified builder description. No stored artifact
migration is needed.

File-group structured-output rejection preserves the original cause and observed
cost without attempting a repair call. Retained diagnostics remain opt-in and
unaccepted. The failure page names its current state and exposes local inspection.

Saving operator Report choices no longer initializes target Git tracking policy
at the operator home. Containment, no-follow checks, schema version 1 and existing
paths remain unchanged. Existing choices need no migration; no ignore file is
changed. See the [scoped qualification and retained earlier failures](docs/assessments/generated-context-rejection-2026-10-23.md).

The Report footer keeps paging visible at 80 columns and labels export readiness
using the same cached-read guard as dispatch. An export declined during refresh
remains visible after loading completes and requires an explicit retry. Nothing
is queued by a declined click. Existing export artifacts and choices need no
migration.

## Complete saved-context comparison

`threat-model:diff` additively returns `data.contextStructure` with schema version
1: complete changed values, exact before/after JSON pointers, matching method,
collection order changes and recognized saved source claims on both sides.
Existing fields, selectors, module names and stored context artifacts retain
their contracts. No artifact migration is required. Reprepare unstarted jobs
whose descriptor digest changes with the updated tool description.

Unique literal IDs match across collection order. Duplicate IDs use explicitly
ambiguous positional comparison; missing IDs remain positional. Added and removed
rows retain complete objects. Missing fields remain distinct from explicit JSON
`null`. Other arrays retain their stored order. Matching context or source claims
does not establish current source, semantic equivalence or finding verdicts.

The study context reader adds Text, Graph, Source and Other comparison views.
Arrows choose a change, paging reads its complete values, and Tab preserves each
view's selection and scroll. Source distinguishes context object references from
recorded source identities. `a` uses the candidate for that study only after a
successful parent read. Comparison and retry make no model requests.

## Evidence-bound architecture context

`threat-model:build` adds `sourcePaths` (`source_paths` alias) for 1 to 256
literal repository-relative files and an exact, non-null `inheritedContextRef`.
This is an inactive, source-only single-synthesis context build through
`campaign:context-study`. It excludes `scanScopeRef` and legacy scope/build
selectors. It neither accepts discovery boundaries nor starts scans. Context
and source must still match their recorded SHA, contents and dirty state.

The additive `provenance.fileContext.receipt` records selected files, actual
excerpts, omissions, inheritance, source identity, model and run. Existing
accepted-group `scopeContext` receipts retain their format. Later selected-text
regeneration of a file context keeps its recorded membership. No artifact
migration is required. Reprepare unstarted jobs if the added descriptor option
changes their recorded descriptor digest; earlier results remain readable.

The diagram `g` action now opens this plan for the displayed immutable context.
Approval and launch remain separate. Unsaved choices require an explicit Stay
or Discard decision before leaving. Job navigation and Back preserve the parent
study and diagram within the session; restart recovers the durable job and
result through campaign history, without restoring spending authorization for
different work.

Exact-file context now reuses the source-bound scope inventory cache. Known
selected members remain usable when enumeration is partial; absent members,
unknown legacy extent and cancellation are still refused. Plans add optional
`sourceInventory`, and file-context results retain `receipt.inventory`.
These additive fields preserve JSON schema version 1 and legacy readers.
Rust callers constructing `ContextStudyReceipt` must initialize
`source_inventory`, using `None` when no extent was recorded. Selected-text
regeneration adds optional inventory evidence without changing its file group.
Source-index persistence now groups at most 128 individual journal events per
sync and projection transaction. Partial projected membership must match its
recorded tree before incremental updates; otherwise full bounded capture is
used. No event or database schema changes are required. The
[actual-cap context follow-up](docs/assessments/source-index-context-acceptance-2026-10-23.md)
records successful import, approval, generation and restart, with broader UX
qualification still open. Approval also authenticates recorded inventory
metadata against the current receipt.

Evidence-context planning now puts scope, call limits, protected Review capacity,
model and unknown dollar cost on the first narrow-terminal screen. Frozen
evidence and model labels remain tied to the prepared receipt. Draft model
labels respect explicit input precedence. Literal DFD paths are quoted and
inventory byte limits use exact readable units.

Inspected study context now uses the full reader area, with architecture and
source status before longer metadata. Context checks remain visible at compact
and medium widths. Catalog loading preserves the exact revision identity, and
failed checks clear the compact source-match status. Existing context, scanner
projection and artifact formats remain readable without migration. See the
[reader and live-test assessment](docs/assessments/context-reader-live-2026-10-23.md).

## Review decision write receipts

`WorkspaceReviewDecisionReceipt` adds optional `committedSeq`, the exact event
sequence of the successful decision write. The receipt retains this value even
when reading its source details fails. Its schema version remains 1; JSON
consumers must allow the additive field. Rust callers constructing the receipt
must initialize `committed_seq`, using `None` when an exact sequence is unavailable.
The existing decision-recording helpers still return the same decision IDs.

The TUI acknowledges only that saved write for the same selected generation and
submitted read version. It does not adopt a later projection version. Consecutive
manual decisions can proceed after the operator's own save, while intervening
external decisions and observations still require a fresh read. Historical
observations and prior decisions remain unchanged.

## Literal finding locations

Finding labels quote paths containing whitespace, control characters, colons,
backslashes or quotes. Line numbers remain outside the quotes. Raw finding
paths, identities and exported location fields keep their existing bytes.
Run comparison preserves literal paths in its labels, fallback keys and
possible-match comparisons rather than trimming or collapsing them. Tool
names, options and stored finding schemas are unchanged.

## Scope context provenance in reports

Scope-study investigation receipts add `scopeProposalRef`,
`inheritedThreatModelRef` and `contextSelections`. These fields retain the exact
accepted scope revision and the operator's common, local and omitted context
choices from the existing frozen study. Existing fields and saved study formats
remain unchanged. Re-export older reports to include the added provenance.
Rust callers constructing `ScopeStudyInvestigationReceipt` must initialize the
three new fields from the authenticated scope-study receipt.

## Literal scope paths

Explicit `StringList` JSON arrays and quoted operator entries now preserve
leading and trailing spaces in each string. Empty strings remain invalid.
Comma-separated shorthand retains its existing trimming behavior. Use arrays
or quoted entries for filenames with spaces at either end or literal commas.

Scope forms, scanner path resolution, accepted-scope dispatch and full-mode
scope-file lines preserve those names too. Blank scope-file lines are skipped;
nonempty lines are literal paths. Tool names, aliases and artifact schemas are
unchanged. Reprepare and approve a new plan if the updated path option
description changes a recorded descriptor digest. Failed jobs from an older
plan remain failed until an operator approves new work.

## External report scan completion

The `vuln-findings` export retains its existing schema and boolean
`scan_completed` field. Previously that field was always `true`, including
workspace history and unfinished studies. It is now `true` only when an
authenticated selected study has nonzero planned work, all of it completed,
and no pending or failed jobs. Workspace-history exports use `false` because
they do not identify a finite scan plan.

Consumers must treat this flag as completion of the selected planned work,
not proof of complete repository coverage, vulnerability confirmation or a fix.
Use the companion investigation receipt for source, scope and partial-work
details. Re-export older reports to obtain the corrected flag; saved exports,
finding decisions, lessons, tool names and options remain unchanged.

## Discovery retains rediscovered observations

`agentic-sast:scan` no longer attaches the prior-findings MCP server or tells
discovery to suppress known findings. A pass can emit a supported rediscovery;
the existing ledger retains the raw observation and consolidates its identity.
Human decisions remain separate. Explicitly supplied reviewed lessons and the
same run's bounded review context remain available.

The tool description changes with this behavior, so a recorded descriptor-set
condition may differ from an older study. Prepare and explicitly approve a new
fixed plan when the existing plan reports that mismatch. Historical plans,
spending and observations are retained. Tool names, options and artifact
formats are unchanged. Other modules can still use findings tools for their
declared review or history work. This does not change the selected runtime,
provider or model.

## Explicit historical source comparison

Automatic scan recommendations, `worklist:rank` and the Rust library helper
`recommend_scans_for_target` now use saved evidence without running Git diffs.
They do not establish current source freshness. Call `coverage:recommend` with
`compareSource=true` for an explicit comparison. Unlike earlier advisory reads,
an explicitly requested comparison propagates inspection failure.

`coverage:sweep` and explicit recommendation comparisons default to at most 32
Git diff requests and 8 MiB aggregate diff stdout. Declared `maxSourceComparisons`
and `maxDiffBytes` options permit reviewed changes within their validated ranges.
Initial sweep and skip revalidation share one allowance in tool execution.
Exhaustion stops before new baseline writes; there is no automatic retry or cap
increase. Git metadata checks keep their existing per-command limits. The byte
allowance is not a total RAM, elapsed-time or dollar ceiling.

Existing public sweep entry points retain their signatures with finite default
limits. Recommendation rows and historical artifact formats are unchanged.
Tool results add `sourceComparisonPerformed` where appropriate and a
`sourceComparison` receipt with limits, comparison attempts and diff bytes.
Reprepare cached dispatch input to see the new options.

## Scope inventory completeness clarification

`pack:scopes` derives `coverage.enumerationComplete` from the inventory's recorded
enumeration receipt. Content prefixes can coexist with complete file enumeration;
they still set `inventoryLimited` and require explicit inventory-limit
acknowledgement before new acceptance. Missing legacy completeness fields mean
unrecorded enumeration, not complete coverage. Such inventories remain readable
and require the existing acknowledgement for new acceptance. Earlier acceptance
records retain their recorded state; source and membership gates remain in force.
No tool option or artifact schema changes. Clients must keep enumeration and
content-inspection limits separate.

- Findings add accepted-scope filters: `scopeId` (`scope`, `scope_id`) and
  `scopeRecord` (`scope_record`), with `scope:` and `scope-record:` expressions.
  CLI `findings` adds `--scope` and `--scope-record`. Scope-filtered JSON adds
  `page.scopeFilter`; unfiltered CLI JSON is unchanged. The accepted-scope
  browser opens this historical view with `v` or its searchable action menu.
- Membership uses authenticated recorded requests and exact accepted records,
  including older matching observations behind current consolidated rows.
  Missing metadata is partial, not zero history. Scope, run, study and source
  constraints apply to the same observation run. The reader refuses more than
  4096 candidate runs; narrow with `run:` or `batch:`. No discovery starts.
- Existing ledger, scope, plan and allowance artifacts are unchanged. Reload
  the first findings page after upgrading because continuation cursors bind the
  extended query. Rust exhaustive `FindingListFilter` and page metadata literals
  must initialize the additive scope fields or use constructors and `Default`.
  See [qualification](docs/assessments/recorded-scope-findings-2026-10-17.md).

- Newly prepared scanner context includes the selected system overview, capped
  at 200 Unicode characters with exact truncation notices in its preview.
  Existing frozen projections and approved jobs retain their recorded bytes.
  Prepare and approve a replacement plan to include the overview in future work.
  Artifact formats are unchanged. See [qualification](docs/assessments/scoped-investigation-context-2026-10-17.md).

- Scope-study receipt reconstruction preserves a frozen scanner projection only
  when its context reference matches the restored common selection. Changing an
  override back to inheritance can prepare a new plan without changing prior
  jobs, approvals or accounting. Artifact formats are unchanged; no migration is
  required. See [qualification](docs/assessments/scope-context-replanning-2026-10-17.md).

Report retains a labeled previous read during refresh, requires current data
for export, and keeps repeated metadata in `p details`. Its
[qualification](docs/assessments/report-reader-2026-10-17.md) has 212 focused passes,
a workspace build, ten passing gates and J121 with 170 machine passes, zero
failures and 108 capture pairs. Twelve final terminal-cell replays were
inspected; eighteen human judgments remain open. All broad milestones stay
open. Publication stays a draft on main, with no new live model request.

- Scan and Report scope labels reflect the viewed page instead of a pinned
  Review finding. Screen context binds viewed run groups and discloses prompt
  truncation. Report uses the same OAuth selector as approval while retaining
  the stored identity in details. Persisted formats are unchanged. The existing
  attempt-receipt type is available through the workspace facade. See the
  [qualification](docs/assessments/screen-context-2026-10-17.md).

- Source-qualified human review retains the cited location and captured
  commit/content identity through verdict, reason and confirmation, including
  narrow terminals. Plain output keeps full location metadata. Missing Git or
  dirty state remains explicit. Decision artifacts and save-time source guards
  are unchanged; no migration is required. See [verification](docs/assessments/source-identity-header-2026-10-17.md).

- Map/Scan/Review chrome shows shared investigation call consumption across
  background workers and resumed sessions. The asynchronous reader authenticates
  viewed run bindings and rejects conflicting investigations. A narrow footer
  keeps the call counter visible; the wide rail and plain output retain protected
  Review, unsettled calls and qualified dollars. No persisted format changes or
  migrations are required. See [verification](docs/assessments/shared-allowance-chrome-2026-10-17.md).

- Partial Scan separates distinct findings from observations when a canceled
  parent has no completed stage. Count labels retain their units when wrapping.
  Selected Scan receipts and findings stay visible across terminal resize;
  pending decisions keep priority. Public artifacts and finding decisions are
  unchanged. See [verification](docs/assessments/partial-scan-counts-2026-10-17.md).

- UAF compiler selection now reaches navigation through a bounded private copy.
  `compileCommandsPath` keeps workspace-read semantics. New
  `externalCompileCommandsPath` (`external_compile_commands_path`) is an explicit
  external read, forbidden in workspace-stored options. The two options are
  mutually exclusive. Source and prepared JSON each have an 8 MiB ceiling and
  at most 100000 commands. Invalid configurations fail before model work.
- Matching helper API and health are checked before model requests. Rebuild or
  install the complete matching binary bundle. MCP navigation/metadata schemas
  add optional `compileCommandsPath`; old direct requests retain default lookup.
  Explicit selection disables repository config and driver probing while
  retaining the read-only process sandbox.
- UAF output adds optional `compileDatabase` identity and a compiler receipt in
  Replay Inputs. Source/prepared hashes identify distinct byte sequences;
  command contents and the model prompt are omitted. Old JSON defaults the
  receipt to absent. Rust `UafHuntReport` literals add `compile_database: None`
  for legacy data. Ordinary teardown removes private copies; crash reclamation
  and full restartable compiler input remain unqualified.

- `uaf-hunt:hunt` is auxiliary Labs Scan work and cannot complete Scan. Its
  exact name, JSON pair controls and artifact paths remain. Local helper I/O
  now enforces the selected deadline and cancellation, fixed frame/reply bounds
  and bounded cleanup. Repository errors and missing navigation return partial
  outcomes, with matching partial finding-run history. There is no automatic
  helper restart after transport failure.
- UAF options now declare their actual defaults and ranges: `maxAgentSteps`
  1..400 (120), `clangTimeoutSecs` 1..300 (60) and `maxFindings` 1..500.
  `max_agent_steps` and `clang_timeout_secs` are declared aliases. Shared dispatch
  refuses out-of-range values instead of silently clamping them. Existing
  requests using larger values must choose an explicit supported limit.
- UAF output adds `repoToolCalls`, optional `firstRepoError`, `maxAgentSteps`,
  `clangTimeoutSecs` and `localIoLimits`. Old serialized reports load defaults;
  Rust callers constructing `UafHuntReport` must initialize `repo_tool_calls`,
  `first_repo_error`, `max_agent_steps` and `clang_timeout_secs`. Summary copy is
  compact; `data.target` retains target identity. Explicit compiler-database
  input recovery and full source grounding remain unqualified. These controls
  do not qualify the experimental detector.

- Shared bounded source prefixes retain exact UTF-8. An incomplete code point
  at a truncated prefix boundary is omitted without inserting replacement
  characters; invalid UTF-8 source is excluded explicitly. Raw inspected bytes
  still consume the budget. Files ending exactly at the read limit are no
  longer falsely labeled truncated. Version 1 coverage adds
  `includedSourceTextBytes` and `incompleteUtf8PrefixBytes`; existing fields
  and complete-coverage semantics remain unchanged.
- Standalone invariant context accepts the gatherer's `data` up to 4 MiB,
  replacing the 128 KiB envelope limit that rejected normal default output.
  Frozen model input contains selected `id`, `filePath` and `startLine` anchors
  plus separately captured source. Lexical annotations, packs and caller
  coverage metadata are omitted explicitly. The 80 KiB prompt limit, request
  count, source limits and approval requirements are unchanged. Consumers of
  `frozenInput.surfaces` must use anchor fields; the original gatherer output
  remains unchanged and retains its complete bounded annotations.

- Investigation receipts add `reviewDecisionCounts`, separating confirmed,
  historical `toFix`, rejected FP, suppressed, deferred and accepted-risk
  decisions. Counts reuse effective decision and source-applicability checks;
  decisions needing reassessment remain pending. Existing `reviewedCount`,
  `confirmedCount`, finding rows, decisions and severity fields are retained.
  This is additive to version 1 report outputs; historical artifacts are not
  rewritten. Rust callers constructing `InvestigationReportReceipt`,
  `InvestigationReportEvidence` or `InvestigationReportSummary` must initialize
  `review_decision_counts`. `WorkspaceReviewCompletion` adds `decisions`.
  Report's header and footer use the selected study or workspace-history
  projection, with explicit loading/unavailable states and FP/deferred totals.
  `load_workspace_review_summary` reads full workspace export membership on a
  read-only ledger snapshot, separate from the selected Scan and list filters.
  A missing ledger is empty without creation; damaged ledgers remain errors.
  Report `r` refreshes its reads and preserves choices.
  Reads carry the last observed ledger watermark. Missing or older known
  ledgers fail without creation; an unknown fresh ledger may still be empty.


- Standalone systems stages are no longer expanded into the bundled systems
  engine through `sast:scan tasks`. The deprecated values
  `systems-hunt:systems-context-gatherer`, `systems-hunt:systems-invariant-extract`,
  `systems-hunt:systems-trigger-synth`, `deep-semantic`, `deep-semantic-hunt` and
  `systems-hunt:deep-semantic-hunt` now fail before admission with exact-action
  planning guidance. Standalone tool names remain. Existing plans are not
  rewritten or widened. Canonical legacy bundle names remain explicit opt-ins;
  the trigger-generating workflow is outside this source-only investigation.

- `chrome-rce:review-trigger` now produces auxiliary Labs Map review hints
  from committed path changes. It no longer inserts vulnerability findings or
  completes Scan. The action name, `diffBase` alias, `count`, `changedFiles`,
  empty `findings` and nullable `persisted` fields remain; consumers that used
  path-derived findings must read `reviewHints` instead. `countKind` identifies
  the hint count. Existing historical findings and decisions are unchanged.
  The shared descriptor adds `maxChangedFiles`, `maxGitOutputBytes` and
  `gitTimeoutMs`. Comparison records the requested base commit, actual merge
  base and HEAD separately. Dirty, staged and untracked content stays excluded.
  The prior implicit scanner prerequisite is removed. Git work has one deadline,
  cancellation, explicit capture limits, NUL framing and selected-target paths.


- Hidden `taint-iris-next:hunt` is now auxiliary Labs Scan work, matching the
  experimental decomposed discovery action. Exact dispatch, options, default
  mode and legacy data status strings remain available. Neither deterministic
  planning nor model candidate output can complete Scan. Invalid model output
  remains a failed result and failed finding run even when the operator opts
  into retaining deterministic review candidates. Candidates, errors, retry
  counts and cost uncertainty remain visible. Historical receipts are unchanged.


- Narrow Replay results lead with saved output rather than repeating the
  summary before it. The complete saved summary remains below the output;
  recorded bytes, wide receipts and plain output are unchanged. Cost labels
  keep exact, estimated, lower-bound and unavailable states. Requested scope
  is explicitly labeled `Scope` in compact and rail summaries.
  Large submitted commands fold in Logs. `z` opens the reader and `c`
  explicitly shows or folds command text, with independent reading positions.
  Normal typing, durable command history and plain output remain complete.

- Standalone `systems-hunt:systems-invariant-extract` now drafts unverified
  safety assumptions as hidden auxiliary Labs Map work under Context allowance.
  It requires explicit `context` data from `systems-hunt:systems-context-gatherer`;
  implicit collection is removed. The tool name and `data.invariants` fields
  remain compatible. `maxInvariants` and `maxSourceBytes` are additive limits.
  Legacy pipeline controls remain declared for compatibility but explicit or
  stored values fail with migration guidance. The standalone path uses one
  tool-free request, retains selected reasoning when no override is supplied,
  validates literal source quotes and never repairs malformed model output.
  Result and authenticated supplied Inputs are separate Replay documents.
  Drafts accept no context, import no findings and complete no phase. Bundled
  research paths remain unqualified and are not covered by this migration.

- Observed model-backed nested dispatch retains optional version 1
  `inherited-allowance.json` after checking ledger identity and before admission.
  It records the offered grant reference, accounting run and work category;
  original `input.json` is unchanged. Retention grants no work or provider call.
  Replay labels inherited grants separately and attributes counts to the
  accounting run rather than claiming isolated child charges. Missing legacy
  metadata remains not recorded; damaged or missing retained bytes are
  unavailable, with no fallback to cached grant data. `RunRequestContext` adds
  `allowance_origin: RecordedAllowanceOrigin`; Rust callers constructing that
  reader value must set its origin. Existing artifacts remain readable.
  The new optional leaf reserves label `Inherited accounting context` and kind
  `json` in the manifest contract. Custom artifact producers should use their
  own filenames for unrelated data.

- Internal `taint-iris-next:codeql-db` now requires an approved Context
  allowance before model-backed preparation. Its existing explicit repository
  execution consent is separate: neither approval substitutes for the other.
  It is auxiliary Labs Map work and cannot complete Map or Scan. The action
  operates on the whole bound target; accepted discovery membership is not
  supported. Its exact name, prompt override and existing options remain;
  canonical `allowanceRef` is additive. Existing results remain readable.
  Deterministic `codeql:create-db` retains its separate runtime-free contract.
  Options now includes the shared descriptor purpose in scrollable detail and
  plain output, keeping the selected option value first.
  See [repository preparation accounting](docs/assessments/repository-preparation-allowance-2026-10-17.md).

- Model-backed nested dispatch now requires the child's work category to match
  its inherited allowance binding for read and workspace-write actions too.
  Context or discovery work cannot consume a parent's protected Review capacity.
  Correctly categorized nested work keeps the existing runtime wrapper, with no
  additional reservation until a provider request. Model-free work is unchanged.
  Callers that relied on borrowing another category must plan and approve the
  child work explicitly. Tool names, option schemas, stored artifacts and models
  are unchanged. See [inherited allowance evidence](docs/assessments/inherited-allowance-2026-10-17.md).

- Deep discovery retains `prepared-model-input.json` before runtime entry.
  Its version 1 envelope records `runId`, `tool` and the existing input data,
  with a 1 MiB encoded limit. Failed and canceled receipts and recovered
  interruptions expose its authenticated document in Replay Inputs. Retention
  does not prove provider delivery, cost or completed discovery. Retention
  errors stop the request; a new request needs a new run identity. Existing
  results and public tool/manifest contracts remain compatible. Other tools
  do not acquire prepared-input retention implicitly.

- Deep discovery now binds stored observations to the original authenticated
  workspace snapshot and retained full cited-file bytes. Insertion uses captured
  bytes for evidence, grounding and identity hints; later working-file edits
  cannot replace them. The additive `publicationSource` receipt reports the
  captured source and byte limit. New descriptor option `maxSnapshotBytes`
  defaults to 16 MiB, with a 512 MiB aggregate ceiling and 64 MiB per-file safety
  ceiling. This limit is separate from model input prefixes. Capture failure
  withholds candidates, retains the paid request and starts no retry. Legacy
  insertion remains available for other adapters; those paths are not yet
  migrated. Shared grounding preserves literal filename whitespace at entry.
  See [captured source evidence](docs/assessments/captured-observation-sources-2026-10-16.md).

- `systems-hunt:deep-semantic-hunt` is Labs source-only Scan work under Discovery
  allowance. Explicit selected `cwes` replace implicit model class selection.
  Existing aliases remain; new `maxSourceBytes`, `scanScopeRef` and `scanContextRef`
  use canonical preparation. Effective source defaults remain 80 files and 2048
  bytes/file, now with an explicit 160-KiB total limit. `maxFindings` defaults to
  ten and excessive output fails without repair. Unsupported stage-only settings
  remain declared but refuse explicit or stored values; remove them before use.
  Missing ledger, model or matching active target fails before inference.
  Exact scope/context, frozen input, unknown cost and publication state are
  retained. Legacy threat context requires import or explicit omission.
  Report fields remain compatible. Inert artifacts now use a run subdirectory
  under `artifactDir`; consume returned artifact paths. Their additive
  `verificationStatus` is `unverified-source-only`; legacy `corroborationStatus`
  remains an engine label and does not establish independent verification.
  Structured evidence uses additive `model-claim-unscored` and
  `source-citation-unscored` kinds. Their legacy confidence value is a zero
  placeholder; readers should label them unscored. Existing kinds retain their
  confidence semantics. Model claims are excluded from source-citation trust.
  Literal source filenames retain whitespace rather than binding another path.
  Detected source drift retains unpublished candidates in the result instead of
  importing them against changed source. No tool, source execution, exploit,
  reproducer, patch or follow-up job is generated.

- `systems-hunt:deep-semantic-cwe-select` is auxiliary Labs Map planning under
  Scope allowance, with optional findings storage and no phase result. It honors
  declared source limits through shared bounded inventory. Defaults are 80 files,
  2048 bytes/file and 160 KiB total. New `maxSourceBytes` follows shared
  preparation; existing `thinkingLevel` keeps the selected runtime setting
  when omitted. Selected discovery scopes are unsupported.
  One tool-free model turn is requested with no output repair. Malformed,
  excessive or duplicate classes fail honestly. Frozen inputs, source checks and
  coverage are retained. Unused legacy options remain declared but reject
  explicit or stored values; remove them before standalone proposal work.
  `data.cwes` retains its shape. Unknown `data.costUsd` is omitted by shared normalization; use
  `observedCostUsd` for the observed subtotal and `costUsdExact` for completeness.
  The exported `DeepSemanticCweOutput` Rust fields are unchanged. Its legacy
  numeric cost remains an observed subtotal, qualified by `cost_usd_exact`.
  No model fallback, scan job, finding, module removal or manifest change is added.

Replay keeps its heading and row position visible during scrolling. Narrow
footers retain Tab, paging, Escape and the current interrupt control, including
active cancellation and notice dismissal. Exact saved diagnostic duplicates
are folded only in the focused presentation. Plain receipt ordering, source
artifacts and dispatch behavior remain unchanged. See the
[reader orientation assessment](docs/assessments/reader-orientation-2026-10-16.md).

- Replay adds a focused saved-output view for healthy, single matching results.
  Tab returns to the full receipt with separate retained scroll positions.
  Compound work, missing metadata and unavailable correlated evidence retain
  their fuller presentation. Reading starts no jobs or provider requests.
  The selected artifact is hydrated asynchronously and authenticated against
  its producing item, digest, declared byte/line counts and status. Oversized
  or unreadable output is explicit. Limits are 4 MiB encoded, 512 KiB per text
  field, 10,000 safe rows per text field, 256 messages per diagnostic list
  and 4 MiB of safe display text overall. Existing semantic
  projections keep their twelve-line limit. New additive Rust APIs are
  `run_artifacts::{RunResultDocument, single_result_artifact,
  decode_correlated_result_document, load_correlated_result_document}` and
  `SafeText::document_lines`.
  Terminal display retains whitespace and long Unicode text while applying
  existing redaction and escaped controls. One authenticated document is shared
  in memory; reopening retries a failed read without running the tool.
  Stored results are unchanged.
  Older notices yield to a new confirmation without deletion; newer alerts
  stay visible, and cancel restores the earlier notice. Catalog draft results
  add `data.baseCatalogDigestRef` and readable source/sink/count labels without
  changing catalog JSON, tool names or module manifests.

- Saved results may add `data.inputDocument = {"schemaVersion": 1, "text": "..."}`
  for historical supplied input. Deep discovery moves its readable frozen-input
  text from the primary `output` into this document. Existing `data.frozenInput`,
  `data.systemPrompt`, raw output and source references retain their formats.
  Older saved results remain readable without an Inputs page. New documents
  cycle through Result, Inputs and Receipt, with independent scroll positions;
  Shift+Tab reverses the order. Plain Replay includes both saved documents.
  All readers retain artifact authentication, redaction and existing size limits.
  Invalid or excessive input text is an explicit Inputs error and does not hide
  a valid primary result. The Rust presentation DTO `RunResultDocument` adds
  `supplied_input`; Rust callers constructing a literal should set it to `None`
  for results without this document. No module manifest or dispatch option changes.

- `taint-iris-next:catalog` now creates an immutable, source-grounded draft
  under Context allowance. It is auxiliary Labs Map work with one model turn,
  no tools and no output-repair request. It never replaces the active catalog.
  New Core actions `taint-iris-next:catalog-read` and
  `taint-iris-next:catalog-accept` provide historical inspection and explicit
  acceptance. Partial inputs need `acknowledgePartial=true`; changed source
  refuses acceptance. An intervening active edit requires its reviewed
  `expectedActiveDigest`, or `absent`, before replacement. Existing catalog
  bytes and accepted versions are retained in the content store.
  Saved-catalog consumers, including `sast:scan`, now require an exact
  `catalogDigestRef`; inspect the active catalog to obtain it. Explicit
  `catalogDigestRef=static` selects built-in rules. With no saved catalog,
  built-in selection remains available. A draft reference cannot substitute
  for an accepted catalog digest. Shell prerequisite handling no longer
  generates a catalog automatically. Existing catalog JSON, tool names and
  option aliases remain readable; Rust `TaintIrisNextInput` literals need
  `catalog_digest_ref: None` for the old unsaved-catalog behavior.

- Standalone `systems-hunt:systems-context-gatherer` now returns auxiliary Map
  context and cannot complete a phase. It uses bounded inventory and source
  prefixes without starting a code index, authenticating CodeQL or executing
  source. `maxSourceBytes` adds an aggregate source allowance. Existing file,
  prefix and surface options now enforce positive upper bounds. Pipeline-only
  options retain their names and aliases but fail explicitly when supplied to
  this standalone action; remove unused model, prompt, handoff and artifact
  settings. Bundled hunt and trigger behavior is unchanged and unqualified.
  `SystemsContextMetadata` adds optional `inspection`, preserving legacy JSON
  without that field. Rust struct-literal callers should add `inspection: None`.
  Existing surfaces, packs, tool names and published manifests remain readable.

- The shell adds `findings refresh`, which retries the current findings read
  while preserving filters, selected study, cursor and view. Existing
  `findings` and `findings filter clear` reset behavior stays available. Failed
  study reads show an unavailable state with retry and explicit workspace
  history controls, rather than zero matches. The additive core
  `findings::read_finding_page_snapshot` API returns the exact study report used
  for membership and cursor binding; `read_finding_page` keeps its signature
  and result shape. No stored artifact or module manifest migration is needed.
  Rust callers matching the public shell command enum exhaustively must add
  `ShellCommand::FindingsRefresh`.

- `findings:list` adds optional `batchId` with `batch_id` and `batch` aliases;
  filter expressions accept `batch:<id>`. Study membership is applied before
  paging while preserving global aliases and current decisions. Retained
  cancelled and superseded observations establish membership without adding
  completed-pass recurrence. Missing or unreadable study metadata does not
  widen the query. Plan, queue and gate reads now enforce a 4 MiB bound per
  document and reject linked paths. Historical documents above this limit need
  inspection before migration; no automatic truncation is performed.
  `FindingListFilter` adds `batch_id: Option<String>`. Rust literal callers
  should use `batch_id: None` or `..Default::default()` for the old behavior.
  Raw store filter readers reject study selectors because they lack workspace
  context; use the shared workspace finding-page reader. Opaque page cursors
  from older filter signatures may require reloading the first page. Module
  names, ledger artifacts and finding identities are unchanged.

- `classifier-gate:score` is an auxiliary Labs Review opinion over finding
  metadata. It cannot complete Review, change saved finding decisions or start
  follow-up work. Missing, malformed and out-of-range scores return partial
  unscored results without training history. Explicit zero remains zero;
  legacy boolean-only responses no longer manufacture numeric values. Existing
  result fields and completed history remain readable, with additive limitation
  and follow-up fields. Model requests use no tools, one turn, a 64 KiB prompt
  limit and a requested 512 output tokens. The adapter may not enforce output
  tokens or dollars; approved provider-call limits remain mandatory.
  Percentiles must be finite and strictly between zero and one. New state keys
  separate percentile histories. Matching legacy state remains readable and
  preserved; changing percentile does not silently reuse another threshold.
  Malformed, oversized or invalid state fails without reset. Persistence
  failure cannot report a saved sample. Historical thresholds remain
  uncalibrated across models and source revisions. Exact tool names, module
  manifests and public classifier types remain available.

- Vendor document tools now declare auxiliary results. Scope, attachment and
  packet work cannot complete repository Map or Scan. Assessment is an
  experimental Review opinion with an explicit Review allowance; pending jobs
  bound to Discovery need a new reviewed plan. Completed history remains readable.
  Scope inspection preserves saved bytes and profile. `clear` is declared only
  for `vendor-assessment:scope`; it clears the current draft while retaining
  earlier packets and reports. Conflicting clear/update input fails.
  Attachment receipts add capture sizes, truncation and a local source digest
  at capture time. Existing document fields and IDs remain readable. URLs stay
  unfetched references with unknown source size. Target-local option storage
  cannot supply any evidence source alias. Local input is capped at 32 MiB,
  text capture at 256000 bytes, saved scope at 8 MiB and assessment context at
  512 KiB. Missing parsed text and excessive context refuse before a model call.
  Assessment permits one turn per request and no agent tools; structured-output
  repair still requires capacity from the approved allowance. Public tool names
  and artifact paths remain unchanged.

- Chunked source planning reuses the bounded repository inventory and streams
  large files into bounded line-aligned windows. Whole-repository planning now
  follows the shared inventory's Git-tracked selection when a Git index exists;
  explicit scopes retain literal membership, including untracked and vendor
  files. Review a fresh plan because chunk membership and IDs can change.
  Planning is limited to 100000 entries/files and 512 MiB of selected source.
  Inventory inspection retains its separate 512 MiB total and 256 KiB file caps.
  Source omissions, cancellation and incomplete enumeration produce partial
  planning receipts and block execution. No scope or allowance expands.
  `FullModePlan.coverage` and `InventoryInspection.enumeration_complete` are
  additive optional fields. Legacy receipts deserialize with unknown coverage;
  completed history stays readable, and execution always requires fresh planning.
  Rust consumers constructing these structs directly must add `coverage: None`
  and `enumeration_complete: None` to legacy struct literals. Partial planning
  headlines now identify an omitted source, cancellation or incomplete inventory
  before detailed geometry. Public tool names and module manifests are unchanged.

- Scan, Report and the empty-findings view now share declared result ownership
  when reading legacy run summaries. A later auxiliary planning result cannot
  hide a blocked primary Scan or imply a clean scan, including after restart.
  Engine results referenced by an explicit scan attempt remain visible, and
  unknown historical scan summaries keep their compatibility reader.

- Chunked `agentic-sast:scan` now rejects supplied standard-only filters,
  inspection/finding/turn limits, modes and prompts, even when their values
  equal a standard default. Supplied aliases and stored values use the same
  check. Unused standard defaults are omitted from chunked prepared input, so
  preparing supported input again remains stable. Standard-only target prompt
  files are not loaded for chunked work. Pending legacy chunked plans carrying
  these settings require a fresh plan and explicit review; completed history
  remains readable. No model, strategy, allowance or work is substituted.

- Incomplete Replay readers with a healthy typed receipt and recorded issue
  open on a summary. Tab switches to the full receipt, preserving each scroll
  position. A prompt draft retains Tab; Navigate can switch without changing
  it. New runs reset the reading choice. Plain output always includes the full
  unscrolled receipt. Stored artifacts and public module contracts are unchanged.

- Standard `agentic-sast:scan` now rejects all chunked-only settings, including
  `dryRun`, `scopeFile`, retry selection and `budgetUsd`. Previously these could
  be accepted without affecting standard discovery. Clear the named stored
  setting or explicitly review a separate chunked job. The strategy is never
  switched automatically. Accepted scope and immutable context still require
  standard discovery. Tool names and stored history remain compatible.

- Chunked retry input declares JSON and accepts the advertised arrays while
  preserving stored/direct CSV strings. Empty or unknown IDs and explicit empty
  scope files now fail instead of widening or reporting empty success. The
  generic settings browser now reads structured retry selection as workflow
  input; supply it through `run` JSON. Stored CSV values remain readable. Empty
  or missing scopes require explicit correction. Missing
  explicitly selected `since.txt` also fails; only an absent implicit default
  leaves whole-repository planning available. Source-list members must be
  contained regular files without symlink components. Missing files fail.
  Regenerate and review stale retry/scope selections before new execution.
  `reuseCachedChunks` becomes a declared boolean; its legacy default stays true.
  False opts into fresh calls under a separately approved allowance. Chunked
  requests reject accepted scope/context and multiple passes; use standard
  discovery for those contracts. The hidden `full-mode:hunt` alias is auxiliary
  Compatibility. Existing history remains readable. Planning adds selection,
  execution, cache and uncertainty fields without granting work. Existing dollar
  bands remain heuristics. See the
  [source contract audit](docs/assessments/chunked-source-contracts-2026-10-16.md).

- `OptionSpec` adds optional `editableJson`, default false and omitted when
  false. Legacy structured options remain workflow supplied in shell settings.
  Descriptor authors may use `.editable_json()` for operator-authored JSON;
  this enables strict JSON text editing and grants no dispatch or spending
  authorization. Typed values remain exact; legacy JSON coercion is unchanged.
  Rust callers constructing `OptionSpec` literals must add `editable_json:
  false` to preserve legacy behavior. Older readers ignore this presentation
  flag, so structured settings require an upgraded shell to edit visibly.
  The two allocation/free arrays for `uaf-hunt:hunt` now declare it. The hidden
  Chromium heuristic is Labs and preserves partial work when its positive
  finding limit is reached. Public tool names and existing findings remain.
  See the [contract audit](docs/assessments/internal-tool-limits-2026-10-16.md).

- Investigation allowances now accept explicit zero provider calls with zero
  protected Review calls. This grants no model capacity; finite local jobs,
  human triage and stored reports remain available. Tool names, version 1
  formats, positive defaults and existing accounting remain unchanged. Upgrade
  before approving zero limits or recovering zero-limit study drafts; older
  validators enforce a positive minimum. Future increases require a new explicit
  revision, and reducing a limit cannot erase committed or unresolved calls.

- Scope sources add optional `enumerationHash`, binding the captured Git path
  list and inspected membership separately from working-file content. Staging
  an existing untracked file now invalidates inventory reuse and current-use
  approval even when SHA and content hashes are unchanged. Cache paths include
  this binding. Historical records without the field remain readable, but
  edits, acceptance, study preparation and execution require a newly built and
  accepted membership-bound scope. Existing findings, spending and completed
  history are preserved; no jobs or allowances are automatically approved.
  Rust callers constructing `ScanScopeSource` literals must add
  `enumeration_hash: None` for legacy data or the recorded binding for new data.
  Older strict readers do not understand the added field; upgrade readers
  before opening new records and retain original history when rolling back.

- Scope review compares its recorded revision with asynchronously observed
  repository facts. A differing SHA shows `SHA DIFFERS`; matching SHAs leave
  file content explicitly unchecked. `r reload` refreshes saved scope history
  and repository facts, preserving boundary approval as a recorded decision.
  This presentation hint does not authorize work or replace shared source
  validation during preparation and execution. No artifact formats change.

- Scope coverage and acceptance now name recorded omitted paths and their
  reasons, prefix-limited files, and the inspection bounds. Each path category
  previews at most 128 entries and discloses additional recorded entries.
  Existing scope references and artifact formats are unchanged. Acknowledging
  inspection limits still approves boundaries only, never scans or spending.

- Review navigation keeps `G` for finding groups and uses `O` for goal relevance.
  This removes the duplicate default `G` assignment. Both readers remain usable
  with a retained composer draft; opening them preserves its text and cursor.
  Typed `groups` and `goals` commands and configured action identities stay
  unchanged.

- Campaign status adds `dispatches`, the lifetime attempt count. Existing
  `attempts` keeps its current retry-counter meaning. Missing or contradictory
  lifetime totals serialize as null and are disclosed in the shell. Rust callers
  constructing `CampaignJobSnapshot` literals must add `dispatches: None` for
  unknown history, or the recorded total when available. Existing queue formats
  remain readable. Derived recurrence now uses each completed pass's final run;
  canceled and superseded observations remain visible with zero recurrence when
  later attempts miss them. Raw observations and human decisions are unchanged.
  Occurrence-row run references now identify actual observation sources rather
  than every run in the logical pass. The shell adds explicit `o observations`
  access to the batch Review scope; `batch clear` restores workspace history.

- Completed study acceptance now references each trial's final successful run.
  Canceled and superseded attempts remain in the original queue, findings ledger
  and investigation exports. Partial acceptance retains all attempt references.
  Report readers accept both the exact final-run set and the legacy exact full
  attempt set; arbitrary subsets remain invalid. Existing artifact formats and
  historical phase receipts remain readable.

- Goal relevance adds `findings:goals`, `findings:goal-assess` and a shell
  browser without changing finding truth or guided phase completion. Version-1
  `finding-goal-relevance-v1` diagnostic audit records retain exact published
  brief references, reviewed goal text, finding generation, observation event,
  run and snapshot identity. Revision-checked replacements and clears append
  history through the existing writer. Older tools and finding records retain
  their contracts. Exports add optional `goalAssessments` history; SARIF uses
  `kuzushiGoalAssessments` and external finding rows use `goal_assessments`.
  CSV reports the omitted history explicitly. Unsaved assessment forms stay
  session-only and are named in Quit without revealing their text. No new
  work, model selection or allowance authority is introduced.
  Rust callers constructing `WorkspaceFindingExportRecord` literals must add
  `goal_assessments: vec![]` or initialize remaining fields with `..Default::default()`.

- Private study checkpoints now cover changed ordinary discovery settings and
  unaccepted goal text as well as context cases. The additive optional
  `briefDraft` field preserves the exact prior revision, text, cursor and mode.
  Interrupted saves return to review without replay. Earlier version-1 records
  remain readable. Untouched forms create no checkpoint. Recovery starts no
  jobs or approval; stale goal saves require explicit reload and review. Failed
  local writes retain settings until Stay or explicit Discard, and Quit hides
  private goal text. Other workflow kinds keep their existing recovery paths.

- Unprepared context-case studies now checkpoint operator choices in private
  version-1 `.kuzushi/v3/study-drafts` files beside session transcripts.
  Reopening `scan batch` offers an explicit saved-draft choice. Recovery retains
  names, partial fields and cursors, baseline, passes, exact context references,
  discovery options and the original investigation identity. Recorded spending
  is read from the existing ledger. It restores no plan, work authorization or
  model runtime. Prepare and approve a fresh finite plan before execution.
  Explicit clearing or successful plan preparation resolves only adopted draft
  hashes; independent edits remain recoverable. Pending or failed writes are
  disclosed. Existing public artifacts remain unchanged; older versions ignore
  the additive private files. Recording-disabled editing stays session-only.

- Manual context-copy editors now checkpoint private text, selected fields and
  cursors while durable shell session recording is available. Version-1 files
  live in the operator's `.kuzushi/v3/context-drafts`, outside transcript and
  target artifact enumeration. Recovery requires the same canonical target and
  inspected immutable context revision; multiple sessions offer an explicit
  choice. Checkpoints carry no runtime, model selection, work or allowance
  authority. Explicit save/discard resolves adopted record hashes without
  erasing another session's later edit. Pending or failed IO remains visible.
  Disabling session recording keeps editing session-only. Existing module,
  manifest, context revision, findings and session transcript formats remain
  readable. Older versions ignore these additive private files. Context-case
  study forms also retain their existing prepared-plan recovery path.

- Repository inventory now opens a trusted root once on Unix and reads directories
  and files relative to its retained handles. Symlinked, missing and nonregular
  tracked members are omitted before membership or content accounting. Safe
  members remain in a partial inventory; replacing the root aborts publication.
  Directory collection reports progress and checks cancellation between entries.
  File inspection uses metadata and a byte-limited reader on the same opened
  handle, preventing a growing file or binary sniff from exceeding its reservation.
  Unix regular-file opens use nonblocking mode so a FIFO cannot stall inspection.
  Existing artifact fields and inventory limits remain unchanged. The dependency
  lock adds an existing filesystem library as a direct Unix dependency, with no
  version upgrade. Other platforms retain their existing contained-read adapters.
  `context:build` now returns partial, with CLI exit 4 and a recorded warning,
  when repository enumeration or inspection is incomplete. Ordinary bounded
  samples retain their existing contract. Earlier receipts remain unchanged;
  explicit later rebuilds may produce complete receipts after the source is fixed.

- Free-form `/plan <goal>` and prose submitted through Map, Scan or Review now
  prepare a fixed, budgeted `planner:propose` study. This additive Labs tool uses
  one request with no tools, delegation or output-repair loop. Prepare, approve,
  launch and review remain separate actions. `/plan` reopens a kept session draft.
  Historical proposal readers remain compatible; the unused private interactive
  planner worker is removed. Proposal actions require the original target, source,
  selected model and capability contract. Malformed or oversized output retains
  a partial receipt and cost disclosure without creating replacement work.
  Questions and proposals cannot complete Map. No exploit, reproducer or
  vulnerability patch work is introduced. Unknown dollar consumption and
  adapter-dependent output-token enforcement remain explicit.

- Finding presence or a stored scan ID alone no longer completes guided Map
  and Scan. Partial and auxiliary observations cannot bypass explicit phase
  acceptance after restart. Existing findings remain readable in Review, and
  compatible completed historical scan receipts retain their reading path.
  Phase-attempt records and public artifact formats are unchanged.

- CodeQL database and scan modules become Labs. Exact names remain, with
  auxiliary Map/Scan behavior. Database creation keeps repository-execution
  consent and additive sourceCommit/targetScope receipt fields. Successful query
  observations now return partial with explicit coverage/review limitations;
  prior finding, SARIF and error fields remain. Historical receipts retain their
  original status. Explicit dbPath must identify an authenticated managed
  database below the target's .kuzushi directory. Raw/unpromoted or stale paths
  are refused before analysis; rebuild with codeql:create-db, including its
  outputPath option for a custom managed destination. Existing provenance and
  operator promotion receipts remain required. Automatic language detection
  uses bounded inventory and fails on truncation/cancellation; pass language
  explicitly when appropriate. timeoutMs accepts one to 86,400,000 per command
  and is now descriptor-validated for both actions. Selected scan timeouts reach
  language resolution. threads defaults to one and threads/ram require one to
  4,294,967,295, without silent clamping. RAM remains a requested CLI allocation.
  No model/runtime fallback or automatic new job is added. Unused private raw-DB
  language/shape helpers are removed after all callers moved to authenticated
  managed handles; no public module or tool is retired. Whole-job bounds,
  source-authentication cancellation, live engine usefulness and UX parity
  remain unqualified.

- The Android APK module becomes Labs. `android-apk:scan` keeps its exact name,
  target-write consent and existing stage/finding fields, while becoming
  auxiliary Scan. Successful parent receipts are partial, including deliberate
  skips. Additive inputReceipt, inputRecheck, sourceVerified and coverage fields
  identify supplied archive bytes and disclose unqualified derived-source
  accuracy. Stage records retain status and code-engine errors. timeoutMs now
  reaches preparation and bundled code scanning, accepts one to 86,400,000 and
  defaults to 600,000 per process. Revise stored zero/out-of-range values.
  Parent options add jadxBin, apktoolBin, unzipBin, semgrepBin and includeLibraries;
  the executable paths keep snake-case aliases. maxApkBytes, alias max_apk_bytes,
  accepts one byte to four GiB, default 512 MiB, before extraction. Increase it
  explicitly for a larger archive. There can be three full digest reads in a
  successful pipeline; this is not a total IO or whole-operation deadline.
  Changed archive bytes during preparation refuse publication; a later input
  recheck failure retains partial observations and the initial successful
  receipt. Cancellation prevents subsequent stages from starting. Exact hidden
  tools and historical artifacts remain. Full generation isolation, original
  digest retention for failed preparation, parser/traversal bounds, real
  decompiler quality and whole-operation recovery remain unqualified.

- `recon:nmap`, `recon:subdomain` and `recon:http-fingerprint` become Labs and
  auxiliary Map. Exact names, explicit external consent, import behavior and
  existing observation fields remain. Successful active-action receipts now
  return `partial` with additive source/coverage limitations. Historical
  receipts remain readable. Passive names use `unknown` instead of `alive`,
  with historical-name and untested-liveness metadata. No database migration
  is required. `timeoutSeconds`, alias `timeout_seconds`, must be one to 300;
  revise stored zero/unbounded values before dispatch. nmap adds this option
  with default 60; subdomain and HTTP retain defaults 20 and 10. The supervisor
  bounds each process even when the executable ignores transport flags, and
  waits for bounded output drainage. Multi-source and redirect work can run
  several processes. nmap rejects flag-like targets and invalid numeric port
  lists/ranges; the port string is capped at 4,096 bytes. Domains require valid
  ASCII DNS labels, at most 253 bytes; use punycode for international names.
  Missing executable errors include the requested path. Cancellation is checked
  before storage. Live probing, CIDR fanout, aggregate row/memory bounds and
  atomic partial storage/recovery remain unqualified.

- Advisory research and harvesting keep their exact names and external-action
  authorization. They are now Labs, auxiliary Map with Learning allowance.
  Existing model-backed invocations need allowanceRef or a matching inherited
  Learning binding. Nested extraction preserves the selected parent model and
  query limits. maxCves accepts one to 32, default eight; harvest rejects more
  than 32 supplied rows before work and deduplicates exact case aliases.
  Research's former maximum of 100 and default of 20 are reduced; revise stored
  values before dispatch. Shared extraction options declare offline fixtures,
  metadata/source/context bounds, reasoning, requested tokens and model turns.
  Research adds osvFixtures, with osv_fixtures as an alias. Missing supplied OSV
  responses are failed lookups and do not fall back to live retrieval. Successful
  parent receipts are partial and add unaccepted/coverage fields, per-advisory
  extraction receipts and deferred counts. Completed catalog drafts survive a
  later allowance limit or cancellation; remaining IDs are explicitly deferred.
  Existing catalog schema and entry identifiers remain readable. New provenance
  labels source claims unverified. Reading or drafting a catalog accepts no
  lesson and starts no hunt. Live retrieval, complete scope, useful detectors,
  append deduplication and whole-operation recovery remain unqualified.

- `ndiff` is Labs throughout; exact tool names remain registered. Extraction
  keeps Map and external-action authorization but cannot own a Map checkpoint.
  `ndiff:extract-fix-pattern` now requires Learning allowance before model work.
  Tagged external actions use the same shared reservation boundary and cannot
  inherit a parent Review category. Untagged external actions retain their
  previous contract. Supply an approved allowanceRef or a matching inherited
  Learning binding; existing invocations without either now fail before a request.
  Optional reasoning inherits the selected runtime instead of forcing high.
  The declared patchPath option now reads a bounded regular file within the
  target, excluding symlinked path components. patchText remains the first
  source when both are supplied. Source and prompt limits are additive options:
  maxMetadataBytes (1 to 8 MiB, default 64 KiB), maxPatchBytes (1 to 8 MiB,
  default 256 KiB), maxSourceBytes (256 to 128 KiB, default 18,000) and
  maxContextBytes (1 to 512 KiB, default 64 KiB). The minimum context bound is
  1,024 bytes. maxOutputTokens is requested (256 to 32,768, default 4,096);
  maxModelTurns allows one to four, default one, including each repair request.
  Token enforcement depends on the provider; no strict dollar ceiling is claimed.
  Missing or malformed required output shapes reject the draft. Additive draft,
  accepted, contextActivated and versioned sourceReceipt fields distinguish
  unreviewed context from a lesson or finding. Excerpted input produces partial
  output with exact omissions. The receipt uses a full-content SHA-256 digest;
  it does not authenticate advisory claims. Cancellation stops final publication
  at stage checks. No active context or finding decisions change automatically.
  Live retrieval, full-operation bounds and useful pattern quality remain open.

- `ndiff:hunt-variants` keeps its exact name and legacy result fields. Its
  declared phase moves from Map to Scan, requiring Scan posture and Discovery
  allowance. It is Labs and cannot complete a phase. Historical receipts remain
  readable. `pattern` is now required; fixShape and vulnerableShape must be
  nonblank text of at most 4,096 bytes, with snake-case shape aliases retained.
  `maxFindings` accepts one to 100, with the descriptor default remaining 25.
  `thinkingLevel` is an optional low/medium/high/xhigh override; omission inherits
  runtime reasoning. New `includeVendored`, `maxOutputTokens` (256 to 32,768,
  default 4,096) and `maxModelTurns` (1 to 16, default four) declare previously
  implicit guidance and query limits. Snake-case aliases and maxTokens are
  accepted by prepared dispatch. Output tokens are requested, not a strict
  provider or dollar ceiling. Successful responses are partial with additive
  coverage, verification, pattern-acceptance and host source-identity fields.
  Cancellation prevents final publication at the stage check. Empty output
  does not resolve findings. Scope and useful detection remain unqualified.

- `offense-review:threat-hunt` becomes Labs, displayed as **Discover actor-guided
  observations**. It and `carlini-threat-hunt:run` keep exact names, legacy data
  fields and Scan authorization while remaining auxiliary. Successful responses
  are partial with additive coverage and verification fields. `thinkingLevel`
  is optional and inherits runtime reasoning, with thinking_level,
  reasoningEffort and effort aliases. `maxOutputTokens` (256 to 32,768, default
  4,096) and `maxModelTurns` (1 to 16, default four) apply to each initial,
  truncation-retry and repair request. Compatibility token/turn aliases remain.
  The truncation retry no longer doubles output allowance. maxActors now accepts
  one to eight and runsPerActor one to three; defaults stay five and one.
  maxFindings accepts one to 500. Lower stored values above these limits before
  dispatch. Invalid direct-capability values fail instead of being clamped.
  Cancellation is checked before work and publication. Historical receipts and
  finding decisions remain unchanged. Scope, useful output and paid partial
  publication still need qualification; no strict dollar ceiling is claimed.

- `trace:expand` keeps its name, options, Prove authorization and existing
  result fields. It is now Labs, displayed as **Draft data-flow claims**, and
  remains auxiliary. Discovery allowance is required before model work and
  cannot borrow protected Review capacity. Successful responses are `partial`,
  with additive `sourceReferencesVerified: false`, `dataflowVerified: false`
  and `coverage.complete: false`. Historical receipts retain their statuses.
  Cancellation prevents publication at explicit stage checks. Trace now shows
  only the last authenticated result's steps, questions, notes and source status;
  earlier graph rows and receipts remain stored. Legacy graph-only history
  discloses missing per-run source binding. Labels distinguish recorded claims
  from verified data flow. Review adds a `t` source-trace reader with its own
  paging surface, plain output and exact focus restoration on back. Reading
  and command drafting start no work. No persisted format, finding decision or guided
  phase order changes. Scope, citation accuracy and useful tracing remain open.

- `triage:chain-hunt` keeps its exact name, Review authorization and legacy
  output fields. It is now Labs, displayed as **Propose finding relationships**,
  and cannot complete Review. Optional synthesis uses Discovery allowance and
  preserves protected Review capacity. `maxChains` now accepts one to 32; callers
  with larger stored values must lower them. Additive `maxCandidates` (2 to 200),
  `maxPriorChains` (0 to 64), `maxContextBytes` (1,024 to 524,288) and
  `maxOutputTokens` (256 to 16,384) options retain snake-case aliases. Every member
  must resolve exactly; unknown, duplicate or nontext references reject the whole
  proposal. More than 128 proposals fails the structured contract. Additive
  `hypotheses`, `relationshipsVerified`, `sourceRevisionVerified` and
  `inputCoverage` fields disclose unreviewed metadata synthesis and omitted
  inputs. Rejected or omitted work is partial. The legacy `attack_path` field
  contains high-level source questions. The request has no source tools and
  inherits selected reasoning. Cancellation and changed member confirmation
  prevent publication at stage checks. Existing receipts and member decisions
  remain unchanged. Source-version isolation and useful detection remain open.

At 40x12, idle Review with an empty composer now keeps its selected observation
visible beside a dismissible notice. The compact reading layout applies in
Prompt and Navigate modes without switching input ownership. Full notice text
remains in logs, and Escape still dismisses warnings before navigation. Drafts,
running work, approvals, spending halts and taller viewports retain their
existing controls. Map keeps its navigation-only compact gallery contract.

Ordinary investigation views now say unknown for unmetered zero subtotals.
The Workbench header preserves typed cost receipts, including estimates,
instead of projecting a scalar and completeness flag. Cost, rail, contextual
strips and Run Focus use qualified labels; unmetered budget shares stay unknown.
Exact zero and positive observed lower bounds remain distinct. Tiny positive
amounts retain a nonzero label. Unknown spend takes precedence over optional
idle chrome in compact Workbench headers. Accounting, approved work, caps,
model selection, stored artifacts and historical free-form labels are unchanged.

- `variant:hunt` keeps its exact dispatch and existing variants, scope,
  originalFinding and persisted fields. It is now Labs, displayed as **Search
  related observations**, and cannot complete Scan. Successful results are
  `partial`, including an empty valid array, with additive coverage fields and
  warnings. An arbitrary object no longer becomes a clean search; every row
  requires nonblank file, severity and confidence, and an optional line must
  fit a positive u32. Existing path/line aliases remain. Optional thinkingLevel
  inherits selected reasoning instead of forcing high. Cancellation prevents
  publication before work and after a response. Existing receipts remain
  unchanged. Scope guidance, path/source authentication and useful detection
  remain unqualified. An empty result never resolves the original finding.

- `variant:lift-pattern` keeps its exact name and existing fingerprint,
  signature and finding fields. It is now Labs, displayed as **Draft source
  pattern**, and cannot publish a Scan checkpoint. Model calls use Learning
  accounting and cannot borrow protected Review capacity. Current effective
  confirmation is required; human rejection overrides automated triage.
  Known signature fields require bounded, nonblank values. The legacy
  `missing_guard` field remains readable. Additive draft, accepted and
  contextActivated flags identify the unaccepted result. Optional
  `thinkingLevel`, with `thinking_level` alias, inherits selected runtime
  reasoning when omitted instead of forcing high. Existing receipts remain
  unchanged. Reviewed context reuse uses `findings:lesson-generate` and explicit
  acceptance. Useful pattern quality and source-version isolation remain open.

- `taint-iris-next:finding-review` remains registered with its existing options,
  prompt paths and outputs. It now appears as Labs and **Discover taint
  candidates**, accurately naming its fresh discovery behavior. It does not
  own a Scan checkpoint; scope, coverage and useful outcomes remain unqualified.
  Cancellation blocks further work and publication at explicit stage checks,
  without claiming interruption inside backend work or a publication batch.
  Typed missing-model refusals retain their blocked, pre-execution status
  without being relabeled as exhausted allowances. Real allowance refusals
  retain their admission class. No historical receipts or decisions are rewritten.

- `ndiff:fetch-cve` remains available by exact name and now appears as Labs.
  It is auxiliary Map work and cannot publish a Map checkpoint. Supplied
  `record` and `fixtures` must be objects; a selected record must match the
  requested advisory id, case-insensitively. Malformed or mismatched metadata
  fails before online fallback. `maxMetadataBytes` limits their combined encoded
  size from 1 byte to 8 MiB, defaulting to 8 MiB. The shared advisory reader
  applies the default ceiling to its other callers too. Existing `data.record`
  and `primaryPatchUrl` remain, with additive `data.retrieval` fields for
  requested id, retrieval mode, unverified source and metadata-only meaning.
  Supplied claims are explicitly labeled unverified. Historical receipts are
  unchanged. Live retrieval and source applicability remain unqualified.

X-Ray generation is now experimental in default discovery. `x-ray:run` and
hidden `x-ray:x-ray` remain registered for exact dispatch and retain their
report paths and formats, but their results cannot complete Map. The bounded
reader remains Core. Existing reports stay readable as unassessed claims.
Generation explicitly opts into Context accounting through `allowanceRef`;
that allowance does not grant target-write authorization or permit borrowing
protected Review capacity. Effort now reaches the runtime, cancellation blocks
publication after a request, and unreported provider spend displays as unknown.
No stored reports or historical phase events are rewritten. Use an accepted
source-bound threat model for the supported Map workflow.

The canonical changelog lives in [CHANGELOG.md](./CHANGELOG.md). Update it as
part of every release commit.

## Bounded deep ranking and saved worklists

`worklist:rank` keeps its existing name, options and auxiliary Map role. Default
ranking still uses saved metadata. Explicit `deep=true` now uses one shared
bounded inventory, followed by at most 2,000 production source file attempts,
16 KiB per prefix and 16 MiB of prefixes. Inventory and prefix reads together
stay within 512 MiB. Symlinks are excluded, read capacity is reserved first,
and cancellation is checked while enumerating, reading and classifying.
Per-file retained classifier evidence is capped at 32 signals. No graph build,
model, finding observation or scan job is introduced. The advertised 1 through
500 row limit now works in deep ranking too.

Additive `systemsInspection` records bounds, read amounts, omissions and
truncation. Partial inspection degrades that contributor. Any degraded worklist
returns a usable partial result, including the default path with malformed
contributor input. Headless callers must handle partial exit 4 and retain its
result data. Complete advisory work does not establish complete source coverage
or vulnerability validity. Aggregate SQL workload remains separately unqualified.

Explicit `worklist` reading after restart can display the last retained ranking
from at most 100 run summaries. It uses bounded asynchronous artifact hydration,
checks the result target and shape, and labels current source/context equivalence
unverified. It never reranks or launches work. Missing, malformed and foreign
results offer receipt inspection instead of fabricated empty counts. The current
Map projection and context-based invalidation of live captures remain intact.
Legacy deep results disclose unrecorded inspection limits. Canonical result paths
and public gathering APIs remain compatible; no stored artifact is rewritten.

## Bounded experimental threat-to-code hints

The retained `threat-leads:build` and `threat-leads:read` actions are Labs and
auxiliary. They cannot complete Map or create scan jobs or findings. Their
unused X-Ray dependency metadata is removed; DAG metadata still establishes no
execution ordering.

Build uses the shared bounded repository inventory, then indexes at most 6,000
source files and 16 MiB of prefixes, with at most 256 KiB per file. Inventory and
indexing together stay within the existing 512 MiB inspection ceiling. Read
capacity is reserved before file IO; failed reads retain their conservative
reservation. At most 256 source threats produce hint cards per build. Larger
inputs remain in the original context and are disclosed as unprocessed.

Existing names, paths, card fields and schema version remain readable. Additive
`sourceCoverage` version 1 records bounds, omissions and truncation with path
previews capped at 128 entries. `sources.threatModelSha256` identifies the exact
consumed legacy document. The retained `sources.xRay` array is empty because
this executor does not read those artifacts. Keyword confidence describes
overlap only. Current source equivalence and accepted context are not verified.

Legacy saved cards with no inspection receipt read as partial and unverified.
Headless `run` uses its existing partial-result exit code 4 for these outcomes;
scripts should inspect the recorded status and data. Terminal resource amounts
use KiB/MiB while JSON retains exact bytes.
Malformed or contradictory cards fail explicitly. Invalid inputs and cancellation
before publication preserve prior artifacts. JSON and Markdown use separate
atomic writes; a mismatch after interruption is disclosed and explicitly repairable.
No provider calls are introduced.

Derived context now borrows at most 2,048 DFD rows per kind, inspects at most 32
references per field, and copies at most 4,096 UTF-8 bytes per text field.
Identifiers over 1,024 bytes are omitted, not shortened. Retained cards are
limited to 128 KiB each and 4 MiB together. Additive `contextProjection` receipts
record omissions, duplicate identities and shortened projections. These make
inspection partial; original context and finding decisions stay unchanged.

JSON is the publication commit point. Readers disclose missing, stale or
unreadable Markdown and exclude it from the artifact list. The build descriptor
adds `repairSummary` with default false. Set it explicitly to regenerate only
Markdown from validated saved JSON, even when current context is missing.
This performs no inventory or model work and preserves saved JSON. A Markdown
write failure after JSON commit returns partial with that distinction. The two
files are still separate atomic writes. Passive hint context uses validated JSON
and consumes Markdown only when it matches. No schema version, path or tool
name is removed. Earlier readers can still consume unmatched Markdown; upgrade
producer and consumer together.

## Internal source-class selection

`pipeline:taint-cwe-select` now declares an input-aware runtime and a required
explicit workspace. Supplying `cwes` or its `cwe` alias remains model-free.
Omitting classes requests model selection and requires an approved Scope
allowance through shared prepared dispatch. The request uses bounded supplied
source without agent tools. A repair attempt must fit the same allowance.

The class-selection result now includes selected identifiers, names and reasons.
It remains planning guidance. Both class selection and `pipeline:task-selector`
are auxiliary and cannot publish completed Scan checkpoints. Existing names,
input aliases and result data remain compatible. No scan job or finding is
created by either selector.

Quit warnings compare planning selections with their recorded defaults.
Untouched Setup defaults no longer require confirmation. Changed current or
saved phase selections and explicit rebuild requests still warn before exit,
including when the operator has deselected every default. No persisted format
changes.

## Optional assessment allowances and discovery tiers

The four model-backed `shinsa` assessment actions now require an approved
Discovery `allowanceRef`, or a matching inherited Discovery binding, through
shared prepared dispatch. An artifact-write approval alone grants no model
capacity. Requests use the selected model, supplied bounded snippets and no
agent tools. The Rust executor retains its explicitly authorized report writes.
Assessment and framework-list actions remain auxiliary and create no Scan
checkpoint. Findings and report artifacts retain their existing paths.
Action names, existing options and artifact paths remain compatible; callers
must supply the additive allowance reference before model work.

The optional `shinsa`, `tob`, `vuln-scout` and `prompt-armor` families remain Labs
when configured. Configuration establishes availability, not Core readiness.
Use `tools --all` or `modules --all` to inspect their maturity. Exact dispatch is
retained. `deep-audit:run` is a hidden Compatibility action with an independent
executor, rather than an equivalent alias for the supported Review path.

## Exact-file finding queries

`findings:list` adds the `filePaths` option, with
`file_paths` as an alias. JSON array entries are literal paths, so commas and
spaces inside a filename remain intact. `filePath` retains its existing
case-insensitive substring behavior. The new exact filter matches any supplied
path, preserves case, and normalizes path separators and leading `./`.

The shared expression grammar adds `files:["src/a b.rs","src/a,b.rs"]`.
Existing CSV tokens and literal bracket values for other keys are unchanged.
Tool filter expressions and typed shell commands preserve literal case and
repeated whitespace inside exact paths.
DFD navigation uses this exact-file query and preserves each observation's own
source history and decisions.

Rust consumers constructing `FindingListFilter` explicitly must initialize its
new `file_paths: Vec<String>` field, or use `..Default::default()`. Existing
stored findings, observations, decisions and report formats need no migration.
Page cursors bind the complete filter. Reload the first page after upgrading;
an earlier cursor is refused rather than reused for a changed query.

## Export compatibility notes

- `taint-iris-next:dataflow-plan` is Labs and auxiliary Scan preparation.
  `taint-iris-next:source-sink-trace` is a Compatibility alias of that same
  planner, with its existing name, options and payload retained. Neither can
  produce a selectable Scan checkpoint. Source traversal is iterative with
  the existing file, entry and byte limits; `.cxx` is now included as the
  declared C++ extension. Partition advice counts captured source membership
  instead of traversing again. Source-scope enforcement, in-progress
  cancellation and useful engine results remain unqualified.
  Missing-context receipts now lead with their cause, retaining full target
  paths in data. A focused module whose primary is experimental requires an
  exact tool choice; `run .` does not choose another tool or global SAST in its
  place. Existing supported primary actions retain their shorthand.

- `threat-intel:apply` is Labs and auxiliary Map work. Exact dispatch and the
  default `dryRun=true` remain available; a dry preview no longer requires a
  model or runtime. Explicit live dispatch still requires them and remains
  outside accepted scope studies. Preview output adds `planned`,
  `dispatchRequests` and `partial` counts. The legacy `dispatched` count still
  includes planned entries in dry runs. Failed child envelopes and transport
  errors now produce failed or partial parent outcomes, with child results
  retained. Skipped children are no longer counted as dispatched work.
  Historical receipts are not rewritten. The tool cannot own a Map result.
  A complete small history containing only auxiliary receipts no longer
  bypasses Setup; real source artifacts/findings and primary or unknown runs
  retain the existing resume behavior. Larger or uninspectable history remains
  conservative. Use finite campaign studies for the supported scan workflow.

- `taint-iris-next:import-sinks` retains its public name, aliases and catalog
  payload. `sinksPath` is now explicitly required. The result adds canonical
  completed/partial status and skipped-row warnings while preserving the clean
  nested `imported` label. Default merge refuses unusable saved catalogs;
  explicit `merge=false` remains available. Input caps are 64 MiB and 100,000
  nonempty lines; publication must fit the existing 8 MiB reader limit. The
  auxiliary action now declares `phase_result: false` and cannot complete Scan.
  Existing receipts and stored catalogs remain readable.

- The shell command `threats regen` now opens saved-context selection. Inspect
  a revision, press `e` to choose a text field, then `g` to prepare its bounded
  regeneration. The existing context-study flow reviews model, guidance and
  allowance before a separate launch. Results are inactive copies with their
  original parent preserved. The command no longer creates a pending context
  patch for `threats apply`; that command still handles already-pending changes.
  Existing tool names, options, context objects and saved campaigns remain
  readable. An open study draft is preserved and must be continued or closed
  before starting separate regeneration.

- `fuzz:status` and `fuzz:import` remain Labs readers with their existing names
  and aliases. Both now declare `phase_result: false`: stored engine history
  cannot complete a new Scan. Skipped malformed index rows return `partial`
  with warnings. Result data adds `verificationAuthority` and
  `localReproductionPerformed`; existing result fields remain available.
  Status adds malformed-row counts and inspection limits. It fails explicitly
  on unreadable, nonregular, oversized or linked index paths instead of calling
  them missing. `workspaceRoot` and `dataRoot` now carry external-read path
  metadata; existing string values and snake-case aliases remain accepted.
  Historical receipts remain unchanged. These changes do not qualify engine
  execution or establish original-source attribution for imported findings.

- `threat-intel:discover` moves to Labs in default discovery. Exact dispatch,
  candidate paths and existing fields remain available. Successful extraction
  now reports `partial` even with nonempty candidates because repository
  coverage is unverified. Results and newly written candidate files add
  `coverage`; existing files remain readable. Callers should retain partial
  candidates and their limitations rather than interpret them as complete
  dependency inventories. Use `sbom-scan:scan` for the inventory workflow.
  Both discovery and catalog reading now declare `phase_result: false`.
  Existing receipt files remain intact and cannot establish Map completion.

- Cargo audit now invokes the selected standalone executable and feeds a
  bounded lockfile snapshot on stdin from an isolated working directory.
  Target-local Cargo/toolchain configuration cannot silently change that
  invocation. `cargo-audit:scan` adds `binary`, `advisoryDb`, `offline`,
  `allowStale`, `timeoutMs` and `maxLockfileBytes`, with corresponding
  `cargoAudit*` options on `sast:scan`. Offline mode disables database updates
  and yanked-package checks. Network-enabled behavior remains the default;
  approval discloses it. Limits default to 600000 ms per job across captures
  and roots and 16 MiB per lockfile. Source authentication is separate.
  Direct tools now fail on a missing lockfile instead of returning a clean
  result. The legacy public unit scanner retains its empty missing-file
  behavior. Child directory scans no longer require a workspace-root lockfile;
  exact membership remains unsupported. Root finding identity is preserved,
  while independent scoped lockfiles now have distinct structural identities.
  Existing findings and report fields remain; `nativeInspections` adds snapshot
  hashes, limits, network policy and coverage disclosure.

- Shell options now open a selectable browser with an inline field editor.
  Existing `show`, `set`, `setg`, `unset` and `unsetg` commands, descriptor
  coercion, option precedence and persistent store formats remain unchanged.
  Structured workflow inputs are disclosed but edited through their owning
  plan/context surfaces. Session drafts retain their text and cursor through
  navigation and resize; they are discarded on process exit with a warning.
  Enter/Ctrl+S saves the displayed scope, and Ctrl+G explicitly chooses global
  persistence. No settings action approves work or changes frozen run inputs.

- Shared dispatch now requires an approved `allowanceRef` for model-backed
  investigation tools, including direct shell/run invocations. Explicit
  deterministic work remains available without model accounting. Guided Context,
  Scan and Review forms prepare and approve their existing finite campaign plans;
  saved unbound model commands need an approved reference before execution.
  `AgentRuntime::allowance_binding()` is an additive default-none inspection
  method for transparent wrappers and nested dispatch. Metered adapters should
  return their existing host binding; wrappers forward it. Nested work validates
  the same workspace ledger, investigation/work, revision, selected model and
  remaining capacity. It cannot replace inherited accounting. Provider attempts
  still reserve atomically at the adapter boundary. This change does not add an
  unmetered compatibility switch or approve additional jobs.

- Triage receipts add `data.unappliedOpinions` and per-result `decisionApplied`
  and `applicationStatus`. A model classification that storage policy declines
  is retained as an unapplied opinion rather than a failed persistence write.
  Existing human decisions and observation history stay authoritative. Consumers
  must not use `decisionApplied=false` opinions to remove findings or inherit
  verdicts. Legacy results without the field retain their previous interpretation.
  Genuine storage errors and missing durable identities still produce degraded
  receipts. Historical failed receipts are never rewritten by this upgrade.
  Review preflight uses its approved work category, including protected Review
  calls. Parked fixed studies resume their existing plan; ended fixed studies
  require a new approved plan for additional work.

- Semgrep now declares `jobs` (1 through 256, default 1), with `semgrepJobs`
  on the selected SAST task. This is separate from study concurrency. Legacy
  direct methods use one worker without changing the public scanner fields.
  Exact-file batches retain ordered literal membership and now allow up to
  1024 files within 12288 encoded argument bytes, including fixed arguments.
  Earlier returned batches survive later failures; there is no automatic retry
  or work expansion. Native receipts add worker and batching limits. Saved
  descriptor-bound plans need re-preparation and explicit approval. Scanner
  output limits and job deadlines remain enforced.

- Semgrep subprocess work now has a 30-minute default deadline. Shared
  `semgrep:scan` dispatch accepts `timeoutMs` (`timeout_ms` alias), and
  `sast:scan` accepts `semgrepTimeoutMs` (`semgrep_timeout_ms` alias) for the
  selected Semgrep task. Limits are positive and at most 86400000 ms. One
  prepared engine shares its allowance across job roots and exact-file batches;
  a deadline kills and reaps the process tree. Earlier completed batches remain
  partial when later work cannot complete. Native time receipts are additive,
  and approval displays the frozen allowance before execution. Source
  authentication remains separate. Existing `SemgrepScanner` fields and
  methods remain available, with the default deadline per direct invocation.
  Reprepare saved plans whose descriptor digest changed, then approve their
  exact terms. There is no automatic deadline increase. Positive remainders
  below one millisecond round up in failure text; clock enforcement is unchanged.
  Shell list input now accepts JSON arrays of strings and quoted single entries;
  unquoted comma-separated text remains available. An unquoted list entry that
  begins with `[` must use complete array syntax, a quoted single entry, or a
  literal path prefix such as `./`. Structured JSON tool input keeps its existing
  coercion contract. Malformed arrays refuse before option storage. Setting-value
  completion uses descriptor choices and never offers another option key there.

- `context:build`, `context-lite:index` and `entry-points:extract` now declare
  `phase_result: false`. They prepare source artifacts for Map and Scan;
  they cannot replace an accepted threat-model context or publish a selectable
  Map checkpoint. Execution authorization, options, output schemas and exact
  dispatch remain compatible. Reprepare frozen work whose descriptor digest
  changed. Historical preparation-only attempts remain in their original run
  and event files but are excluded from phase selection. Genuine Map attempts
  containing a primary context producer remain available. Single-tool shell
  receipts now name the tool and its actual outcome before generic run totals.

- Source-review captures add optional `citedFile` metadata. New captures can
  retain one complete text file in the existing content store, with a declared
  `maxCitedSourceBytes` limit from 1 to 262144. Legacy captures deserialize with
  no cited code. Rust `ReviewSourceCapture` literals must add `cited_file: None`
  when no code is captured; existing capture helper signatures remain available.
  Reads authenticate frozen bytes and never substitute current checkout text.
  The Review header now opens a capture/code/verdict/reason/save form. Composer
  state and source identity remain separate, and every save still uses shared
  prepared dispatch. Existing raw tool options and result fields remain.

- `findings:review-source` adds explicit capture, read and human decide actions
  through shared prepared dispatch. Captures bind target, finding generation,
  ledger cutoff, Git state and source content identity. Source or ledger drift
  refuses a save. Capture makes no finding observation or model request.
  JSON/JSONL finding exports add optional `reviewedSource`; SARIF adds
  `kuzushiReviewedSource`, and Markdown includes the human-selected capture.
  Existing `reviewDecisionBasis` retains its observation-derived meaning.
  The new `DecisionCommand::ReviewDecisionOnSource` variant preserves existing
  `DecisionWrite` literals; exhaustive enum consumers must add an arm.
  Projected decision ids can change on rebuild; event hashes retain identity.
  No database-column migration, automatic fix conclusion or source execution
  is introduced. Existing decisions and observations remain unchanged.

- `decision --json` adds version-1 `sourceReceipt` and
  `currentCheckoutApplicability=not_assessed`. Existing result fields retain
  their meaning. CLI and shell save receipts name the observation and available
  source identity behind the exact committed decision. Missing legacy source
  stays unavailable. A failed source read after commit reports a saved decision
  with unavailable source, so it does not invite a duplicate write. No decision
  is rewritten or automatically approved for another checkout.

- `runs diff` plain output reports recorded observation presence instead of
  "Resolved" or "carry forward" claims. JSON adds `observationSchemaVersion=1`,
  `observationCounts` and `observationPresence`, with finding identity, title,
  source path, tool, coverage reason and `fixStatus=not_assessed`. The statuses
  are `newly_observed`, `seen_again`, `not_observed`, `not_reassessed` and
  `unknown`. Existing JSON fields, counts and legacy Rust comparison classes
  remain unchanged; `legacyClassifications.fixEvidence=false` names their
  compatibility role. `decisionSummary.carryForward` remains a legacy counter
  and gains `sourceApplicability=not_assessed` and
  `carryForwardIsSourceApproval=false`. Clients should read neutral presence
  fields and review source-qualified decisions before reuse. CLI/TUI summaries
  display recorded decisions and differing snapshot verdicts without granting
  reuse permission. No stored finding or decision is rewritten.

- Shell `full [target]` and `pipeline [target]` now enter aggregate Setup,
  including shared finite Map planning and allowance review, instead of the
  legacy question wizard. Active target requirements and explicit path
  selection remain; failed activation and busy work still refuse entry.
  Merely opening Setup starts no work and accepts no result. Exact tool
  dispatch, CLI scan behavior and stored artifacts remain compatible.
  Legacy wizard helpers retain transition regression coverage.

- Allowance review leads with the matching immutable work receipt and keeps
  technical identities after the terms. Scan, Review, context work and scope
  or context experiments retain distinct workload descriptions. Mismatches and
  unknown records remain explicit; bounded path previews disclose omissions.
  The same paged document supplies TTY/plain output and approval availability.
  Picker phase cycling and automatic Map advancement now open finite Scan.
  Study cancellation restores the previous phase and Map selection/cursor.
  Intentional entry clears old transient notices while retaining their logs.
  Existing public module contracts and persisted artifact formats remain.

- Guided Scan navigation now opens the existing finite-study form. `plan scan`
  and an unreached `scan` offer three passes, one worker, canonical SAST engine
  options, explicit context selection and shared allowance review before work.
  The phase rail uses the same route. Completed or pending Scan results retain
  their durable reading behavior. Existing individual-tool dispatch and internal
  compatibility pickers remain available without rewriting saved selections.
  Canceling allowance review preserves the draft; leaving the form restores its
  origin. A retained notice no longer implies preparation is still running after
  cancellation. Public module names and artifact formats do not change.

- IaC scanning adds descriptor-backed `maxEntries` and `maxTotalBytes` limits,
  iterative depth-bounded traversal, actual read accounting and explicit partial
  coverage. `maxFileBytes` now rejects invalid values instead of clamping them.
  SAST adds `iacScanMaxEntries`, `iacScanMaxTotalBytes` and
  `iacScanMaxFileBytes`, with snake-case aliases, and shares their limits across
  one prepared job's roots. JSON and terminal output retain cumulative receipts.
  Direct child-directory findings now use workspace-relative paths and source
  bindings. Exact-file scopes remain unsupported and fail before discovery.
  These are configuration signals, with no target execution or model call.
  `IacScanOptions` gains `max_entries` and `max_total_bytes`; Rust callers can
  retain defaults through `..Default::default()`. `IacScanReport` gains a defaulted
  `inspection: IacInspection` field. Direct literals initialize it; old serialized
  reports remain readable, with zero/default accounting meaning unavailable
  historical inspection evidence. Existing tool names and finding fields remain.
  Re-run affected scans for source-bound, partial-aware receipts; old artifacts
  cannot retroactively prove full coverage.
  `ScanEngine::rebind_scoped_finding` adds a default path-only compatibility
  hook. IaC overrides it to retain its line or structural identity when a
  directory scope becomes a workspace path. Direct and SAST findings now share
  that identity. Other engines retain their previous behavior. Existing split
  observations are preserved; no historical merge or human decision is changed
  automatically.

- Live watcher handling now checks staged Git membership, modes, object ids and
  merge stages before treating an index write as inventory staleness. Cache-only
  index rewrites preserve known inventory. The metadata probe runs off the TUI
  thread with a two-second deadline and 16 MiB output ceiling; an unavailable or
  limited read retains the warning. Other source events remain unchanged.
  Public watcher classification and persisted artifacts retain their contracts.
  Workspace staleness precedes routing details in the full footer. Compact
  chrome keeps its warning with the operator ceiling and finding count.

- The Semgrep descriptor publishes its existing default `binary` value.
  Existing names, executable path semantics and `scannerBin` aliases remain.
  CodeQL's optional binary retains its adapter resolution instead of acquiring
  a new default. Shared dependency inspection reads canonical options without invoking commands;
  the capability picker performs it in the background and offers `r` to recheck.
  Unix presence checks reject files without execute permissions. Semgrep preflight
  consumes the same lookup, preserving structured missing-dependency failures.
  Presence is a preparation hint, not a supported-output or version guarantee.
  Semgrep preserves exact executable filenames, including trailing spaces,
  so presence inspection and execution refer to the same selected file.
  Shell text/path options now accept complete double-quoted JSON strings,
  preserving spaces and escapes inside the delimiters. Malformed quoting is an
  error. Unquoted text keeps its prior trimming behavior; typed JSON inputs and
  previously stored values keep their literal-string contract. Literal outer
  quotes can be escaped inside a quoted string.
  Stored findings and public module manifests require no schema migration.

- Finding exports add optional `provenance.sourceHistory` in JSON and JSONL,
  `kuzushiSourceHistory` in SARIF result properties, and `sourceHistory` in each
  Markdown bundle manifest entry. These preserve recorded source summaries,
  including their first/latest run references and recorded dates. They are not
  a complete observation log or evidence of applicability at another commit.
  Markdown displays up to eight summaries and preserves the rest in its manifest.
  CSV discloses omission through `provenance.sourceHistory`; the external scanner
  format continues to omit provenance. Report shows this format tradeoff before
  export. Repeated producer/signature records count as one distinct source,
  separately from confidence and human decisions.
  Rust callers constructing `WorkspaceFindingProvenanceSummary` literals should
  initialize `source_history` with an empty vector when no summaries are recorded.
  Existing stored observations, finding identity and tool options are unchanged.

- `campaign:review-study` adds a versioned Review draft in the existing campaign
  format. It freezes 1 to 100 exact observation generations, the effective
  strategy, context, source and selected model into one job and one attempt.
  Existing allowance approval preserves consumption and protects Review calls;
  approval starts no work. Generic approval can read workspace findings when
  its optional handle is absent. Legacy `triage:run` inputs remain compatible.
  Review stage receipts now add `stageKind=model-review` and a readable
  `stageLabel`, retaining `stage=haiku` as a deprecated compatibility alias.
  Consumers should select the model stage by kind and read its `model` field.
  Classification cost fields move from the incorrectly annotated dedupe row to
  that model stage. Array order and run totals remain unchanged. Historical
  receipts are preserved; use their run total rather than the old dedupe cost.
  Standard Review adds optional `sourceEvidence`, `maxSourceEvidenceBytes` and
  `sourceEvidenceRef` inputs. Cited preparation stores an immutable version 1
  source-evidence document and adds optional `sourceEvidence` to
  `ReviewStudyReceipt`. Older plans omit it and retain their existing behavior.
  Optional `sourceEvidenceFiles` selects up to 16 explicit supporting paths.
  Nonempty selections use evidence version 2 with optional `supportingFiles`
  on each observation; empty selections retain version 1. Rust callers building
  `ReviewSourceObservation` literals must initialize `supporting_files` with an
  empty vector when absent. Supporting files share the existing whole-batch
  source byte cap. New readers retain version 1 support. Older binaries reject
  version 2 or its new options rather than silently omitting supporting input.
  Evidence metadata reads are bounded to 16 MiB to accommodate path receipts;
  the raw source text maximum stays 256 KiB. There is no new queue, allowance,
  finding or job schema, and no automatic dependency expansion.
  Rust callers constructing receipt literals should set `source_evidence: None`
  when absent. No finding, campaign queue or allowance schema changes are needed.
  Saved evidence is read historically without replacing its bytes with the live
  checkout; new execution still requires matching source and exact approval.
  The Review picker prepares the bounded form before authentication, preserving
  explicit options and other paused choices. Draft completion restores the form
  without treating deferred choices as active continuation.
  New drafts add optional `observationSources`, recording each generation's
  original run commit separately from the planned Review source. Missing or
  unreadable metadata stays unknown. Older version 1 drafts remain readable;
  their absent source records are disclosed.
  Rust callers constructing `ReviewStudyReceipt` literals should initialize
  `observation_sources` with an empty vector when no recorded metadata exists.
  Broad selections now freeze raw-generation data before approval; older drafts
  containing consolidated rows can require explicit regeneration. Their stored
  plans are retained. Source aggregation follows ledger order, and repeat runs
  retain provenance without inflating distinct-source corroboration. Stored raw
  observations, decisions and source formats are unchanged.

- Standard triage reuse now requires a captured source snapshot, the complete
  review request and runtime attestation. `AgentRuntime` adds optional
  `triage_semantic_cache_identity`, defaulting to `None`; existing adapters
  execute live until they attest this specific path. Tracing and runtime handles
  preserve attestations. Failed or incomplete runs discard entries for their
  snapshot. Explicit retriage stays fresh. Persisted findings, decisions and tool
  inputs remain compatible; no provider or model fallback is added.

- Explicit generation references open pinned finding readers without requesting
  a current folded-page anchor. Earlier observations stay readable beside the
  current list, with existing selection disclosures and decision/source guards.
  No finding identity or stored format changes.

- Terminal input uses a pinned local crossterm 0.29.0 patch with its original
  archive and license retained. The two Unix parsers preserve repeated Escape
  presses and Escape followed by navigation; typed and pasted sequence-looking
  text stays literal. Legacy Alt-navigation double prefixes are interpreted as
  Escape then navigation; explicit encoded modifiers remain supported. Windows
  input and persisted investigation/module contracts are unchanged. The risk
  gate authenticates copied upstream code and scores every changed local function.

- Collapsed paste exposes inspection, clear, interrupt and undo at compact
  widths. Ctrl+Y can inspect the nearest paste block after appended text;
  inspection leaves the draft and cursor unchanged. Expansion and deletion keep
  their existing cursor targeting. Inspector controls fit at 40×12 and Map
  gallery paging replaces generic paging guidance. No persisted formats change.

- Foreground completion retains composer focus over newer drafts, including
  Unicode cursor position and collapsed multiline paste. Empty returns and
  background focus keep their existing behavior. Result shortcuts require an
  empty composer, including remapped keys. Result hints and footer use the same
  availability check and name the configured prompt-focus action for a held
  Navigate draft. Stored phase, finding, context and allowance formats are unchanged.

- `dep-hygiene:check` now inspects recognized manifests in nested directories
  through one bounded file inventory. Symlinks, repository state, installed
  dependencies and build output are excluded. Structured document failures keep
  other policy signals and return partial results with `data.inspection` counts,
  limits, exclusions and gaps. Source hashes bind the result to its inspected
  target. These checks inspect version constraints, without advisory lookup.
  The public `DepHygieneReport` shape and scanner unit struct remain unchanged;
  legacy APIs without a coverage channel now return an error for incomplete
  inspection. Directory scopes remain supported; accepted exact-file scopes
  still refuse before discovery. SAST readable output now includes recorded
  reasons for partial engine outcomes, matching its existing structured warnings.

- `cpg:build` moves to Labs and auxiliary Map work. Exact tool names, options,
  aliases and graph paths remain available. Completed graphs cannot publish a
  Map checkpoint. A later language failure returns a partial receipt with saved
  graphs and its stop reason. Build output adds the actual `sourceRoot` and
  `stopReason`; import adds `currentCheckoutApplicability: "not_assessed"`.
  Import now refuses `languages`, `subdir` and `maxSourceFiles` instead of ignoring
  them. Remove those stored/inline build options before importing. Graph formats
  remain unchanged. Collection bounds and mid-operation cancellation remain
  experimental; the file cap is a frontend construction limit.

- Report keeps a short source-status notice visible while reading earlier-source
  studies, explicitly selected studies and workspace history. Paging uses the
  remaining reader height. Shared structured export metadata adds
  `currentCheckoutApplicability: "not_assessed"`; recorded finding source and
  decision applicability keep their existing meanings. No current-checkout
  reassessment runs during export, and no persisted investigation format changes.

- Idle compact Review navigation reclaims passive status and repeated workflow
  guidance for the finding. Source drift, local paging/back keys and the composer
  remain visible; decision gates, active work and typing keep ordinary chrome.
  The shared rendered geometry also sets PageDown distance. Compact prompt copy
  follows configured and unbound keys. No persisted format or dispatch changes.

- `sast:scan` adds optional `agenticMaxModelTurns`, with the
  `agentic_max_model_turns` alias and range 1 through 40. It requires the agentic
  task, reaches its existing per-query limit, and leaves omitted defaults intact.
  Canonical prepared input, frozen plans and Settings retain it. Internal repairs
  and retries still share the investigation allowance; no dollar ceiling is added.

- Coverage recommendations no longer infer saturation or force gap-fill from
  historical record counts. Parent/engine records cannot establish comparable
  passes or diminishing returns. Existing `Saturated` and `all_baselines` public
  contracts remain for compatibility; new recommendations do not use them.

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

- Exact `threat-model:read` receipts add versioned `scannerContextPreview`
  metadata. It renders the existing agentic/triage threat-model digest, with
  text hash, item/field limits and omissions. Old receipts lacking this field
  remain readable; the TUI shows reread guidance for their missing projection.
  The context picker adds `p` for this read-only view and `Home`/`End` for text
  navigation. Existing menu choices keep their order. Context references,
  documents, accepted plans, model selection and execution prompt text remain
  unchanged. Preview hashes identify the digest portion only. Runtime source
  checks, supporting context and other engines' context behavior remain separate.
  Omission notices now identify selected ordinary fields, open questions and
  flattened historical pattern limits. Matching pattern-code cuts share one
  notice with exact indexes and counts for each field. Schema version 1 and
  digest text/hash remain compatible; no accepted work is rewritten.

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

- Dependency inventory now declares `maxTotalBytes` (64 MiB default, 512 MiB
  maximum) and `maxFileBytes` (64 MiB default and maximum). Parser stages reuse
  one captured copy of each input. Inventories exceeding either allowance fail
  without publishing components; explicitly approve different input limits
  before rerunning. Captured bytes remain in memory until the operation ends.
  Direct results add `data.inspection` with limits, reserved/read bytes and
  captured-input hashes, including available evidence on failure. Existing
  report fields and `scan_sbom` callers remain compatible; the additive
  `scan_sbom_with_options` API returns inspection evidence separately. This is
  a per-operation capture, not authenticated Git freshness or complete coverage.
  Reprepare frozen dispatch inputs if the changed descriptor binding requires it.

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

- The compatibility `campaign:plan` now prepares every child input before
  publishing a plan and cannot contribute Map evidence. Existing plan IDs
  refuse replacement; use a new `campaignId` for a revised plan. Its optional
  `scopeInventory` receipt links an authenticated inventory artifact and
  discloses inspection limits. Scope files use one bounded inventory with no
  recursive traversal, at most 100,000 total file memberships and 4 MiB per
  list. Incomplete enumeration refuses planning. Existing scope-file consumers
  keep the same line format. Standard agentic discovery refuses this legacy
  scope-file adapter; use accepted scopes through `campaign:study`. Explicit
  `full-mode:hunt` remains a compatibility consumer and does not accept threat
  seasoning. No strategy, model or runtime changes silently.

- Runtime-free status projects historical spending under its existing `data`
  fields. Shared dispatch adds `dataCostScope: projection` from the resolved
  descriptor and removes module-supplied markers. Current execution cost is
  parsed from envelope fields in that case; historical values stay unchanged.
  Model-backed tools cannot declare this scope. Missing current cost remains
  unavailable, and an operational read cannot add old spend to its own run.
  This declaration is supported by Rust descriptors only. The local KWP host
  rejects `costDataProjection`: worker cost claims are sanitized and current
  execution charges remain owned by the broker.

- Model-backed discovery and Review plans add declared `threatModelDigestRef`
  schema 1. Its authenticated, target-bound blob freezes exact threat-model
  text, absence, limits and omissions separately from supporting Map text.
  The 512 KiB serialized limit is a storage bound, not a token or dollar cap.
  The reference participates in existing prepared-input and approval hashes.
  Execution rechecks source and reviewed-lesson eligibility, then consumes
  saved bytes without invoking the current renderer. Historical reads remain
  available after source drift. `threat-model:read` accepts the reference with
  its exact `threatModelRef`; the study picker uses it for matching receipts.
  Missing or damaged objects never trigger context substitution. Legacy
  approved model work without this binding requires a separately prepared and
  approved replacement; consumed attempts, spending and history remain intact.
  Unbudgeted direct calls retain their compatibility renderer. Imported variant
  patterns are described as unverified leads, not confirmed current findings.

- Frozen scanner-context inspection adds `frozenReference` to its version-1
  preview metadata. This identifies the authenticated object read, without
  changing saved text or artifact formats. The study picker matches both the
  context revision and this reference before accepting a completed read. Late
  ordinary reads or another saved projection cannot replace the current plan's
  preview, scroll or draft. Ordinary revision inspection remains unbound.

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
  The shell case editor adds exact-revision inspection, draft naming and
  case-specific replacement. Display-name changes retain stable case ids,
  baseline roles and spending while invalidating the prepared draft.
  `ContextCaseInput::validate` is public so editors reuse the existing pure
  validation rules. Serialized case, plan and artifact formats are unchanged.

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

- `pack:scopes edit` adds `create-shared-context` (`scopeId`, `sharedScopeId`)
  and `remove-shared-context`. Creation copies a primary boundary as context,
  preserves original discovery membership and starts no jobs. Replacement and
  removal of referenced shared context require separate explicit edits.
  `ScanScopeEdit` gains `CreateSharedContext` and `RemoveSharedContext`; typed
  Rust consumers with exhaustive matches must handle those variants. Existing
  edit payloads, version-1 draft artifacts and tool dispatch names stay valid.
  New revisions require acceptance and a newly approved study before use.

- `pack:scopes edit` additionally accepts `add-scope` with a `scope` object
  using the existing proposed-scope shape. `ScanScopeEdit` gains `AddScope`;
  typed Rust consumers with exhaustive matches must handle that variant.
  Existing payloads, version-1 artifacts and dispatch names stay valid.
  Adding membership validates the saved inventory, publishes a new unaccepted
  revision and starts no jobs or model requests. Earlier accepted revisions
  and plans retain their original membership.

- Campaign snapshots add optional `display_label`, derived from recorded case
  labels and valid pass numbers. Typed Rust `CampaignJobSnapshot` constructors
  must initialize it; missing legacy metadata uses `None`. `campaign:status`
  adds `jobs[].displayLabel` while preserving job ids, state, attempts and plan
  artifacts. Queue diagnostics in this reading projection are bounded and
  terminal-safe; original queue and run artifacts remain unchanged. The TUI
  adds selected-job inspection without changing dispatch or allowance policy.

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

  Context studies also accept the additive `generationTool: "threat-model:ask"`
  action. Its one approved question job freezes an exact context, question,
  model and source identity. The shell's ordinary Ask opens that review flow
  after a current Map is accepted; it no longer starts an unbound session query.
  Saved answers are guidance, cannot complete Map and do not change findings or
  the active context. Existing context-study artifacts keep their default
  generation tool and remain readable. No stored-artifact migration is required.
  New deterministic context builds persist the captured source tree hash before
  committing the immutable revision. Older revisions without that hash remain
  readable, but source-bound actions require a new current revision.

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

- Git inventory acquisition now has bounded output, a 30-second deadline and
  cancellation before the entry-processing loop. Acquisition failures preserve
  prior context and scope drafts instead of silently using filesystem membership.
  Missing Git, non-repositories and empty indexes retain their prior fallback.
  Canceled acquisition adds `inspection.enumeration = "interrupted"` with a
  partial reason. Rust consumers matching `ContextEnumeration` must handle the
  new `Interrupted` variant. Older readers may show unknown enumeration until
  upgraded; existing saved inventories are not rewritten.

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

### Recorded import phase ownership (unreleased)

`recon:import`, `bounty:import-har` and `bounty:import-burp` now declare
`phase_result=false`. Their Scan classification, authorization, exact tool
names, input aliases and existing output/storage formats remain intact. They
supply recorded evidence for inspection and cannot establish local discovery
coverage or a selectable Scan result. Existing phase-result recovery retains
raw historical attempts while filtering known supporting-only tools.

The shared imported-evidence predicate adds canonical HAR/Burp UUID run IDs
to the existing reserved ledger-import namespace. Completed historical import
receipts also respect descriptor result ownership, even when labeled Scan.
Imported observations remain Review-readable but cannot supply the legacy
local-discovery checkpoint. The
existing `is_ledger_import_run_id` public helper is preserved.

Literal import paths retain leading/trailing filename spaces; whitespace-only
paths still refuse. JSONL imports check cancellation before reading and between
records. Record-processing failures disclose that earlier saved evidence may remain and preserve
the cause. Import is not atomic, and these checks do not interrupt an ongoing
bounded file read or SQLite operation. HAR/Burp and XML cancellation remain
unqualified. No active network request is introduced.


## Native model-work admission migration

Direct native runtime queries and tool-loop steps now require an approved
`AllowanceBinding` through `AgentRuntime::with_allowance_binding`. Shared
prepared module dispatch already supplies the approved binding. Unbound direct
callers fail before bridge spawn rather than executing outside accounting.
`LangGraphRuntime::preflight_model_work_blocking` is additive and reserves no
calls; credential readiness and authentication ping remain model-free checks.

Unstarted session allowance refusals persist as blocked with editable questions.
Failures after attempted work retain failed state and unknown-cost evidence.
No public module identifier, descriptor option, artifact path or format changes.
The approved finite Ask flow remains under implementation; a root question does
not inherit authorization from a previously consumed campaign job.

## Recorded component Map display (unreleased)

Map Summary and DFD now display a recorded named component even when its context
contains no data flows. The display states that relationships remain unknown.
Generated repository-scope placeholders remain empty. Map completion, context
verification and acceptance rules are unchanged; display availability does not
establish complete architecture coverage.

The project context receipt distinguishes document availability from accepted,
awaiting-review and historical status labels. It labels a zero-flow DFD
`components only`. Accepted context remains bound to its exact revision when
another context is activated, including restart.

At 12 rows or fewer, idle Map navigation reserves document space and shows short
reading controls. Draft input, active work and pending decisions retain their
normal controls. No stored artifact, descriptor option or public module contract
changes. No migration is required.

## Go scanner output and support (unreleased)

The existing Go scanner parser now reads successive JSON values rather than
requiring one value per line. It accepts protocol v1.0.0, requires its initial
config, rejects invalid or unrecognized streams, and limits parsing to 16 MiB
and 100000 events. Unsupported versions fail explicitly.

Findings retain SignalOnly proof while distinguishing reported modules,
packages and symbols. The summary no longer labels every signal reachable.
Module-relative scanner paths remain unverified target citations.
Default discovery classifies the tool as Labs. Exact dispatch, scan aliases and
stored finding formats remain available. Re-run output inspection to apply the
new labels; historical findings are not rewritten. Installed execution, network
containment, scope coverage and operator-controlled subprocess limits remain
unqualified.

Filtered tool browsing now distinguishes matching Experimental or Compatibility
tools from an unknown-tool empty state and shows their exact settings command.
The reason and action appear before empty-result details in compact reading.
Discovery defaults and dispatch authorization remain unchanged.

## Support settings controls (unreleased)

An empty supported-tool filter with matching Experimental or Compatibility
tools now has a selectable settings reader. Arrows select every matching tool;
Enter opens its descriptor-backed settings without starting work. Selection is
stored by tool name and survives resize and return from settings.

Settings Escape returns to the same tools filter. Field Escape retains its
draft first. Support Escape restores composer input; drafts, cursor position,
warning dismissal and captured input keep their ownership. Matching tools still
require the ordinary dispatch and allowance policy before execution. No artifact
or public module migration is required. Mixed supported/experimental lists retain
their existing behavior.

## License rules in scan coverage (unreleased)

Scan engine receipts add optional `ruleIds`, the rules enabled for that engine.
Omission means unrecorded policy; an empty list means no enabled rules. Existing
receipts remain readable. Rust callers constructing `ScanStageEngine` literals
must add `rule_ids: None` for legacy or unspecified policy, or the recorded
enabled checks. Upgrade strict readers before opening newly written receipts.
Retain original history when rolling back.

Direct `license-scan:scan` results now include source-verified Scan coverage in
the existing `phaseStages` result and `phase-stages.jsonl` artifact. Coverage
uses the same persisted run identity and finding delta as the ledger. SAST
records the license engine's actual default policy. A later disabled rule or
legacy unrecorded license policy is `not_reassessed`. Enabled, completed work
can establish `not_observed`, which does not establish a fix. Post-scan source
failure persists partial work and cannot establish covered absence. Existing
finding identities, human decisions, tool names and descriptor options remain.

The additive `scan_reassessment_block_for_rule` helper is the supported
comparison API when a finding's rule is available. The earlier engine/path
helper remains available for compatibility. Other engines without recorded
rules retain their existing coverage semantics; this change does not certify
every scanner's rule or configuration parity.

## Scan coverage after source verification (unreleased)

Single-study, context-matrix and scope-study investigation receipts add
`reassessmentRequiredCount`, using the existing shared decision-source
comparison. A nonzero count appears beside Report review totals, with an
explanation that earlier decisions remain recorded. It counts findings whose
retained decisions need source reassessment separately from ordinary unreviewed
findings. Existing decisions, totals and historical artifacts are unchanged.
Readers must accept the additive field and treat its absence in older receipts
as unrecorded. No schema version bump or new tool option is required.

Semgrep execution explicitly excludes `**/.kuzushi/**` through its shared
command builder, including direct, whole-repository and exact-file paths.
This prevents generated source caches from appearing as duplicate findings on
unversioned targets where Git ignore policy is not applied. Inspection receipts
add `excludedPaths` to disclose the exclusion. Ordinary source and similarly
named directories remain eligible. Existing tool options and historical findings
are preserved; strict receipt readers should permit the additive field.

`sast:scan` now publishes its existing Scan receipt after final source
verification. A source mismatch downgrades Scan coverage and the saved run to
partial before absence reconciliation can run. Its output headline also says
partial. Per-engine completed work remains recorded, but does not establish
completed coverage over the changed source. Earlier observations and human
decisions remain available. Cancellation at publication refuses completed
coverage and uses the existing stopped-run persistence path.

Existing tool names, options, result paths and receipt schemas remain. Historical
receipts are not rewritten. This corrects shared SAST settlement; other direct
scanner adapters require separate qualification. No new jobs, model calls,
execution permission or finding verdicts follow from the change.

## Direct scanner settlement and observation artifacts (unreleased)

Direct `semgrep:scan` verifies its captured source before committing observations
and final run status. A source change preserves partial work in both result and
ledger, for empty and nonempty observations. Existing static-evidence options,
normalized finding fields, inspection receipts and persisted run references
remain. This changes settlement order through shared prepared dispatch; it adds
no option, model request or automatic follow-up work.

Direct `license-scan:scan` now lists its successfully published observation
snapshot in `scan.artifactDelta`, including empty `findings.json` snapshots.
The existing field uses the canonical run-relative artifact path. The phase
receipt itself is not listed recursively. No schema migration is needed;
historical receipts retain their original bytes. Other direct adapters and
configuration-equivalence guarantees require separate qualification.

## Source-bound outcomes and direct scan settlement (unreleased)

A failed final source check no longer replaces an existing failed or skipped
outcome with partial status or a different headline. The original errors and
unresolved spending metadata remain; the source problem is an additional
warning. Usable completed or partial work still becomes partial when its source
cannot be verified.

Source-bound result objects may add `data.sourceCheckCurrent`. True records a
successful final check against that operation's captured source content; false
records an unsuccessful check. Missing means unrecorded, not true. This is not
a coverage, finding-validity or standalone Git revision guarantee. Exact context
checks retain their additional recorded-revision checks and no longer infer
source currency from the tool outcome. Strict data readers should permit the
additive field. Historical results are not rewritten.

Direct `cargo-audit:scan` and `iac-scan:scan` now settle source verification
before committing findings and final run status. Positive and empty changed-source
results remain partial. Existing inspection limits, normalized observations,
selected-directory rebasing, tool ids and input options remain. The shared
prepared dispatch path applies the change in shell and headless execution.

Scan and Report now say scope is `not recorded` when a typed Scan coverage
receipt is unavailable. A workspace target alone does not establish the scope
that an earlier tool inspected. Typed receipts continue to supply their recorded
scope. Other adapters, persistence-fault timing and full coverage guarantees
require separate qualification. No model request, retry or follow-up job is added.

## Direct scanner scope and file coverage (unreleased)

Direct `iac-scan:scan` and `cargo-audit:scan` now publish their own typed Scan
receipts through authenticated correlated tool results. Both publish canonical
`findings.json` snapshots, including empty results, and measured finding deltas.
Requested paths stay workspace-relative. IaC records the selected directory,
enabled rule families and fully inspected files. Cargo records only the selected
`Cargo.lock`; nested lockfiles and source reachability remain outside its scope.

`ScanStageScope` adds optional `inspectedFiles`. Missing preserves the historical
path-only contract. An empty recorded set covers no files. A populated set
restricts path coverage to those exact files. Reconciliation and comparisons use
this membership; successful excluded-file scans cannot retire an earlier signal.
Rust callers constructing `ScanStageScope` literals must supply
`inspected_files: None` for legacy data or the recorded set for new evidence.
`IacScanReport` adds the same optional field. Upgrade strict readers before
opening newly written receipts. Stored historical results are not rewritten.

IaC and Cargo rule-aware comparisons require recorded rule policy. IaC records
its enabled rule identifiers. Cargo's advisory policy remains unrecorded, so an
absent later observation is not reassessed. Completed Cargo jobs retain that
limitation in Scan and Report. Report hydrates displayed Scan receipts directly,
without a prior visit to Scan. Relative paths and inspected-file counts precede
the workspace path in typed scope labels. Unknown resource cost remains unknown.

Direct selected-directory Cargo findings now rebind their file and structural
locator to the workspace, preserving separate identities for different
lockfiles. This agrees with the scoped adapter. Existing unqualified historical
identities are retained, not automatically merged or rewritten. Operators can
inspect source and scope before recording a reversible relationship. No absent
observation establishes a fix or changes a human verdict.

## Auxiliary scanner persistence and routing (unreleased)

Direct `govulncheck:scan` and `codeql:scan` authenticate source before committing
observations and final run status. They publish canonical `findings.json`,
including empty results, using the persisted run identity. Changed source keeps
work partial. CodeQL remains an auxiliary Labs action and cannot complete Scan.
Static indexing is omitted visibly when final source authentication fails.

Selected-directory Go identities become workspace-relative. Its unrecorded
advisory policy cannot establish reassessment from later absence. Historical
identities and human decisions are retained. The registered Go action now reaches
the native executor through shared prepared dispatch. Missing installations fail
actionably without reporting clean coverage or using a model.

Source-bound CodeQL failures name the requested operation while retaining their
original cause chain. Public tool names and input options remain compatible.
No installed-engine usefulness, configurable whole-operation resource ceiling or
module maturity promotion is claimed by these fixes.

## Exact observation references in Review (unreleased)

Review actions display an existing `open generation:<id>` command for persisted
observations. It reopens the recorded generation within the current workspace,
even after positional aliases change as findings arrive. Unsaved observations
do not receive this action. Later source generations retain separate references
and decision-source disclosures. Public reference syntax, stored artifacts and
alias behavior remain compatible. This does not establish that a finding was
fixed or authorize a new scan.

## Search scope actions (unreleased)

The scope action menu adds `/ search`, using the existing field editor and
canonical action list. Arrow keys select matching actions; Enter cannot activate
a hidden action when no results match. Esc clears search before returning to
boundaries. Paste and editing chords belong to the query rather than the shell
composer. Refused actions preserve the query, and paging keeps its selection.
The query title leaves source status visible. Plain and no-color readers retain
the same choices. Filtering approves no work; existing scope, source and spending
checks continue to apply when an action is selected.

## PASTA draft artifact contracts (unreleased)

- `randori:pasta` now defaults to preserving existing draft files and honors
  `emitFindings=false` for unsolicited bridge findings. To replace a previous
  output directory, explicitly pass `preserveUserEdits=false`; use a new
  directory to retain both drafts. It is an auxiliary Labs Map action with
  Context accounting. Generation does not activate or accept context.
  Declared `maxElements` inputs must be 5 through 500 and `maxThreats` inputs
  1 through 500. Invalid values refuse before model work; these remain prompt
  targets rather than guaranteed output counts.
- `randori:threat-model` remains dispatch-compatible as an auxiliary
  Compatibility reader. Prefer `threat-model:read` with the same `outputDir`
  and `methodology=pasta`. Directory names retain literal whitespace. Additive
  `artifactRead` metadata reports bounded file reads and unverified source
  identity. Bad optional files produce partial output; an unusable primary
  refuses fallback. The legacy model option is explicitly ignored.

### Tracked inventory symlinks

Unix inventory now records known tracked symlinks and non-regular leaves as
visible exclusions, matching the filesystem enumeration policy. Missing or
unsafe paths still produce partial results. Other platforms retain their
strict partial-result behavior. No artifact schema or public tool changes.
See [the inventory assessment](docs/assessments/tracked-symlink-inventory-2026-10-24.md).

### Partial context import and reporting

Current authenticated partial catalogs can support observed-row verification.
The additive verification values `verdict=partial` and
`groundingSource=partial-catalog` retain their reason in `groundingDegraded`.
Complete-set consumers still reject partial catalogs. Partial imports require
`activate=false` and explicit acknowledgment during Map selection.

Investigation receipts add `scope.contextEvidence` with `schemaVersion=1`;
context matrices also add `scope.caseContextEvidence`. Existing fields and
historical receipts are retained. Readers should treat partial verification as
requiring attention, and absent historical verification as unrecorded. No model,
provider, runtime, scan work or allowance is substituted. See the
[partial context assessment](docs/assessments/partial-context-map-2026-10-24.md).

Model generation can now use authenticated partial catalog observations with
`activate=false`. Its bounded source projection retains `snapshotCoverage`,
and generated catalog receipts add `status=partial`. Counts describe recorded
observations. Older receipt readers must recognize the new status while
preserving authentication; unsupported readers should refuse it. Complete-set
consumers retain their strict guard. Generated context remains inactive and
requires explicit partial Map acknowledgment. See the
[generation evidence](docs/assessments/partial-context-generation-2026-10-24.md).

### Generated-context source receipts in Report

Version-one investigation `contextEvidence` additively includes `sourceContext`
with `schemaVersion=1`, `projection=metadata-only` and `sourceTextIncluded=false`.
Its `scopeContext` and `fileContext` entries retain known source-input receipt
metadata from the exact selected revision. Captured source lines retain their
references but omit text. Missing entries are null; malformed or unsupported
receipts are unavailable. Existing fields and public tool inputs are unchanged.
Readers may ignore the additive field and must not infer complete coverage from
it. See the [workflow evidence](docs/assessments/generated-scope-investigation-2026-10-24.md).
