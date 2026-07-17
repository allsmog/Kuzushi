# Kuzushi Artifacts

Kuzushi runs are replayable evidence bundles under:

```text
<target>/.kuzushi/v3/runs/<runId>/
```

The run artifact contract is intentionally independent of the TUI. Shell, run,
and scan mode should all write artifacts through the same Rust substrate.
When `kuzushi run` executes a targetless tool such as `config:show`, artifacts
are rooted at the process current directory so the run still has a durable
`.kuzushi/v3/runs/<runId>/` bundle.

## Source-Of-Truth Boundary

The run directory is a replay/export bundle, not a second mutable state store.
V3 source of truth is:

- content-addressed objects for source snapshots and code-derived payloads;
- the target-wide append-only event log for findings, human decisions, rekeys,
  proofs, patch attempts, and target projections;
- each run's hash-linked `items.jsonl` for plan/task/call lifecycle, bounded
  operator-visible progress, terminal outcome, and phase receipt;
- SQLite as a disposable projection and search index with `meta.applied_seq`
  committed in the same transaction as the projected rows.

Terminal run facts are bridged into the target-wide log idempotently by
`(runId, terminalItemHash)`. The target log is not used to reconstruct a run.

Files such as `context.json`, `attack-surface.json`, `findings.json`, and
`proof.json` are no longer synthesized per-run snapshot files. A producer may
still declare those names, or any other JSON sidecar, in `artifacts.json` when
it intentionally writes an export. Otherwise, domain payloads stay inside
`result.json`, the content-addressed object store, or the event/projection
state they derive from. New state transitions must go through the storage
writer actor.

## Per-Run Bundle Files

Every run should converge on these files:

| File | Purpose |
| --- | --- |
| `run.json` | Run metadata: canonical `runId`, kind, tool, target, status, `startedAtUnix`/completed time, model/provider/prompt hashes/cost where relevant, and reproducibility fingerprints such as house rules. |
| `items.jsonl` | Authoritative versioned semantic run lifecycle with stable item/task/call/attempt identities, monotonic sequence, and a hash chain. |
| `events.jsonl` | Compatibility projection from committed typed items during the current major release. Legacy readers remain supported. |
| `trace.jsonl` | Non-authoritative bounded diagnostics/model audit during the compatibility release. It never contains prompts or model-response previews. |
| `failures.json` | Empty success marker or bounded failure-to-LLM handoff for partial/failed runs. |
| `report.md` | Human-readable report for the run. |
| `artifacts.json` | Manifest of written artifacts with label/path/kind and CAS object references when available. |

Every dispatched tool run writes the canonical prepared input to `input.json`
and its normalized result envelope to `result.json`. This includes the
`sast:scan` umbrella and the APK scan path, not only `kuzushi run`.

The SAST umbrella additionally owns four declared pipeline artifacts:

| File | Purpose |
| --- | --- |
| `scan-input.json` | Canonical SAST umbrella input, including the parent run id. |
| `triage.jsonl` | Triage-stage records only. |
| `verify.jsonl` | Verification-stage records only. |
| `patch.jsonl` | Patch-stage records only; patch records are never multiplexed into `verify.jsonl`. |

`report.sarif` is optional. A producer may return it in `reportSarif` or
`data.reportSarif`; `kuzushi scan --sarif <path>` instead exports the findings
observed by that scan's parent/child run-id union and excludes older workspace
findings. Any other JSON file under the run directory is a producer-declared
artifact, not part of the canonical bundle.

The target should also maintain:

```text
<target>/.kuzushi/v3/latest
```

`latest` points to the chronologically newest run by `startedAtUnix` (with run
id as the deterministic tie-break), not whichever run happened to finish last.
Summary writers and prune repair serialize compare-and-write updates so an
older completion cannot move the pointer backward.

### Parent and child scan identity

One caller-created run id is canonical for an umbrella scan. The registry
context wins over input aliases; Kuzushi injects that id into canonical input
before engine dispatch and reports it as `data.runId`. Engine-native run ids
remain available under `data.runIds` for provenance and findings lookup.

Finding counts, `--fail-on`, and scan-scoped SARIF operate on the union of the
parent and every nested child id. They de-duplicate by durable `identityId`
when present and fall back to the observation fingerprint only when identity
is unavailable. Consequently `data.findingsCount` is the length of the same
de-duplicated `data.coreFindings` set, rather than a sum of per-engine counts.

### Run lifecycle vocabulary

Run metadata and lifecycle events use one additive status vocabulary across
scan, shell, run, Jobs, Timeline, replay, and reports:

- `running` and `paused` are non-terminal;
- `completed`, `partial`, and `skipped` are normal terminal projections;
- `failed` means execution genuinely failed;
- `canceled` means an operator or budget policy requested cancellation and
  cleanup reached a terminal result;
- `interrupted` is reserved for watchdog escalation, process loss, and
  abnormal shutdown.

An active cancellation request is presented as `canceling` in the TUI but is
not persisted as a terminal run status. Existing `interrupted` artifacts remain
valid and keep their original abnormal-termination meaning.

Writers persist the `running` summary, prepared input, and start event/trace
before dispatch. On completion they persist `result.json` and the terminal
`run.json`, durably append and flush the typed terminal item, and only then
repair compatibility event/trace rows. A committed-item subscriber is notified
after `sync_data`, so live Run Focus cannot outrun replay durability.

One pure `RunProjection` reducer drives committed live updates, restarted
replay, plain/scripted output, and `kuzushi runs replay`. Malformed lines,
unknown versions, gaps, hash mismatches, and truncated tails stop at the last
valid prefix and disclose a degraded projection; readers never skip forward.

Terminal artifact settlement is idempotently repairable; tool execution is
never retried automatically. Reapplying the same terminal status may restore
missing result state or a derivative event/trace row without duplicating an
existing row. A conflicting terminal status is rejected instead of rewriting
history.

If a persisted `running` summary names a process that no longer exists, read
repair converts it to `interrupted`, clears the process id, refreshes the
canonical failure/report markers, and appends a canonical `run` interruption
event plus a refused trace step.

Operators can prune accumulated run directories with
`kuzushi runs prune --older-than-days <n>` and/or `--keep-last <n>`.
`--dry-run` reports the selected run ids without deleting them. The Rust CLI
repairs `.kuzushi/v3/latest` after deletion so replay and failure handoff keep
pointing at the newest remaining run.

`schemas/run.summary.schema.json` is the machine-readable contract for
standard `run.json` metadata. It covers required run
identity/status/timing fields, optional tool/model/cost/error/reproducibility
fields, LLM audit call metadata, malformed trace JSONL row counts when present,
target git metadata, and artifact manifest entries embedded in the run summary.
Published npm packages expose these files through `kuzushi/schemas/*`, for example
`kuzushi/schemas/run.summary.schema.json`.
`schemas/run.artifacts.schema.json` is the machine-readable contract for
`artifacts.json`, including the run id and each artifact's label, path, and
kind. Persisted artifact objects use only canonical `"label"`, `"path"`, and
`"kind"` fields; obsolete aliases are rejected instead of normalized.
The same canonical artifact object shape is used for available artifacts inside
`failures.json`, so failure handoff and follow-up agent prompts cite the same
artifact contract as the run manifest.
`schemas/run.failures.schema.json` is the machine-readable contract for
`failures.json`, including each failed tool, the bounded failure-to-LLM context,
available/missing artifacts, recovery options, fallback prompt, and forbidden
claims.
`schemas/run.events.schema.json` is the machine-readable contract for each
JSON line in `events.jsonl`, including sequence number, kind, status, message,
timestamp, optional tool, and optional artifact pointer.
The currently published event kinds are `tool`, `scan`, `run`, and `shell`.
Concurrent in-process writers are serialized per event file and the writer
assigns the authoritative monotonic sequence number while holding that lock.
Run events use canonical `atUnix`, `tool`, and `artifact` fields only; obsolete
event aliases are rejected instead of normalized. Event artifacts use the
canonical `artifact` object with `"label"`, `"path"`, and `"kind"` fields.
`schemas/run.trace.schema.json` is the machine-readable contract for each JSON
line in `trace.jsonl`, including trace step identity, optional module/verb
metadata, parent-step linkage, severity, timing, and LLM audit metadata.
Trace and summary LLM-audit vocabularies include `plan`, `llm`, and `critic`
records emitted by the agent planning path.
Trace streams use canonical snake_case fields only, including `module_id`,
`parent_step`, `started_at_ms`, `cost_usd`, and `prompt_hash`; obsolete
camelCase trace aliases are rejected instead of normalized.
Context, attack-surface, threat-model, recommendations, strategy, findings, and
proof payloads are no longer canonical per-run snapshot files. A tool may still
emit any of those as explicit artifacts through `artifacts.json`, but the product
does not synthesize or require fixed snapshot leaves for them. Their durable
source is either the event log/CAS object it cites or the SQLite projection that
can be rebuilt from those sources.
The schema contract uses canonical run metadata, event, failure handoff, and
trace fields only. Remaining alias coverage is limited to external producer
payloads that have not been converted in the current slice. The architecture
gate checks that those temporary alias fields are explicit and that canonical
artifact fields stay required.
The same gate also checks vocabulary fields that must stay aligned with Rust
producers: artifact kind, run/failure status, run kind, event and trace
kind/severity, LLM audit call kind, route path shape, attack-surface kind/risk
tier, route method, recommendation priority, threat-model methodology, finding
severity/confidence, proof kind, proof level, proof-state aliases, and proof
verdicts.

When a producer declares an `attack-surface.json` export, entries include
deterministic `risk` metadata: `rank`, `score`, `tier`, and explanatory
`reasons`. The summary also exposes `highRisk`, `maxRiskScore`, and
`byRiskTier` so the recommender and TUI can prioritize boundaries without
reimplementing scoring.

## Current Rust Substrate

The current Rust substrate already writes:

- `.kuzushi/v3/latest`
- `.kuzushi/v3/runs/<runId>/run.json`
- `.kuzushi/v3/runs/<runId>/items.jsonl`
- `.kuzushi/v3/runs/<runId>/events.jsonl`
- `.kuzushi/v3/runs/<runId>/trace.jsonl`
- `.kuzushi/v3/runs/<runId>/input.json`
- `.kuzushi/v3/runs/<runId>/result.json`
- `.kuzushi/v3/runs/<runId>/scan-input.json`, `triage.jsonl`,
  `verify.jsonl`, and `patch.jsonl` for `sast:scan`
- `.kuzushi/v3/runs/<runId>/failures.json`
- `.kuzushi/v3/runs/<runId>/report.md`; the recorder writes a deterministic
  placeholder when no producer report is available and replaces it when a
  producer returns `reportMarkdown` or `data.reportMarkdown`
- `.kuzushi/v3/runs/<runId>/report.sarif` when a producer returns
  `reportSarif` or `data.reportSarif`
- `.kuzushi/v3/runs/<runId>/artifacts.json`

`items.jsonl` is the durable per-run lifecycle contract. Context,
attack-surface, threat-model,
recommendation, strategy, findings, and proof data are not promoted into fixed
snapshot leaves by the run recorder. They remain in `result.json`, CAS/event
state, SQLite projections, or producer-declared artifacts recorded in
`artifacts.json`. `module-recommender:recommend` results are preserved as the
full recommendation report inside the result envelope, including repository
signals and capability coverage, rather than being promoted to a sidecar list.
The recorder still records producer-declared artifacts from top-level
`artifacts` and nested `data.artifacts` into `run.json` and `artifacts.json`,
so module-owned reports and sidecar outputs stay discoverable even when they
are not one of the standard filenames.

TUI synthetic scan and agent runs also append explicit `sast:scan` and
`agent:ask` success/failure lifecycle events to `events.jsonl` when the panel
resolves, including failed runs that exist only to carry bounded failure handoff
context.

## Typed stream content and safety

The stream stores bounded semantics, never payload bodies. Full results,
evidence, findings, reports, patches, stdout/stderr, and model-generated
documents remain artifacts referenced by digest and producing item identity.
Each serialized item is at most 64 KiB; previews are at most twelve
500-character lines; artifact/finding samples are bounded; the stream budget is
64 MiB with a reserved terminal/decision/receipt tail.

All free-form persisted text uses the shared redactor, escaped control
characters, and explicit bounds. Model-call items contain provider/model,
timing, usage, cost, fingerprints, and error classification only. Kuzushi never
persists raw prompts, raw tool argument values, raw model responses, hidden
reasoning, or chain-of-thought. `SafeReasoningSummary` is accepted only through
the explicit operator-visible redacted API.

## Workflow receipts

`workflow/phase-attempts.v2.jsonl` is a reference-only ledger containing the
attempt/phase, run references, final typed receipt item reference, outcome,
disposition, and target-content identity. It does not copy result or evidence
bodies. Workflow v1 remains wire-compatible and is dual-written for this major
release; readers prefer v2 and fall back conservatively. Dirty/non-Git targets
with a bound indexed snapshot reuse evidence only while a fresh read-only tree
hash still matches. Targets without that bound tree identity use
`Unavailable(reason)` and cannot reuse an older attempt as current evidence.

`run.json` includes `houseRules` when
`<target>/.kuzushi/house-rules/*.md` exists and `promptOverrides` when
`<target>/.kuzushi/prompts/<module>/<verb>.md` exists. Each entry records the
module id, relative path, and `sha256:` digest, plus the prompt verb where
applicable, so report readers can tell which operator rules and prompts shaped
the run without embedding the file text. When
`<target>/.kuzushi/threat-model.json` exists, run metadata also records
`threatModelSha256` so downstream reports can identify the exact persisted
threat model snapshot used or available during the run.
Environment influence is recorded as `envFingerprint` for `KUZUSHI_*`,
`*_API_KEY`, and token-like variables. Non-secret values are stored as
`sha256:` digests; secret-looking values record only `<set>`.
When the target is a git worktree, `targetGit` records the scanned commit SHA,
current branch when available, and whether the worktree had uncommitted
changes. This is separate from Kuzushi build provenance (`gitSha` /
`gitBranch`).

Reproducibility metadata is a start-time snapshot. Later terminal writes keep
the original start timestamp, resolved model/config hash, loaded modules, CLI
arguments, environment fingerprints, target git state, prompt overrides,
house rules, and threat-model digest. Only trace-derived audit rollups are
refreshed as the run progresses.

## Module Result Envelope

Every module result must include:

```json
{
  "ok": true,
  "status": "completed",
  "summary": "short operator summary",
  "artifacts": [],
  "warnings": [],
  "errors": []
}
```

`artifacts` may be an array of paths or objects with `"label"`, `"path"`, and
`"kind"`. `data.artifacts` may also be an object map of label to path or label
to canonical artifact object. Object entries with obsolete path, label, or kind
aliases are ignored rather than normalized. The run recorder ignores malformed
or empty artifact entries instead of failing the run.

Allowed status values:

- `completed`
- `partial`
- `skipped`
- `failed`
- `canceled`
- `interrupted`

`fallback_context` is optional on the direct result. For partial/failed runs,
the durable fallback handoff belongs in `failures.json`.

## Failure-To-LLM Contract

When a run is `partial` or `failed`, `failures.json` must bound what the agent
is allowed to infer:

- failed stage/tool;
- concrete cause;
- available artifacts;
- missing artifacts;
- allowed proof level;
- forbidden claims;
- next files or artifacts to inspect;
- recovery options;
- fallback prompt for the inherited agent/session mechanism.

The failure list and all array fields inside the failure handoff context are
capped at twelve entries in the writer and in
`schemas/run.failures.schema.json`. Longer reports should point to
`artifacts.json` or a concrete report artifact instead of expanding the
handoff payload.

When `report.md` or optional `report.sarif` already exists for the failed run,
the bounded next-inspection list should include those report artifacts so a
follow-up agent can inspect existing human-readable and SARIF evidence without
treating optional SARIF as required.

The fallback context must forbid unsupported success claims:
`success claim without explicit verification`, `verified claim`,
`exploited claim`, `fixed claim`, `empirical proof claim`,
`runtime proof claim`, `exploit proven`, `fix confirmed`,
`false positive verdict`, and `no vulnerability verdict` unless the
corresponding proof or verification artifact exists.
