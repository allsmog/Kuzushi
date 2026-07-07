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
- the append-only event log for human decisions, rekeys, proofs, patch
  attempts, model/plugin audit, and run lifecycle;
- SQLite as a disposable projection and search index with `meta.applied_seq`
  committed in the same transaction as the projected rows.

Files such as `context.json`, `attack-surface.json`, `findings.json`, and
`proof.json` are run-scoped exports or deterministic absence markers. When a
producer emits durable payloads for those files, the run recorder also writes
the payload to the content-addressed store and records the object reference in
`artifacts.json`. Readers may inspect the JSON files for replay and reports,
but new state transitions must go through the storage writer actor.

## Per-Run Bundle Files

Every run should converge on these files:

| File | Purpose |
| --- | --- |
| `run.json` | Run metadata: canonical `runId`, kind, tool, target, status, `startedAtUnix`/completed time, model/provider/prompt hashes/cost where relevant, and reproducibility fingerprints such as house rules. |
| `events.jsonl` | Ordered run events for replay and plain progress. |
| `trace.jsonl` | Runtime trace steps, including LLM model, provider, prompt hash, latency, and cost when a model call occurs. |
| `context.json` | Derived repository context export used by the run, or deterministic absence marker. |
| `attack-surface.json` | Derived attack-surface export used by scanners, threat modeling, and recommender, or deterministic absence marker. |
| `threat-model.json` | Derived threat-model export or deterministic absence marker. |
| `recommendations.json` | Derived module recommender export or deterministic absence marker. |
| `strategy.json` | Derived strategy proposal export or deterministic absence marker. |
| `findings.json` | Derived finding-observation export for this run, or deterministic absence marker. |
| `proof.json` | Derived proof/verification export referenced by this run, or deterministic absence marker. |
| `failures.json` | Empty success marker or bounded failure-to-LLM handoff for partial/failed runs. |
| `report.md` | Human-readable report for the run. |
| `report.sarif` | Optional SARIF output when a scanner/report can produce it cleanly; reports summarize runs, results, levels, rule IDs, and affected files when present. |
| `artifacts.json` | Manifest of written artifacts with label/path/kind and CAS object references when available. |

The target should also maintain:

```text
<target>/.kuzushi/v3/latest
```

`latest` points to the most recent run id for quick shell, replay, and failure
handoff lookup.

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
Run events use canonical `atUnix`, `tool`, and `artifact` fields only; obsolete
event aliases are rejected instead of normalized. Event artifacts use the
canonical `artifact` object with `"label"`, `"path"`, and `"kind"` fields.
`schemas/run.trace.schema.json` is the machine-readable contract for each JSON
line in `trace.jsonl`, including trace step identity, optional module/verb
metadata, parent-step linkage, severity, timing, and LLM audit metadata.
Trace streams use canonical snake_case fields only, including `module_id`,
`parent_step`, `started_at_ms`, `cost_usd`, and `prompt_hash`; obsolete
camelCase trace aliases are rejected instead of normalized.
`schemas/run.context.schema.json` is the machine-readable contract for
`context.json`, covering the deterministic absence marker plus known rich
context snapshot fields such as indexed file counts, repository context, and
application model. The schema and report reader also accept wrapped producer
snapshots under `context` and `contextSnapshot`.
`schemas/run.attack-surface.schema.json` is the machine-readable contract for
`attack-surface.json`, covering the deterministic absence marker plus known
rich attack-surface snapshot fields such as surface lists, summary counts, risk
tiers, kind counts, and per-surface risk metadata.
`schemas/run.threat-model.schema.json` is the machine-readable contract for
`threat-model.json`, covering the deterministic absence marker plus known rich
threat-model document fields such as methodology, DFD nodes/flows/trust
boundaries, threats, related CWE aliases, narrative input categories including
camelCase and snake_case data-egress flow aliases, and deterministic
degradation metadata.
`schemas/run.recommendations.schema.json` is the machine-readable contract for
`recommendations.json`, covering the deterministic absence marker plus the full
module recommender report shape, including signals, capabilities, recommended
tools, priorities, runtime requirements, and next-input hints. It also
documents full-report envelopes under `data`, `recommendationReport`, and
nested `data.recommendationReport` producer envelopes.
`schemas/run.strategy.schema.json` is the machine-readable contract for
`strategy.json`, covering the deterministic absence marker plus strategy
proposal snapshots, phase, base/recommended/corrected strategy lineage,
preflight status, resource risk, proposal status, source run id, next input,
and applied correction metadata.
`schemas/run.findings.schema.json` is the machine-readable contract for
`findings.json`, covering the deterministic absence marker plus finding arrays
with location, severity, confidence, CWE/evidence, proof-state aliases, and
durable lifecycle metadata. Finding arrays may be emitted directly or wrapped
under `coreFindings`, `core_findings`, or `findings`.
`schemas/run.proof.schema.json` is the machine-readable contract for
`proof.json`, covering the deterministic absence marker plus static proof
summaries, verification proof snapshots, proof levels, verdicts, runtime proof
flags, state counts, and proof finding entries. Static and verification
snapshots may also be wrapped under `proof`, `proofs`, or `verification`.
The schema contract uses canonical run metadata, event, failure handoff, and
trace fields only. Remaining alias coverage is limited to external producer
payloads that have not been converted in the current slice. The architecture
gate checks that those temporary alias fields are explicit and that canonical
artifact fields stay required.
The same gate also checks vocabulary fields that must stay aligned with Rust
producers: artifact kind, run/failure/snapshot status, run kind, event and
trace kind/severity, LLM audit call kind, route path shape, attack-surface
kind/risk tier, route method, recommendation priority, threat-model
methodology, finding severity/confidence, proof kind, proof level,
proof-state aliases, and proof verdicts.

`attack-surface.json` entries include deterministic `risk` metadata:
`rank`, `score`, `tier`, and explanatory `reasons`. The summary also exposes
`highRisk`, `maxRiskScore`, and `byRiskTier` so the recommender and TUI can
prioritize boundaries without reimplementing scoring.

## Current Rust Substrate

The current Rust substrate already writes:

- `.kuzushi/v3/latest`
- `.kuzushi/v3/runs/<runId>/run.json`
- `.kuzushi/v3/runs/<runId>/events.jsonl`
- `.kuzushi/v3/runs/<runId>/trace.jsonl`
- `.kuzushi/v3/runs/<runId>/input.json`
- `.kuzushi/v3/runs/<runId>/result.json`
- `.kuzushi/v3/runs/<runId>/context.json`
- `.kuzushi/v3/runs/<runId>/attack-surface.json`
- `.kuzushi/v3/runs/<runId>/threat-model.json`
- `.kuzushi/v3/runs/<runId>/recommendations.json`
- `.kuzushi/v3/runs/<runId>/strategy.json`
- `.kuzushi/v3/runs/<runId>/findings.json`
- `.kuzushi/v3/runs/<runId>/proof.json`
- `.kuzushi/v3/runs/<runId>/failures.json`
- `.kuzushi/v3/runs/<runId>/report.md`; the recorder writes a deterministic
  placeholder when no producer report is available and replaces it when a
  producer returns `reportMarkdown` or `data.reportMarkdown`
- `.kuzushi/v3/runs/<runId>/report.sarif` when a producer returns
  `reportSarif` or `data.reportSarif`
- `.kuzushi/v3/runs/<runId>/artifacts.json`

This is sufficient for current run replay and failure handoff, but it is not
the durable state contract. Context, attack-surface, threat-model,
recommendation, strategy, findings, proof, and report files may be deterministic
placeholder markers until producer modules return rich snapshot fields. The run
recorder promotes known result fields into standard run export files and records them in
`artifacts.json`; module-specific producers should prefer those fields over
ad-hoc side files. `module-recommender:recommend` results are preserved as the
full recommendation report, including repository signals and capability
coverage, rather than only the recommendation list. It also records
producer-declared artifacts from top-level
`artifacts` and nested `data.artifacts` into `run.json` and `artifacts.json`,
so module-owned reports and sidecar outputs stay discoverable even when they
are not one of the standard filenames.

TUI synthetic scan and agent runs also append explicit `sast:scan` and
`agent:ask` success/failure lifecycle events to `events.jsonl` when the panel
resolves, including failed runs that exist only to carry bounded failure handoff
context.

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
