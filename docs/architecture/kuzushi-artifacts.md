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

## Canonical Per-Run Files

Every run should converge on these files:

| File | Purpose |
| --- | --- |
| `run.json` | Run metadata: run id, kind, tool, target, status, started/completed times, model/provider/prompt hashes/cost where relevant, and reproducibility fingerprints such as house rules. |
| `events.jsonl` | Ordered run events for replay and plain progress. |
| `trace.jsonl` | Runtime trace steps, including LLM model, provider, prompt hash, latency, and cost when a model call occurs. |
| `context.json` | Repository context snapshot used by the run. |
| `attack-surface.json` | Attack-surface map used by scanners, threat modeling, and recommender. |
| `threat-model.json` | Threat model snapshot or deterministic absence marker. |
| `recommendations.json` | Module recommender output or deterministic absence marker. |
| `strategy.json` | Strategy proposal snapshot or deterministic absence marker. |
| `findings.json` | Findings emitted or referenced by this run. |
| `proof.json` | Proof state and verification outcomes referenced by this run. |
| `failures.json` | Empty success marker or bounded failure-to-LLM handoff for partial/failed runs. |
| `report.md` | Human-readable report for the run. |
| `report.sarif` | Optional SARIF output when a scanner/report can produce it cleanly; reports summarize runs, results, levels, rule IDs, and affected files when present. |
| `artifacts.json` | Manifest of written artifacts with label/path/kind. |

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
canonical `run.json` metadata. It covers required run
identity/status/timing fields, optional tool/model/cost/error/reproducibility
fields, LLM audit call metadata, malformed trace JSONL row counts when present,
target git metadata, and artifact manifest entries embedded in the run summary.
Published npm packages expose these files through `kuzushi/schemas/*`, for example
`kuzushi/schemas/run.summary.schema.json`.
`schemas/run.artifacts.schema.json` is the machine-readable contract for
`artifacts.json`, including the run id and each artifact's label, path, and
kind. Rust readers also accept compatibility aliases such as `name`/`title`,
`report_json_path`, and `type` when loading older or producer-authored
manifests, then normalize them back to label/path/kind in memory.
The same artifact-field aliases are accepted when loading available artifacts
inside `failures.json`, so failure handoff and follow-up agent prompts can
consume legacy or producer-authored sidecar pointers.
`schemas/run.failures.schema.json` is the machine-readable contract for
`failures.json`, including each failed tool, the bounded failure-to-LLM context,
available/missing artifacts, recovery options, fallback prompt, and forbidden
claims.
`schemas/run.events.schema.json` is the machine-readable contract for each
JSON line in `events.jsonl`, including sequence number, kind, status, message,
timestamp, optional tool, and optional artifact pointer.
Report readers accept `toolName` and `tool_name` compatibility spellings when
summarizing older or producer-authored event streams. They also count
`artifactPath` and `artifact_path` as artifact pointers in event summaries.
Rust event readers also normalize `toolName` and `tool_name` back to `tool`
for replay and TUI consumers, and normalize `artifactPath`/`artifact_path`
strings into canonical artifact pointers.
`schemas/run.trace.schema.json` is the machine-readable contract for each JSON
line in `trace.jsonl`, including trace step identity, optional module/verb
metadata, parent-step linkage, severity, timing, and LLM audit metadata.
Report readers summarize `moduleId`/`module_id`, `costUsd`/`cost_usd`, and
`promptHash`/`prompt_hash` compatibility spellings from trace streams.
Rust trace readers accept camelCase compatibility aliases such as `moduleId`,
`parentStep`, `startedAtMs`, and `promptHash`, but Kuzushi writers continue to
emit the canonical snake_case trace fields.
`schemas/run.context.schema.json` is the machine-readable contract for
`context.json`, covering the deterministic absence marker plus known rich
context snapshot fields such as indexed file counts, repository context, and
application model. The schema and report reader also accept wrapped producer
snapshots under `context`, `contextSnapshot`, and `context_snapshot`.
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
`recommendation_report`, plus nested `data.recommendationReport` and
`data.recommendation_report` producer envelopes.
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
The schema contract intentionally accepts both canonical camelCase artifact
fields and the snake_case aliases already supported by Rust readers for run
metadata, artifact manifests, and failure handoff payloads. The architecture
gate checks that alias fields are declared and, where they identify required
metadata such as `runId`/`run_id`, `startedAtUnix`/`started_at_unix`,
`promptHash`/`prompt_hash`, and `agentThreadContext`/
`agent_thread_context`, that the schema requires at least one spelling.
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
  producer returns `reportMarkdown`, `report_markdown`,
  `data.reportMarkdown`, or `data.report_markdown`
- `.kuzushi/v3/runs/<runId>/report.sarif` when a producer returns
  `reportSarif`, `report_sarif`, `data.reportSarif`, or `data.report_sarif`
- `.kuzushi/v3/runs/<runId>/artifacts.json`

This is sufficient for current run replay and failure handoff, but it is not
the final canonical contract. Context, attack-surface, threat-model,
recommendation, strategy, findings, proof, and report files may be deterministic
placeholder markers until producer modules return rich snapshot fields. The run
recorder promotes known result fields into canonical files and records them in
`artifacts.json`; module-specific producers should prefer those fields over
ad-hoc side files. `module-recommender:recommend` results are preserved as the
full recommendation report, including repository signals and capability
coverage, rather than only the recommendation list. It also records
producer-declared artifacts from top-level
`artifacts` and nested `data.artifacts` into `run.json` and `artifacts.json`,
so module-owned reports and sidecar outputs stay discoverable even when they
are not one of the canonical filenames.

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

`artifacts` may be an array of paths or objects with `path`, `label`, and
`kind`. Path fields may use the canonical `path` key or compatibility aliases
such as `filePath`/`file_path`, `reportJsonPath`/`report_json_path`,
`outputDir`/`output_dir`, and `promptsDir`/`prompts_dir`. Label fields may use
`name` or `title`, and kind fields may use `type`. Compatibility output under
`data.artifacts` may also be an object map of label to path or label to artifact
object. The run recorder ignores malformed or empty artifact entries instead of
failing the run.

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
