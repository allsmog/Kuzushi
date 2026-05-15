# Kuzushi Artifacts

Kuzushi runs are replayable evidence bundles under:

```text
<target>/.kuzushi/runs/<runId>/
```

The run artifact contract is intentionally independent of the TUI. Shell, run,
and scan mode should all write artifacts through the same Rust substrate.
When `kuzushi run` executes a targetless tool such as `config:show`, artifacts
are rooted at the process current directory so the run still has a durable
`.kuzushi/runs/<runId>/` bundle.

## Canonical Per-Run Files

Every run should converge on these files:

| File | Purpose |
| --- | --- |
| `run.json` | Run metadata: run id, kind, tool, target, status, started/completed times, model/provider/prompt hashes/cost where relevant. |
| `events.jsonl` | Ordered run events for replay and plain progress. |
| `trace.jsonl` | Runtime trace steps, including LLM model, provider, prompt hash, latency, and cost when a model call occurs. |
| `context.json` | Repository context snapshot used by the run. |
| `attack-surface.json` | Attack-surface map used by scanners, threat modeling, and recommender. |
| `threat-model.json` | Threat model snapshot or deterministic absence marker. |
| `recommendations.json` | Module recommender output or deterministic absence marker. |
| `findings.json` | Findings emitted or referenced by this run. |
| `proof.json` | Proof state and verification outcomes referenced by this run. |
| `failures.json` | Empty success marker or bounded failure-to-LLM handoff for partial/failed runs. |
| `report.md` | Human-readable report for the run. |
| `report.sarif` | Optional SARIF output when a scanner/report can produce it cleanly. |
| `artifacts.json` | Manifest of written artifacts with label/path/kind. |

The target should also maintain:

```text
<target>/.kuzushi/latest
```

`latest` points to the most recent run id for quick shell, replay, and failure
handoff lookup.

`attack-surface.json` entries include deterministic `risk` metadata:
`rank`, `score`, `tier`, and explanatory `reasons`. The summary also exposes
`highRisk`, `maxRiskScore`, and `byRiskTier` so the recommender and TUI can
prioritize boundaries without reimplementing scoring.

## Current Rust Substrate

The current Rust substrate already writes:

- `.kuzushi/latest`
- `.kuzushi/runs/<runId>/run.json`
- `.kuzushi/runs/<runId>/summary.json`
- `.kuzushi/runs/<runId>/events.jsonl`
- `.kuzushi/runs/<runId>/trace.jsonl`
- `.kuzushi/runs/<runId>/input.json`
- `.kuzushi/runs/<runId>/result.json`
- `.kuzushi/runs/<runId>/context.json`
- `.kuzushi/runs/<runId>/attack-surface.json`
- `.kuzushi/runs/<runId>/threat-model.json`
- `.kuzushi/runs/<runId>/recommendations.json`
- `.kuzushi/runs/<runId>/findings.json`
- `.kuzushi/runs/<runId>/proof.json`
- `.kuzushi/runs/<runId>/failures.json`
- `.kuzushi/runs/<runId>/report.md`
- `.kuzushi/runs/<runId>/report.sarif` when a producer returns
  `reportSarif` or `data.reportSarif`
- `.kuzushi/runs/<runId>/artifacts.json`

This is sufficient for current run replay and failure handoff, but it is not
the final canonical contract. Context, attack-surface, threat-model,
recommendation, findings, proof, and report files may be deterministic
placeholder markers until producer modules return rich snapshot fields. The run
recorder promotes known result fields into canonical files and records them in
`artifacts.json`; module-specific producers should prefer those fields over
ad-hoc side files. `module-recommender:recommend` results are preserved as the
full recommendation report, including repository signals and capability
coverage, rather than only the recommendation list. It also records
producer-declared artifacts from top-level
`artifacts` and nested `data.artifacts` into both `summary.json` and
`artifacts.json`, so module-owned reports and sidecar outputs stay discoverable
even when they are not one of the canonical filenames. Those replacements must
not break existing `summary.json` or `trace.jsonl` readers. Readers that need
run metadata should prefer canonical `run.json` and use `summary.json` only as
a legacy fallback.

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
`kind`. Compatibility output under `data.artifacts` may also be an object map of
label to path or label to artifact object. The run recorder ignores malformed or
empty artifact entries instead of failing the run.

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

The fallback context must forbid claims such as "validated", "verified",
"exploited", "fixed", "false positive", and "no vulnerability" unless the
corresponding proof or verification artifact exists.
