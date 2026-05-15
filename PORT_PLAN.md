# Kuzushi Port Plan

This is the working port plan for shipping Kuzushi as the Rust app while
tracking upstream OpenAI Codex as substrate only.

## Substrate Decision

- Upstream source: https://github.com/openai/codex
- Local tracking: git remote `upstream-codex`
- Strategy: port small substrate changes from upstream into Kuzushi-owned Rust
  boundaries. Do not vendor or subtree whole upstream app files unless a future
  sync requires it and the local patch is documented in `UPSTREAM_CODEX.md`.
- License and notices: keep Kuzushi MIT licensing in `LICENSE`, retain upstream
  Apache-2.0 text in `LICENSES/Apache-2.0.txt`, and record attribution in
  `NOTICE`.

## Product Identity

Kuzushi ships as:

- binary: `kuzushi`
- alias: `kz`
- prompt: `kuzushi>` or `kz>`
- header: `KUZUSHI`
- state directory: `.kuzushi/`

Codex wording is allowed only for upstream provenance, compatibility adapter
names, provider/OAuth implementation details, or dependency names. Public help,
docs, package metadata, and errors should say Kuzushi.

## DDD Boundaries

The required boundary contract lives in
`docs/architecture/kuzushi-boundaries.md`. The CI guard is
`pnpm quality:architecture`.

Required contexts:

- `context`
- `attack_surface`
- `threat_model`
- `modules`
- `recommender`
- `scanners`
- `findings`
- `proof`
- `triage`
- `verify`
- `patch`
- `report`
- `run_trace`
- `failure`
- `ui_*`

## Artifact Contract

The target run artifact contract lives in
`docs/architecture/kuzushi-artifacts.md`. The current Rust run substrate writes
run metadata, legacy run summaries, events, trace steps, input/result
artifacts, manifests, latest-run lookup, canonical snapshot placeholders,
LLM trace metadata, and failure handoff. The run recorder also promotes rich
context, attack-surface, threat-model, recommendation, findings, proof, and
Markdown report fields from tool output into canonical files. Triage, verify,
patch, threat-model, and report producers now return canonical snapshot fields;
remaining work is enrichment for older or deferred producers that do not yet
return those fields.

## Quality Gate

The quality gate lives in `docs/quality/crap-gate.md`.

Required command:

```bash
pnpm quality:crap-risk
```

All new or modified Kuzushi-owned production code must keep CRAP-risk below 7,
function complexity at or below 4, and function bodies under 40 logical lines.

## Phase Ledger

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Locate Kuzushi, add upstream Codex remote, write plan/upstream/boundary/artifact/quality docs. | Implemented; `upstream-codex` points to `https://github.com/openai/codex.git`, and the port plan, upstream strategy, boundary, artifact, and CRAP-risk docs exist. |
| 1 | Convert public identity to Kuzushi. | Implemented with public identity guard. |
| 2 | Build run/artifact substrate. | Partial; run dirs, `run.json`, legacy `summary.json`, `.kuzushi/latest`, events, canonical empty `trace.jsonl`, trace with LLM metadata, manifest, result, synchronized empty failure markers, failed-result envelope artifacts, returned partial/failed `result.json` fallback handoff, targetless run-mode artifact recording under cwd, coherent module-result output normalization, canonical `completed`/skipped/partial/failed result status handling, canonical run metadata reads with legacy summary fallback, canonical snapshot placeholders, generic rich snapshot promotion including optional `report.sarif`, core-finding snapshot promotion, derived `proof.json` promotion from normalized scanner proof states, full module-recommender report promotion, SAST umbrella core-finding emission, CodeQL SARIF surfacing, and triage/verify/patch/threat-model/report producer enrichment exist; older/deferred producer enrichment remains. |
| 3 | Port findings/proof. | Partial; findings store, aliases, severities, suppressions, and proof states exist. Deterministic `dep-hygiene`, `secret-scan`, `semgrep`, `codeql`, and `iac-scan` findings persist through the shared findings store when a workspace store is available, normalized scanner findings carry conservative `signal_only` proof state, and tool-run canonical `findings.json`/`proof.json` snapshots are regression-covered across those scanner surfaces. |
| 4 | Port `context:build`. | Implemented for deterministic inventory, file index, attack-surface map, and app model including routes, outbound clients, service boundaries, data stores, and background jobs; LLM enrichment fails explicitly. |
| 5 | Build attack surface. | Partial; routes, sinks, stores, jobs, outbound service clients, auth boundaries, session-state boundaries, request-trust boundaries, and tenant-isolation boundaries are represented from deterministic signals with stable risk score/rank metadata and summary tier distribution. Empirical calibration still needs continued hardening. |
| 6 | Build threat model. | Partial; `threat-model:build/read` exist with STRIDE/PASTA/DREAD artifact support, explicit runtime/model enforcement, deterministic no-runtime partial artifact generation, outbound-service DFD/threat enrichment from attack-surface client evidence, auth-boundary DFD/threat enrichment from deterministic guard evidence, session-state DFD/threat enrichment from token/session evidence, request-trust DFD/threat enrichment from CSRF/CORS evidence, tenant-isolation DFD/threat enrichment from tenant/org/workspace evidence, DFD element-targeted deterministic threats, and structured deterministic narrative fields with attacker stories linked to generated threat IDs. LLM-enriched quality and calibration remain. |
| 7 | Build catalog/recommender. | Implemented for visible modules; deferred modules are hidden from public catalog, and recommender reports include deterministic source provenance plus attack-surface risk tier distribution for context, attack-surface, threat-model, and findings signals. |
| 8 | Port deterministic modules. | Partial; secret scan, dep hygiene, Semgrep, CodeQL, and IaC exist and publish findings into the shared store/artifact path. Expected scanner failures across those deterministic scanner surfaces now return structured failed results. |
| 9 | Port triage/verify/patch/report. | Partial; model-backed triage/verify/patch and artifact-only `report:build` exist with no-silent-model checks, canonical findings/proof/report snapshots, standard verify/patch/report envelopes, required run metadata, artifact manifest, events/trace artifact summaries, attack-surface tier distribution summaries, recorded LLM audit metadata surfaced in Markdown, bounded failure-handoff proof limits plus available artifacts and fallback prompt surfaced in Markdown, report warnings for missing canonical artifacts, generated report markdown recorded in the manifest, and optional SARIF report surfacing. |
| 10 | Trim AI modules. | Implemented for public surfaces; high-risk/deferred modules and legacy helper tools are hidden unless explicitly invoked by exact tool name and are excluded from default recommender output. `offense-review:threat-hunt` is the product-facing surface for the Carlini threat-hunt executor across catalog, SAST task, KB attachment, and module-detail flows; `carlini-threat-hunt:run` remains directly executable as a hidden compatibility alias. `taint-iris-next` publicly exposes `dataflow-plan`, `source-sink-trace`, and model-backed `finding-review`; legacy `hunt` plus internal `catalog`/`codeql-db` tools remain exact-only for compatibility and prerequisite chains. |
| 11 | Failure-to-LLM integration. | Implemented for the Rust tool-run/session path: `failures.json`, bounded fallback prompt, missing-artifact context, bounded next-artifact inspection list, recovery options, explicit forbidden success/proof claims, one-shot agent-session injection, artifact-backed handoff display, CLI failed-result envelopes, TUI synthetic scan/agent failure handoffs, TUI agent-call LLM audit metadata, and TUI `fallback_context` surfacing for partial/failed outputs exist. |
| 12 | Kuzushi TUI cockpit. | Implemented; Rust TUI identity, blue/cyan semantic theme, prompt, activity, Home/Recommend, Modules, Module Detail, Findings, Run Timeline, Failure Handoff, artifact rails (`✓`/`○`/`⚠`/`■`/`◆`), plain snapshots for cockpit views, artifact-backed risk summaries with attack-surface tier distribution, canonical run metadata-backed timeline/replay with legacy summary fallback, and the `KUZUSHI mode:... | target ... | ctx ... | model ...` cockpit strip exist. |

## Deferred By Default

The following remain hidden or exact-invocation-only unless justified:

- `recon`
- `chrome-rce`
- `prompt-armor`
- `systems-hunt`
- `pwn`
- `vendor-assessment`
- `shinsa`
- `tob`
- old `vuln-scout` adapter
- broad MCP zoo
