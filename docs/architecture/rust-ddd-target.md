# Rust DDD Target

This document is the migration contract for the Rust-first bounded-context
layout. The goal is clearer ownership for Kuzushi's security behavior without
adding enterprise ceremony or changing operator-visible behavior.

## Ownership Rules

- `modules/` owns runtime/catalog concerns: public tool contracts, descriptors,
  option metadata, DAG descriptors, registry lookup, and dispatch adapters.
- `modules/` must not become the home for specialist security algorithms.
- Specialist security behavior belongs in `capabilities/*`.
- Static evidence, ranking, context assembly, registry matching, and narrative
  reporting belong in `evidence/*`.
- Proof state, validation, suppressions, and whitebox policy belong in
  `proof/*`.
- Repository intelligence belongs in `workspace/*`.
- Finding lifecycle, persistence, aliases, exports, and finding report
  projections belong in `findings/*`.
- Scan execution, verification, remediation, runtime governance, CLI delivery,
  TUI delivery, and provider adapters each keep their own bounded contexts.

Side effects stay at the edge. Domain modules should prefer value types,
parsers, classifiers, and decisions that can be tested without filesystem,
process, network, terminal, or model calls.

## Target Contexts

- `capabilities/`: systems hunt, Carlini threat hunt, variant/ndiff,
  threat model, x-ray, recon, agentic SAST, taint iris, deep auditor,
  classifier gate, prompt armor, vendor assessment, Chrome RCE, and plugin
  assessment behavior.
- `evidence/`: static evidence graph and store, static context, static
  registry, static ranking, static narrative, and scanner-result evidence
  indexing.
- `proof/`: proof-state vocabulary, static proof validation, whitebox policy,
  suppressions, verification classification, and proof persistence adapters.
- `workspace/`: workspace target, repository inventory, attack surface,
  artifact knowledge, source spans, and diff scopes.
- `findings/`: finding identity, deduplication, persistence, reporting,
  aliases, PR-comment projections, and workspace finding exports.
- `scan/`: scan runs, scan tasks, scan engines, subprocess execution,
  cancellation, artifacts, and scan adapters.
- `verification/`: finding validation, exploit verification, trigger
  construction, sandbox adapters, and runtime-process validation.
- `remediation/`: patch/remediation prompt construction, patch execution, patch
  validation, and tool JSON conversion.
- `runtime/`: runtime/model governance, no-silent-fallback policy, routed
  runtime dispatch, and agent tool-loop application services.
- `cli/`, `tui/`, and `openai/`: delivery and infrastructure adapters.

## Compatibility Shims

Existing public root modules stay available while behavior moves. A moved
module keeps an old root shim like:

```rust
pub use crate::evidence::narrative::*;
```

Shims are retained for public or widely used paths until a deliberate semver
migration removes them. Private-only shims can be deleted once imports and
tests prove they are unused.

## Migration Phases

1. Add roots and compatibility shims for `capabilities`, `evidence`, `proof`,
   and `remediation`.
2. Move static/evidence/proof/whitebox contexts under `evidence` and `proof`.
3. Move repository intelligence under `workspace`.
4. Move specialist security families under `capabilities`, one family at a
   time, with thin `modules/adapters/*` tool adapters preserving tool IDs.
5. Finish scan, verification, and remediation boundaries.
6. Finish CLI/TUI delivery cleanup.
7. Audit public exports, persisted formats, tool catalogs, parity, tests, and
   CRAP results.

## Current Migration Notes

- `x_ray` is split as a capability bounded context:
  - `capabilities/x_ray/domain` owns report data, verdict parsing, entry-point
    counting, invariant counting, and required artifact names.
  - `capabilities/x_ray/application` owns report artifact IO, read/run
    summaries, and X-Ray prompt/schema request construction.
  - `capabilities/x_ray/adapters` owns `x-ray:*` tool dispatch and JSON input
    parsing.
- The public `crate::x_ray` shim still re-exports
  `crate::capabilities::x_ray::*`, so existing callers and public exports keep
  using the same names.
- `chrome_rce` now follows the capability boundary shape:
  - `capabilities/chrome_rce/domain` owns hot-path matching and Chrome source
    surface classification.
  - `capabilities/chrome_rce/application` owns repository scanning, finding
    collection, persistence calls, and scan/review response construction.
  - `capabilities/chrome_rce/adapters` owns the git diff subprocess boundary
    for `chrome-rce:review-trigger`.
- The `chrome-rce:*` tool IDs and module dispatch path remain unchanged.
- `recon` is now split into:
  - `capabilities/recon/domain` for recon records, nmap/HTTP/subdomain parsing,
    target normalization, and technology inference.
  - `capabilities/recon/application` for the `recon:*` use cases that persist
    discovered hosts, services, notes, and tool reports.
  - `capabilities/recon/adapters` for tool JSON dispatch, input coercion, and
    subprocess execution/cancellation.
  - `capabilities/recon/persistence` for the SQLite workspace store and row
    mapping.
- Public recon exports remain `execute_recon_tool`, `ReconHost`,
  `ReconService`, `ReconNote`, and `ReconWorkspaceStore`.
- `variant_ndiff` is now split into:
  - `capabilities/variant_ndiff/domain` for CVE/advisory records, whitebox
    variant patterns, CVSS/advisory scoring helpers, deterministic variant
    candidate matching, and human-readable variant messages.
  - `capabilities/variant_ndiff/application` for prompt construction, patch
    fetch/source resolution, NVD mapping, variant normalization, and whitebox
    variant search.
  - `capabilities/variant_ndiff/adapters` for `variant:*` and `ndiff:*` JSON
    tool inputs/outputs and runtime-backed tool entrypoints.
  - `capabilities/variant_ndiff/persistence` for finding persistence and
    advisory fixture/online lookup boundaries.
- The public `crate::variant_ndiff` shim and public exports still preserve
  `variant:lift-pattern`, `variant:hunt`, `ndiff:fetch-cve`,
  `ndiff:extract-fix-pattern`, and `ndiff:hunt-variants` behavior.
- `threat_model` is now split into:
  - `capabilities/threat_model/domain` for DFD normalization, DREAD/STRIDE
    scoring labels, evidence-anchor parsing, Randori artifact document
    contracts, stage selection, and build/read flavor contracts.
  - `capabilities/threat_model/application` for threat model build/read use
    cases, Randori artifact conversion, methodology overlays, inventory and
    manifest summaries, and normalized document construction.
  - `capabilities/threat_model/adapters` for `threat-model:*` and `randori:*`
    tool dispatch plus JSON build-input parsing.
  - `capabilities/threat_model/persistence` for `.kuzushi/threat-model.json`
    and normalized artifact writes.
- The public `crate::threat_model` shim and public exports still preserve
  `threat-model:build`, `threat-model:read`, `threat-model:methodologies`,
  `randori:pasta`, and `randori:threat-model` behavior.
- `carlini_threat_hunt` is now split into:
  - `capabilities/carlini_threat_hunt/domain` for DFD actors/flows, actor
    prompt sections, threat search text, tool contract constants, and the
    persisted/public report data.
  - `capabilities/carlini_threat_hunt/application` for actor prompt
    construction, actor/run selection, threat model document resolution,
    runtime querying, finding normalization, static-profile marking, and
    report assembly.
  - `capabilities/carlini_threat_hunt/adapters` for tool input coercion,
    attachment rendering, target resolution, actor fingerprint helpers, and
    tool JSON output.
- The public `crate::carlini_threat_hunt` shim and public exports still
  preserve `carlini-threat-hunt:run`, `run_carlini_threat_hunt`,
  `run_carlini_threat_hunt_report`, `CarliniThreatHuntReport`, and
  `CarliniThreatHuntPersistedRun`.
- `systems_hunt` is now split into:
  - `capabilities/systems_hunt/domain` for systems surface metadata, context
    output, line/surface classification, surface packs, invariant/trigger/CWE
    parsing, prompt constants, and public report data.
  - `capabilities/systems_hunt/application` for context gathering, repository
    inventory walking, code-index augmentation, invariant/trigger/deep semantic
    runtime queries, finding normalization, artifact persistence preparation,
    and systems/deep-semantic report assembly.
  - `capabilities/systems_hunt/adapters` for `systems-hunt:*` tool dispatch,
    tool input coercion, artifact-dir/path helpers, tool JSON envelopes, and
    the public `gather_surfaces` adapter.
- The public `crate::systems_hunt` shim and public exports still preserve
  `systems-hunt:systems-context-gatherer`,
  `systems-hunt:systems-invariant-extract`,
  `systems-hunt:systems-trigger-synth`, `systems-hunt:systems-hunt`,
  `systems-hunt:deep-semantic-cwe-select`,
  `systems-hunt:deep-semantic-hunt`, `run_systems_hunt_report`,
  `gather_surfaces`, `try_augment_with_index`, and all public systems context,
  invariant, trigger, CWE, and report data types.
- `agentic_sast` is now split into:
  - `capabilities/agentic_sast/domain` for scan input options and public
    persisted/report data.
  - `capabilities/agentic_sast/application` for repository inventory walking,
    prompt assembly, structured runtime querying, finding normalization,
    whitebox static validation, pass merging, and scan-task selection.
  - `capabilities/agentic_sast/adapters` for `agentic-sast:scan` JSON input
    coercion and target/model option resolution.
  - `capabilities/agentic_sast/persistence` for finding-store scan-run writes.
- The public `crate::agentic_sast` shim and public exports still preserve
  `agentic-sast:scan`, `run_agentic_sast_report`,
  `split_agentic_sast_tasks`, `AgenticSastReport`, and
  `AgenticSastPersistedRun`.
- `taint_iris` is now split into:
  - `capabilities/taint_iris/domain` for CWE selections, run options, public
    report/persistence data, and prompt contract constants.
  - `capabilities/taint_iris/application` for CWE selection, prompt assembly,
    CodeQL DB discovery, runtime-backed IRIS querying, finding normalization,
    and report assembly.
  - `capabilities/taint_iris/adapters` for `taint-iris:hunt` and
    `pipeline:taint-cwe-select` JSON input/output coercion plus target/model
    resolution.
  - `capabilities/taint_iris/persistence` for finding-store scan-run writes.
- The public `crate::taint_iris` shim and crate-visible exports still preserve
  `taint-iris:hunt`, `pipeline:taint-cwe-select`, `run_taint_iris_report`,
  `run_taint_cwe_select`, `sanitize_rule_segment`, and
  `summarize_taint_path`.
- `taint_iris_next` is now split into:
  - `capabilities/taint_iris_next/domain` for run options, catalog entries,
    ranked plan/evidence/report data, agent result data, and prompt contract
    text.
  - `capabilities/taint_iris_next/application` for plan construction, context
    language/CWE extraction, catalog ranking, backend selection, source-file
    collection, structural evidence extraction, agent prompt/runtime handling,
    deterministic fallback, normalization, scoring, rendering, and report
    assembly.
  - `capabilities/taint_iris_next/adapters` for `taint-iris-next:hunt` JSON
    input coercion plus target/model/list/number parsing.
  - `capabilities/taint_iris_next/persistence` for finding-store scan-run
    writes.
- The crate-visible module path still preserves `taint-iris-next:hunt`,
  `run_taint_iris_next_report`, `TaintIrisNextReport`,
  `TaintIrisNextEvidenceResult`, catalog ranking helpers, and existing SAST
  pipeline integration.
- `classifier_gate` is now split into:
  - `capabilities/classifier_gate/domain` for classifier config, score
    vocabulary, and P² quantile estimator state/update math.
  - `capabilities/classifier_gate/application` for prompt rendering,
    structured/loose classifier response parsing, runtime-backed scoring,
    adaptive threshold decisions, and skip-outcome construction.
  - `capabilities/classifier_gate/persistence` for the SQLite
    `kuzushi_state` quantile store.
- The public `crate::capabilities::classifier_gate` exports still preserve
  `ClassifierConfig`, `Score`, `LikelyVulnClassifier`, `QuantileEstimator`,
  and the classifier threshold constants.
- `deep_auditor` is now split into:
  - `capabilities/deep_auditor/domain` for the deep audit config, outcome,
    vulnerability analysis, evidence citation data, and prompt/default budget
    constants.
  - `capabilities/deep_auditor/application` for tool-loop request assembly,
    static-evidence prompt enrichment, spend settlement, structured/loose
    verdict parsing, implicit evidence extraction, and triage outcome mapping.
  - `capabilities/deep_auditor/persistence` for optional
    `findings_evidence` row persistence.
- The public `crate::capabilities::deep_auditor` exports still preserve
  `run_deep_auditor`, `save_evidence`, `DeepAuditConfig`,
  `DeepAuditOutcome`, `EvidenceCitation`, `VulnAnalysis`, and the deep-audit
  default constants.
- `full_mode_multi` is now split into:
  - `capabilities/full_mode_multi/domain` for scan config, language, chunk
    plan, file bucket, report, budget constants, and dry-run cost summary
    data.
  - `capabilities/full_mode_multi/application` for workspace walking, chunk
    planning, chunk prompt assembly, structured model-output parsing,
    severity normalization, runtime dispatch, and spend settlement.
  - `capabilities/full_mode_multi/adapters` for report-to-tool JSON
    projection.
- The public `crate::capabilities::full_mode_multi` and
  `crate::full_mode_multi` exports still preserve `FullModeConfig`,
  `FullModePlan`, `FullModeReport`, `ChunkPlan`, `FileBucket`,
  `CostSummary`, `plan`, `run`, `cost_summary`, `report_to_tool_json`, and
  the full-mode budget/token constants.
- `semgrep_rule_synthesis` is now split into:
  - `capabilities/semgrep_rule_synthesis/domain` for candidate rule reports,
    validation reports, fixtures, candidate ID/token vocabulary, slugging,
    language selection, and token matching helpers.
  - `capabilities/semgrep_rule_synthesis/application` for selecting
    statically-confirmed findings, loading evidence nodes, synthesizing
    candidate rules, validating positive/negative fixtures, and rendering the
    disabled-by-default Semgrep YAML.
- The public `crate::capabilities::semgrep_rule_synthesis` and
  `crate::semgrep_rule_synthesis` exports still preserve
  `synthesize_candidate_semgrep_rules`, `SemgrepRuleFixture`,
  `SemgrepCandidateRule`, `SemgrepRuleSynthesisReport`, and
  `SemgrepRuleValidation`.
- `prompt_armor` is now split into:
  - `capabilities/prompt_armor/domain` for command-name mapping,
    authorization policy, and `.prompt-armor` output path ownership.
  - `capabilities/prompt_armor/application` for local config/diff/report
    commands, runtime prompt assembly, structured output contracts,
    PromptArmor runtime querying, finding normalization, and persistence.
  - `capabilities/prompt_armor/adapters` for the tool-facing
    authorization-refusal JSON response.
- The `modules/prompt_armor` adapter remains the public tool boundary and
  preserves all `prompt-armor:*` tool IDs and option contracts.
- `vendor_assessment` is now split into:
  - `capabilities/vendor_assessment/domain` for assessment scope update data,
    attachment input data, stable scope defaults, and scope merge semantics.
  - `capabilities/vendor_assessment/application` for scope persistence,
    attachment parsing, prompt bundle generation, runtime-backed assessment,
    fallback report construction, and run artifact writes.
  - `capabilities/vendor_assessment/adapters` for Markdown report rendering.
- The `modules/vendor_assessment` adapter remains the public tool boundary and
  preserves all `vendor-assessment:*` tool IDs and option contracts.
- `plugin_adapters` is now split into:
  - `capabilities/plugin_adapters/domain` for plugin adapter specs and stable
    adapter identity/configuration.
  - `capabilities/plugin_adapters/adapters` for module-facing JSON input
    coercion, explicit model resolution, target resolution, and plugin-root
    lookup.
  - `capabilities/plugin_adapters/application` for ToB/Shinsa discovery,
    plugin-backed finding adapter execution, Shinsa prompt/report handling,
    artifact writes, finding normalization, and persistence.
- The `modules/plugin_adapters` adapter remains the public tool boundary and
  preserves the ToB and Shinsa tool IDs/options.
- `scan` now has first-class DDD subcontexts for the native scan path:
  - `scan/domain` owns scan engine traits, scan engine output data, scanner
    structs exposed through the public API, and persisted/tool report data.
  - `scan/application` owns scan-run orchestration, engine selection,
    collection, filtering, static-evidence indexing, finding persistence, and
    Semgrep JSON normalization used by the public scan APIs.
  - `scan/engines/codeql` owns CodeQL scanner execution, database/language
    handling, SARIF normalization, flow/static-evidence indexing, and CodeQL
    scanner tests through the existing public `CodeqlScanner` export.
  - `scan/engines/semgrep` owns Semgrep config parsing and the `ScanEngine`
    implementation for `SemgrepScanner`.
  - `scan/adapters` owns tool-facing scanner input coercion.
- Public `crate::scan::*` exports still preserve `ScanEngine`,
  `ScanEngineOutput`, `SemgrepScanner`, `CodeqlScanner`, `ScanRun`,
  `ScanRunOptions`, `run_semgrep_scan`, `run_scan_engines`,
  `run_scan_engines_with_options`, `normalize_semgrep_json`,
  `normalize_codeql_sarif`, and `index_codeql_sarif_as_static_evidence`.
- Native scanner implementations now live under the scan engine boundary:
  - `scan/engines/dep_hygiene` owns dependency hygiene and `cargo audit`
    parsing/execution.
  - `scan/engines/iac_scan` owns deterministic IaC file collection and
    Dockerfile/GitHub Actions/Terraform checks.
  - `scan/engines/secret_scan` owns deterministic secret-token scanning,
    token classification, and scanner reports.
- Public root shims `crate::dep_hygiene`, `crate::iac_scan`, and
  `crate::secret_scan` re-export those scan engine APIs for compatibility.
- PR comment projection is now under `findings/presentation/pr_comment`;
  `crate::pr_comment` remains a compatibility shim preserving
  `build_pr_comment` and `PrCommentInput`.
- `runtime` now separates domain contracts, application flow, and governance:
  - `runtime/domain` owns agent request/response contracts, runtime traits,
    model tiers, sub-agent roles, tool-loop request/step data, and tool-call
    handler types.
  - `runtime/application` owns the canonical tool-augmented loop driver.
  - `runtime/policy` owns explicit-model validation and no-silent-fallback
    enforcement helpers.
- Public `crate::runtime::*` and crate-root re-exports still preserve
  `AgentRuntime`, `AgentQueryRequest`, `AgentQueryResponse`, `TriageRequest`,
  `AgentToolLoopRequest`, `ToolBox`, `run_tool_loop`, `ModelTier`,
  `SubagentRole`, `require_configured_model`, `resolve_explicit_model`, and
  `validate_model_spec`.
- `kuzushi-cli` now keeps delivery concerns behind explicit adapter-oriented
  modules:
  - `application/` owns command use cases for auth, catalog, config, findings,
    permissions, PR comments, run-tool dispatch, runs, scan, and suppressions.
  - `dispatch/` owns CLI command routing only.
  - `presentation/` owns terminal/plain output, scan CI lines, scan JSON
    output, and run-artifact output formatting.
  - `adapters/` owns auth/provider bridge helpers for the ping flow.
- Private crate-root shims for CLI command modules were removed after imports
  moved to the delivery boundaries above.
- `kuzushi-openai` now keeps provider infrastructure behind explicit adapter
  modules:
  - `pi_agent_core/` owns the Pi Agent Core runtime config, runtime trait
    implementation, JSON bridge process boundary, next-step bridge, and bridge
    payload contracts.
  - `messages/` owns Anthropic Messages API history shaping used by tool-loop
    bridge calls.
  - `anthropic_oauth/` and `oauth/` remain the Anthropic provider adapter and
    OAuth readiness boundary.
- `PiAgentCoreRuntime`, `AnthropicOAuthRuntime`, OAuth readiness probing, and
  legacy `bridge`/`runtime` module exports remain available.

## Test Strategy

Every phase must run:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Add focused tests for the behavior moved in that phase. Required coverage
includes public module exports, tool catalog stability, hidden DAG behavior,
scan/shell/run parity for touched tools, finding DB compatibility, `.kuzushi`
path compatibility, no-silent-model-fallback regressions, CLI public behavior,
TUI command/rendering behavior, and provider adapter behavior where relevant.

## CRAP Gate

Every phase must run the repo CRAP gate or an equivalent baseline comparison.
The gate must:

- keep changed/new production functions below CRAP 15;
- prevent touched existing CRAP offenders from increasing;
- report exact blockers if the tooling cannot run;
- never be claimed as passing without measurement.

The repeatable gate is:

```bash
scripts/crap-gate.sh --create-baseline
scripts/crap-gate.sh
```

The script requires both `cargo llvm-cov` and `cargo crap`, writes LCOV and
reports under `target/crap/`, compares against a JSON baseline, fails CRAP
regressions, and fails new changed production functions at or above CRAP 15.
When continuing an already-started migration, create a fresh baseline only at
the start of a clearly documented phase; do not reset the baseline to hide a
regression inside the same phase.

## Non-Goals

- Do not rename public tool IDs.
- Do not change persisted schemas without migration tests.
- Do not duplicate proof-state behavior in findings, reports, CLI, or TUI.
- Do not move all specialist security logic into `modules/`.
- Do not introduce vague `utils.rs` dumping grounds or generic service layers
  around one-function behavior.
- Do not resurrect TypeScript/Ink TUI paths.
