import {
  failureHandoffFields,
  forbiddenFailureClaims,
  reportLifecycleFields,
} from "./artifact-contract-fields.mjs";
import { requiredRunArtifacts, toolInputArtifacts } from "./canonical-run-artifacts.mjs";

const failureReportFollowUpRustFields = [
  "report_artifact_spec().leaf",
  "failure_artifact_spec().leaf",
  "OPTIONAL_RUN_ARTIFACTS",
];
const failureReportFollowUpDocFields = ["report.md", "report.sarif"];
const canonicalArtifactFields = ["label", "path", "kind"];
const declaredArtifactFields = [
  "CanonicalRunArtifactSpec",
  "CANONICAL_RUN_ARTIFACTS",
  "OPTIONAL_RUN_ARTIFACTS",
  "TOOL_INPUT_ARTIFACTS",
  "TOOL_RESULT_ARTIFACTS",
];
const runArtifactNormalizationFields = [
  "RunArtifact",
  "from_declared",
  "normalized",
  "deserialize_artifact_label",
  "deserialize_trimmed_string",
  "deserialize_artifact_kind",
  "normalize_artifact_label",
  "normalize_artifact_kind",
  "infer_artifact_kind",
  ...canonicalArtifactFields,
];
const artifactBoundaryNormalizationTokens = ["artifact.normalized()"];

export function checkArtifactTokenContractInvariants() {
  return [];
}

export const tokenChecks = [
  {
    label: "failure handoff Rust substrate",
    file: "crates/kuzushi-core/src/run_artifacts/run_failures.rs",
    tokens: [
      ...failureHandoffFields,
      ...failureReportFollowUpRustFields,
      ...forbiddenFailureClaims,
    ],
  },
  {
    label: "report placeholder Rust substrate",
    file: "crates/kuzushi-core/src/run_artifacts/canonical_run_markers.rs",
    tokens: [
      "write_missing_report_marker",
      "missing_report",
      "No report was recorded for this run.",
    ],
  },
  {
    label: "report JSONL reader canonical lifecycle fields",
    file: "crates/kuzushi-core/src/report/artifact_summary/jsonl.rs",
    tokens: reportLifecycleFields,
  },
  {
    label: "report result exploit-chain fields",
    file: "crates/kuzushi-core/src/report/artifact_summary/result.rs",
    tokens: ["/data/chains", "overallSeverity", "impactDescription", "filePath", "startLine"],
  },
  {
    label: "report context snapshot envelope aliases",
    file: "crates/kuzushi-core/src/report/artifact_summary/context.rs",
    tokens: ["contextSnapshot", "/data/context", "/data/snapshot"],
  },
  {
    label: "report findings snapshot envelope aliases",
    file: "crates/kuzushi-core/src/report/artifact_summary/findings.rs",
    tokens: ["coreFindings", "/data/coreFindings", "/data/findings"],
  },
  {
    label: "report proof snapshot envelope aliases",
    file: "crates/kuzushi-core/src/report/artifact_summary/proof.rs",
    tokens: ["/data/proof"],
  },
  {
    label: "report recommendation envelope aliases",
    file: "crates/kuzushi-core/src/report/artifact_summary/recommendations.rs",
    tokens: ["recommendationReport", "/data/recommendationReport", "/data/recommendations"],
  },
  {
    label: "TUI recommendation view model artifact envelope aliases",
    file: "crates/kuzushi-tui/src/ui_view_models/recommendation.rs",
    tokens: [
      "recommendation_report_data",
      "recommendationReport",
      "/data/recommendationReport",
      "recommendation_model_reads_data_wrapped_latest_artifact",
    ],
  },
  {
    label: "report threat-model envelope aliases",
    file: "crates/kuzushi-core/src/report/artifact_summary.rs",
    tokens: ["/data/document", "trustBoundaries", "relatedCwe", "inputCategories"],
  },
  {
    label: "report artifact manifest uses canonical artifact fields",
    file: "crates/kuzushi-core/src/report/artifact_summary/artifact_manifest.rs",
    tokens: ["CANONICAL_RUN_ARTIFACTS", "nonempty_value_string", ...canonicalArtifactFields],
  },
  {
    label: "report reader and writer resolve required artifact labels from shared specs",
    file: "crates/kuzushi-core/src/report/application.rs",
    tokens: ["canonical_run_artifact_spec", "canonical_report_spec", "write_report_markdown"],
  },
  {
    label: "run artifact normalization boundary",
    file: "crates/kuzushi-core/src/run_artifacts/run_artifact.rs",
    tokens: runArtifactNormalizationFields,
  },
  {
    label: "run artifact manifest write normalization",
    file: "crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs",
    tokens: ["record_run_artifact", ".normalized()", "run artifact path must not be empty"],
  },
  {
    label: "shared canonical artifact manifest enumerates every required artifact",
    file: "crates/kuzushi-core/src/artifact_contract.rs",
    tokens: ["CanonicalRunArtifactSpec", "CANONICAL_RUN_ARTIFACTS", ...requiredRunArtifacts],
  },
  {
    label: "run artifact manifest writer uses shared canonical artifacts",
    file: "crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs",
    tokens: ["CANONICAL_RUN_ARTIFACTS", "spec.artifact(target, run_id)"],
  },
  {
    label: "tool input writer uses shared artifact spec",
    file: "crates/kuzushi-core/src/run_artifacts/tool_run_record.rs",
    tokens: [
      'tool_input_artifact_spec("input.json")',
      "spec.leaf",
      "spec.label",
      ...toolInputArtifacts,
    ],
  },
  {
    label: "tool result writer uses shared artifact spec",
    file: "crates/kuzushi-core/src/run_artifacts/tool_run_record.rs",
    tokens: ['tool_result_artifact_spec("result.json")', "spec.leaf", "spec.label"],
  },
  {
    label: "failure handoff writer uses shared artifact spec",
    file: "crates/kuzushi-core/src/run_artifacts/run_failures.rs",
    tokens: [
      'canonical_run_artifact_spec("failures.json")',
      'canonical_run_artifact_spec("report.md")',
      "failure_artifact_spec",
      "write_run_artifact_json(",
      "read_run_artifact_text(target, run_id, failure_artifact_spec().leaf)",
      "report_artifact_spec",
      "spec.leaf",
      "spec.label",
    ],
  },
  {
    label: "canonical run file creation writes required v3 placeholders",
    file: "crates/kuzushi-core/src/run_artifacts/canonical_run_files.rs",
    tokens: [
      "write_empty_failures_marker(",
      'required_artifact_spec("failures.json").leaf',
      "write_json_if_missing(",
      'required_artifact_spec("artifacts.json").leaf',
      'write_text_if_missing(dir.join(required_artifact_spec("events.jsonl").leaf)',
      'write_text_if_missing(dir.join(required_artifact_spec("items.jsonl").leaf)',
      "write_missing_report_marker(",
      'required_artifact_spec("report.md").leaf',
      "record_canonical_run_artifacts",
      'optional_run_artifact_spec("report.sarif")',
    ],
  },
  {
    label: "run summary writes canonical metadata before placeholder substrate",
    file: "crates/kuzushi-core/src/run_artifacts/run_summary_store.rs",
    tokens: [
      "run_metadata_artifact_spec().leaf",
      'canonical_run_artifact_spec("run.json")',
      "checked_run_artifact_path(",
      "write_run_summary_file(&metadata_path",
      "ensure_canonical_run_files(target, &summary.run_id, &summary.status)",
      "write_latest_run_id(target, &summary)",
    ],
  },
  {
    label: "run summary embedded artifact normalization",
    file: "crates/kuzushi-core/src/run_artifacts/running.rs",
    tokens: ["with_artifact", "artifact.normalized()"],
  },
  {
    label: "run event artifact normalization",
    file: "crates/kuzushi-core/src/run_artifacts/run_events.rs",
    tokens: ["with_artifact", ...artifactBoundaryNormalizationTokens],
  },
  {
    label: "run artifact writer return normalization",
    file: "crates/kuzushi-core/src/run_artifacts/write_run_artifact_json.rs",
    tokens: ["write_run_artifact_json", "RunArtifact::from_declared", "record_run_artifact"],
  },
  {
    label: "run text artifact writer return normalization",
    file: "crates/kuzushi-core/src/run_artifacts/write_run_artifact_text.rs",
    tokens: ["write_run_artifact_text", "RunArtifact::from_declared", "record_run_artifact"],
  },
  {
    label: "failure handoff artifact normalization",
    file: "crates/kuzushi-core/src/run_artifacts/run_failures.rs",
    tokens: [
      "available_failure_artifacts",
      "append_available_artifact_paths",
      "contained_failure_artifact",
      "artifact.normalized()",
    ],
  },
  {
    label: "shared declared artifact fields",
    file: "crates/kuzushi-core/src/artifact_contract.rs",
    tokens: declaredArtifactFields,
  },
  {
    label: "tool output declared artifact uses canonical fields",
    file: "crates/kuzushi-core/src/run_artifacts/output_declared_artifacts.rs",
    tokens: [
      'nonempty_object_string(object, "path")',
      'nonempty_object_string(object, "label")',
      'nonempty_object_string(object, "kind")',
    ],
  },
  {
    label: "tool output declared artifact architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    tokens: ["data.artifacts", '"label"', '"path"', '"kind"'],
  },
  {
    label: "mode parity doc names canonical run bundle for shell and run",
    file: "docs/assessments/mode-parity.md",
    tokens: [
      "All three write the canonical run bundle",
      "`run.json`",
      "`events.jsonl`",
      "`items.jsonl`",
      "`failures.json`",
      "`report.md`",
      "`artifacts.json`",
      "tool input/result artifacts",
    ],
  },
  {
    label: "run event reader canonical tool and artifact fields",
    file: "crates/kuzushi-core/src/run_artifacts/run_events.rs",
    tokens: ["pub tool: Option<String>", "pub artifact: Option<RunArtifact>"],
  },
  {
    label: "report JSONL canonical lifecycle architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    tokens: ["schemas/run.items.schema.json", ...reportLifecycleFields],
  },
  {
    label: "CLI run entrypoint starts canonical artifact recording",
    file: "crates/kuzushi-cli/src/application/run_tool_prepare.rs",
    tokens: [
      "record_cli_tool_run_started",
      "record_tool_run_started_with_reproducibility",
      'ToolRunRecord::new(target, run_id, "run", tool)',
      "cli_tool_run_artifact_target",
    ],
  },
  {
    label: "CLI run entrypoint finishes canonical artifact recording",
    file: "crates/kuzushi-cli/src/tool_run_artifacts.rs",
    tokens: [
      "finish_cli_tool_run",
      "fail_cli_tool_run",
      "try_record_tool_run_complete",
      "try_record_tool_run_failed",
      'ToolRunRecord::new(target, run_id, "run", tool)',
    ],
  },
  {
    label: "TUI tool entrypoint starts canonical artifact recording",
    file: "crates/kuzushi-tui/src/app/tool_runner/run_tool/background/dispatch.rs",
    tokens: [
      "prepare_background_tool_run",
      "record_tool_run_started_with_reproducibility",
      'ToolRunRecord::new(&target, &run_id, "tool", tool_name)',
      "background_tool_trace_handle",
    ],
  },
  {
    label: "TUI tool entrypoint finishes canonical artifact recording",
    file: "crates/kuzushi-tui/src/app/tool_runner/tool_run_records.rs",
    tokens: [
      "record_tool_run_complete",
      "record_tool_run_failed",
      "try_record_tool_run_complete",
      "try_record_tool_run_failed",
      "try_record_tool_run_canceled",
      "try_record_tool_run_interrupted",
      "try_record_tool_run_refused",
      'ToolRunRecord::new(target, run_id, "tool", tool_name)',
    ],
  },
  {
    label: "failure handoff architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    tokens: [
      "failed stage/tool",
      "concrete cause",
      "available artifacts",
      "missing artifacts",
      "allowed proof level",
      "forbidden claims",
      "next files or artifacts to inspect",
      "recovery options",
      "fallback prompt",
      ...failureReportFollowUpDocFields,
      ...forbiddenFailureClaims,
    ],
  },
];
