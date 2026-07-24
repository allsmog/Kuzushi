#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();

const canonicalArtifactFieldKeys = ['"label"', '"path"', '"kind"'];

const checks = [
  {
    label: "artifact field contract is canonical",
    file: "crates/kuzushi-core/src/artifact_contract.rs",
    tokens: [
      "CanonicalRunArtifactSpec",
      "CANONICAL_RUN_ARTIFACTS",
      "OPTIONAL_RUN_ARTIFACTS",
      "TOOL_INPUT_ARTIFACTS",
      "TOOL_RESULT_ARTIFACTS",
    ],
  },
  {
    label: "registry dispatch normalizes mapped tool outputs",
    file: "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs",
    tokens: [
      "use super::output_contract::normalize_tool_output_contract;",
      "let result = self.invoke_prepared_executor(name, &input, execution_ctx, runtime);",
      "fn invoke_prepared_executor(",
      ".map(|output| normalize_tool_output_contract(name, output))",
      "registered tool or DAG node {name:?} has no Rust executor mapping",
    ],
  },
  {
    label: "tool output contract only exempts catalog metadata arrays",
    file: "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/output_contract.rs",
    tokens: [
      "normalize_module_result(output)",
      'matches!(name, "catalog:modules" | "catalog:tools")',
      "normalize_tool_output_contract",
    ],
  },
  {
    label: "tool output contract covers canonical raw output shapes",
    file: "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/output_contract_tests.rs",
    tokens: [
      "wraps_non_object_outputs",
      "leaves_catalog_metadata_arrays_unwrapped",
      "preserves_unknown_domain_status_under_data",
      "lifts_nested_artifact_map_to_contract_artifacts",
      "drops_artifact_objects_without_canonical_path",
    ],
  },
  {
    label: "report artifact summary covers canonical fields",
    file: "crates/kuzushi-core/src/report/tests.rs",
    tokens: [
      "report_artifact_manifest_summary_uses_only_canonical_fields",
      "labels run metadata, run events, semantic run items, failure handoff",
    ],
  },
  {
    label: "result normalization uses canonical artifact path",
    file: "crates/kuzushi-core/src/module_result.rs",
    tokens: ['object.get("path").and_then(Value::as_str)'],
  },
  {
    label: "run artifact extraction uses canonical artifact fields",
    file: "crates/kuzushi-core/src/run_artifacts/output_declared_artifacts.rs",
    tokens: [
      'nonempty_object_string(object, "path")',
      'nonempty_object_string(object, "label")',
      'nonempty_object_string(object, "kind")',
    ],
  },
  {
    label: "report artifact summaries use canonical artifact fields",
    file: "crates/kuzushi-core/src/report/artifact_summary/artifact_manifest.rs",
    tokens: ["CANONICAL_RUN_ARTIFACTS", "nonempty_value_string", ...canonicalArtifactFieldKeys],
  },
  {
    label: "module result envelope helpers expose all canonical statuses",
    file: "crates/kuzushi-core/src/module_result/envelope.rs",
    tokens: [
      "completed_output_result",
      "failed_output_result",
      "skipped_output_result",
      "partial_output_result",
      '"status": "completed"',
      '"status": "failed"',
      "completed_result_uses_canonical_envelope_fields",
      "failed_result_copies_output_into_errors",
      "skipped_and_partial_results_preserve_warning_arrays",
    ],
  },
];

const failures = checks.flatMap(checkTokens);

if (failures.length > 0) {
  console.error("Kuzushi result envelope contract failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("result envelope contract passed");

function checkTokens(check) {
  const file = path.join(root, check.file);
  if (!existsSync(file)) return [`${check.label}: missing ${check.file}`];
  const source = readFileSync(file, "utf8");
  return check.tokens
    .filter((token) => !source.includes(token))
    .map((token) => `${check.label}: ${check.file} does not mention ${token}`);
}
