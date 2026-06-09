#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  artifactKindAliasFields,
  artifactLabelAliasFields,
  artifactPathAliasFields,
} from "./canonical-run-artifacts.mjs";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();

const quotedArtifactPathAliasFields = artifactPathAliasFields.map((alias) => `"${alias}"`);
const quotedArtifactLabelAliasFields = artifactLabelAliasFields.map((alias) => `"${alias}"`);
const quotedArtifactKindAliasFields = artifactKindAliasFields.map((alias) => `"${alias}"`);
const canonicalArtifactAliasKeys = ['"label"', '"path"', '"kind"'];

const checks = [
  {
    label: "artifact alias contract is shared by run and result normalization",
    file: "crates/kuzushi-core/src/artifact_contract.rs",
    tokens: [
      "ARTIFACT_PATH_KEYS",
      "ARTIFACT_LABEL_KEYS",
      "ARTIFACT_KIND_KEYS",
      "CanonicalRunArtifactSpec",
      "CANONICAL_RUN_ARTIFACTS",
      "OPTIONAL_RUN_ARTIFACTS",
      "TOOL_INPUT_ARTIFACTS",
      "TOOL_RESULT_ARTIFACTS",
      "first_nonempty_string",
      "first_nonempty_value_string",
      ...quotedArtifactPathAliasFields,
      ...quotedArtifactLabelAliasFields,
      ...quotedArtifactKindAliasFields,
    ],
  },
  {
    label: "registry dispatch normalizes mapped tool outputs",
    file: "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs",
    tokens: [
      "use super::output_contract::normalize_tool_output_contract;",
      "return result.map(|output| normalize_tool_output_contract(name, output));",
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
    label: "tool output contract covers legacy raw output shapes",
    file: "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/output_contract_tests.rs",
    tokens: [
      "wraps_non_object_outputs",
      "leaves_catalog_metadata_arrays_unwrapped",
      "preserves_unknown_domain_status_under_data",
      "lifts_nested_artifact_map_to_contract_artifacts",
      "normalizes_snake_case_artifact_path_aliases",
    ],
  },
  {
    label: "report artifact summary covers canonical alias exclusions",
    file: "crates/kuzushi-core/src/report/tests.rs",
    tokens: [
      "report_artifact_manifest_alias_counts_exclude_canonical_fields",
      "aliases labels=1, paths=1, kinds=1",
    ],
  },
  {
    label: "result normalization uses shared artifact aliases",
    file: "crates/kuzushi-core/src/module_result.rs",
    tokens: ["use crate::artifact_contract::ARTIFACT_PATH_KEYS;"],
  },
  {
    label: "run artifact extraction uses shared artifact aliases",
    file: "crates/kuzushi-core/src/run_artifacts/output_declared_artifacts.rs",
    tokens: [
      "use crate::artifact_contract::{",
      "first_nonempty_string",
      "ARTIFACT_KIND_KEYS",
      "ARTIFACT_LABEL_KEYS",
      "ARTIFACT_PATH_KEYS",
    ],
  },
  {
    label: "report artifact summaries use shared artifact aliases",
    file: "crates/kuzushi-core/src/report/artifact_summary/artifact_manifest.rs",
    tokens: [
      "use crate::artifact_contract::{",
      "first_nonempty_value_string",
      "ARTIFACT_KIND_KEYS",
      "ARTIFACT_LABEL_KEYS",
      "ARTIFACT_PATH_KEYS",
      "CANONICAL_RUN_ARTIFACTS",
      "compatibility_alias_count",
      ...canonicalArtifactAliasKeys,
    ],
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
