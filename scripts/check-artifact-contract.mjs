#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  runArtifactManifestSchemaFields,
  runAttackSurfaceSchemaFields,
  runContextSchemaFields,
  runEventsSchemaFields,
  runFailuresSchemaFields,
  runFindingsSchemaFields,
  runProofSchemaFields,
  runRecommendationsSchemaFields,
  reportJsonlAliasFields,
  schemaAliasContractFields,
  runSummarySchemaFields,
  runThreatModelSchemaFields,
  runTraceSchemaFields,
} from "./artifact-contract-fields.mjs";
import { checkCanonicalRunSchemas } from "./artifact-schema-contract.mjs";
import { checkArtifactSchemaInventory } from "./artifact-schema-inventory-contract.mjs";
import { tokenChecks } from "./artifact-token-contracts.mjs";
import { checkFailureSchemaBounds } from "./check-failure-schema-bounds.mjs";
import { rustFunctionBody } from "./rust-source-contracts.mjs";
import {
  optionalRunArtifacts,
  requiredRunArtifacts,
  toolResultArtifacts,
} from "./canonical-run-artifacts.mjs";
import {
  checkCanonicalManifestInventory,
  checkCanonicalSnapshotInventory,
  checkCanonicalSpecialWriterInventory,
  checkFailureMissingArtifactInventory,
  checkFailureFollowUpInventory,
  checkOptionalAndToolResultArtifactInventory,
  checkReportReaderInventory,
  checkRunMetadataWriterInventory,
} from "./artifact-manifest-contract.mjs";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();

const reportAliasFields = ["reportMarkdown", "report_markdown", "data.reportMarkdown", "data.report_markdown", "reportSarif", "report_sarif", "data.reportSarif", "data.report_sarif"];
const reportSubstrateAliasFields = ["reportMarkdown", "report_markdown", "reportSarif", "report_sarif"];

const checks = [
  {
    label: "artifact architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: [...requiredRunArtifacts, ...optionalRunArtifacts, ...toolResultArtifacts, ...reportAliasFields],
  },
  {
    label: "README artifact table",
    file: "README.md",
    artifacts: [...requiredRunArtifacts, ...optionalRunArtifacts, ...toolResultArtifacts, ...reportAliasFields],
  },
  {
    label: "run artifact substrate",
    files: [
      "crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs",
      "crates/kuzushi-core/src/run_artifacts/canonical_run_files.rs",
      "crates/kuzushi-core/src/run_artifacts/run_summary_store.rs",
    ],
    artifacts: [...requiredRunArtifacts, ...reportSubstrateAliasFields],
  },
  {
    label: "report artifact reader",
    files: [
      "crates/kuzushi-core/src/report/application.rs",
      "crates/kuzushi-core/src/artifact_contract.rs",
    ],
    artifacts: [...requiredRunArtifacts, ...optionalRunArtifacts, ...toolResultArtifacts],
  },
  {
    label: "run artifact file-existence regression helper",
    file: "crates/kuzushi-core/src/run_artifacts/tests.rs",
    artifacts: requiredRunArtifacts,
    functions: ["assert_canonical_run_files_exist"],
  },
  {
    label: "run artifact manifest regression helper",
    file: "crates/kuzushi-core/src/run_artifacts/tests.rs",
    artifacts: requiredRunArtifacts,
    functions: ["assert_manifest_has_canonical_run_artifacts"],
    sharedInventory: "CANONICAL_RUN_ARTIFACTS",
  },
  {
    label: "optional SARIF promotion regression",
    file: "crates/kuzushi-core/src/run_artifacts/tests.rs",
    artifacts: optionalRunArtifacts,
    functions: [
      "tool_run_complete_promotes_result_snapshots_to_canonical_files",
      "tool_run_complete_promotes_snake_case_report_artifacts",
    ],
  },
  {
    label: "tool result envelope artifact regression",
    file: "crates/kuzushi-core/src/run_artifacts/tests.rs",
    artifacts: toolResultArtifacts,
    functions: ["tool_run_complete_records_contract_complete_result_envelope"],
  },
  {
    label: "run summary schema",
    file: "schemas/run.summary.schema.json",
    artifacts: ["run.json", "summary.json", ...runSummarySchemaFields],
  },
  {
    label: "run summary schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.summary.schema.json", "run.json", "summary.json"],
  },
  {
    label: "run artifact manifest schema",
    file: "schemas/run.artifacts.schema.json",
    artifacts: ["artifacts.json", ...runArtifactManifestSchemaFields],
  },
  {
    label: "run artifact manifest schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.artifacts.schema.json", "artifacts.json"],
  },
  {
    label: "run failures schema",
    file: "schemas/run.failures.schema.json",
    artifacts: ["failures.json", ...runFailuresSchemaFields],
  },
  {
    label: "run failures schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.failures.schema.json", "failures.json"],
  },
  {
    label: "schema alias contract architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: schemaAliasContractFields,
  },
  {
    label: "schema alias contract README",
    file: "README.md",
    artifacts: ["schemas/run.*.schema.json", "kuzushi/schemas/*", ...schemaAliasContractFields],
  },
  {
    label: "schema package export architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["kuzushi/schemas/*", "kuzushi/schemas/run.summary.schema.json"],
  },
  {
    label: "run events schema",
    file: "schemas/run.events.schema.json",
    artifacts: ["events.jsonl", ...runEventsSchemaFields],
  },
  {
    label: "run events schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.events.schema.json", "events.jsonl"],
  },
  {
    label: "run trace schema",
    file: "schemas/run.trace.schema.json",
    artifacts: ["trace.jsonl", ...runTraceSchemaFields],
  },
  {
    label: "run trace schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.trace.schema.json", "trace.jsonl"],
  },
  {
    label: "run context schema",
    file: "schemas/run.context.schema.json",
    artifacts: runContextSchemaFields,
  },
  {
    label: "run context schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.context.schema.json", "context.json"],
  },
  {
    label: "run attack-surface schema",
    file: "schemas/run.attack-surface.schema.json",
    artifacts: runAttackSurfaceSchemaFields,
  },
  {
    label: "run attack-surface schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.attack-surface.schema.json", "attack-surface.json"],
  },
  {
    label: "run threat-model schema",
    file: "schemas/run.threat-model.schema.json",
    artifacts: runThreatModelSchemaFields,
  },
  {
    label: "run threat-model schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.threat-model.schema.json", "threat-model.json"],
  },
  {
    label: "run recommendations schema",
    file: "schemas/run.recommendations.schema.json",
    artifacts: runRecommendationsSchemaFields,
  },
  {
    label: "run recommendations schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.recommendations.schema.json", "recommendations.json"],
  },
  {
    label: "run findings schema",
    file: "schemas/run.findings.schema.json",
    artifacts: runFindingsSchemaFields,
  },
  {
    label: "run findings schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.findings.schema.json", "findings.json"],
  },
  {
    label: "run proof schema",
    file: "schemas/run.proof.schema.json",
    artifacts: runProofSchemaFields,
  },
  {
    label: "run proof schema architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: ["schemas/run.proof.schema.json", "proof.json"],
  },
];

const failures = [
  ...checks.flatMap(checkArtifactReferences),
  ...checkCanonicalManifestInventory(root),
  ...checkOptionalAndToolResultArtifactInventory(root),
  ...checkReportReaderInventory(root),
  ...checkFailureFollowUpInventory(root),
  ...checkFailureMissingArtifactInventory(root),
  ...checkCanonicalSnapshotInventory(root),
  ...checkCanonicalSpecialWriterInventory(root),
  ...checkRunMetadataWriterInventory(root),
  ...checkArtifactSchemaInventory(),
  ...tokenChecks.flatMap(checkTokenReferences),
  ...checkCanonicalRunSchemas(root),
  ...checkFailureSchemaBounds(root),
];

if (failures.length > 0) {
  console.error("Kuzushi artifact contract check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `Artifact contract check passed for ${requiredRunArtifacts.length} required artifacts, ${optionalRunArtifacts.length} optional artifacts, ${toolResultArtifacts.length} tool-result artifact, report placeholder behavior, and failure handoff safety fields.`,
);

function checkArtifactReferences(check) {
  const files = check.files ?? [check.file];
  const missing = files.filter((file) => !existsSync(path.join(root, file)));
  if (missing.length > 0) return missing.map((file) => `${check.label}: missing ${file}`);
  const rawSource = files.map((file) => readFileSync(path.join(root, file), "utf8")).join("\n");
  const source = check.functions ? checkedFunctionBodies(check, rawSource) : rawSource;
  const sourceLabel = files.length === 1 ? files[0] : files.join(", ");
  if (check.sharedInventory && source.includes(check.sharedInventory)) return [];
  return check.artifacts
    .filter((artifact) => !source.includes(artifact))
    .map((artifact) => `${check.label}: ${sourceLabel} does not mention ${artifact}`);
}

function checkTokenReferences(check) {
  const file = path.join(root, check.file);
  if (!existsSync(file)) return [`${check.label}: missing ${check.file}`];
  const source = readFileSync(file, "utf8");
  return check.tokens
    .filter((token) => !source.includes(token))
    .map((token) => `${check.label}: ${check.file} does not mention ${token}`);
}

function checkedFunctionBodies(check, source) {
  return check.functions
    .map((name) => {
      const body = rustFunctionBody(source, name);
      if (body === null) {
        console.error(`Kuzushi artifact contract check failed:\n- ${check.label}: missing function ${name}`);
        process.exit(1);
      }
      return body;
    })
    .join("\n");
}
