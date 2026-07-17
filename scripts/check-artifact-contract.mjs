#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  runArtifactManifestSchemaFields,
  runEventsSchemaFields,
  runFailuresSchemaFields,
  runSummarySchemaFields,
  runTraceSchemaFields,
  schemaAliasContractFields,
} from "./artifact-contract-fields.mjs";
import {
  checkArtifactManifestContractHelpers,
  checkCanonicalManifestInventory,
  checkCanonicalSpecialWriterInventory,
  checkCliRunsPathConsumers,
  checkContextSnapshotPathHelper,
  checkFailureFollowUpInventory,
  checkFailureMissingArtifactInventory,
  checkHomeCockpitArtifactRail,
  checkManifestLoaderToolInputMetadata,
  checkOauthCredentialPathHelper,
  checkOptionalAndToolResultArtifactInventory,
  checkPatchWorktreePathHelper,
  checkPersistentThreatModelPathHelper,
  checkPromptPathHelpers,
  checkReportArtifactManifestSummary,
  checkReportJsonlArtifactSummary,
  checkReportReaderInventory,
  checkRunArtifactPathHelpers,
  checkRunMetadataWriterInventory,
  checkTaintIrisNextArtifactPathHelpers,
  checkThreatIntelCatalogPathHelper,
  checkThreatLeadsPathHelpers,
  checkTuiFailureHandoffArtifactLeaf,
  checkTuiPrereqChainPathHelpers,
  checkTuiRunsRootHelper,
  checkTuiRunTimelineArtifactLeaves,
  checkTuiThreatModelArtifactLeaf,
  checkWorkspaceStatePathHelpers,
} from "./artifact-manifest-contract.mjs";
import { checkCanonicalRunSchemas } from "./artifact-schema-contract.mjs";
import {
  checkArtifactSchemaInventory,
  checkArtifactSchemaInventoryHelpers,
} from "./artifact-schema-inventory-contract.mjs";
import { checkArtifactTokenContractInvariants, tokenChecks } from "./artifact-token-contracts.mjs";
import {
  checkCanonicalRunArtifactInvariantHelpers,
  checkCanonicalRunArtifactInvariants,
  optionalRunArtifacts,
  requiredRunArtifacts,
  toolInputArtifacts,
  toolResultArtifacts,
} from "./canonical-run-artifacts.mjs";
import {
  requiredArtifactSchemaFiles,
  requiredArtifactSchemaReferences,
} from "./canonical-run-schema-files.mjs";
import { checkFailureSchemaBounds } from "./check-failure-schema-bounds.mjs";
import { checkRustSourceContractParsers } from "./rust-source-contract-checks.mjs";
import { rustFunctionBody } from "./rust-source-contracts.mjs";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();

const reportAliasFields = [
  "reportMarkdown",
  "data.reportMarkdown",
  "reportSarif",
  "data.reportSarif",
];
const reportSubstrateAliasFields = ["reportMarkdown", "reportSarif"];
const schemaArchitectureDocChecks = requiredArtifactSchemaReferences().map((reference) => ({
  label: `run schema architecture doc ${reference.artifactPath}`,
  file: "docs/architecture/kuzushi-artifacts.md",
  artifacts: [reference.schemaFile, reference.artifactPath],
}));

const manifestContractGuardrailLabels = [
  "TUI workspace state label must expose workspace_state_relative_path",
  "TUI workspace state label must cache its derived relative path label",
  "TUI workspace state label must derive from workspace_state_dir",
  "TUI workspace state label must not hardcode .kuzushi/v3",
  "TUI workspace state fallback must use workspace_state_relative_path",
  "TUI workspace findings DB label must expose findings_db_relative_path",
  "TUI workspace findings DB label must cache its derived relative path label",
  "TUI workspace findings DB label must derive from workspace_findings_db_path",
  "TUI workspace findings DB label must not hardcode .kuzushi/v3/index.sqlite3",
  "TUI workspace findings DB fallback must use findings_db_relative_path",
  "TUI findings empty state must use findings_db_relative_path",
  "TUI findings empty state must not hardcode .kuzushi/v3/index.sqlite3",
  "TUI module playbook findings DB label must use findings_db_relative_path",
  "TUI module playbook findings DB label must not hardcode .kuzushi/v3/index.sqlite3",
  "Carlini attachment renderer must read the shared attachment store",
  "Carlini attachment renderer must accept product and compatibility attachment modules",
  "Carlini attachment renderer must resolve attachments through WorkspaceTarget",
  "Carlini attachment renderer must handle path and URL attachment records",
  "Carlini attachment renderer must not hardcode per-module attachment paths",
];

const checks = [
  {
    label: "artifact manifest guardrail labels",
    file: "scripts/artifact-manifest-contract.mjs",
    artifacts: manifestContractGuardrailLabels,
  },
  {
    label: "artifact architecture doc",
    file: "docs/architecture/kuzushi-artifacts.md",
    artifacts: [
      ...requiredRunArtifacts,
      ...optionalRunArtifacts,
      ...toolInputArtifacts,
      ...toolResultArtifacts,
      ...reportAliasFields,
    ],
  },
  {
    label: "README artifact table",
    file: "README.md",
    artifacts: [
      ...requiredRunArtifacts,
      ...optionalRunArtifacts,
      ...toolInputArtifacts,
      ...toolResultArtifacts,
      ...reportAliasFields,
    ],
  },
  {
    label: "replay trace artifact inventory",
    file: "docs/assessments/replay-trace-audit.md",
    artifacts: [
      ...requiredRunArtifacts,
      ...optionalRunArtifacts,
      ...toolInputArtifacts,
      ...toolResultArtifacts,
    ],
  },
  {
    label: "run artifact substrate",
    files: [
      "crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs",
      "crates/kuzushi-core/src/run_artifacts/canonical_run_files.rs",
      "crates/kuzushi-core/src/run_artifacts/canonical_run_markers.rs",
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
    artifacts: [
      ...requiredRunArtifacts,
      ...optionalRunArtifacts,
      ...toolInputArtifacts,
      ...toolResultArtifacts,
    ],
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
    label: "optional SARIF report artifact regression",
    file: "crates/kuzushi-core/src/run_artifacts/tests.rs",
    artifacts: optionalRunArtifacts,
    functions: [
      "tool_run_complete_keeps_domain_snapshots_inside_result_json",
      "tool_run_complete_rejects_snake_case_report_artifacts",
    ],
  },
  {
    label: "tool input artifact regression",
    file: "crates/kuzushi-core/src/run_artifacts/tests.rs",
    artifacts: toolInputArtifacts,
    functions: ["tool_run_start_records_input_summary_event_and_trace"],
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
    artifacts: ["run.json", ...runSummarySchemaFields],
  },
  {
    label: "run artifact manifest schema",
    file: "schemas/run.artifacts.schema.json",
    artifacts: ["artifacts.json", ...runArtifactManifestSchemaFields],
  },
  {
    label: "run failures schema",
    file: "schemas/run.failures.schema.json",
    artifacts: ["failures.json", ...runFailuresSchemaFields],
  },
  ...schemaArchitectureDocChecks,
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
    artifacts: ["kuzushi/schemas/*", ...requiredArtifactSchemaFiles()],
  },
  {
    label: "run events schema",
    file: "schemas/run.events.schema.json",
    artifacts: ["events.jsonl", ...runEventsSchemaFields],
  },
  {
    label: "run trace schema",
    file: "schemas/run.trace.schema.json",
    artifacts: ["trace.jsonl", ...runTraceSchemaFields],
  },
];

const failures = [
  ...checks.flatMap(checkArtifactReferences),
  ...checkCanonicalManifestInventory(root),
  ...checkOptionalAndToolResultArtifactInventory(root),
  ...checkReportReaderInventory(root),
  ...checkReportArtifactManifestSummary(root),
  ...checkReportJsonlArtifactSummary(root),
  ...checkFailureFollowUpInventory(root),
  ...checkFailureMissingArtifactInventory(root),
  ...checkCanonicalSpecialWriterInventory(root),
  ...checkRunMetadataWriterInventory(root),
  ...checkWorkspaceStatePathHelpers(root),
  ...checkPatchWorktreePathHelper(root),
  ...checkThreatIntelCatalogPathHelper(root),
  ...checkPersistentThreatModelPathHelper(root),
  ...checkOauthCredentialPathHelper(root),
  ...checkThreatLeadsPathHelpers(root),
  ...checkContextSnapshotPathHelper(root),
  ...checkPromptPathHelpers(root),
  ...checkTaintIrisNextArtifactPathHelpers(root),
  ...checkTuiPrereqChainPathHelpers(root),
  ...checkHomeCockpitArtifactRail(root),
  ...checkTuiFailureHandoffArtifactLeaf(root),
  ...checkTuiThreatModelArtifactLeaf(root),
  ...checkTuiRunTimelineArtifactLeaves(root),
  ...checkRunArtifactPathHelpers(root),
  ...checkTuiRunsRootHelper(root),
  ...checkCliRunsPathConsumers(root),
  ...checkArtifactManifestContractHelpers(),
  ...checkManifestLoaderToolInputMetadata(root),
  ...checkArtifactSchemaInventory(),
  ...checkArtifactSchemaInventoryHelpers(),
  ...tokenChecks.flatMap(checkTokenReferences),
  ...checkCanonicalRunSchemas(root),
  ...checkFailureSchemaBounds(root),
  ...checkRustSourceContractParsers(),
  ...checkArtifactTokenContractInvariants(),
  ...checkCanonicalRunArtifactInvariants(),
  ...checkCanonicalRunArtifactInvariantHelpers(),
];

if (failures.length > 0) {
  console.error("Kuzushi artifact contract check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `Artifact contract check passed for ${requiredRunArtifacts.length} required artifacts, ${optionalRunArtifacts.length} optional artifacts, ${toolInputArtifacts.length} tool-input artifact, ${toolResultArtifacts.length} tool-result artifact, report placeholder behavior, and failure handoff safety fields.`,
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
        console.error(
          `Kuzushi artifact contract check failed:\n- ${check.label}: missing function ${name}`,
        );
        process.exit(1);
      }
      return body;
    })
    .join("\n");
}
