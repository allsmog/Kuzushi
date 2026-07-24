import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  optionalRunArtifactSpecs,
  requiredRunArtifactSpecs,
  requiredRunArtifacts,
  toolInputArtifactSpecs,
  toolInputArtifacts,
  toolResultArtifactSpecs,
  toolResultArtifacts,
} from "./canonical-run-artifacts.mjs";
import {
  rustArrayConstantBody,
  rustCanonicalRunArtifactSpecs,
  rustStringArrayConstant,
  rustStringConstants,
} from "./rust-source-contracts.mjs";

const artifactContractFile = "crates/kuzushi-core/src/artifact_contract.rs";

export function checkCanonicalManifestInventory(root) {
  const sourcePath = path.join(root, artifactContractFile);
  if (!existsSync(sourcePath))
    return [`canonical manifest inventory: missing ${artifactContractFile}`];
  const actualSpecs =
    rustCanonicalRunArtifactSpecs(readFileSync(sourcePath, "utf8"), "CANONICAL_RUN_ARTIFACTS") ??
    [];
  const actual = actualSpecs.map((artifact) => artifact.path).sort();
  return [
    ...missingEntries(requiredRunArtifacts, actual, "canonical manifest missing required artifact"),
    ...missingEntries(actual, requiredRunArtifacts, "canonical manifest has uncontracted artifact"),
    ...duplicateEntries(actual).map(
      (artifact) => `canonical manifest duplicates artifact ${artifact}`,
    ),
    ...requiredRunArtifactSpecs.flatMap((spec) =>
      specFieldMismatches(actualSpecs, spec, "canonical manifest"),
    ),
  ];
}

export function checkOptionalAndToolResultArtifactInventory(root) {
  const sourcePath = path.join(root, artifactContractFile);
  if (!existsSync(sourcePath))
    return [`optional/tool-result inventory: missing ${artifactContractFile}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    ...specInventoryFailures(
      optionalRunArtifactSpecs,
      rustCanonicalRunArtifactSpecs(source, "OPTIONAL_RUN_ARTIFACTS") ?? [],
      "optional run artifact inventory",
    ),
    ...specInventoryFailures(
      toolResultArtifactSpecs,
      rustCanonicalRunArtifactSpecs(source, "TOOL_RESULT_ARTIFACTS") ?? [],
      "tool-result artifact inventory",
    ),
    ...specInventoryFailures(
      toolInputArtifactSpecs,
      rustCanonicalRunArtifactSpecs(source, "TOOL_INPUT_ARTIFACTS") ?? [],
      "tool-input artifact inventory",
    ),
  ];
}

export function checkReportReaderInventory(root) {
  const file = "crates/kuzushi-core/src/report/application.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`report reader inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const actualSpecs = reportReaderArtifactSpecs(root, source);
  const expectedSpecs = reportReaderExpectedSpecs();
  return [
    ...reportReaderSourceFailures(source),
    ...reportReaderInventoryFailures(expectedSpecs, actualSpecs),
    ...expectedSpecs.flatMap((expected) => reportReaderMismatches(actualSpecs, expected)),
  ];
}

export function checkReportArtifactManifestSummary(root) {
  const file = "crates/kuzushi-core/src/report/artifact_summary/artifact_manifest.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`report artifact manifest summary: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes("TOOL_INPUT_ARTIFACTS")
      ? null
      : "report artifact manifest summary must use TOOL_INPUT_ARTIFACTS",
    source.includes("tool_input_segment(artifacts)")
      ? null
      : "report artifact manifest summary must render tool-input segment",
    source.includes("tool inputs {}")
      ? null
      : "report artifact manifest summary must label tool-input artifacts",
  ].filter(Boolean);
}

export function checkReportJsonlArtifactSummary(root) {
  const file = "crates/kuzushi-core/src/report/artifact_summary/jsonl.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`report JSONL artifact summary: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes('canonical_run_artifact_spec("events.jsonl")')
      ? null
      : "report JSONL summary must use shared run events artifact spec",
    source.includes("fn run_events_artifact_leaf() -> &'static str")
      ? null
      : "report JSONL summary must centralize run events artifact leaf",
    source.includes('canonical_run_artifact_spec("trace.jsonl")')
      ? null
      : "report JSONL summary must use shared runtime trace artifact spec",
    source.includes("fn run_trace_artifact_leaf() -> &'static str")
      ? null
      : "report JSONL summary must centralize runtime trace artifact leaf",
    source.includes("file == run_events_artifact_leaf()")
      ? null
      : "report JSONL summary must dispatch events through shared artifact leaf",
    source.includes("file == run_trace_artifact_leaf()")
      ? null
      : "report JSONL summary must dispatch trace through shared artifact leaf",
  ].filter(Boolean);
}

export function checkFailureFollowUpInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/run_failures.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`failure follow-up inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    ...failureFollowUpOrderFailures(),
    ...failureFollowUpSourceFailures(source),
    ...failureArtifactPathHelperFailures(source, root),
  ].filter(Boolean);
}

function failureFollowUpOrderFailures() {
  return [
    ...arrayOrderMismatch(
      failureFollowUpRequiredOrder(),
      expectedFailureFollowUpRequiredOrder(),
      "failure follow-up required order drift",
    ),
    ...duplicateEntries(failureFollowUpRequiredOrder()).map(
      (artifact) => `failure follow-up duplicates required artifact ${artifact}`,
    ),
  ];
}

function failureFollowUpSourceFailures(source) {
  return [
    source.includes("TOOL_RESULT_ARTIFACTS")
      ? null
      : "failure follow-up must use TOOL_RESULT_ARTIFACTS",
    source.includes("TOOL_INPUT_ARTIFACTS")
      ? null
      : "failure follow-up must use TOOL_INPUT_ARTIFACTS",
    source.includes("OPTIONAL_RUN_ARTIFACTS")
      ? null
      : "optional failure follow-up must use OPTIONAL_RUN_ARTIFACTS",
    source.includes(
      "push_existing_follow_up_path(paths, target, run_id, report_artifact_spec().leaf)",
    )
      ? null
      : "optional failure follow-up must use report_artifact_spec().leaf",
    source.includes("read_run_artifact_text(target, run_id, failure_artifact_spec().leaf)")
      ? null
      : "failure loader must read failure_artifact_spec().leaf through the safe reader",
    source.includes("manifest_artifact_spec().leaf")
      ? null
      : "failure follow-up must use manifest_artifact_spec().leaf",
    source.includes("run_metadata_artifact_spec().leaf")
      ? null
      : "failure follow-up must use run_metadata_artifact_spec().leaf",
  ].filter(Boolean);
}

function failureArtifactPathHelperFailures(source, root) {
  return [
    source.includes(
      "pub(crate) fn run_failure_artifact_path(target: &Path, run_id: &str) -> Result<PathBuf>",
    )
      ? null
      : "failure artifact path helper must stay crate-visible and fallible",
    source.includes("checked_run_artifact_path(target, run_id, failure_artifact_spec().leaf)")
      ? null
      : "failure artifact path helper must use failure_artifact_spec().leaf through checked containment",
    source.includes("read_run_artifact_text(target, run_id, failure_artifact_spec().leaf)") &&
    source.includes('.require("Run failures artifact")')
      ? null
      : "failure artifact loader must use the required safe artifact reader",
    ...reportFailureHandoffPathFailures(root),
  ].filter(Boolean);
}

function failureFollowUpRequiredOrder() {
  return [
    "failures.json",
    ...toolResultArtifacts,
    ...toolInputArtifacts,
    "artifacts.json",
    "run.json",
  ];
}

function reportFailureHandoffPathFailures(root) {
  const file = "crates/kuzushi-core/src/report/failure_handoff.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`report failure handoff path: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes("run_failure_artifact_path(target, run_id)")
      ? null
      : "report failure handoff must use run_failure_artifact_path",
    source.includes('join("failures.json")')
      ? "report failure handoff must not join failures.json directly"
      : null,
  ].filter(Boolean);
}

function expectedFailureFollowUpRequiredOrder() {
  return [
    "failures.json",
    ...toolResultArtifacts,
    ...toolInputArtifacts,
    "artifacts.json",
    "run.json",
  ];
}

export function checkFailureMissingArtifactInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/run_failures.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`failure missing-artifact inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const shared = (
    rustCanonicalRunArtifactSpecs(
      readFileSync(path.join(root, artifactContractFile), "utf8"),
      "CANONICAL_RUN_ARTIFACTS",
    ) ?? []
  ).map((artifact) => artifact.path);
  return [
    source.includes("CANONICAL_FAILURE_ARTIFACTS")
      ? "failure missing-artifact inventory must not keep a local canonical list"
      : null,
    source.includes("CANONICAL_RUN_ARTIFACTS")
      ? null
      : "failure missing-artifact inventory must use CANONICAL_RUN_ARTIFACTS",
    source.includes("let failure_artifact = failure_artifact_spec().leaf")
      ? null
      : "failure missing-artifact inventory must centralize failure artifact leaf",
    source.includes("*artifact != failure_artifact")
      ? null
      : "failure missing-artifact inventory must exclude shared failure artifact leaf",
    ...missingEntries(
      requiredRunArtifacts,
      shared,
      "canonical run artifact leaves missing artifact",
    ),
    ...missingEntries(
      shared,
      requiredRunArtifacts,
      "canonical run artifact leaves has uncontracted artifact",
    ),
    ...duplicateEntries(shared).map(
      (artifact) => `canonical run artifact leaves duplicates artifact ${artifact}`,
    ),
  ].filter(Boolean);
}

export function checkCanonicalSpecialWriterInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/canonical_run_files.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`canonical special writer inventory: missing ${file}`];
  const markerFile = "crates/kuzushi-core/src/run_artifacts/canonical_run_markers.rs";
  const markerPath = path.join(root, markerFile);
  if (!existsSync(markerPath)) return [`canonical special writer inventory: missing ${markerFile}`];
  const source = `${readFileSync(sourcePath, "utf8")}\n${readFileSync(markerPath, "utf8")}`;
  const actual = canonicalSpecialWriterArtifacts(source);
  const expected = requiredSpecialWriterArtifacts();
  return [
    ...missingEntries(expected, actual, "canonical special writer missing artifact"),
    ...missingEntries(actual, expected, "canonical special writer has uncontracted artifact"),
    ...duplicateEntries(actual).map(
      (artifact) => `canonical special writer duplicates artifact ${artifact}`,
    ),
  ];
}

export function checkRunMetadataWriterInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/run_summary_store.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`run metadata writer inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes('canonical_run_artifact_spec("run.json")')
      ? null
      : "run metadata writer must use shared run metadata spec",
    source.includes("checked_run_artifact_path(") &&
    source.includes("run_metadata_artifact_spec().leaf") &&
    source.includes("write_run_summary_file(&metadata_path")
      ? null
      : "run metadata writer must write the checked run_metadata_artifact_spec().leaf path",
  ].filter(Boolean);
}

export function checkWorkspaceStatePathHelpers(root) {
  const file = "crates/kuzushi-core/src/workspace/domain/workspace_target.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`workspace state path helper: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const constants = rustStringConstants(source, [
    "KUZUSHI_STATE_DIR",
    "WORKSPACE_STATE_VERSION_DIR",
    "WORKSPACE_CONFIG_FILE",
    "WORKSPACE_OPTIONS_FILE",
    "WORKSPACE_FINDINGS_DB_FILE",
    "WORKSPACE_STATIC_EVIDENCE_DB_FILE",
    "WORKSPACE_ARTIFACT_KB_DB_FILE",
    "WORKSPACE_ATTACHMENTS_FILE",
    "WORKSPACE_MODELS_FILE",
    "WORKSPACE_CODEQL_DB_DIR",
    "LEGACY_CODEQL_STATE_DIR",
    "LEGACY_CODEQL_DB_DIR",
  ]);
  return [
    workspaceStatePathConstantFailures(constants),
    workspaceStatePathHelperFailures(source),
    ...workspaceStatePathConsumerFailures(root),
    ...tuiWorkspaceStateLabelFailures(root),
    ...tuiFindingsDbLabelFailures(root),
    ...tuiKnowledgeBaseAttachmentStorePathFailures(root),
    ...carliniAttachmentRendererPathFailures(root),
  ]
    .flat()
    .filter(Boolean);
}

function workspaceStatePathConstantFailures(constants) {
  return [
    constants.KUZUSHI_STATE_DIR === ".kuzushi"
      ? null
      : "workspace state helper must name KUZUSHI_STATE_DIR as .kuzushi",
    constants.WORKSPACE_STATE_VERSION_DIR === "v3"
      ? null
      : "workspace state helper must name WORKSPACE_STATE_VERSION_DIR as v3",
    constants.WORKSPACE_CONFIG_FILE === "config.toml"
      ? null
      : "workspace state helper must name WORKSPACE_CONFIG_FILE as config.toml",
    constants.WORKSPACE_OPTIONS_FILE === "options.json"
      ? null
      : "workspace state helper must name WORKSPACE_OPTIONS_FILE as options.json",
    constants.WORKSPACE_FINDINGS_DB_FILE === "index.sqlite3"
      ? null
      : "workspace state helper must name WORKSPACE_FINDINGS_DB_FILE as index.sqlite3",
    constants.WORKSPACE_STATIC_EVIDENCE_DB_FILE === "static-evidence.sqlite3"
      ? null
      : "workspace state helper must name WORKSPACE_STATIC_EVIDENCE_DB_FILE as static-evidence.sqlite3",
    constants.WORKSPACE_ARTIFACT_KB_DB_FILE === "artifact-kb.sqlite3"
      ? null
      : "workspace state helper must name WORKSPACE_ARTIFACT_KB_DB_FILE as artifact-kb.sqlite3",
    constants.WORKSPACE_ATTACHMENTS_FILE === "attachments.json"
      ? null
      : "workspace state helper must name WORKSPACE_ATTACHMENTS_FILE as attachments.json",
    constants.WORKSPACE_MODELS_FILE === "models.toml"
      ? null
      : "workspace state helper must name WORKSPACE_MODELS_FILE as models.toml",
    constants.WORKSPACE_CODEQL_DB_DIR === "codeql-db"
      ? null
      : "workspace state helper must name WORKSPACE_CODEQL_DB_DIR as codeql-db",
    constants.LEGACY_CODEQL_STATE_DIR === ".codeql"
      ? null
      : "workspace state helper must name LEGACY_CODEQL_STATE_DIR as .codeql",
    constants.LEGACY_CODEQL_DB_DIR === "db"
      ? null
      : "workspace state helper must name LEGACY_CODEQL_DB_DIR as db",
  ];
}

function workspaceStatePathHelperFailures(source) {
  return [
    ...workspaceStatePathFunctionFailures(source),
    ...workspaceStatePathDerivationFailures(source),
    source.includes("workspace_state_dir(&self.root)")
      ? null
      : "WorkspaceTarget::state_dir must use workspace_state_dir",
    source.includes("workspace_findings_db_path(&self.root)")
      ? null
      : "WorkspaceTarget::findings_db_path must use workspace_findings_db_path",
  ];
}

function workspaceStatePathFunctionFailures(source) {
  return [
    source.includes("pub fn workspace_state_dir(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_state_dir",
    source.includes("pub fn workspace_config_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_config_path",
    source.includes("pub fn workspace_options_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_options_path",
    source.includes("pub fn workspace_findings_db_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_findings_db_path",
    source.includes("pub fn workspace_static_evidence_db_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_static_evidence_db_path",
    source.includes("pub fn workspace_artifact_kb_db_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_artifact_kb_db_path",
    source.includes("pub fn workspace_attachments_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_attachments_path",
    source.includes("pub fn workspace_models_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_models_path",
    source.includes("pub fn workspace_codeql_db_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose workspace_codeql_db_path",
    source.includes("pub fn legacy_workspace_codeql_db_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose legacy_workspace_codeql_db_path",
    source.includes("pub fn legacy_codeql_db_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "workspace state helper must expose legacy_codeql_db_path",
  ];
}

function workspaceStatePathDerivationFailures(source) {
  return [
    source.includes("workspace_state_dir(root).join(WORKSPACE_CODEQL_DB_DIR)")
      ? null
      : "workspace codeql helper must derive from workspace_state_dir",
    source.includes("workspace_state_root(root).join(WORKSPACE_CODEQL_DB_DIR)")
      ? null
      : "legacy workspace codeql helper must derive from workspace_state_root",
    source.includes("workspace_state_dir(root).join(WORKSPACE_STATIC_EVIDENCE_DB_FILE)")
      ? null
      : "workspace static evidence helper must derive from workspace_state_dir",
    source.includes("workspace_state_dir(root).join(WORKSPACE_ARTIFACT_KB_DB_FILE)")
      ? null
      : "workspace artifact KB helper must derive from workspace_state_dir",
    source.includes("workspace_state_dir(root).join(WORKSPACE_ATTACHMENTS_FILE)")
      ? null
      : "workspace attachments helper must derive from workspace_state_dir",
  ];
}

function workspaceStatePathConsumerFailures(root) {
  const consumers = [
    "crates/kuzushi-core/src/config/config_model.rs",
    "crates/kuzushi-core/src/agent_router/router_state.rs",
    "crates/kuzushi-core/src/scan/engines/codeql/scanner/database.rs",
    "crates/kuzushi-core/src/scan/engines/codeql/hex_value/codeql_binary.rs",
    "crates/kuzushi-core/src/capabilities/taint_iris/application/prompts.rs",
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/codeql_build.rs",
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/codeql_dataflow.rs",
    "crates/kuzushi-core/src/evidence/static_evidence/evidence_store.rs",
    "crates/kuzushi-core/src/evidence/context/match_registry_for.rs",
    "crates/kuzushi-core/src/workspace/artifact_kb/render_prompt_block.rs",
    "crates/kuzushi-core/src/attachments/attachment_store.rs",
    "crates/kuzushi-core/src/modules/execution_context/mod.rs",
  ];
  return consumers.flatMap((file) => workspaceStatePathConsumerFailure(root, file));
}

function workspaceStatePathConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`workspace state path consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    ...workspaceStateRequiredHelperFailures(source, file),
    workspaceStatePathConsumerHardcodesPath(productionSource)
      ? `workspace state path consumer must not hardcode workspace state config paths: ${file}`
      : null,
  ].filter(Boolean);
}

function workspaceStateRequiredHelperFailures(source, file) {
  const required = workspaceStateRequiredHelpersByFile[file] ?? [];
  return required
    .filter(({ needle }) => !source.includes(needle))
    .map(({ message }) => `${message}: ${file}`);
}

const workspaceStateRequiredHelpersByFile = {
  "crates/kuzushi-core/src/config/config_model.rs": [
    {
      needle: "workspace_config_path(",
      message: "workspace state path consumer must use workspace_config_path",
    },
    {
      needle: "workspace_options_path(",
      message: "workspace state path consumer must use workspace_options_path",
    },
  ],
  "crates/kuzushi-core/src/agent_router/router_state.rs": [
    {
      needle: "workspace_models_path(",
      message: "workspace state path consumer must use workspace_models_path",
    },
  ],
  "crates/kuzushi-core/src/scan/engines/codeql/scanner/database.rs": [
    {
      needle: "workspace_codeql_db_path(",
      message: "CodeQL scanner must use workspace_codeql_db_path",
    },
  ],
  "crates/kuzushi-core/src/scan/engines/codeql/hex_value/codeql_binary.rs": [
    {
      needle: "cached_codeql_binary_path(",
      message: "CodeQL binary cache lookup must use cached_codeql_binary_path",
    },
    {
      needle: "cached_codeql_binary_path(home: &Path) -> PathBuf",
      message: "CodeQL binary cache helper must expose cached_codeql_binary_path",
    },
    {
      needle: "workspace_state_root(home)",
      message: "CodeQL binary cache helper must derive from workspace_state_root",
    },
  ],
  "crates/kuzushi-core/src/capabilities/taint_iris_next/application/codeql_build.rs": [
    {
      needle: "workspace_codeql_db_path(",
      message: "taint-iris-next CodeQL build must use workspace_codeql_db_path",
    },
    {
      needle: "CodeqlRepositoryExecution::prepare(",
      message: "taint-iris-next CodeQL build must use trusted repository execution",
    },
    {
      needle: "repository_source_binding(input)",
      message: "taint-iris-next CodeQL build must require repository source binding",
    },
  ],
  "crates/kuzushi-core/src/capabilities/taint_iris_next/application/codeql_dataflow.rs":
    managedCodeqlDbResolverRequirements("taint-iris-next CodeQL dataflow"),
  "crates/kuzushi-core/src/evidence/static_evidence/evidence_store.rs": [
    {
      needle: "workspace_static_evidence_db_path(",
      message: "static evidence store must use workspace_static_evidence_db_path",
    },
  ],
  "crates/kuzushi-core/src/evidence/context/match_registry_for.rs": [
    {
      needle: "workspace_static_evidence_db_path(",
      message: "static context subgraph loader must use workspace_static_evidence_db_path",
    },
  ],
  "crates/kuzushi-core/src/workspace/artifact_kb/render_prompt_block.rs": [
    {
      needle: "workspace_artifact_kb_db_path(",
      message: "artifact KB path must use workspace_artifact_kb_db_path",
    },
  ],
  "crates/kuzushi-core/src/attachments/attachment_store.rs": [
    {
      needle: "workspace_attachments_path(",
      message: "attachment store path must use workspace_attachments_path",
    },
  ],
  "crates/kuzushi-core/src/modules/execution_context/mod.rs": [
    {
      needle: "workspace_artifact_kb_db_path(",
      message: "execution context artifact KB fallback must use workspace_artifact_kb_db_path",
    },
  ],
};

function managedCodeqlDbResolverRequirements(label) {
  return [
    {
      needle: "resolve_managed_codeql_database(",
      message: `${label} must resolve a provenance-authenticated managed database`,
    },
  ];
}

function workspaceStatePathConsumerHardcodesPath(source) {
  return [
    'join(".kuzushi").join("v2").join("config.toml")',
    'join(".kuzushi").join("v2").join("options.json")',
    'join(".kuzushi/v3/config.toml")',
    'join(".kuzushi/v3/options.json")',
    'join(".kuzushi").join("models.toml")',
    'join(".kuzushi").join("codeql-db")',
    'join(".kuzushi/codeql-db")',
    'join(".kuzushi/v3/codeql-db")',
    'join(".kuzushi").join("bin")',
    'join(".kuzushi/bin")',
    'join(".kuzushi").join("v2").join("static-evidence.sqlite3")',
    'join(".kuzushi/v3").join("static-evidence.sqlite3")',
    'join(".kuzushi").join("v2").join("artifact-kb.sqlite3")',
    'join(".kuzushi/v3").join("artifact-kb.sqlite3")',
    'join(".codeql").join("db")',
    'join(".codeql/db")',
  ].some((needle) => source.includes(needle));
}

function tuiWorkspaceStateLabelFailures(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/workspace.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI workspace state label: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("pub(crate) fn workspace_state_relative_path() -> &'static str")
      ? null
      : "TUI workspace state label must expose workspace_state_relative_path",
    source.includes("static WORKSPACE_STATE_RELATIVE_PATH: OnceLock<String> = OnceLock::new();")
      ? null
      : "TUI workspace state label must cache its derived relative path label",
    source.includes('workspace_state_dir("")') &&
    source.includes(".display()") &&
    source.includes(".to_string()")
      ? null
      : "TUI workspace state label must derive from workspace_state_dir",
    productionSource.includes(".kuzushi/v3")
      ? "TUI workspace state label must not hardcode .kuzushi/v3"
      : null,
    source.includes("view.state_dir.as_deref()") &&
    source.includes("workspace_state_relative_path()")
      ? null
      : "TUI workspace state fallback must use workspace_state_relative_path",
  ].filter(Boolean);
}

function tuiFindingsDbLabelFailures(root) {
  const workspaceFile = "crates/kuzushi-tui/src/ui_view_models/workspace.rs";
  const emptyStateFile = "crates/kuzushi-tui/src/ui_view_models/findings.rs";
  const workspacePath = path.join(root, workspaceFile);
  const emptyStatePath = path.join(root, emptyStateFile);
  if (!existsSync(workspacePath))
    return [`TUI workspace findings DB label: missing ${workspaceFile}`];
  if (!existsSync(emptyStatePath)) return [`TUI findings empty state: missing ${emptyStateFile}`];

  return [
    ...workspaceFindingsDbLabelChecks(readFileSync(workspacePath, "utf8")),
    ...emptyStateFindingsDbLabelChecks(readFileSync(emptyStatePath, "utf8")),
    modulePlaybookFindingsDbLabelFailures(root),
  ].filter(Boolean);
}

function workspaceFindingsDbLabelChecks(workspaceSource) {
  const workspaceProductionSource = workspaceSource.split("#[cfg(test)]")[0];
  return [
    workspaceSource.includes("pub(crate) fn findings_db_relative_path() -> &'static str")
      ? null
      : "TUI workspace findings DB label must expose findings_db_relative_path",
    workspaceSource.includes(
      "static FINDINGS_DB_RELATIVE_PATH: OnceLock<String> = OnceLock::new();",
    )
      ? null
      : "TUI workspace findings DB label must cache its derived relative path label",
    workspaceSource.includes('workspace_findings_db_path("")') &&
    workspaceSource.includes(".display()") &&
    workspaceSource.includes(".to_string()")
      ? null
      : "TUI workspace findings DB label must derive from workspace_findings_db_path",
    countOccurrences(workspaceProductionSource, ".kuzushi/v3/index.sqlite3") === 0
      ? null
      : "TUI workspace findings DB label must not hardcode .kuzushi/v3/index.sqlite3",
    workspaceSource.includes("compact_path_or(") &&
    workspaceSource.includes("view.findings_db.as_deref()") &&
    workspaceSource.includes("findings_db_relative_path()")
      ? null
      : "TUI workspace findings DB fallback must use findings_db_relative_path",
  ];
}

function emptyStateFindingsDbLabelChecks(emptyStateSource) {
  const emptyStateProductionSource = emptyStateSource.split("#[cfg(test)]")[0];
  return [
    emptyStateSource.includes("findings_db_relative_path()")
      ? null
      : "TUI findings empty state must use findings_db_relative_path",
    emptyStateProductionSource.includes(".kuzushi/v3/index.sqlite3")
      ? "TUI findings empty state must not hardcode .kuzushi/v3/index.sqlite3"
      : null,
  ];
}

function modulePlaybookFindingsDbLabelFailures(root) {
  const file = "crates/kuzushi-tui/src/renderer/shared/catalog/module_playbook_lines.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI module playbook findings DB label: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("findings_db_relative_path")
      ? null
      : "TUI module playbook findings DB label must use findings_db_relative_path",
    productionSource.includes(".kuzushi/v3/index.sqlite3")
      ? "TUI module playbook findings DB label must not hardcode .kuzushi/v3/index.sqlite3"
      : null,
  ].filter(Boolean);
}

function tuiKnowledgeBaseAttachmentStorePathFailures(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/knowledge_base.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI KB attachment store path: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("fn attachments_store_relative_path() -> &'static str")
      ? null
      : "TUI KB attachment store label must expose attachments_store_relative_path",
    source.includes('workspace_attachments_path("")') &&
    source.includes(".display()") &&
    source.includes(".to_string()")
      ? null
      : "TUI KB attachment store label must derive from workspace_attachments_path",
    source.includes("attachments_store_relative_path().to_string()")
      ? null
      : "TUI KB attachment store fallback must use attachments_store_relative_path",
    productionSource.includes(".kuzushi/v3/attachments.json")
      ? "TUI KB attachment store label must not hardcode .kuzushi/v3/attachments.json"
      : null,
  ].filter(Boolean);
}

function carliniAttachmentRendererPathFailures(root) {
  const file =
    "crates/kuzushi-core/src/capabilities/carlini_threat_hunt/adapters/render_attachments.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`Carlini attachment renderer path: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("crate::attachments::list_attachments(workspace)")
      ? null
      : "Carlini attachment renderer must read the shared attachment store",
    source.includes('matches!(module_id, "offense-review" | "carlini-threat-hunt")')
      ? null
      : "Carlini attachment renderer must accept product and compatibility attachment modules",
    source.includes("WorkspaceTarget::new(root)")
      ? null
      : "Carlini attachment renderer must resolve attachments through WorkspaceTarget",
    source.includes("AttachmentKind::Path") && source.includes("AttachmentKind::Url")
      ? null
      : "Carlini attachment renderer must handle path and URL attachment records",
    productionSource.includes('join(".kuzushi")') ||
    productionSource.includes('join("attachments.json")') ||
    productionSource.includes(".kuzushi/carlini-threat-hunt/attachments.json")
      ? "Carlini attachment renderer must not hardcode per-module attachment paths"
      : null,
  ].filter(Boolean);
}

export function checkPatchWorktreePathHelper(root) {
  const file = "crates/kuzushi-core/src/remediation/patch/ensure_git_repository.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`patch worktree path helper: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  const constants = rustStringConstants(source, ["PATCH_WORKTREES_DIR"]);
  return [
    constants.PATCH_WORKTREES_DIR === "worktrees"
      ? null
      : "patch worktree path helper must name PATCH_WORKTREES_DIR as worktrees",
    source.includes("pub(crate) fn patch_worktrees_root(repo_root: &Path) -> PathBuf")
      ? null
      : "patch worktree path helper must expose patch_worktrees_root",
    source.includes("workspace_state_root(repo_root).join(PATCH_WORKTREES_DIR)")
      ? null
      : "patch worktree path helper must derive from workspace_state_root",
    source.includes("= patch_worktrees_root(repo_root)") &&
    source.includes(".strip_prefix(repo_root)")
      ? null
      : "patch worktree creation must use patch_worktrees_root",
    productionSource.includes('join(".kuzushi").join("worktrees")') ||
    productionSource.includes('join(".kuzushi/worktrees")') ||
    productionSource.includes('Path::new(".kuzushi")')
      ? "patch worktree creation must not hardcode .kuzushi/worktrees"
      : null,
  ].filter(Boolean);
}

export function checkThreatIntelCatalogPathHelper(root) {
  const file =
    "crates/kuzushi-core/src/capabilities/threat_intel/application/catalog_storage_paths.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`threat-intel catalog path helper: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const constants = rustStringConstants(source, [
    "THREAT_INTEL_CATALOGS_DIR",
    "HARVESTED_THREAT_INTEL_CATALOG_FILE",
  ]);
  return [
    constants.THREAT_INTEL_CATALOGS_DIR === "catalogs"
      ? null
      : "threat-intel catalog path helper must name THREAT_INTEL_CATALOGS_DIR as catalogs",
    constants.HARVESTED_THREAT_INTEL_CATALOG_FILE === "harvested.toml"
      ? null
      : "threat-intel catalog path helper must name HARVESTED_THREAT_INTEL_CATALOG_FILE as harvested.toml",
    source.includes("pub fn threat_intel_catalogs_dir(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "threat-intel catalog path helper must expose threat_intel_catalogs_dir",
    source.includes("pub fn harvested_threat_intel_catalog_path(root: impl AsRef<Path>) -> PathBuf")
      ? null
      : "threat-intel catalog path helper must expose harvested_threat_intel_catalog_path",
    source.includes("workspace_state_root(root).join(THREAT_INTEL_CATALOGS_DIR)")
      ? null
      : "threat-intel catalog path helper must derive from workspace_state_root",
    ...threatIntelCatalogPathConsumerFailures(root),
  ].filter(Boolean);
}

function threatIntelCatalogPathConsumerFailures(root) {
  const consumers = [
    "crates/kuzushi-core/src/capabilities/threat_intel/application/catalog_path.rs",
    "crates/kuzushi-core/src/capabilities/threat_intel/application/harvest_input.rs",
  ];
  return consumers.flatMap((file) => threatIntelCatalogPathConsumerFailure(root, file));
}

function threatIntelCatalogPathConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`threat-intel catalog path consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    threatIntelCatalogPathConsumerUsesHelper(source)
      ? null
      : `threat-intel catalog path consumer must use shared catalog path helpers: ${file}`,
    threatIntelCatalogPathConsumerHardcodesPath(source)
      ? `threat-intel catalog path consumer must not hardcode catalog storage paths: ${file}`
      : null,
  ].filter(Boolean);
}

function threatIntelCatalogPathConsumerUsesHelper(source) {
  return ["threat_intel_catalogs_dir(", "harvested_threat_intel_catalog_path("].some((needle) =>
    source.includes(needle),
  );
}

function threatIntelCatalogPathConsumerHardcodesPath(source) {
  return [
    'join(".kuzushi").join("catalogs")',
    'join(".kuzushi/catalogs")',
    'join("catalogs").join("harvested.toml")',
  ].some((needle) => source.includes(needle));
}

export function checkPersistentThreatModelPathHelper(root) {
  const storeFile = "crates/kuzushi-core/src/capabilities/threat_model/persistence/store.rs";
  const storePath = path.join(root, storeFile);
  if (!existsSync(storePath)) return [`persistent threat-model path helper: missing ${storeFile}`];
  const store = readFileSync(storePath, "utf8");
  const constants = rustStringConstants(store, ["THREAT_MODEL_FILE"]);
  return [
    constants.THREAT_MODEL_FILE === "threat-model.json"
      ? null
      : "persistent threat model path must name THREAT_MODEL_FILE as threat-model.json",
    store.includes("pub fn persistent_threat_model_path(root: &Path) -> PathBuf")
      ? null
      : "persistent threat model path helper must be public for TUI consumers",
    store.includes("workspace_state_root(root).join(THREAT_MODEL_FILE)")
      ? null
      : "persistent threat model path helper must derive from workspace_state_root",
    store.includes("let path = persistent_threat_model_path(root)")
      ? null
      : "persistent threat model load/save must use persistent_threat_model_path",
    ...persistentThreatModelPathCallerFailures(root),
    ...threatModelBuildSummaryStatusFailures(root),
    ...moduleRecommenderThreatModelSourceFailures(root),
    ...carliniContextSnippetPathFailures(root),
    ...threatModelDefaultOutputDirFailures(root),
  ].filter(Boolean);
}

export function checkOauthCredentialPathHelper(root) {
  const configFile = "crates/kuzushi-core/src/config/config_model.rs";
  const statusFile = "crates/kuzushi-tui/src/app/settings/normalize_thinking_level/oauth_status.rs";
  const processFile =
    "crates/kuzushi-tui/src/app/settings/normalize_thinking_level/auth_process.rs";
  const config = readRequiredSource(root, configFile, "OAuth credential path helper");
  const status = readRequiredSource(root, statusFile, "OAuth credential status path consumer");
  const process = readRequiredSource(root, processFile, "OAuth credential login path consumer");
  const missing = [config, status, process].filter(Array.isArray).flat();
  if (missing.length > 0) return missing;
  return [
    ...oauthCredentialHelperFailures(config),
    ...oauthCredentialConsumerFailures(statusFile, status),
    ...oauthCredentialConsumerFailures(processFile, process),
  ];
}

export function checkThreatLeadsPathHelpers(root) {
  const sources = readThreatLeadsPathSources(root);
  if (Array.isArray(sources)) return sources;
  const { file, outputFile, source, output } = sources;
  return [
    ...threatLeadsConstantFailures(source),
    ...threatLeadsSourcePathFailures(source),
    ...threatLeadsOutputPathFailures(output),
    ...threatLeadsHardcodedPathFailures(file, source),
    ...threatLeadsHardcodedPathFailures(outputFile, output),
  ];
}

export function checkContextSnapshotPathHelper(root) {
  const contextFile = "crates/kuzushi-core/src/context.rs";
  const contextPath = path.join(root, contextFile);
  if (!existsSync(contextPath)) return [`context snapshot path helper: missing ${contextFile}`];
  const context = readFileSync(contextPath, "utf8");
  const constants = rustStringConstants(context, ["CONTEXT_SNAPSHOT_FILE"]);
  return [
    constants.CONTEXT_SNAPSHOT_FILE === "context-snapshot.json"
      ? null
      : "context snapshot path must name CONTEXT_SNAPSHOT_FILE as context-snapshot.json",
    context.includes("pub fn context_snapshot_path(target: impl AsRef<Path>) -> PathBuf")
      ? null
      : "context snapshot path helper must stay public",
    context.includes("workspace_state_root(target).join(CONTEXT_SNAPSHOT_FILE)")
      ? null
      : "context snapshot path helper must derive from workspace_state_root",
    ...tuiContextSnapshotRelativePathFailures(root),
    ...attachmentKnownArtifactPathFailures(root),
    ...contextSnapshotPathConsumerFailures(root),
  ].filter(Boolean);
}

function attachmentKnownArtifactPathFailures(root) {
  const file = "crates/kuzushi-core/src/attachments/reparse_source.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`attachment known-artifact path helpers: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("known_artifact_relative_path(")
      ? null
      : "attachment known artifacts must centralize relative artifact paths",
    source.includes("context_snapshot_path(")
      ? null
      : "attachment known artifacts must use context_snapshot_path",
    source.includes("persistent_threat_model_path(")
      ? null
      : "attachment known artifacts must use persistent_threat_model_path",
    source.includes("workspace_findings_db_path(")
      ? null
      : "attachment known artifacts must use workspace_findings_db_path",
    productionSource.includes('".kuzushi/context-snapshot.json"') ||
    productionSource.includes('".kuzushi/threat-model.json"') ||
    productionSource.includes('".kuzushi/v3/index.sqlite3"')
      ? "attachment known artifacts must not hardcode persistent artifact paths"
      : null,
  ].filter(Boolean);
}

function tuiContextSnapshotRelativePathFailures(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/context_snapshot.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI context snapshot relative path: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("static CONTEXT_SNAPSHOT_RELATIVE_PATH: OnceLock<String> = OnceLock::new();")
      ? null
      : "TUI context snapshot must cache its derived relative path label",
    source.includes("pub(crate) fn context_snapshot_relative_path() -> &'static str")
      ? null
      : "TUI context snapshot must expose context_snapshot_relative_path helper",
    source.includes('kuzushi_core::context_snapshot_path("")') &&
    source.includes(".display()") &&
    source.includes(".to_string()")
      ? null
      : "TUI context snapshot relative path must derive from context_snapshot_path",
    source.includes("context_snapshot_relative_path().to_string()")
      ? null
      : "TUI context snapshot fallback label must use context_snapshot_relative_path",
    source.includes("context build writes {}") &&
    source.includes("context build rewrites {}") &&
    source.includes("context_snapshot_relative_path()")
      ? null
      : "TUI context snapshot next-step labels must use context_snapshot_relative_path",
    countOccurrences(productionSource, ".kuzushi/context-snapshot.json") === 0
      ? null
      : "TUI context snapshot production source must not hardcode context snapshot path",
    ...tuiContextSnapshotRendererLabelFailures(root),
    ...tuiQuickstartContextSnapshotLabelFailures(root),
  ].filter(Boolean);
}

function tuiContextSnapshotRendererLabelFailures(root) {
  const file = "crates/kuzushi-tui/src/renderer/views/module/append_sast_pipeline_progress.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI context snapshot renderer label: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("context_snapshot_relative_path()")
      ? null
      : "TUI module context progress must use context_snapshot_relative_path",
    productionSource.includes(".kuzushi/context-snapshot.json")
      ? "TUI module context progress must not hardcode .kuzushi/context-snapshot.json"
      : null,
  ].filter(Boolean);
}

function tuiQuickstartContextSnapshotLabelFailures(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/help.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI quickstart context snapshot label: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    productionSource.includes(".kuzushi/context-snapshot.json")
      ? "TUI quickstart context snapshot step must not hardcode .kuzushi/context-snapshot.json"
      : null,
  ].filter(Boolean);
}

export function checkPromptPathHelpers(root) {
  const helperFile = "crates/kuzushi-core/src/options/prompt_paths.rs";
  const helperPath = path.join(root, helperFile);
  if (!existsSync(helperPath)) return [`prompt path helper: missing ${helperFile}`];
  const helper = readFileSync(helperPath, "utf8");
  const constants = rustStringConstants(helper, ["PROMPTS_DIR", "HOUSE_RULES_DIR"]);
  return [
    constants.PROMPTS_DIR === "prompts"
      ? null
      : "prompt path helper must name PROMPTS_DIR as prompts",
    constants.HOUSE_RULES_DIR === "house-rules"
      ? null
      : "prompt path helper must name HOUSE_RULES_DIR as house-rules",
    ...promptPathHelperFunctionFailures(helper),
    ...promptPathHelperDerivationFailures(helper),
    ...promptPathConsumerFailures(root),
  ].filter(Boolean);
}

export function checkTaintIrisNextArtifactPathHelpers(root) {
  const helperFile =
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/artifact_paths.rs";
  const helperPath = path.join(root, helperFile);
  if (!existsSync(helperPath))
    return [`taint-iris-next artifact path helper: missing ${helperFile}`];
  const helper = readFileSync(helperPath, "utf8");
  const constants = rustStringConstants(helper, [
    "TAINT_IRIS_NEXT_DISCOVERED_SIGNALS_FILE",
    "TAINT_IRIS_NEXT_TARGET_CATALOG_FILE",
  ]);
  return [
    ...taintIrisNextArtifactPathConstantFailures(constants),
    ...taintIrisNextArtifactPathFunctionFailures(helper),
    ...taintIrisNextArtifactPathConsumerFailures(root),
  ].filter(Boolean);
}

export function checkTuiPrereqChainPathHelpers(root) {
  const file = "crates/kuzushi-tui/src/app/prereq_chain/mod.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI prereq chain path helper: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  const constants = rustStringConstants(source, ["TAINT_IRIS_NEXT_CATALOG_ARTIFACT"]);
  return [
    constants.TAINT_IRIS_NEXT_CATALOG_ARTIFACT === "taint-iris-next-catalog.json"
      ? null
      : "TUI prereq chain must name TAINT_IRIS_NEXT_CATALOG_ARTIFACT as taint-iris-next-catalog.json",
    source.includes("kuzushi_core::workspace_state_root(target)")
      ? null
      : "TUI prereq chain must derive artifact paths from workspace_state_root",
    source.includes("kuzushi_core::capabilities::persistent_threat_model_path(target)")
      ? null
      : "TUI prereq chain threat-model step must use persistent_threat_model_path",
    source.includes("prereq_workspace_root(target).join(TAINT_IRIS_NEXT_CATALOG_ARTIFACT)")
      ? null
      : "TUI prereq chain taint catalog step must use shared root helper",
    productionSource.includes('join(".kuzushi")') || productionSource.includes('join(".kuzushi/')
      ? "TUI prereq chain must not hardcode .kuzushi artifact paths"
      : null,
  ].filter(Boolean);
}

function taintIrisNextArtifactPathConstantFailures(constants) {
  return [
    constants.TAINT_IRIS_NEXT_DISCOVERED_SIGNALS_FILE === "discovered-signals.json"
      ? null
      : "taint-iris-next artifact path must name TAINT_IRIS_NEXT_DISCOVERED_SIGNALS_FILE as discovered-signals.json",
    constants.TAINT_IRIS_NEXT_TARGET_CATALOG_FILE === "taint-iris-next-catalog.json"
      ? null
      : "taint-iris-next artifact path must name TAINT_IRIS_NEXT_TARGET_CATALOG_FILE as taint-iris-next-catalog.json",
  ];
}

function taintIrisNextArtifactPathFunctionFailures(helper) {
  return [
    helper.includes("taint_iris_next_discovered_signals_path(target: &Path) -> PathBuf")
      ? null
      : "taint-iris-next artifact path helper must expose discovered signals path",
    helper.includes("taint_iris_next_target_catalog_artifact_path(target: &Path) -> PathBuf")
      ? null
      : "taint-iris-next artifact path helper must expose target catalog path",
    helper.includes("workspace_state_root(target).join(TAINT_IRIS_NEXT_DISCOVERED_SIGNALS_FILE)")
      ? null
      : "taint-iris-next discovered signals path must derive from workspace_state_root",
    helper.includes("workspace_state_root(target).join(TAINT_IRIS_NEXT_TARGET_CATALOG_FILE)")
      ? null
      : "taint-iris-next target catalog path must derive from workspace_state_root",
  ];
}

function taintIrisNextArtifactPathConsumerFailures(root) {
  const consumers = [
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/source_sink_discovery.rs",
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/dynamic_catalog.rs",
  ];
  return consumers.flatMap((file) => taintIrisNextArtifactPathConsumerFailure(root, file));
}

function taintIrisNextArtifactPathConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`taint-iris-next artifact path consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    taintIrisNextArtifactPathConsumerUsesHelper(source)
      ? null
      : `taint-iris-next artifact path consumer must use shared artifact path helpers: ${file}`,
    taintIrisNextArtifactPathConsumerHardcodesPath(productionSource)
      ? `taint-iris-next artifact path consumer must not hardcode artifact paths: ${file}`
      : null,
  ].filter(Boolean);
}

function taintIrisNextArtifactPathConsumerUsesHelper(source) {
  return [
    "taint_iris_next_discovered_signals_path(",
    "taint_iris_next_target_catalog_artifact_path(",
  ].some((needle) => source.includes(needle));
}

function taintIrisNextArtifactPathConsumerHardcodesPath(source) {
  return [
    'join(".kuzushi").join("cpg.bin")',
    'join(".kuzushi/cpg.bin")',
    'join(".kuzushi").join("discovered-signals.json")',
    'join(".kuzushi/discovered-signals.json")',
    'join(".kuzushi").join("taint-iris-next-catalog.json")',
    'join(".kuzushi/taint-iris-next-catalog.json")',
  ].some((needle) => source.includes(needle));
}

function promptPathHelperFunctionFailures(helper) {
  return [
    helper.includes("pub fn prompt_overrides_root(target: impl AsRef<Path>) -> PathBuf")
      ? null
      : "prompt path helper must expose prompt_overrides_root",
    helper.includes("pub fn module_prompt_root(target: impl AsRef<Path>, module: &str) -> PathBuf")
      ? null
      : "prompt path helper must expose module_prompt_root",
    helper.includes(
      "pub fn prompt_override_path(target: impl AsRef<Path>, module: &str, verb: &str) -> PathBuf",
    )
      ? null
      : "prompt path helper must expose prompt_override_path",
    helper.includes("pub fn house_rules_root(target: impl AsRef<Path>) -> PathBuf")
      ? null
      : "prompt path helper must expose house_rules_root",
    helper.includes("pub fn house_rule_path(target: impl AsRef<Path>, module: &str) -> PathBuf")
      ? null
      : "prompt path helper must expose house_rule_path",
    helper.includes("pub fn relative_prompt_override_path(module: &str, verb: &str) -> PathBuf")
      ? null
      : "prompt path helper must expose relative_prompt_override_path",
    helper.includes("pub fn relative_house_rule_path(module: &str) -> PathBuf")
      ? null
      : "prompt path helper must expose relative_house_rule_path",
  ];
}

function promptPathHelperDerivationFailures(helper) {
  return [
    helper.includes("workspace_state_root(target).join(PROMPTS_DIR)")
      ? null
      : "prompt overrides root must derive from workspace_state_root",
    helper.includes("workspace_state_root(target).join(HOUSE_RULES_DIR)")
      ? null
      : "house rules root must derive from workspace_state_root",
  ];
}

export function checkHomeCockpitArtifactRail(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/home_cockpit.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`home cockpit artifact rail: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const expected = homeCockpitExpectedArtifacts();
  const filtered = homeCockpitFilteredArtifacts(source);
  return [
    source.includes("canonical_run_artifact_specs")
      ? null
      : "home cockpit artifact rail must use canonical_run_artifact_specs",
    source.includes("filter(home_artifact_belongs_in_rail)")
      ? null
      : "home cockpit artifact rail must filter shared canonical specs",
    source.includes("HomeArtifactSpec::new")
      ? "home cockpit artifact rail must not duplicate artifact leaves locally"
      : null,
    ...missingEntries(expected, filtered, "home cockpit artifact rail missing artifact"),
    ...missingEntries(filtered, expected, "home cockpit artifact rail has uncontracted artifact"),
    ...duplicateEntries(filtered).map(
      (artifact) => `home cockpit artifact rail duplicates artifact ${artifact}`,
    ),
    ...homeCockpitRunMetadataFailures(source),
  ].filter(Boolean);
}

function promptPathConsumerFailures(root) {
  const consumers = [
    "crates/kuzushi-core/src/run_artifacts/run_reproducibility_metadata.rs",
    "crates/kuzushi-tui/src/app/prompts/tune_action_count/prompt_paths.rs",
    "crates/kuzushi-tui/src/app/prompts/tune_action_count/prompt_list.rs",
    "crates/kuzushi-tui/src/app/prompts/tune_action_count/house_rules.rs",
    "crates/kuzushi-tui/src/ui_view_models/module_detail.rs",
    "crates/kuzushi-tui/src/ui_view_models/prompt_tuning.rs",
  ];
  return consumers.flatMap((file) => promptPathConsumerFailure(root, file));
}

function promptPathConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`prompt path consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    promptPathConsumerUsesHelper(source)
      ? null
      : `prompt path consumer must use shared prompt path helpers: ${file}`,
    promptPathConsumerHardcodesPath(productionSource)
      ? `prompt path consumer must not hardcode prompt paths: ${file}`
      : null,
  ].filter(Boolean);
}

function promptPathConsumerUsesHelper(source) {
  return [
    "prompt_override_path(",
    "prompt_overrides_root(",
    "module_prompt_root(",
    "house_rule_path(",
    "house_rules_root(",
    "relative_prompt_override_path(",
    "relative_house_rule_path(",
  ].some((needle) => source.includes(needle));
}

function promptPathConsumerHardcodesPath(source) {
  const templateOpen = String.fromCharCode(123);
  return [
    'join(".kuzushi").join("prompts")',
    'join(".kuzushi/prompts")',
    'join(".kuzushi").join("house-rules")',
    `".kuzushi/prompts/${templateOpen}`,
    `".kuzushi/house-rules/${templateOpen}`,
  ].some((needle) => source.includes(needle));
}

function contextSnapshotPathConsumerFailures(root) {
  const consumers = [
    "crates/kuzushi-core/src/modules/context/attack_surface_routes.rs",
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/plan.rs",
    "crates/kuzushi-tui/src/app/shell_lifecycle/construction.rs",
    "crates/kuzushi-tui/src/app/workspace_context/show_workspace_status/context_actions.rs",
    "crates/kuzushi-tui/src/app/prereq_chain/mod.rs",
  ];
  return consumers.flatMap((file) => contextSnapshotPathConsumerFailure(root, file));
}

function contextSnapshotPathConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`context snapshot path consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("context_snapshot_path(")
      ? null
      : `context snapshot path consumer must use context_snapshot_path: ${file}`,
    productionSource.includes('join(".kuzushi").join("context-snapshot.json")') ||
    productionSource.includes('join(".kuzushi/context-snapshot.json")')
      ? `context snapshot path consumer must not hardcode context snapshot path: ${file}`
      : null,
  ].filter(Boolean);
}

export function checkTuiAttackSurfaceArtifactLeaf(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/attack_surface.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI attack-surface artifact leaf: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes('canonical_run_artifact_spec("attack-surface.json")')
      ? null
      : "TUI attack-surface must use shared attack-surface artifact spec",
    source.includes("fn attack_surface_artifact_leaf() -> &'static str")
      ? null
      : "TUI attack-surface must centralize artifact leaf",
    source.includes("run_dir.join(attack_surface_artifact_leaf())")
      ? null
      : "TUI attack-surface reader must use shared artifact leaf",
    source.includes('format!("malformed {}", attack_surface_artifact_leaf())')
      ? null
      : "TUI attack-surface malformed label must use shared artifact leaf",
    source.includes('format!("{} is not a file", attack_surface_artifact_leaf())')
      ? null
      : "TUI attack-surface non-file label must use shared artifact leaf",
  ].filter(Boolean);
}

export function checkTuiRecommendationArtifactLeaf(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/recommendation.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI recommendation artifact leaf: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes('canonical_run_artifact_spec("recommendations.json")')
      ? null
      : "TUI recommendation must use shared recommendations artifact spec",
    source.includes("fn recommendations_artifact_leaf() -> &'static str")
      ? null
      : "TUI recommendation must centralize artifact leaf",
    source.includes("run_dir.join(recommendations_artifact_leaf())")
      ? null
      : "TUI recommendation source must use shared artifact leaf",
    source.includes('format!("malformed {}", recommendations_artifact_leaf())')
      ? null
      : "TUI recommendation malformed label must use shared artifact leaf",
    source.includes('format!("{} is not a file", recommendations_artifact_leaf())')
      ? null
      : "TUI recommendation non-file label must use shared artifact leaf",
    source.includes("recommendations_artifact_leaf().to_string()")
      ? null
      : "TUI recommendation artifact rows must use shared artifact leaf",
  ].filter(Boolean);
}

export function checkTuiFailureHandoffArtifactLeaf(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/failure_handoff.rs";
  const runPathsFile = "crates/kuzushi-tui/src/ui_view_models/run_paths.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI failure-handoff artifact leaf: missing ${file}`];
  const runPathsPath = path.join(root, runPathsFile);
  if (!existsSync(runPathsPath))
    return [`TUI failure-handoff artifact leaf: missing ${runPathsFile}`];
  const source = readFileSync(sourcePath, "utf8");
  const runPaths = readFileSync(runPathsPath, "utf8");
  return [
    ...tuiFailureHandoffSourceFailures(source),
    ...tuiRunArtifactRelativePathFailures(runPaths),
  ];
}

function tuiFailureHandoffSourceFailures(source) {
  return [
    source.includes('canonical_run_artifact_spec("failures.json")')
      ? null
      : "TUI failure handoff must use shared failures artifact spec",
    source.includes("fn failures_artifact_leaf() -> &'static str")
      ? null
      : "TUI failure handoff must centralize artifact leaf",
    source.includes(".join(failures_artifact_leaf())")
      ? null
      : "TUI failure handoff artifact path must use shared artifact leaf",
    source.includes('format!("malformed {}", failures_artifact_leaf())')
      ? null
      : "TUI failure handoff malformed label must use shared artifact leaf",
    source.includes('format!("{} is not a file", failures_artifact_leaf())')
      ? null
      : "TUI failure handoff non-file label must use shared artifact leaf",
    source.includes("ui_run_artifact_relative_path(run_id, failures_artifact_leaf())")
      ? null
      : "TUI failure handoff next path must use shared run artifact helper",
    source.includes('format!(".kuzushi/v3/runs/{run_id}/{failures_artifact_leaf()}")')
      ? "TUI failure handoff next path must not hardcode .kuzushi/v3/runs"
      : null,
    source.includes("failures_artifact_leaf().to_string()")
      ? null
      : "TUI failure handoff rows must use shared artifact leaf",
  ].filter(Boolean);
}

function tuiRunArtifactRelativePathFailures(runPaths) {
  return [
    runPaths.includes(
      "pub(crate) fn ui_run_artifact_relative_path(run_id: &str, leaf: &str) -> String",
    )
      ? null
      : "TUI run artifact relative path helper must live in run_paths",
    runPaths.includes("Path::new(ui_runs_root_relative_path())")
      ? null
      : "TUI run artifact relative path helper must use runs-root label",
  ].filter(Boolean);
}

export function checkTuiThreatModelArtifactLeaf(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/threat_model.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI threat-model artifact leaf: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes("kuzushi_core::capabilities::persistent_threat_model_path(root.as_ref())")
      ? null
      : "TUI threat model artifact path must use persistent_threat_model_path",
    source.includes('join(".kuzushi")') || source.includes('join(".kuzushi/')
      ? "TUI threat model artifact path must not hardcode .kuzushi joins"
      : null,
    source.includes('threat_model_artifact_path("")')
      ? null
      : "TUI threat model relative path must derive from persistent artifact path",
    source.includes('format!("malformed {}", threat_model_relative_path())')
      ? null
      : "TUI threat model malformed label must use threat_model_relative_path",
    source.includes('format!("{} is not a file", threat_model_relative_path())')
      ? null
      : "TUI threat model non-file label must use threat_model_relative_path",
    source.includes("threat_model_file_name()")
      ? null
      : "TUI threat model missing-input label must use the persistent artifact file name",
    ...tuiThreatRendererPathFailures(root),
    ...tuiModulePlaybookPathFailures(root),
    ...tuiLiveActivityThreatModelPathFailures(root),
  ].filter(Boolean);
}

function tuiThreatRendererPathFailures(root) {
  const files = [
    {
      file: "crates/kuzushi-tui/src/renderer/views/threat/threat_editor_lines.rs",
      helperMessage: "TUI threat editor artifact label must use threat_model_relative_path",
      literalMessage:
        "TUI threat editor artifact label must not hardcode .kuzushi/threat-model.json",
    },
    {
      file: "crates/kuzushi-tui/src/renderer/views/threat/threat_lines/summary.rs",
      helperMessage: "TUI threat summary export label must use threat_model_relative_path",
      literalMessage:
        "TUI threat summary export label must not hardcode .kuzushi/threat-model.json",
    },
  ];
  return files
    .flatMap(({ file, helperMessage, literalMessage }) => {
      const sourcePath = path.join(root, file);
      if (!existsSync(sourcePath)) return [`${helperMessage}: missing ${file}`];
      const source = readFileSync(sourcePath, "utf8");
      const productionSource = source.split("#[cfg(test)]")[0];
      return [
        source.includes("threat_model_relative_path") ? null : helperMessage,
        productionSource.includes('".kuzushi/threat-model.json"') ? literalMessage : null,
      ];
    })
    .filter(Boolean);
}

function tuiLiveActivityThreatModelPathFailures(root) {
  const files = [
    {
      file: "crates/kuzushi-tui/src/ui_view_models/live_activity.rs",
      marker: "fn plain_live_activity_model_projects_plain_lines()",
    },
    {
      file: "crates/kuzushi-tui/src/renderer/tests.rs",
      marker: "fn plain_live_activity_has_no_ansi_or_box_drawing()",
    },
  ];
  return files
    .flatMap(({ file, marker }) => {
      const sourcePath = path.join(root, file);
      if (!existsSync(sourcePath)) {
        return [`TUI live activity threat-model label: missing ${file}`];
      }
      const source = readFileSync(sourcePath, "utf8");
      const markerIndex = source.indexOf(marker);
      if (markerIndex === -1) {
        return [`TUI live activity threat-model label: missing ${marker} in ${file}`];
      }
      const nextTestIndex = source.indexOf("\n#[test]", markerIndex + marker.length);
      const block = source.slice(markerIndex, nextTestIndex === -1 ? undefined : nextTestIndex);
      return [
        block.includes("threat_model_relative_path")
          ? null
          : "TUI live activity threat-model label must use threat_model_relative_path",
        block.includes(".kuzushi/threat-model.json")
          ? "TUI live activity threat-model label must not hardcode .kuzushi/threat-model.json"
          : null,
      ];
    })
    .filter(Boolean);
}

function tuiModulePlaybookPathFailures(root) {
  const file = "crates/kuzushi-tui/src/renderer/shared/catalog/module_playbook_lines.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI module playbook path helpers: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("enum PlaybookText") ? null : "TUI module playbook paths must use PlaybookText",
    source.includes("ContextSnapshotRun") && source.includes("ContextSnapshotPath")
      ? null
      : "TUI module playbook context rows must use context snapshot playbook variants",
    source.includes("ThreatModelPath")
      ? null
      : "TUI module playbook threat-model rows must use threat-model playbook variant",
    source.includes("FindingsDbPath") && source.includes("FindingsDbPathWithSarif")
      ? null
      : "TUI module playbook findings rows must use findings DB playbook variants",
    source.includes("context_snapshot_relative_path()")
      ? null
      : "TUI module playbook context rows must use context_snapshot_relative_path",
    source.includes("findings_db_relative_path()")
      ? null
      : "TUI module playbook findings rows must use findings_db_relative_path",
    source.includes("threat_model_relative_path()")
      ? null
      : "TUI module playbook threat-model rows must use threat_model_relative_path",
    productionSource.includes("context_snapshot_relative_path") &&
    productionSource.includes("findings_db_relative_path") &&
    productionSource.includes("threat_model_relative_path")
      ? null
      : "TUI module playbook path helpers must import view-model artifact labels",
    countOccurrences(productionSource, ".kuzushi/context-snapshot.json") === 0 &&
    countOccurrences(productionSource, ".kuzushi/v3/index.sqlite3") === 0 &&
    countOccurrences(productionSource, ".kuzushi/threat-model.json") === 0
      ? null
      : "TUI module playbook production source must keep persistent artifact labels centralized",
  ].filter(Boolean);
}

export function checkTuiRunTimelineArtifactLeaves(root) {
  const file = "crates/kuzushi-tui/src/ui_view_models/run_timeline.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI run timeline artifact leaves: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const usesTypedSummaryEntries =
    source.includes("RunSummaryEntryState") &&
    (source.includes(".run_summary_entries(") || source.includes(".cached_run_summary_entries("));
  return [
    source.includes('canonical_run_artifact_spec("run.json")')
      ? null
      : "TUI run timeline must use shared run metadata artifact spec",
    source.includes("fn run_metadata_artifact_leaf() -> &'static str")
      ? null
      : "TUI run timeline must centralize metadata artifact leaf",
    usesTypedSummaryEntries ||
    (source.includes(".join(metadata_leaf)") && source.includes("run_metadata_artifact_leaf()"))
      ? null
      : "TUI run timeline canonical metadata path must use shared metadata artifact leaf",
    usesTypedSummaryEntries || source.includes("malformed_past_run_metadata(metadata_leaf)")
      ? null
      : "TUI run timeline canonical malformed label must use shared metadata artifact leaf",
    usesTypedSummaryEntries || source.includes("non_file_past_run_metadata(metadata_leaf)")
      ? null
      : "TUI run timeline canonical non-file label must use shared metadata artifact leaf",
  ].filter(Boolean);
}

export function checkTuiRunsRootHelper(root) {
  const helperFile = "crates/kuzushi-tui/src/ui_view_models/run_paths.rs";
  const helperPath = path.join(root, helperFile);
  if (!existsSync(helperPath)) return [`TUI runs-root helper: missing ${helperFile}`];
  const helper = readFileSync(helperPath, "utf8");
  return [
    helper.includes("pub(crate) fn ui_runs_root(target: Option<&Path>) -> PathBuf")
      ? null
      : "TUI runs-root helper must expose ui_runs_root",
    helper.includes("pub(crate) fn ui_runs_root_relative_path() -> &'static str")
      ? null
      : "TUI runs-root helper must expose ui_runs_root_relative_path",
    helper.includes('".kuzushi/v3/runs"')
      ? null
      : "TUI runs-root relative label must name .kuzushi/v3/runs",
    helper.includes("pub(crate) fn ui_run_dir(target: Option<&Path>, run_id: &str) -> PathBuf")
      ? null
      : "TUI run-dir helper must expose ui_run_dir",
    helper.includes("pub(crate) fn ui_latest_run_path(target: Option<&Path>) -> PathBuf")
      ? null
      : "TUI latest-run helper must expose ui_latest_run_path",
    helper.includes("pub(crate) fn ui_latest_run_relative_path() -> &'static str")
      ? null
      : "TUI latest-run helper must expose ui_latest_run_relative_path",
    helper.includes('".kuzushi/v3/latest"')
      ? null
      : "TUI latest-run relative label must name .kuzushi/v3/latest",
    helper.includes("kuzushi_core::runs_root")
      ? null
      : "TUI runs-root helper must delegate to kuzushi_core::runs_root",
    helper.includes("kuzushi_core::run_dir")
      ? null
      : "TUI run-dir helper must delegate to kuzushi_core::run_dir",
    helper.includes("kuzushi_core::latest_run_path")
      ? null
      : "TUI latest-run helper must delegate to kuzushi_core::latest_run_path",
    ...tuiRunsRootConsumerFailures(root),
    ...tuiLatestRunConsumerFailures(root),
  ].filter(Boolean);
}

export function checkRunArtifactPathHelpers(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/run_paths.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`run artifact path helper: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("pub fn kuzushi_root(target: impl AsRef<Path>) -> PathBuf")
      ? null
      : "run artifact path helper must expose kuzushi_root",
    source.includes("crate::workspace::workspace_state_root(target)")
      ? null
      : "run artifact path helper must derive kuzushi_root from workspace_state_root",
    source.includes('kuzushi_root(target).join("runs")')
      ? null
      : "run artifact path helper must derive runs_root from kuzushi_root",
    source.includes('kuzushi_root(target).join("latest")')
      ? null
      : "run artifact path helper must derive latest_run_path from kuzushi_root",
    productionSource.includes('join(".kuzushi")') ||
    productionSource.includes('join(".kuzushi/v3/runs")') ||
    productionSource.includes('join(".kuzushi/v3/latest")')
      ? "run artifact path helper must not hardcode .kuzushi paths"
      : null,
  ].filter(Boolean);
}

export function checkCliRunsPathConsumers(root) {
  const consumers = [
    "crates/kuzushi-cli/src/application/runs.rs",
    "crates/kuzushi-cli/src/application/runs_diff.rs",
    "crates/kuzushi-cli/src/application/runs_prune.rs",
    "crates/kuzushi-cli/src/application/pr_comment.rs",
    "crates/kuzushi-cli/src/presentation/runs_output.rs",
    "crates/kuzushi-core/src/workspace/artifact_kb/discover_workspace_artifact_records.rs",
  ];
  return [
    ...consumers.flatMap((file) => cliRunsPathConsumerFailure(root, file)),
    ...workspaceArtifactKbDiscoveryPathFailures(root),
  ];
}

function cliRunsPathConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`CLI runs path consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const required = cliRunsPathRequirementsByFile[file] ?? [];
  return [
    ...required
      .filter(({ needle }) => !source.includes(needle))
      .map(({ message }) => `${message}: ${file}`),
    cliRunsPathHardcodes(source)
      ? `CLI runs path consumer must not hardcode run paths: ${file}`
      : null,
  ].filter(Boolean);
}

const cliRunsPathRequirementsByFile = {
  "crates/kuzushi-cli/src/application/runs.rs": [
    { needle: "runs_root(", message: "CLI runs show must use runs_root" },
    {
      needle: "read_run_artifact_text(",
      message: "CLI runs trace must use the safe artifact reader",
    },
    {
      needle: 'canonical_run_artifact_spec("trace.jsonl")',
      message: "CLI runs trace must use shared trace artifact spec",
    },
  ],
  "crates/kuzushi-cli/src/application/runs_diff.rs": [
    {
      needle: "read_run_artifact_text(",
      message: "CLI runs diff must use the safe artifact reader",
    },
    {
      needle: 'tool_result_artifact_spec("result.json")',
      message: "CLI runs diff must use shared tool-result artifact spec",
    },
    {
      needle: "run_result_artifact_leaf()",
      message: "CLI runs diff must centralize result artifact leaf",
    },
  ],
  "crates/kuzushi-cli/src/application/runs_prune.rs": [
    { needle: "run_dir(", message: "CLI runs prune must use run_dir" },
    {
      needle: "repair_latest_run_pointer(",
      message: "CLI runs prune must use atomic chronological latest repair",
    },
  ],
  "crates/kuzushi-cli/src/application/pr_comment.rs": [
    {
      needle: "read_run_artifact_text(",
      message: "CLI PR comment must use the safe artifact reader",
    },
    {
      needle: 'tool_result_artifact_spec("result.json")',
      message: "CLI PR comment must use shared tool-result artifact spec",
    },
    {
      needle: "result_artifact_leaf()",
      message: "CLI PR comment must centralize result artifact leaf",
    },
  ],
  "crates/kuzushi-cli/src/presentation/runs_output.rs": [
    { needle: "runs_root(", message: "CLI runs list output must use runs_root" },
  ],
  "crates/kuzushi-core/src/workspace/artifact_kb/discover_workspace_artifact_records.rs": [
    { needle: "runs_root(", message: "artifact KB discovery must use runs_root" },
  ],
};

function cliRunsPathHardcodes(source) {
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    '".kuzushi/v3/latest"',
    'join(".kuzushi/v3/runs")',
    'join(".kuzushi").join("runs")',
    'join(".kuzushi/v3/latest")',
    'join(".kuzushi").join("latest")',
  ].some((needle) => productionSource.includes(needle));
}

function workspaceArtifactKbDiscoveryPathFailures(root) {
  const file =
    "crates/kuzushi-core/src/workspace/artifact_kb/discover_workspace_artifact_records.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`artifact KB discovery path helpers: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("persistent_workspace_artifact_paths(")
      ? null
      : "artifact KB discovery must centralize persistent workspace artifact paths",
    source.includes("context_snapshot_path(")
      ? null
      : "artifact KB discovery must use context_snapshot_path",
    source.includes("persistent_threat_model_path(")
      ? null
      : "artifact KB discovery must use persistent_threat_model_path",
    source.includes("run_artifact_source_prefix(")
      ? null
      : "artifact KB discovery must centralize run artifact source prefix",
    source.includes("relative_workspace_path(root, &runs_root(root))")
      ? null
      : "artifact KB discovery run source prefix must derive from runs_root",
    source.includes("is_run_artifact_source_path(workspace.root(), &source_path)")
      ? null
      : "artifact KB discovery sourceKind must use run artifact source helper",
    source.includes('strip_prefix(&run_artifact_source_prefix(Path::new("")))')
      ? null
      : "artifact KB discovery run-id parsing must use run artifact source helper",
    productionSource.includes('".kuzushi/context-snapshot.json"') ||
    productionSource.includes('".kuzushi/threat-model.json"')
      ? "artifact KB discovery must not hardcode persistent workspace artifact paths"
      : null,
    productionSource.includes('".kuzushi/v3/runs/"')
      ? "artifact KB discovery must not hardcode .kuzushi/v3/runs source prefix"
      : null,
    ...workspaceArtifactKbFindingsIndexPathFailures(root),
  ].filter(Boolean);
}

function workspaceArtifactKbFindingsIndexPathFailures(root) {
  const file = "crates/kuzushi-core/src/workspace/artifact_kb/open/findings_index.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`artifact KB findings index path helpers: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("fn finding_source_path(fingerprint: &str) -> String")
      ? null
      : "artifact KB findings index must centralize finding source paths",
    source.includes('workspace_findings_db_path(Path::new(""))')
      ? null
      : "artifact KB findings index must derive source path from workspace_findings_db_path",
    source.includes('"{}#finding/{}"')
      ? null
      : "artifact KB findings index must append finding fragment to shared DB path",
    productionSource.includes('".kuzushi/v3/index.sqlite3')
      ? "artifact KB findings index must not hardcode findings DB path"
      : null,
  ].filter(Boolean);
}

export function checkArtifactManifestContractHelpers() {
  const duplicates = duplicateEntries([
    "run.json",
    "run.json",
    "run.json",
    "events.jsonl",
    "events.jsonl",
  ]);
  const equalOrderFailures = arrayOrderMismatch(
    ["failures.json", "result.json", "input.json", "artifacts.json"],
    ["failures.json", "result.json", "input.json", "artifacts.json"],
    "artifact manifest array-order equal regression",
  );
  const mismatchOrderFailures = arrayOrderMismatch(
    ["result.json", "failures.json"],
    ["failures.json", "result.json", "input.json"],
    "artifact manifest array-order mismatch regression",
  );
  const missingFailures = missingEntries(
    ["run.json", "events.jsonl", "unknown.json"],
    ["run.json", "events.jsonl"],
    "artifact manifest missing-entry regression",
  );
  return [
    duplicates.join("\n") === "run.json\nevents.jsonl"
      ? null
      : `artifact manifest duplicate helper drift: expected unique duplicate paths, got ${duplicates.join(", ")}`,
    equalOrderFailures.length === 0
      ? null
      : `artifact manifest array-order equal regression drift: got ${equalOrderFailures.join(", ")}`,
    mismatchOrderFailures.join("\n") ===
    "artifact manifest array-order mismatch regression: expected failures.json, result.json, input.json"
      ? null
      : `artifact manifest array-order mismatch regression drift: got ${mismatchOrderFailures.join(", ")}`,
    missingFailures.join("\n") === "artifact manifest missing-entry regression: unknown.json"
      ? null
      : `artifact manifest missing-entry regression drift: got ${missingFailures.join(", ")}`,
    sharedArtifactSpecRegressionFailure(),
  ].filter(Boolean);
}

export function checkManifestLoaderToolInputMetadata(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`manifest loader tool-input metadata: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    source.includes("tool_input_artifact_spec")
      ? null
      : "manifest loader must use tool_input_artifact_spec",
    source.includes("tool_input_artifact_spec(leaf)")
      ? null
      : "manifest loader must match input.json through shared tool-input spec",
  ].filter(Boolean);
}

function sharedArtifactSpecRegressionFailure() {
  const actual = sharedArtifactSpec([], "unknown.json", "report reader shared artifact regression");
  return actual.path === "unknown.json" &&
    actual.label === "report reader shared artifact regression" &&
    actual.kind === "unknown"
    ? null
    : `artifact manifest shared artifact helper drift: got ${JSON.stringify(actual)}`;
}

function requiredSnapshotJsonArtifacts() {
  const excluded = new Set(["run.json", "artifacts.json", "failures.json"]);
  return requiredRunArtifactSpecs
    .filter((artifact) => artifact.kind === "json" && !excluded.has(artifact.path))
    .map((artifact) => artifact.path);
}

function requiredSpecialWriterArtifacts() {
  const excluded = new Set(["run.json", ...requiredSnapshotJsonArtifacts()]);
  return requiredRunArtifacts.filter((artifact) => !excluded.has(artifact));
}

function tuiRunsRootConsumerFailures(root) {
  const consumers = [
    "crates/kuzushi-tui/src/ui_view_models/run_trace.rs",
    "crates/kuzushi-tui/src/ui_view_models/run_timeline.rs",
    "crates/kuzushi-tui/src/renderer/views/runs/runs_lines.rs",
    "crates/kuzushi-tui/src/renderer/views/patch/patch_lines.rs",
    "crates/kuzushi-tui/src/app/line_editor/is_word_char/completion_sources.rs",
  ];
  return consumers.flatMap((file) => tuiRunsRootConsumerFailure(root, file));
}

function tuiLatestRunConsumerFailures(root) {
  const consumers = [
    "crates/kuzushi-tui/src/ui_view_models/recommendation.rs",
    "crates/kuzushi-tui/src/ui_view_models/home_cockpit.rs",
    "crates/kuzushi-tui/src/ui_view_models/failure_handoff.rs",
  ];
  return consumers.flatMap((file) => tuiLatestRunConsumerFailure(root, file));
}

function tuiLatestRunConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI latest-run consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("ui_latest_run_path(") ||
    source.includes(".latest_run_pointer(") ||
    source.includes(".cached_latest_run_pointer(")
      ? null
      : `TUI latest-run consumer must use the shared latest-run reader: ${file}`,
    source.includes("ui_run_dir(") ? null : `TUI latest-run consumer must use ui_run_dir: ${file}`,
    productionSource.includes('".kuzushi/v3/latest"')
      ? `TUI latest-run consumer must not hardcode .kuzushi/v3/latest: ${file}`
      : null,
  ].filter(Boolean);
}

function tuiRunsRootConsumerFailure(root, file) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`TUI runs-root consumer: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const usesSharedRoot =
    source.includes("ui_runs_root(") ||
    source.includes("ui_runs_root_relative_path(") ||
    source.includes("kuzushi_core::runs_root(") ||
    source.includes(".run_summary_entries(") ||
    source.includes(".cached_run_summary_entries(") ||
    source.includes(".run_artifact_text(") ||
    source.includes(".cached_run_artifact_text(");
  return [
    usesSharedRoot ? null : `TUI runs-root consumer must use shared helper: ${file}`,
    source.includes(".kuzushi/v3/runs")
      ? `TUI runs-root consumer must not hardcode .kuzushi/v3/runs: ${file}`
      : null,
  ].filter(Boolean);
}

function homeCockpitExpectedArtifacts() {
  const timelineArtifacts = new Set(["run.json", "events.jsonl", "trace.jsonl"]);
  return requiredRunArtifacts.filter((artifact) => !timelineArtifacts.has(artifact));
}

function homeCockpitFilteredArtifacts(source) {
  const body = rustArrayConstantBody(source, "HOME_TIMELINE_ARTIFACTS");
  if (body === null) return [];
  const hidden = new Set([...body.matchAll(/"([^"]+)"/g)].map((match) => match[1]));
  return requiredRunArtifacts.filter((artifact) => !hidden.has(artifact));
}

function homeCockpitRunMetadataFailures(source) {
  return [
    source.includes('canonical_run_artifact_spec("run.json")')
      ? null
      : "home cockpit run status must use shared run metadata artifact spec",
    source.includes("fn run_metadata_artifact_leaf() -> &'static str")
      ? null
      : "home cockpit run status must centralize metadata artifact leaf",
    source.includes("run_artifact_text(app, run, run_metadata_artifact_leaf())") &&
    source.includes(".cached_run_artifact_text(")
      ? null
      : "home cockpit run status must use the hydrated safe-reader cache with the shared metadata leaf",
    source.includes("malformed_run_metadata_label")
      ? null
      : "home cockpit run status must share malformed metadata label",
  ].filter(Boolean);
}

function persistentThreatModelPathCallerFailures(root) {
  const callers = [
    "crates/kuzushi-core/src/capabilities/threat_model/application/build_threat_model.rs",
    "crates/kuzushi-core/src/capabilities/threat_model/application/deterministic_build.rs",
    "crates/kuzushi-core/src/capabilities/carlini_threat_hunt/application/resolve_threat_model_document.rs",
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/plan.rs",
    "crates/kuzushi-core/src/capabilities/threat_leads/mod.rs",
    "crates/kuzushi-core/src/run_artifacts/run_reproducibility_metadata.rs",
  ];
  return callers.flatMap((file) => {
    const sourcePath = path.join(root, file);
    if (!existsSync(sourcePath)) return [`persistent threat-model path caller: missing ${file}`];
    const source = readFileSync(sourcePath, "utf8");
    const productionSource = source.split("#[cfg(test)]")[0];
    return [
      source.includes("persistent_threat_model_path(")
        ? []
        : [`persistent threat-model path caller must use helper: ${file}`],
      file.endsWith("resolve_threat_model_document.rs") &&
      productionSource.includes(".kuzushi/threat-model.json")
        ? [
            "Carlini threat-model diagnostic must derive the label from persistent_threat_model_path",
          ]
        : [],
    ].flat();
  });
}

function threatModelBuildSummaryStatusFailures(root) {
  const file = "crates/kuzushi-core/src/capabilities/threat_model/application/build_summary.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`threat-model build summary status: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("saved_threat_model_status(persisted, has_concrete_content, &input.target)")
      ? null
      : "threat-model build summary saved label must pass the target",
    source.includes("persistent_threat_model_path(target)")
      ? null
      : "threat-model build summary saved label must use persistent_threat_model_path",
    productionSource.includes(".kuzushi/threat-model.json")
      ? "threat-model build summary saved label must not hardcode .kuzushi/threat-model.json"
      : null,
  ].filter(Boolean);
}

function moduleRecommenderThreatModelSourceFailures(root) {
  const modFile = "crates/kuzushi-core/src/capabilities/module_recommender/mod.rs";
  const adapterFile = "crates/kuzushi-core/src/capabilities/module_recommender/adapters.rs";
  const modSource = readRequiredSource(root, modFile, "module recommender threat-model source");
  const adapterSource = readRequiredSource(
    root,
    adapterFile,
    "module recommender threat-model source",
  );
  if (Array.isArray(modSource) || Array.isArray(adapterSource)) {
    return [
      ...(Array.isArray(modSource) ? modSource : []),
      ...(Array.isArray(adapterSource) ? adapterSource : []),
    ];
  }
  const productionSource = adapterSource.split("#[cfg(test)]")[0];
  return [
    modSource.includes("persistent_threat_model_path")
      ? null
      : "module recommender threat-model source must import persistent_threat_model_path",
    adapterSource.includes("threat_model_source(target, threat_model)")
      ? null
      : "module recommender threat-model source must pass target to source label helper",
    adapterSource.includes("persistent_threat_model_path(target)")
      ? null
      : "module recommender threat-model source must use persistent_threat_model_path",
    productionSource.includes(".kuzushi/threat-model.json")
      ? "module recommender threat-model source must not hardcode .kuzushi/threat-model.json"
      : null,
  ].filter(Boolean);
}

function carliniContextSnippetPathFailures(root) {
  const file = "crates/kuzushi-core/src/capabilities/carlini_threat_hunt/adapters/output.rs";
  const source = readRequiredSource(root, file, "Carlini context snippet artifact paths");
  if (Array.isArray(source)) return source;
  const productionSource = source.split("#[cfg(test)]")[0];
  return [
    source.includes("persistent_threat_model_source_path(target)")
      ? null
      : "Carlini context snippets must use persistent threat-model source helper",
    source.includes("context_snapshot_source_path(target)")
      ? null
      : "Carlini context snippets must use context snapshot source helper",
    source.includes("persistent_threat_model_path(target)")
      ? null
      : "Carlini context snippets must derive threat-model path from persistent_threat_model_path",
    source.includes("context_snapshot_path(target)")
      ? null
      : "Carlini context snippets must derive context path from context_snapshot_path",
    productionSource.includes(".kuzushi/threat-model.json")
      ? "Carlini context snippets must not hardcode .kuzushi/threat-model.json"
      : null,
    productionSource.includes(".kuzushi/context-snapshot.json")
      ? "Carlini context snippets must not hardcode .kuzushi/context-snapshot.json"
      : null,
  ].filter(Boolean);
}

function threatModelDefaultOutputDirFailures(root) {
  const toolContractFile =
    "crates/kuzushi-core/src/capabilities/threat_model/domain/tool_contract.rs";
  const buildInputFile =
    "crates/kuzushi-core/src/capabilities/threat_model/adapters/build_input.rs";
  const deterministicInputFile =
    "crates/kuzushi-core/src/capabilities/threat_model/application/deterministic_input.rs";
  const toolContract = readRequiredSource(
    root,
    toolContractFile,
    "threat-model default output dir",
  );
  const buildInput = readRequiredSource(root, buildInputFile, "threat-model default output dir");
  const deterministicInput = readRequiredSource(
    root,
    deterministicInputFile,
    "threat-model default output dir",
  );
  const readFailures = [toolContract, buildInput, deterministicInput].filter(Array.isArray).flat();
  if (readFailures.length > 0) return readFailures;
  return threatModelDefaultOutputDirChecks(toolContract, buildInput, deterministicInput);
}

function threatModelDefaultOutputDirChecks(toolContract, buildInput, deterministicInput) {
  const productionSources = [toolContract, buildInput, deterministicInput]
    .map((source) => source.split("#[cfg(test)]")[0])
    .join("\n");
  return [
    toolContract.includes(
      "pub(crate) fn default_output_dir(self, target: &Path, run_id: &str) -> String",
    )
      ? null
      : "threat-model default output dir must live on BuildFlavor",
    toolContract.includes("crate::run_artifacts::run_dir(target, run_id)")
      ? null
      : "threat-model default output dir must use run_dir",
    buildInput.includes("flavor.default_output_dir(&target, &run_id)")
      ? null
      : "threat-model model-backed input must use default_output_dir",
    deterministicInput.includes("flavor.default_output_dir(&target, &run_id)")
      ? null
      : "threat-model deterministic input must use default_output_dir",
    productionSources.includes(".kuzushi/v3/runs/{run_id}")
      ? "threat-model default output dir must not hardcode .kuzushi/v3/runs"
      : null,
  ].filter(Boolean);
}

function readRequiredSource(root, file, label) {
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`${label}: missing ${file}`];
  return readFileSync(sourcePath, "utf8");
}

function oauthCredentialHelperFailures(source) {
  const constants = rustStringConstants(source, ["OAUTH_CREDENTIALS_FILE"]);
  return [
    constants.OAUTH_CREDENTIALS_FILE === "oauth-credentials.json"
      ? null
      : "OAuth credential path helper must name OAUTH_CREDENTIALS_FILE as oauth-credentials.json",
    source.includes("pub fn default_oauth_credentials_path(home_dir: impl AsRef<Path>) -> PathBuf")
      ? null
      : "OAuth credential path helper must expose default_oauth_credentials_path",
    source.includes("workspace_state_root(home_dir).join(OAUTH_CREDENTIALS_FILE)")
      ? null
      : "OAuth credential path helper must derive from workspace_state_root",
  ].filter(Boolean);
}

function oauthCredentialConsumerFailures(file, source) {
  return [
    source.includes("default_oauth_credentials_path") ||
    source.includes("default_oauth_credentials_path_display")
      ? null
      : `OAuth credential path consumer must use default_oauth_credentials_path: ${file}`,
    source.includes("oauth-credentials.json") && !source.includes("OAUTH_CREDENTIALS_FILE")
      ? `OAuth credential path consumer must not hardcode oauth-credentials.json: ${file}`
      : null,
  ].filter(Boolean);
}

function readThreatLeadsPathSources(root) {
  const file = "crates/kuzushi-core/src/capabilities/threat_leads/mod.rs";
  const outputFile = "crates/kuzushi-core/src/capabilities/threat_leads/output.rs";
  const sourcePath = path.join(root, file);
  const outputPath = path.join(root, outputFile);
  if (!existsSync(sourcePath)) return [`threat-leads path helper: missing ${file}`];
  if (!existsSync(outputPath)) return [`threat-leads output path consumer: missing ${outputFile}`];
  return {
    file,
    outputFile,
    source: readFileSync(sourcePath, "utf8"),
    output: readFileSync(outputPath, "utf8"),
  };
}

function threatLeadsConstantFailures(source) {
  const constants = rustStringConstants(source, [
    "THREAT_LEADS_ARTIFACT_FILE",
    "THREAT_LEADS_SUMMARY_FILE",
  ]);
  return [
    constants.THREAT_LEADS_ARTIFACT_FILE === "threat-leads.json"
      ? null
      : "threat-leads artifact path must name THREAT_LEADS_ARTIFACT_FILE as threat-leads.json",
    constants.THREAT_LEADS_SUMMARY_FILE === "threat-leads.md"
      ? null
      : "threat-leads summary path must name THREAT_LEADS_SUMMARY_FILE as threat-leads.md",
  ].filter(Boolean);
}

function threatLeadsSourcePathFailures(source) {
  return [
    source.includes("pub(super) fn threat_leads_artifact_path(target: &Path) -> PathBuf")
      ? null
      : "threat-leads path helper must expose threat_leads_artifact_path",
    source.includes("pub(super) fn threat_leads_summary_path(target: &Path) -> PathBuf")
      ? null
      : "threat-leads path helper must expose threat_leads_summary_path",
    source.includes("workspace_state_root(target).join(THREAT_LEADS_ARTIFACT_FILE)")
      ? null
      : "threat-leads artifact path must derive from workspace_state_root",
    source.includes("workspace_state_root(target).join(THREAT_LEADS_SUMMARY_FILE)")
      ? null
      : "threat-leads summary path must derive from workspace_state_root",
    source.includes("let path = threat_leads_artifact_path(target)")
      ? null
      : "threat-leads read/write must use threat_leads_artifact_path",
    source.includes("let summary_path = threat_leads_summary_path(target)")
      ? null
      : "threat-leads write must use threat_leads_summary_path",
    source.includes("persistent_threat_model_path(target)")
      ? null
      : "threat-leads threat-model reader must use persistent_threat_model_path",
  ].filter(Boolean);
}

function threatLeadsOutputPathFailures(output) {
  return [
    output.includes("super::threat_leads_artifact_path(target)")
      ? null
      : "threat-leads output must use threat_leads_artifact_path",
    output.includes("super::threat_leads_summary_path(target)")
      ? null
      : "threat-leads output must use threat_leads_summary_path",
  ].filter(Boolean);
}

function threatLeadsHardcodedPathFailures(file, source) {
  return [
    'join(".kuzushi/threat-leads.json")',
    'join(".kuzushi/threat-leads.md")',
    'join(".kuzushi").join("threat-leads.json")',
    'join(".kuzushi").join("threat-leads.md")',
    'join(".kuzushi/threat-model.json")',
    'join(".kuzushi").join("threat-model.json")',
    'ARTIFACT_REL_PATH.replace("threat-leads", "threat-model")',
  ]
    .filter((needle) => source.includes(needle))
    .map((needle) => `threat-leads path consumer must not hardcode ${needle}: ${file}`);
}

function dirJoinArtifacts(source) {
  return [...source.matchAll(/dir\.join\("([^"]+)"\)/g)].map((match) => match[1]);
}

function canonicalSpecialWriterArtifacts(source) {
  return [
    ...dirJoinArtifacts(source),
    ...[...source.matchAll(/required_artifact_spec\("([^"]+)"\)\.leaf/g)].map((match) => match[1]),
  ];
}

function reportReaderArtifactSpecs(root, source) {
  const sharedSpecs =
    rustCanonicalRunArtifactSpecs(
      readFileSync(path.join(root, artifactContractFile), "utf8"),
      "CANONICAL_RUN_ARTIFACTS",
    ) ?? [];
  const canonicalSpecs = source.includes("CANONICAL_RUN_ARTIFACTS")
    ? sharedSpecs.filter(
        (spec) => spec.path !== "report.md" && (spec.kind === "json" || spec.kind === "jsonl"),
      )
    : [
        ...(rustStringArrayConstant(source, "CANONICAL_JSON_FILES") ?? []).map((artifact) =>
          sharedArtifactSpec(sharedSpecs, artifact, "report reader canonical JSON"),
        ),
        ...(rustStringArrayConstant(source, "CANONICAL_TEXT_FILES") ?? []).map((artifact) =>
          sharedArtifactSpec(sharedSpecs, artifact, "report reader canonical text"),
        ),
      ];
  return [
    ...canonicalSpecs,
    ...(source.includes("TOOL_RESULT_ARTIFACTS") ? toolResultArtifactSpecs : []),
    ...(source.includes("TOOL_INPUT_ARTIFACTS") ? toolInputArtifactSpecs : []),
    ...(source.includes("OPTIONAL_RUN_ARTIFACTS") ? optionalRunArtifactSpecs : []),
  ];
}

function reportReaderSourceFailures(source) {
  return [
    source.includes("CANONICAL_RUN_ARTIFACTS")
      ? null
      : "report reader must derive canonical artifacts from CANONICAL_RUN_ARTIFACTS",
    source.includes("canonical_report_json_specs")
      ? null
      : "report reader must centralize canonical JSON artifact selection",
    source.includes("canonical_report_text_specs")
      ? null
      : "report reader must centralize canonical text artifact selection",
    source.includes("load_declared_json_artifacts")
      ? null
      : "report reader must summarize explicit declared JSON artifacts",
    source.includes("is_shared_report_leaf")
      ? null
      : "report reader declared JSON loader must skip shared report leaves",
  ].filter(Boolean);
}

function sharedArtifactSpec(specs, artifact, label) {
  return (
    specs.find((spec) => spec.path === artifact) ?? {
      path: artifact,
      label,
      kind: "unknown",
    }
  );
}

function reportReaderExpectedSpecs() {
  return [
    ...requiredRunArtifactSpecs.filter((artifact) => artifact.path !== "report.md"),
    ...optionalRunArtifactSpecs,
    ...toolResultArtifactSpecs,
    ...toolInputArtifactSpecs,
  ];
}

function reportReaderInventoryFailures(expectedSpecs, actualSpecs) {
  const expectedPaths = expectedSpecs.map((artifact) => artifact.path);
  const actualPaths = actualSpecs.map((artifact) => artifact.path).sort();
  return [
    ...missingEntries(actualPaths, expectedPaths, "report reader has uncontracted artifact"),
    ...duplicateEntries(actualPaths).map(
      (artifact) => `report reader duplicates artifact ${artifact}`,
    ),
  ];
}

function reportReaderMismatches(actualSpecs, expected) {
  if (expected.path === "report.md") return [];
  const actual = actualSpecs.find((artifact) => artifact.path === expected.path);
  if (!actual) return [`report reader missing canonical artifact ${expected.path}`];
  return ["label", "kind"].flatMap((field) =>
    actual[field] === expected[field]
      ? []
      : [`report reader artifact ${expected.path} must have ${field} ${expected[field]}`],
  );
}

function specInventoryFailures(expected, actual, label) {
  const actualPaths = actual.map((artifact) => artifact.path).sort();
  const expectedPaths = expected.map((artifact) => artifact.path);
  return [
    ...missingEntries(expectedPaths, actualPaths, `${label} missing artifact`),
    ...missingEntries(actualPaths, expectedPaths, `${label} has uncontracted artifact`),
    ...duplicateEntries(actualPaths).map((artifact) => `${label} duplicates artifact ${artifact}`),
    ...expected.flatMap((spec) => specFieldMismatches(actual, spec, label)),
  ];
}

function specFieldMismatches(actualSpecs, expected, label) {
  const actual = actualSpecs.find((artifact) => artifact.path === expected.path);
  if (!actual) return [];
  return ["label", "kind"].flatMap((field) =>
    actual[field] === expected[field]
      ? []
      : [`${label} artifact ${expected.path} must have ${field} ${expected[field]}`],
  );
}

function missingEntries(source, allowed, label) {
  return source.filter((entry) => !allowed.includes(entry)).map((entry) => `${label}: ${entry}`);
}

function duplicateEntries(entries) {
  const seen = new Set();
  const duplicates = new Set();
  for (const entry of entries) {
    if (seen.has(entry)) duplicates.add(entry);
    seen.add(entry);
  }
  return Array.from(duplicates);
}

function countOccurrences(source, needle) {
  return source.split(needle).length - 1;
}

function arrayOrderMismatch(actual, expected, label) {
  return actual.join("\n") === expected.join("\n")
    ? []
    : [`${label}: expected ${expected.join(", ")}`];
}
