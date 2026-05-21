#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";

const repo = process.cwd();

const requiredDocs = [
  {
    file: "PORT_PLAN.md",
    needles: ["upstream-codex", "docs/architecture/kuzushi-boundaries.md", "Phase Ledger"],
  },
  {
    file: "UPSTREAM_CODEX.md",
    needles: [
      "https://github.com/openai/codex",
      "upstream-codex",
      "Kuzushi ships as Kuzushi",
      "LICENSES/Apache-2.0.txt",
      "NOTICE",
    ],
  },
  {
    file: "NOTICE",
    needles: ["OpenAI Codex", "https://github.com/openai/codex", "LICENSES/Apache-2.0.txt"],
  },
  {
    file: "LICENSES/Apache-2.0.txt",
    needles: ["Apache License", "Version 2.0, January 2004"],
  },
  {
    file: "docs/architecture/kuzushi-boundaries.md",
    needles: ["Required Contexts", "pnpm quality:architecture", "pnpm quality:model-safety"],
  },
  {
    file: "docs/architecture/kuzushi-artifacts.md",
    needles: [".kuzushi/runs/<runId>/", "run.json", "failures.json", "report.md"],
  },
  {
    file: "docs/quality/crap-gate.md",
    needles: [
      "pnpm quality:crap-risk",
      "scripts/crap-gate.sh",
      "default threshold is also 7",
      "CRAP-risk",
      "greater than or equal to 7",
    ],
  },
];

const packageRequirements = [
  '"kuzushi": "./bin/kuzushi-rs.mjs"',
  '"kz": "./bin/kuzushi-rs.mjs"',
  '"build:native": "cargo build -p kuzushi-cli --release && node scripts/stage-native-binary.mjs"',
  '"prepack": "pnpm build:clean && pnpm build:native"',
  "scripts/verify-pack.mjs",
  "scripts/check-native-bindings.mjs",
  '"schemas"',
  '"./schemas/*": "./schemas/*"',
  '"postinstall": "node scripts/check-native-bindings.mjs"',
  "scripts/check-port-contract.mjs",
  "scripts/check-public-identity.mjs",
  "scripts/check-retired-ts-runtime.mjs",
  "scripts/check-ddd-boundaries.mjs",
  "scripts/check-ddd-context-docs.mjs",
  "scripts/check-artifact-contract.mjs",
  "scripts/check-result-envelope-contract.mjs",
  "scripts/check-deferred-surface-contract.mjs",
  "scripts/check-model-safety.mjs",
  "scripts/check-validated-wording.mjs",
  "UPSTREAM_CODEX.md",
];

const artifactContractRequirements = [
  "./artifact-contract-fields.mjs",
  "./artifact-manifest-contract.mjs",
  "./artifact-schema-contract.mjs",
  "./artifact-schema-inventory-contract.mjs",
  "./artifact-token-contracts.mjs",
  "./canonical-run-artifacts.mjs",
  "./check-failure-schema-bounds.mjs",
  "requiredRunArtifacts",
  "optionalRunArtifacts",
  "checkCanonicalManifestInventory(root)",
  "checkOptionalAndToolResultArtifactInventory(root)",
  "checkReportReaderInventory(root)",
  "checkFailureFollowUpInventory(root)",
  "checkFailureMissingArtifactInventory(root)",
  "checkCanonicalSnapshotInventory(root)",
  "checkCanonicalSpecialWriterInventory(root)",
  "checkRunMetadataWriterInventory(root)",
  "tokenChecks.flatMap(checkTokenReferences)",
];

const artifactSchemaInventoryRequirements = [
  "requiredRunArtifactSpecs",
  "canonicalRunSchemaFiles",
  "required artifact missing schema",
  "schema has no required artifact",
];

const artifactSchemaShapeRequirements = [
  "snapshotMarkerShapeSpecs",
  "properties\", \"runId",
  "properties\", \"run_id",
  "properties\", \"status",
  "properties\", \"runStatus",
  "properties\", \"summary",
  "properties\", \"warnings",
  "properties\", \"errors",
  "schemas/run.attack-surface.schema.json",
  "schemas/run.context.schema.json",
  "schemas/run.findings.schema.json",
  "schemas/run.proof.schema.json",
  "schemas/run.recommendations.schema.json",
  "schemas/run.threat-model.schema.json",
  "#/definitions/appModel",
  "#/definitions/appRoute",
  "#/definitions/fileIndex",
  "#/definitions/finding",
  "#/definitions/findingProperties",
  "definitions\", \"confidence\", \"anyOf",
  "#/definitions/inputCategories",
  "#/definitions/methodology",
  "#/definitions/narrative",
  "#/definitions/priority",
  "#/definitions/proofFinding",
  "#/definitions/proofKind",
  "#/definitions/proofLevel",
  "#/definitions/proofState",
  "#/definitions/proofVerdict",
  "#/definitions/recommendation",
  "#/definitions/risk",
  "#/definitions/riskTier",
  "#/definitions/routeMethod",
  "#/definitions/severity",
  "#/definitions/surface",
  "#/definitions/surfaceKind",
  "#/definitions/stringList",
  "#/definitions/threat",
  "filesIndexed",
  "files_indexed",
  "repoContext",
  "repo_context",
  "totalFiles",
  "total_files",
  "patternMatches",
  "pattern_matches",
  "outboundClients",
  "outbound_clients",
  "serviceBoundaries",
  "service_boundaries",
  "dataStores",
  "data_stores",
  "backgroundJobs",
  "background_jobs",
  "trustBoundaries",
  "trust_boundaries",
  "methodology",
  "relatedCwe",
  "related_cwe",
  "attackerStories",
  "attackerControlled",
  "attacker_controlled",
  "operatorControlled",
  "operator_controlled",
  "developerControlled",
  "developer_controlled",
  "externalServices",
  "external_services",
  "credentialFlows",
  "credential_flows",
  "authorizationFlows",
  "authorization_flows",
  "fileIngestFlows",
  "file_ingest_flows",
  "dataEgressFlows",
  "data_egress_flows",
  "callbackFlows",
  "callback_flows",
  "sandboxBoundary",
  "sandbox_boundary",
  "criticalityBuckets",
  "outOfScope",
  "attackSurface",
  "degradation",
  "availableToolCount",
  "available_tool_count",
  "recommendedToolCount",
  "recommended_tool_count",
  "skippedMissingTools",
  "skipped_missing_tools",
  "target",
  "moduleId",
  "module_id",
  "tool",
  "reason",
  "requiresRuntime",
  "requires_runtime",
  "staticProofState",
  "static_proof_state",
  "proofState",
  "proof_state",
  "proofLevel",
  "proof_level",
  "proofVerdict",
  "proof_verdict",
  "snoozedUntil",
  "snoozed_until",
  "remediation",
  "startLine",
  "start_line",
  "endLine",
  "end_line",
  "maximum",
  "checkMaximum",
  "surfaceCount",
  "surface_count",
  "highRisk",
  "high_risk",
  "maxRiskScore",
  "max_risk_score",
  "byRiskTier",
  "by_risk_tier",
  "byKind",
  "by_kind",
  "rank",
  "score",
  "tier",
  "reasons",
  "metadata",
  "runtimeVerification",
  "runtime_verification",
  "countsByState",
  "counts_by_state",
  "verifiedCount",
  "verified_count",
  "verificationResults",
  "verification_results",
  "itemRef",
  "checkRef",
  "checkItemRef",
  "checkMinimum",
];

const failureSchemaBoundsRequirements = [
  "failureArrayLimit",
  "boundedFailureArrays",
  "nonEmptyFailureStrings",
  "nonEmptyFailureArrayItems",
  "failureStringMinLength",
  "failureArrayItemMinLength",
  "schemaNode",
  "must set minLength 1",
  "items must set minLength 1",
  "definitions.failureContext.properties.allowedProofLevel",
  "definitions.failureContext.properties.fallbackPrompt",
  "definitions.failureContext.properties.claimsForbidden",
];

const rustSourceContractRequirements = [
  "rustFunctionBody",
  "matchingBraceIndex",
  "braceDepthDelta",
];

const artifactTokenContractRequirements = [
  "./canonical-run-artifacts.mjs",
  "requiredRunArtifacts",
  "...requiredRunArtifacts",
  "failureReportFollowUpRustFields",
  "failureReportFollowUpDocFields",
  "shared declared artifact compatibility aliases",
  "tool output declared artifact uses shared aliases",
  "report artifact manifest uses shared aliases",
  "report reader and writer resolve required artifact labels from shared specs",
  "shared canonical artifact manifest enumerates every required artifact",
  "run artifact manifest writer uses shared canonical artifacts",
  "tool result writer uses shared artifact spec",
  "failure handoff writer uses shared artifact spec",
  "optional_run_artifact_spec(\\\"report.sarif\\\")",
];

const canonicalRunArtifactRequirements = [
  "requiredRunArtifactSpecs",
  "optionalRunArtifactSpecs",
  "toolResultArtifactSpecs",
  "requiredRunArtifacts",
  "run metadata",
  "events.jsonl",
  "jsonl",
  "failure handoff",
  "SARIF report",
  "report.sarif",
  "sarif",
  "tool result",
  "result.json",
  "report.md",
  "markdown",
];

const artifactManifestContractRequirements = [
  "CANONICAL_RUN_ARTIFACTS",
  "canonical manifest missing required artifact",
  "canonical manifest has uncontracted artifact",
  "canonical manifest duplicates artifact",
  "canonical manifest artifact ${expected.path} must have ${field} ${expected[field]}",
  "optional run artifact inventory",
  "tool-result artifact inventory",
  "${label} missing artifact",
  "${label} has uncontracted artifact",
  "specFieldMismatches",
  "FOLLOW_UP_RUN_FILES",
  "optionalRunArtifactSpecs",
  "toolResultArtifactSpecs",
  "report reader missing canonical artifact",
  "report reader artifact ${expected.path} must have ${field} ${expected[field]}",
  "sharedArtifactSpec",
  "stringArrayConstant(source, \"CANONICAL_JSON_FILES\")",
  "stringArrayConstant(source, \"CANONICAL_TEXT_FILES\")",
  "failure follow-up must use failure_artifact_spec().leaf",
  "failure follow-up has uncontracted artifact",
  "failure follow-up required order drift",
  "failure follow-up must use TOOL_RESULT_ARTIFACTS",
  "optional failure follow-up must use OPTIONAL_RUN_ARTIFACTS",
  "optional failure follow-up must use report_artifact_spec().leaf",
  "failure missing-artifact inventory must not keep a local canonical list",
  "failure missing-artifact inventory must use CANONICAL_RUN_ARTIFACTS",
  "failure missing-artifact inventory must exclude failures.json",
  "canonical run artifact leaves missing artifact",
  "canonical run artifact leaves has uncontracted artifact",
  "JSON_SNAPSHOT_FILES",
  "canonical snapshot writer missing artifact",
  "canonical snapshot writer has uncontracted artifact",
  "dir\\.join",
  "canonicalSpecialWriterArtifacts",
  "canonical special writer missing artifact",
  "canonical special writer has uncontracted artifact",
  "RUN_METADATA_FILE",
  "LEGACY_SUMMARY_FILE",
  "run metadata writer must own run.json",
  "legacy summary writer must keep summary.json",
];

const resultEnvelopeRequirements = [
  "artifact alias contract is shared by run and result normalization",
  "ARTIFACT_PATH_KEYS",
  "ARTIFACT_LABEL_KEYS",
  "ARTIFACT_KIND_KEYS",
  "CanonicalRunArtifactSpec",
  "CANONICAL_RUN_ARTIFACTS",
  "OPTIONAL_RUN_ARTIFACTS",
  "TOOL_RESULT_ARTIFACTS",
  "first_nonempty_string",
  "first_nonempty_value_string",
  "result normalization uses shared artifact aliases",
  "run artifact extraction uses shared artifact aliases",
  "report artifact summaries use shared artifact aliases",
  "normalize_tool_output_contract",
  "catalog:modules",
  "catalog:tools",
  "wraps_non_object_outputs",
  "completed_output_result",
  "failed_output_result",
  "completed_result_uses_canonical_envelope_fields",
  "failed_result_copies_output_into_errors",
  "skipped_and_partial_results_preserve_warning_arrays",
  "normalizes_snake_case_artifact_path_aliases",
];

const docDriftRequirements = [
  "\"AGENTS.md\"",
  '".github"',
  "modelGuidanceFiles.flatMap",
  "staleSplitPathPatterns",
  "staleModelPathPatterns",
  "deleted TS model enforcement path",
];

const modelSafetyRequirements = [
  "FORBIDDEN_MODEL_DEFAULT_BLOCKS",
  "hardcoded multiline model fallback expression",
  "hardcoded multiline model field literal",
  "source.matchAll(pattern)",
  "lineNumberAt(source, match.index ?? 0)",
];

const crapGateRequirements = [
  "KUZUSHI_CRAP_THRESHOLD      Default CRAP threshold, 7.",
  'threshold="${KUZUSHI_CRAP_THRESHOLD:-7}"',
  "Number(entry.crap) >= threshold",
];

const ciRequirements = [
  "pnpm quality:crap-risk",
  "pnpm quality:identity",
  "pnpm quality:architecture",
  "pnpm quality:model-safety",
  "pnpm check:docs",
  "verify-pack:",
  "pnpm verify:pack",
  "node scripts/stage-native-binary.mjs",
  "native-linux-x64",
];

const releaseRequirements = [
  "name: dist",
  "name: native-linux-x64",
  "path: native/",
  "pnpm verify:pack",
  "npm publish --access public --provenance --ignore-scripts",
  "npm publish --access public --ignore-scripts",
  "npm pack --ignore-scripts",
];

const publishScriptRequirements = [
  "typecheck + tests + clean JS/native build + package verification must pass",
  "pnpm run build:clean",
  "pnpm run build:native",
  "pnpm run verify:pack",
  "npm pack --dry-run --ignore-scripts",
  "PUBLISH_ARGS=(publish --access public --ignore-scripts)",
];

const stageNativeRequirements = [
  '["kuzushi.exe", "kz.exe"]',
  '["kuzushi", "kz"]',
  '["codex.exe", "kuzushi-ts.exe"]',
  '["codex", "kuzushi-ts"]',
  "rmSync(stale, { force: true })",
];

const packagingRequirements = [
  "package artifact contract failed",
  "^\\.codex(?:\\/|$)",
  "^dist\\/cli(?:\\/|\\.|$)",
  "^src\\/copilot\\/shell(?:-|\\.|$)",
  "^src\\/ui\\/(?:App\\.tsx|components(?:\\/|$)|primitives(?:\\/|$)|render\\.ts|setup\\.ts)",
  "^native\\/[^/]+\\/(?:codex|kuzushi-ts)(?:\\.exe)?$",
  "package bin.${name} must point to ${expected}",
  "package bin.${name} must not be published",
  "package scripts.${name} references unshipped file ${file}",
  "./artifact-schema-inventory-contract.mjs",
  "./canonical-run-schema-files.mjs",
  "...canonicalRunSchemaFiles",
  "checkArtifactSchemaInventory",
  "schemaInventoryFailures",
  "packagedRunSchemaFailures",
  "required run schema not shipped",
  "uncontracted run schema shipped",
  "requiredPackageFiles",
  "packageExportFailures",
  "schemaExportFailures",
  "schemaExportedByWildcard",
  'package exports["./schemas/*"] must point to ./schemas/*',
  "required package file ${file} is not exported by ./schemas/*",
  "required package file missing",
  "KUZUSHI_VERIFY_PACK_OMIT_NATIVE",
  "missing shipped native directory native/<platform>-<arch>",
  "missing shipped native binary",
  "native binary pairs are consistent",
];

const retiredRuntimeRequirements = [
  "Command" + "Catalog symbol",
  "Command" + "Router symbol",
  "Slash" + "Command symbol",
  "Local" + "CommandResult symbol",
  "Shell" + "CommandResult symbol",
  "normalizedImportTarget",
  "pointsAtRetiredTypeScriptRuntime",
  "imports retired TypeScript runtime path",
];

const deferredSurfaceRequirements = [
  "carlini_threat_hunt_module().deferred()",
  "prompt_armor::module().deferred()",
  "recon_module().deferred()",
  "shinsa_module().deferred()",
  "tob_module().deferred()",
  "vuln_scout_module().deferred()",
  "optionalAdapterPackages",
  "optionalDependencies",
  "must not install deferred adapter package",
  "hidden_module(\\n        \"systems-hunt\"",
  "recommenderForbiddenTools",
  "deferredDocNeedles",
  "systems-hunt:*` entries are internal DAG",
  "`carlini-threat-hunt`",
  "`uaf-hunt`",
  "internally registered DAG nodes",
  "chrome-rce:review-trigger",
  "prompt-armor:scan",
  "pwn:profile-binary",
  "recon:subdomain",
  "hiddenDagNodeNeedles",
  "systems-hunt:systems-context-gatherer",
  "is_registered_dag_node",
  "vendor-assessment:attach",
  "shinsa:",
  "tob:",
  "vuln-scout:",
  "deferred exact opt-in",
];

const failures = [
  ...checkUpstreamCodexRemote(),
  ...requiredDocs.flatMap(checkFileNeedles),
  ...checkNeedles("package.json", packageRequirements),
  ...checkNeedles("scripts/crap-gate.sh", crapGateRequirements),
  ...checkNeedles("scripts/check-artifact-contract.mjs", artifactContractRequirements),
  ...checkNeedles("scripts/artifact-manifest-contract.mjs", artifactManifestContractRequirements),
  ...checkNeedles("scripts/artifact-schema-inventory-contract.mjs", artifactSchemaInventoryRequirements),
  ...checkNeedles("scripts/artifact-schema-shapes.mjs", artifactSchemaShapeRequirements),
  ...checkNeedles("scripts/check-failure-schema-bounds.mjs", failureSchemaBoundsRequirements),
  ...checkNeedles("scripts/artifact-token-contracts.mjs", artifactTokenContractRequirements),
  ...checkNeedles("scripts/rust-source-contracts.mjs", rustSourceContractRequirements),
  ...checkNeedles("scripts/canonical-run-artifacts.mjs", canonicalRunArtifactRequirements),
  ...checkNeedles("scripts/check-result-envelope-contract.mjs", resultEnvelopeRequirements),
  ...checkNeedles("scripts/check-doc-command-drift.mjs", docDriftRequirements),
  ...checkNeedles("scripts/check-model-safety.mjs", modelSafetyRequirements),
  ...checkNeedles("scripts/check-deferred-surface-contract.mjs", deferredSurfaceRequirements),
  ...checkNeedles("scripts/check-retired-ts-runtime.mjs", retiredRuntimeRequirements),
  ...checkNeedles("scripts/stage-native-binary.mjs", stageNativeRequirements),
  ...checkNeedles("scripts/verify-pack.mjs", packagingRequirements),
  ...checkNeedles("scripts/publish-npm.sh", publishScriptRequirements),
  ...checkNeedles(".github/workflows/ci.yml", ciRequirements),
  ...checkNeedles(".github/workflows/release.yml", releaseRequirements),
  ...checkForbiddenNeedles(".github/workflows/ci.yml", ["**/*.md", "docs/**"]),
  ...checkNoWholesaleCodexSubtree(),
];

if (failures.length > 0) {
  console.error("Kuzushi port contract check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("port contract check passed");

function checkUpstreamCodexRemote() {
  const expected = "https://github.com/openai/codex.git";
  try {
    const actual = execFileSync("git", ["remote", "get-url", "upstream-codex"], {
      cwd: repo,
      encoding: "utf8",
    }).trim();
    return actual === expected
      ? []
      : [`git remote upstream-codex must point at ${expected}; found ${actual}`];
  } catch {
    return [`git remote upstream-codex is missing; add ${expected}`];
  }
}

function checkFileNeedles({ file, needles }) {
  return checkNeedles(file, needles);
}

function checkNeedles(file, needles) {
  const source = readFileSync(path.join(repo, file), "utf8");
  return needles
    .filter((needle) => !source.includes(needle))
    .map((needle) => `${file} does not mention ${needle}`);
}

function checkForbiddenNeedles(file, needles) {
  const source = readFileSync(path.join(repo, file), "utf8");
  return needles
    .filter((needle) => source.includes(needle))
    .map((needle) => `${file} must not ignore ${needle}; docs changes need check:docs`);
}

function checkNoWholesaleCodexSubtree() {
  const forbiddenRoots = [
    "codex",
    "openai-codex",
    "upstream-codex",
    "vendor/codex",
    "vendor/openai-codex",
    "third_party/codex",
    "third_party/openai-codex",
    "reference/codex",
    "reference/openai-codex",
  ];
  return repoFiles()
    .filter((file) => forbiddenRoots.some((root) => file === root || file.startsWith(`${root}/`)))
    .map((file) => `${file} looks like a wholesale Codex subtree; port small substrate changes instead`);
}

function repoFiles() {
  return [
    ...new Set([
      ...gitLines(["ls-files"]),
      ...gitLines(["ls-files", "--others", "--exclude-standard"]),
    ]),
  ]
    .map((file) => file.replaceAll("\\", "/"))
    .filter((file) => !ignoredRepoFile(file))
    .sort();
}

function ignoredRepoFile(file) {
  return (
    file.startsWith("node_modules/") ||
    file.startsWith("target/") ||
    file.startsWith("dist/") ||
    file.startsWith("coverage/")
  );
}

function gitLines(args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}
