import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { checkFieldShapeSpecs } from "./artifact-schema-shapes.mjs";
import { checkThreatModelNarrativeFlowAliases } from "./artifact-schema-threat-model.mjs";
import { canonicalRunSchemaFiles } from "./canonical-run-schema-files.mjs";

export { canonicalRunSchemaFiles };

const artifactAliasGroups = [{ path: ["definitions", "artifact"], kind: "allOfAnyOf", fields: ["label", "name", "title"] }, { path: ["definitions", "artifact"], kind: "allOfAnyOf", fields: ["path", "file", "filePath", "file_path", "reportPath", "report_path", "reportJsonPath", "report_json_path", "scopePath", "scope_path", "dir", "outputDir", "output_dir", "promptsDir", "prompts_dir"] }, { path: ["definitions", "artifact"], kind: "allOfAnyOf", fields: ["kind", "type"] }];

const requiredAliasGroupsBySchema = {
  "schemas/run.artifacts.schema.json": [
    { path: [], kind: "anyOf", fields: ["runId", "run_id"] },
    ...artifactAliasGroups,
  ],
  "schemas/run.events.schema.json": [
    { path: [], kind: "allOfAnyOf", fields: ["atUnix", "at_unix"] },
    ...artifactAliasGroups,
  ],
  "schemas/run.failures.schema.json": [
    { path: [], kind: "anyOf", fields: ["runId", "run_id"] },
    { path: ["definitions", "failure"], kind: "anyOf", fields: ["agentThreadContext", "agent_thread_context"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["failedStage", "failed_stage"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["whatFailed", "what_failed"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["artifactsAvailable", "artifacts_available"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["missingArtifacts", "missing_artifacts"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["allowedProofLevel", "allowed_proof_level"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["nextFilesOrArtifactsToInspect", "next_files_or_artifacts_to_inspect"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["recoveryOptions", "recovery_options"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["fallbackPrompt", "fallback_prompt"] },
    { path: ["definitions", "failureContext"], kind: "allOfAnyOf", fields: ["claimsForbidden", "claims_forbidden"] },
    ...artifactAliasGroups,
  ],
  "schemas/run.summary.schema.json": [
    { path: [], kind: "allOfAnyOf", fields: ["runId", "run_id"] },
    { path: [], kind: "allOfAnyOf", fields: ["startedAtUnix", "started_at_unix"] },
    { path: [], kind: "declared", fields: ["traceMalformedLines", "trace_malformed_lines"] },
    { path: ["definitions", "llmCall"], kind: "anyOf", fields: ["promptHash", "prompt_hash"] },
    { path: ["definitions", "llmCall"], kind: "declared", fields: ["latencyMs", "latency_ms", "costUsd", "cost_usd"] },
    ...artifactAliasGroups,
  ],
  "schemas/run.trace.schema.json": [{ path: [], kind: "declared", fields: ["latencyMs", "latency_ms", "costUsd", "cost_usd", "moduleId", "module_id", "parentStep", "parent_step", "startedAtMs", "started_at_ms", "promptHash", "prompt_hash"] }],
};

const snapshotEnvelopeFieldsBySchema = {
  "schemas/run.context.schema.json": ["context", "contextSnapshot", "context_snapshot"],
  "schemas/run.findings.schema.json": ["coreFindings", "core_findings", "findings"],
  "schemas/run.proof.schema.json": ["proof", "proofs", "verification"],
  "schemas/run.recommendations.schema.json": ["data", "recommendationReport", "recommendation_report"],
};

const routePatternBySchema = {
  "schemas/run.attack-surface.schema.json": [["properties", "route"], ["definitions", "surface", "properties", "route"]],
  "schemas/run.context.schema.json": [["definitions", "appRoute", "properties", "path"], ["definitions", "appRoute", "properties", "route"]],
};

const proofStateEnumBySchema = {
  "schemas/run.findings.schema.json": [["definitions", "proofState"]],
  "schemas/run.proof.schema.json": [["definitions", "proofState"]],
};

const proofStateRefBySchema = {
  "schemas/run.findings.schema.json": [
    ["definitions", "finding", "properties", "staticProofState"],
    ["definitions", "finding", "properties", "static_proof_state"],
    ["definitions", "finding", "properties", "proofState"],
    ["definitions", "finding", "properties", "proof_state"],
    ["definitions", "findingProperties", "properties", "staticProofState"],
    ["definitions", "findingProperties", "properties", "static_proof_state"],
    ["definitions", "findingProperties", "properties", "proofState"],
    ["definitions", "findingProperties", "properties", "proof_state"],
  ],
  "schemas/run.proof.schema.json": [
    ["definitions", "proofFinding", "properties", "staticProofState"],
    ["definitions", "proofFinding", "properties", "static_proof_state"],
  ],
};

const expectedProofStates = ["signal_only", "code_cited", "source_sink_linked", "sanitizer_checked", "statically_confirmed", "statically_rejected", "needs_runtime_evidence", "execution_confirmed", "runtime_confirmed", "dynamic_confirmed", "exploit_confirmed", "poc_confirmed", "runtime_reviewed", "execution_attempted", "execution_rejected"];

const findingEnumSpecs = [
  {
    name: "severity",
    path: ["definitions", "severity"],
    values: ["critical", "high", "medium", "low", "info", "unknown", "ERROR", "WARNING", "INFO"],
    refs: [["definitions", "finding", "properties", "severity"]],
  },
  {
    name: "confidence",
    path: ["definitions", "confidence", "anyOf", 0],
    values: ["high", "medium", "low", "unknown", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
    refs: [["definitions", "finding", "properties", "confidence"]],
  },
];

const attackSurfaceEnumSpecs = [
  {
    name: "surfaceKind",
    path: ["definitions", "surfaceKind"],
    values: ["http_route", "rpc_handler", "cli_entrypoint", "background_job", "deserialization_point", "file_upload_parse_path", "external_service_client", "auth_boundary", "session_state_boundary", "request_trust_boundary", "tenant_isolation_boundary", "db_query_boundary", "command_execution_boundary"],
    refs: [["properties", "kind"], ["definitions", "surface", "properties", "kind"]],
  },
  {
    name: "riskTier",
    path: ["definitions", "riskTier"],
    values: ["critical", "high", "medium", "low"],
    refs: [["properties", "tier"], ["definitions", "risk", "properties", "tier"]],
  },
];

const artifactKindSpec = (refs) => ({ name: "artifactKind", path: ["definitions", "artifactKind"], values: ["json", "jsonl", "markdown", "sarif", "directory", "artifact"], refs });
const runStatusSpec = (refs) => ({ name: "runStatus", path: ["definitions", "runStatus"], values: ["running", "completed", "failed", "interrupted", "partial", "skipped", "paused"], refs });
const runSummaryStatusSpec = { name: "runSummaryStatus", path: ["properties", "status"], values: ["running", "completed", "failed", "interrupted", "partial", "skipped", "paused"], refs: [] };
const routeMethodSpec = (refs) => ({
  name: "routeMethod",
  path: ["definitions", "routeMethod"],
  values: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT", "ANY", "USE"],
  refs,
});
const proofVerdictValues = ["confirmed", "exploited", "not_reproduced", "harness_failed_to_build", "infrastructure_error", "language_unsupported_yet", "insufficient_finding_detail", "needs-runtime-evidence"];
const proofKindValues = ["verification", "llm-exploitability-review", "empirical-verification", "verification-outcome", "patch-validation"];
const proofLevelValues = ["runtime-and-static", "static-signal-only"];
const traceKindValues = ["tool", "reasoning", "tool-progress", "done", "refused"];

const schemaEnumSpecs = {
  "schemas/run.artifacts.schema.json": [artifactKindSpec([["definitions", "artifact", "properties", "kind"], ["definitions", "artifact", "properties", "type"]])],
  "schemas/run.attack-surface.schema.json": attackSurfaceEnumSpecs,
  "schemas/run.context.schema.json": [routeMethodSpec([["definitions", "appRoute", "properties", "method"]])],
  "schemas/run.failures.schema.json": [
    artifactKindSpec([["definitions", "artifact", "properties", "kind"], ["definitions", "artifact", "properties", "type"]]),
    runStatusSpec([["properties", "status"], ["definitions", "failure", "properties", "status"]]),
  ],
  "schemas/run.findings.schema.json": findingEnumSpecs,
  "schemas/run.recommendations.schema.json": [{ name: "priority", path: ["definitions", "priority"], values: ["high", "medium", "low"], refs: [["definitions", "recommendation", "properties", "priority"]] }],
  "schemas/run.events.schema.json": [
    { name: "eventKind", path: ["definitions", "eventKind"], values: ["tool"], refs: [["properties", "kind"]] },
    { name: "eventStatus", path: ["definitions", "eventStatus"], values: ["started", "running", "completed", "failed", "partial", "skipped", "paused"], refs: [["properties", "status"]] },
    artifactKindSpec([["definitions", "artifact", "properties", "kind"], ["definitions", "artifact", "properties", "type"]]),
  ],
  "schemas/run.trace.schema.json": [
    { name: "traceKind", path: ["definitions", "traceKind"], values: traceKindValues, refs: [["properties", "kind"]] },
    { name: "traceSeverity", path: ["definitions", "traceSeverity"], values: ["info", "warn", "danger"], refs: [["properties", "severity"]] },
  ],
  "schemas/run.summary.schema.json": [
    runSummaryStatusSpec,
    { name: "runKind", path: ["definitions", "runKind"], values: ["run", "tool", "scan", "shell"], refs: [["properties", "kind"]] },
    { name: "llmCallKind", path: ["definitions", "llmCallKind"], values: traceKindValues, refs: [["definitions", "llmCall", "properties", "kind"]] },
    artifactKindSpec([["definitions", "artifact", "properties", "kind"], ["definitions", "artifact", "properties", "type"]]),
  ],
  "schemas/run.threat-model.schema.json": [{ name: "methodology", path: ["definitions", "methodology"], values: ["pasta", "stride", "dread"], refs: [["properties", "methodology"]] }],
  "schemas/run.proof.schema.json": [
    { name: "proofKind", path: ["definitions", "proofKind"], values: proofKindValues, refs: [["properties", "kind"]] },
    { name: "proofLevel", path: ["definitions", "proofLevel", "anyOf", 0], values: proofLevelValues, refs: [["properties", "proofLevel"], ["properties", "proof_level"]] },
    { name: "proofVerdict", path: ["definitions", "proofVerdict"], values: proofVerdictValues, refs: [["properties", "proofVerdict"], ["properties", "proof_verdict"]] },
  ],
};

for (const file of ["schemas/run.attack-surface.schema.json", "schemas/run.context.schema.json", "schemas/run.findings.schema.json", "schemas/run.proof.schema.json", "schemas/run.recommendations.schema.json", "schemas/run.threat-model.schema.json"]) {
  requiredAliasGroupsBySchema[file] = [{ path: [], kind: "declared", fields: ["runId", "run_id", "status", "runStatus"] }];
  schemaEnumSpecs[file] = [...(schemaEnumSpecs[file] ?? []), runStatusSpec([["properties", "status"], ["properties", "runStatus"]])];
}
for (const [file, fields] of Object.entries(snapshotEnvelopeFieldsBySchema)) {
  requiredAliasGroupsBySchema[file].push({ path: [], kind: "declared", fields });
}
schemaEnumSpecs["schemas/run.attack-surface.schema.json"].push(
  routeMethodSpec([["properties", "method"], ["definitions", "surface", "properties", "method"]]),
);

export function checkCanonicalRunSchemas(root) {
  return [
    ...checkSchemaInventory(root, canonicalRunSchemaFiles),
    ...canonicalRunSchemaFiles.flatMap((file) => checkSchemaFile(root, file)),
  ];
}

function checkSchemaInventory(root, expectedFiles) {
  const actualFiles = readdirSync(path.join(root, "schemas"))
    .filter((file) => /^run\..*\.schema\.json$/.test(file))
    .map((file) => `schemas/${file}`)
    .sort();
  return [
    ...missingEntries(expectedFiles, actualFiles, "missing canonical schema"),
    ...missingEntries(actualFiles, expectedFiles, "unlisted canonical schema"),
  ];
}

function missingEntries(source, allowed, label) {
  return source.filter((entry) => !allowed.includes(entry)).map((entry) => `${label}: ${entry}`);
}

function checkSchemaFile(root, relativeFile) {
  const absoluteFile = path.join(root, relativeFile);
  if (!existsSync(absoluteFile)) return [`schema contract: missing ${relativeFile}`];
  const schema = readSchema(absoluteFile);
  if (schema === null) return [`schema contract: ${relativeFile} is not parseable JSON`];
  return checkSchemaDocument(relativeFile, schema);
}

function readSchema(absoluteFile) {
  try {
    return JSON.parse(readFileSync(absoluteFile, "utf8"));
  } catch {
    return null;
  }
}

function checkSchemaDocument(relativeFile, schema) {
  const schemaName = path.basename(relativeFile);
  const expectedId = `https://kuzushi.dev/schemas/${schemaName}`;
  return [
    schema["$schema"] === "http://json-schema.org/draft-07/schema#"
      ? null
      : `${relativeFile}: missing draft-07 $schema`,
    schema["$id"] === expectedId ? null : `${relativeFile}: expected $id ${expectedId}`,
    typeof schema.title === "string" && schema.title.includes("Kuzushi")
      ? null
      : `${relativeFile}: title must identify Kuzushi`,
    schemaAcceptsObject(schema) ? null : `${relativeFile}: root type must accept object payloads`,
    isPlainObject(schema.properties) ? null : `${relativeFile}: missing root properties object`,
    ...checkRequiredAliasGroups(relativeFile, schema),
    ...checkRoutePatterns(relativeFile, schema),
    ...checkProofStateEnums(relativeFile, schema),
    ...checkProofStateRefs(relativeFile, schema),
    ...(relativeFile === "schemas/run.proof.schema.json" && ((schemaNode(schema, ["definitions", "proofLevel", "anyOf", 1])?.type !== "integer") || schemaNode(schema, ["definitions", "proofLevel", "anyOf", 1])?.minimum !== 1 || schemaNode(schema, ["definitions", "proofLevel", "anyOf", 1])?.maximum !== 4) ? [`${relativeFile}: proofLevel numeric branch must constrain integer 1..4`] : []),
    ...(relativeFile === "schemas/run.threat-model.schema.json" && (schemaNode(schema, ["properties", "dfd"])?.$ref !== "#/definitions/dfd" || !schemaNode(schema, ["definitions", "dfd", "properties", "trustBoundaries"]) || !schemaNode(schema, ["definitions", "dfd", "properties", "trust_boundaries"])) ? [`${relativeFile}: DFD schema must preserve trust-boundary aliases`] : []),
    ...(relativeFile === "schemas/run.threat-model.schema.json" && (schemaNode(schema, ["properties", "relatedCwe"])?.$ref !== "#/definitions/stringList" || schemaNode(schema, ["properties", "related_cwe"])?.$ref !== "#/definitions/stringList" || schemaNode(schema, ["properties", "cwe"])?.$ref !== "#/definitions/stringList" || schemaNode(schema, ["properties", "threats", "items"])?.$ref !== "#/definitions/threat" || schemaNode(schema, ["definitions", "threat", "properties", "relatedCwe"])?.$ref !== "#/definitions/stringList" || schemaNode(schema, ["definitions", "threat", "properties", "related_cwe"])?.$ref !== "#/definitions/stringList" || schemaNode(schema, ["definitions", "threat", "properties", "cwe"])?.$ref !== "#/definitions/stringList") ? [`${relativeFile}: threat schema must preserve related-CWE aliases`] : []),
    ...checkThreatModelNarrativeFlowAliases(relativeFile, schema),
    ...checkFieldShapeSpecs(relativeFile, schema, schemaNode),
    ...checkNamedEnums(relativeFile, schema),
  ].filter(Boolean);
}

function schemaAcceptsObject(schema) {
  if (schema.type === "object") return true;
  return Array.isArray(schema.type) && schema.type.includes("object");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function checkRequiredAliasGroups(relativeFile, schema) {
  return (requiredAliasGroupsBySchema[relativeFile] ?? []).flatMap((group) =>
    checkRequiredAliasGroup(relativeFile, schema, group),
  );
}

function checkRequiredAliasGroup(relativeFile, schema, group) {
  const node = schemaNode(schema, group.path);
  if (!isPlainObject(node)) return [`${relativeFile}: missing alias schema node ${group.path.join(".")}`];
  return [
    aliasGroupIsRequired(node, group)
      ? null
      : `${relativeFile}: missing required alias group ${group.fields.join("/")}`,
    ...missingDeclaredAliasFields(relativeFile, node, group),
  ].filter(Boolean);
}

function aliasGroupIsRequired(schema, group) {
  return group.kind === "declared" ? true : group.kind === "anyOf" ? anyOfRequiresFields(schema.anyOf, group.fields) : allOfContainsAnyOfRequirement(schema.allOf, group.fields);
}

function schemaNode(schema, nodePath) {
  return nodePath.reduce((node, segment) => {
    if (Array.isArray(node) && Number.isInteger(segment)) return node[segment];
    return isPlainObject(node) ? node[segment] : undefined;
  }, schema);
}

function allOfContainsAnyOfRequirement(allOf, fields) {
  return Array.isArray(allOf) && allOf.some((entry) => anyOfRequiresFields(entry.anyOf, fields));
}

function anyOfRequiresFields(anyOf, fields) {
  return Array.isArray(anyOf) && fields.every((field) => anyOf.some((entry) => requiredFields(entry).includes(field)));
}

function missingDeclaredAliasFields(relativeFile, schema, group) {
  if (!isPlainObject(schema.properties)) {
    return [`${relativeFile}: missing properties for alias group ${group.fields.join("/")}`];
  }
  return group.fields
    .filter((field) => !Object.hasOwn(schema.properties, field))
    .map((field) => `${relativeFile}: alias field ${field} is required but not declared`);
}

function requiredFields(schema) {
  return Array.isArray(schema?.required) ? schema.required : [];
}

function checkRoutePatterns(relativeFile, schema) {
  return (routePatternBySchema[relativeFile] ?? []).flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    return node?.pattern === "^(\\/|\\*)" ? [] : [`${relativeFile}: missing route path pattern at ${nodePath.join(".")}`];
  });
}

function checkProofStateEnums(relativeFile, schema) {
  return (proofStateEnumBySchema[relativeFile] ?? []).flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    if (!Array.isArray(node?.enum)) return [`${relativeFile}: missing proof-state enum at ${nodePath.join(".")}`];
    return missingEntries(expectedProofStates, node.enum, `${relativeFile}: missing proof-state`);
  });
}

function checkProofStateRefs(relativeFile, schema) {
  return (proofStateRefBySchema[relativeFile] ?? []).flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    return node?.$ref === "#/definitions/proofState"
      ? []
      : [`${relativeFile}: proof-state field must reference enum at ${nodePath.join(".")}`];
  });
}

function checkEnumValues(relativeFile, schema, spec) {
  const node = schemaNode(schema, spec.path);
  if (!Array.isArray(node?.enum)) return [`${relativeFile}: missing ${spec.name} enum at ${spec.path.join(".")}`];
  return missingEntries(spec.values, node.enum, `${relativeFile}: missing ${spec.name}`);
}

function checkDefinitionRefs(relativeFile, schema, spec) {
  return spec.refs.flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    return node?.$ref === `#/definitions/${spec.name}`
      ? []
      : [`${relativeFile}: ${spec.name} field must reference enum at ${nodePath.join(".")}`];
  });
}

function checkNamedEnums(relativeFile, schema) {
  return (schemaEnumSpecs[relativeFile] ?? []).flatMap((spec) => [
    ...checkEnumValues(relativeFile, schema, spec),
    ...checkDefinitionRefs(relativeFile, schema, spec),
  ]);
}
