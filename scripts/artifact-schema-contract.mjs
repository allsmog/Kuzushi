import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { checkFieldShapeSpecs } from "./artifact-schema-shapes.mjs";
import {
  optionalRunArtifactSpecs,
  requiredRunArtifactSpecs,
  toolInputArtifactSpecs,
  toolResultArtifactSpecs,
} from "./canonical-run-artifacts.mjs";
import { canonicalRunSchemaFiles } from "./canonical-run-schema-files.mjs";

export { canonicalRunSchemaFiles };

const artifactFieldGroups = [
  { path: ["definitions", "artifact"], kind: "required", fields: ["label", "path", "kind"] },
];
const reservedArtifactMetadataSpecs = [
  ...requiredRunArtifactSpecs,
  ...optionalRunArtifactSpecs,
  ...toolInputArtifactSpecs,
  ...toolResultArtifactSpecs,
];

const requiredAliasGroupsBySchema = {
  "schemas/run.artifacts.schema.json": [
    { path: [], kind: "required", fields: ["runId", "artifacts"] },
    ...artifactFieldGroups,
  ],
  "schemas/run.events.schema.json": [
    { path: [], kind: "required", fields: ["atUnix"] },
    ...artifactFieldGroups,
  ],
  "schemas/run.failures.schema.json": [
    { path: [], kind: "required", fields: ["runId"] },
    {
      path: ["definitions", "failure"],
      kind: "required",
      fields: ["agentThreadContext"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["failedStage"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["whatFailed"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["artifactsAvailable"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["missingArtifacts"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["allowedProofLevel"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["nextFilesOrArtifactsToInspect"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["recoveryOptions"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["fallbackPrompt"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["claimsForbidden"],
    },
    ...artifactFieldGroups,
  ],
  "schemas/run.summary.schema.json": [
    { path: [], kind: "required", fields: ["runId", "startedAtUnix"] },
    { path: [], kind: "declared", fields: ["traceMalformedLines"] },
    { path: ["definitions", "llmCall"], kind: "required", fields: ["promptHash"] },
    {
      path: ["definitions", "llmCall"],
      kind: "declared",
      fields: ["latencyMs", "costUsd"],
    },
    ...artifactFieldGroups,
  ],
  "schemas/run.trace.schema.json": [
    {
      path: [],
      kind: "declared",
      fields: [
        "latency_ms",
        "cost_usd",
        "module_id",
        "parent_step",
        "started_at_ms",
        "prompt_hash",
      ],
    },
  ],
};

const snapshotEnvelopeFieldsBySchema = {};

const routePatternBySchema = {};

const proofStateEnumBySchema = {};

const proofStateRefBySchema = {};

const expectedProofStates = [
  "signal_only",
  "code_cited",
  "source_sink_linked",
  "sanitizer_checked",
  "statically_confirmed",
  "statically_rejected",
  "needs_runtime_evidence",
  "execution_confirmed",
  "runtime_confirmed",
  "dynamic_confirmed",
  "exploit_confirmed",
  "poc_confirmed",
  "runtime_reviewed",
  "execution_attempted",
  "execution_rejected",
];

const artifactKindSpec = (refs) => ({
  name: "artifactKind",
  path: ["definitions", "artifactKind"],
  values: ["json", "jsonl", "markdown", "sarif", "directory", "artifact"],
  refs,
});
const runStatusSpec = (refs) => ({
  name: "runStatus",
  path: ["definitions", "runStatus"],
  values: ["running", "completed", "failed", "interrupted", "partial", "skipped", "paused"],
  refs,
});
const runSummaryStatusSpec = {
  name: "runSummaryStatus",
  path: ["properties", "status"],
  values: ["running", "completed", "failed", "interrupted", "partial", "skipped", "paused"],
  refs: [],
};
const traceKindValues = ["tool", "reasoning", "tool-progress", "done", "refused"];

const schemaEnumSpecs = {
  "schemas/run.artifacts.schema.json": [
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
  ],
  "schemas/run.failures.schema.json": [
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
    runStatusSpec([
      ["properties", "status"],
      ["definitions", "failure", "properties", "status"],
    ]),
  ],
  "schemas/run.events.schema.json": [
    {
      name: "eventKind",
      path: ["definitions", "eventKind"],
      values: ["tool"],
      refs: [["properties", "kind"]],
    },
    {
      name: "eventStatus",
      path: ["definitions", "eventStatus"],
      values: ["started", "running", "completed", "failed", "partial", "skipped", "paused"],
      refs: [["properties", "status"]],
    },
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
  ],
  "schemas/run.trace.schema.json": [
    {
      name: "traceKind",
      path: ["definitions", "traceKind"],
      values: traceKindValues,
      refs: [["properties", "kind"]],
    },
    {
      name: "traceSeverity",
      path: ["definitions", "traceSeverity"],
      values: ["info", "warn", "danger"],
      refs: [["properties", "severity"]],
    },
  ],
  "schemas/run.summary.schema.json": [
    runSummaryStatusSpec,
    {
      name: "runKind",
      path: ["definitions", "runKind"],
      values: ["run", "tool", "scan", "shell"],
      refs: [["properties", "kind"]],
    },
    {
      name: "llmCallKind",
      path: ["definitions", "llmCallKind"],
      values: traceKindValues,
      refs: [["definitions", "llmCall", "properties", "kind"]],
    },
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
  ],
};

for (const [file, fields] of Object.entries(snapshotEnvelopeFieldsBySchema)) {
  requiredAliasGroupsBySchema[file].push({ path: [], kind: "declared", fields });
}

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
    ...checkProofLevelNumericBranch(relativeFile, schema),
    ...checkFieldShapeSpecs(relativeFile, schema, schemaNode),
    ...checkRunArtifactManifestReservedMetadata(relativeFile, schema),
    ...checkNamedEnums(relativeFile, schema),
  ].filter(Boolean);
}

function checkProofLevelNumericBranch(relativeFile, schema) {
  void relativeFile;
  void schema;
  return [];
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
  if (!isPlainObject(node))
    return [`${relativeFile}: missing alias schema node ${group.path.join(".")}`];
  return [
    aliasGroupIsRequired(node, group)
      ? null
      : `${relativeFile}: missing required alias group ${group.fields.join("/")}`,
    ...missingDeclaredAliasFields(relativeFile, node, group),
  ].filter(Boolean);
}

function aliasGroupIsRequired(schema, group) {
  return group.kind === "declared"
    ? true
    : group.kind === "required"
      ? group.fields.every((field) => requiredFields(schema).includes(field))
      : group.kind === "anyOf"
        ? anyOfRequiresFields(schema.anyOf, group.fields)
        : allOfContainsAnyOfRequirement(schema.allOf, group.fields);
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
  return (
    Array.isArray(anyOf) &&
    fields.every((field) => anyOf.some((entry) => requiredFields(entry).includes(field)))
  );
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
    return node?.pattern === "^(\\/|\\*)"
      ? []
      : [`${relativeFile}: missing route path pattern at ${nodePath.join(".")}`];
  });
}

function checkProofStateEnums(relativeFile, schema) {
  return (proofStateEnumBySchema[relativeFile] ?? []).flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    if (!Array.isArray(node?.enum))
      return [`${relativeFile}: missing proof-state enum at ${nodePath.join(".")}`];
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
  if (!Array.isArray(node?.enum))
    return [`${relativeFile}: missing ${spec.name} enum at ${spec.path.join(".")}`];
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

function checkRunArtifactManifestReservedMetadata(relativeFile, schema) {
  if (relativeFile !== "schemas/run.artifacts.schema.json") return [];
  const rules = schemaNode(schema, ["definitions", "canonicalArtifactMetadata", "allOf"]);
  if (!Array.isArray(rules)) {
    return [`${relativeFile}: missing canonical artifact metadata rules`];
  }
  return reservedArtifactMetadataSpecs.flatMap((spec) => {
    const rule = rules.find((candidate) =>
      ruleMatchesPath(candidate, artifactPathPattern(spec.path)),
    );
    if (!rule) return [`${relativeFile}: missing reserved metadata rule for ${spec.path}`];
    return missingArtifactMetadataConsts(relativeFile, rule, spec);
  });
}

function ruleMatchesPath(rule, pattern) {
  return (
    requiredFields(rule?.if).includes("path") && rule?.if?.properties?.path?.pattern === pattern
  );
}

function missingArtifactMetadataConsts(relativeFile, rule, spec) {
  const properties = rule?.then?.properties;
  const expected = { label: spec.label, kind: spec.kind };
  return Object.entries(expected)
    .filter(([field, value]) => properties?.[field]?.const !== value)
    .map(([field]) => `${relativeFile}: reserved metadata rule for ${spec.path} must set ${field}`);
}

function artifactPathPattern(artifactPath) {
  return `(^|/)${artifactPath.replaceAll(".", "\\.")}$`;
}
