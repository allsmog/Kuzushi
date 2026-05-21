import { readFileSync } from "node:fs";
import path from "node:path";

const failureArrayLimit = 12;
const boundedFailureArrays = [
  "properties.failures",
  "definitions.failureContext.properties.artifactsAvailable",
  "definitions.failureContext.properties.artifacts_available",
  "definitions.failureContext.properties.missingArtifacts",
  "definitions.failureContext.properties.missing_artifacts",
  "definitions.failureContext.properties.nextFilesOrArtifactsToInspect",
  "definitions.failureContext.properties.next_files_or_artifacts_to_inspect",
  "definitions.failureContext.properties.recoveryOptions",
  "definitions.failureContext.properties.recovery_options",
  "definitions.failureContext.properties.claimsForbidden",
  "definitions.failureContext.properties.claims_forbidden",
];

const nonEmptyFailureStrings = [
  "definitions.failureContext.properties.failedStage",
  "definitions.failureContext.properties.failed_stage",
  "definitions.failureContext.properties.cause",
  "definitions.failureContext.properties.whatFailed",
  "definitions.failureContext.properties.what_failed",
  "definitions.failureContext.properties.allowedProofLevel",
  "definitions.failureContext.properties.allowed_proof_level",
  "definitions.failureContext.properties.fallbackPrompt",
  "definitions.failureContext.properties.fallback_prompt",
];

const nonEmptyFailureArrayItems = [
  "definitions.failureContext.properties.missingArtifacts",
  "definitions.failureContext.properties.missing_artifacts",
  "definitions.failureContext.properties.nextFilesOrArtifactsToInspect",
  "definitions.failureContext.properties.next_files_or_artifacts_to_inspect",
  "definitions.failureContext.properties.recoveryOptions",
  "definitions.failureContext.properties.recovery_options",
  "definitions.failureContext.properties.claimsForbidden",
  "definitions.failureContext.properties.claims_forbidden",
];

export function checkFailureSchemaBounds(root) {
  const schema = JSON.parse(
    readFileSync(path.join(root, "schemas/run.failures.schema.json"), "utf8"),
  );
  return [
    ...boundedFailureArrays.flatMap((nodePath) =>
      failureArrayBound(schema, nodePath) === failureArrayLimit
        ? []
        : [`run.failures schema: ${nodePath} must set maxItems ${failureArrayLimit}`],
    ),
    ...nonEmptyFailureStrings.flatMap((nodePath) =>
      failureStringMinLength(schema, nodePath) === 1
        ? []
        : [`run.failures schema: ${nodePath} must set minLength 1`],
    ),
    ...nonEmptyFailureArrayItems.flatMap((nodePath) =>
      failureArrayItemMinLength(schema, nodePath) === 1
        ? []
        : [`run.failures schema: ${nodePath}.items must set minLength 1`],
    ),
  ];
}

function failureArrayBound(schema, nodePath) {
  return nodePath
    .split(".")
    .reduce((node, segment) => node?.[segment], schema)?.maxItems;
}

function failureStringMinLength(schema, nodePath) {
  return schemaNode(schema, nodePath)?.minLength;
}

function failureArrayItemMinLength(schema, nodePath) {
  return schemaNode(schema, nodePath)?.items?.minLength;
}

function schemaNode(schema, nodePath) {
  return nodePath.split(".").reduce((node, segment) => node?.[segment], schema);
}
