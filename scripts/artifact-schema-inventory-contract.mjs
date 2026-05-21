import { requiredRunArtifactSpecs } from "./canonical-run-artifacts.mjs";
import { canonicalRunSchemaFiles } from "./canonical-run-schema-files.mjs";

const schemaByArtifact = {
  "run.json": "schemas/run.summary.schema.json",
  "artifacts.json": "schemas/run.artifacts.schema.json",
  "events.jsonl": "schemas/run.events.schema.json",
  "trace.jsonl": "schemas/run.trace.schema.json",
};

export function checkArtifactSchemaInventory() {
  const expected = requiredArtifactSchemaFiles();
  return [
    ...missingEntries(expected, canonicalRunSchemaFiles, "required artifact missing schema"),
    ...missingEntries(canonicalRunSchemaFiles, expected, "schema has no required artifact"),
  ];
}

function requiredArtifactSchemaFiles() {
  return requiredRunArtifactSpecs
    .filter((artifact) => artifact.kind === "json" || artifact.kind === "jsonl")
    .map((artifact) => schemaForArtifact(artifact.path))
    .filter(Boolean)
    .sort();
}

function schemaForArtifact(artifactPath) {
  return schemaByArtifact[artifactPath] ?? `schemas/run.${artifactPath.replace(/\.jsonl?$/, "")}.schema.json`;
}

function missingEntries(source, allowed, label) {
  return source.filter((entry) => !allowed.includes(entry)).map((entry) => `${label}: ${entry}`);
}
