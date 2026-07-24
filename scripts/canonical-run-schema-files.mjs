import { requiredRunArtifactSpecs } from "./canonical-run-artifacts.mjs";

const schemaByArtifact = {
  "run.json": "schemas/run.summary.schema.json",
  "artifacts.json": "schemas/run.artifacts.schema.json",
  "events.jsonl": "schemas/run.events.schema.json",
  "items.jsonl": "schemas/run.items.schema.json",
};

export const canonicalRunSchemaFiles = requiredArtifactSchemaFiles();

export function specialArtifactSchemaReferences() {
  return Object.entries(schemaByArtifact).map(([artifactPath, schemaFile]) => ({
    artifactPath,
    schemaFile,
  }));
}

export function schemaBackedRunArtifactSpecs() {
  return requiredRunArtifactSpecs.filter(
    (artifact) => artifact.kind === "json" || artifact.kind === "jsonl",
  );
}

export function requiredArtifactSchemaReferences() {
  return schemaBackedRunArtifactSpecs()
    .map((artifact) => ({
      artifactPath: artifact.path,
      schemaFile: schemaForArtifact(artifact.path),
    }))
    .filter((reference) => reference.schemaFile)
    .sort((left, right) => left.schemaFile.localeCompare(right.schemaFile));
}

export function requiredArtifactSchemaFiles() {
  return requiredArtifactSchemaReferences().map((reference) => reference.schemaFile);
}

export function schemaReferenceForArtifact(artifactPath) {
  return requiredArtifactSchemaReferences().find(
    (reference) => reference.artifactPath === artifactPath,
  );
}

function schemaForArtifact(artifactPath) {
  return (
    schemaByArtifact[artifactPath] ??
    `schemas/run.${artifactPath.replace(/\.jsonl?$/, "")}.schema.json`
  );
}
