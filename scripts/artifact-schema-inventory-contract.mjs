import {
  canonicalRunSchemaFiles,
  requiredArtifactSchemaFiles,
  requiredArtifactSchemaReferences,
  schemaBackedRunArtifactSpecs,
  schemaReferenceForArtifact,
  specialArtifactSchemaReferences,
} from "./canonical-run-schema-files.mjs";

export function checkArtifactSchemaInventory() {
  const expected = requiredArtifactSchemaFiles();
  return [
    ...requiredSchemaReferenceFailures(),
    ...missingEntries(expected, canonicalRunSchemaFiles, "required artifact missing schema"),
    ...missingEntries(canonicalRunSchemaFiles, expected, "schema has no required artifact"),
    ...specialSchemaReferenceFailures(),
    ...specialSchemaMappingFailures(),
    ...defaultSchemaMappingFailures(),
  ];
}

export function checkArtifactSchemaInventoryHelpers() {
  return [
    duplicateHelperDriftFailure(),
    schemaFilePathHelperDriftFailure(),
    missingEntryHelperDriftFailure(),
    artifactPathHelperDriftFailure(),
  ].filter(Boolean);
}

function duplicateHelperDriftFailure() {
  const duplicates = duplicateEntries(
    ["run.json", "run.json", "run.json", "events.jsonl", "events.jsonl"],
    "schema inventory duplicate",
  );
  return duplicates.join("\n") ===
    "schema inventory duplicate: run.json\nschema inventory duplicate: events.jsonl"
    ? null
    : `artifact schema inventory duplicate helper drift: expected unique duplicate paths, got ${duplicates.join(", ")}`;
}

function schemaFilePathHelperDriftFailure() {
  const pathFailures = schemaFilePathFailures(
    [
      "schemas/run.summary.schema.json",
      "schemas/run.events.schema.json",
      "schemas/module.manifest.schema.json",
      "run.context.schema.json",
    ],
    "schema inventory path",
  );
  return pathFailures.join("\n") ===
    "schema inventory path: schemas/module.manifest.schema.json\nschema inventory path: run.context.schema.json"
    ? null
    : `artifact schema inventory path helper drift: got ${pathFailures.join(", ")}`;
}

function missingEntryHelperDriftFailure() {
  const missingFailures = missingEntries(
    ["schemas/run.summary.schema.json", "schemas/run.extra.schema.json"],
    ["schemas/run.summary.schema.json"],
    "schema inventory missing-entry",
  );
  return missingFailures.join("\n") ===
    "schema inventory missing-entry: schemas/run.extra.schema.json"
    ? null
    : `artifact schema inventory missing-entry helper drift: got ${missingFailures.join(", ")}`;
}

function artifactPathHelperDriftFailure() {
  const artifactPathFailures = schemaArtifactPathFailures(
    ["run.json", "events.jsonl", "nested/run.json", "report.md"],
    "schema inventory artifact path",
  );
  return artifactPathFailures.join("\n") ===
    "schema inventory artifact path: nested/run.json\nschema inventory artifact path: report.md"
    ? null
    : `artifact schema inventory artifact-path helper drift: got ${artifactPathFailures.join(", ")}`;
}

function requiredSchemaReferenceFailures() {
  const references = requiredArtifactSchemaReferences();
  return [
    ...schemaArtifactPathFailures(
      references.map(({ artifactPath }) => artifactPath),
      "required artifact schema has invalid artifact path",
    ),
    ...schemaFilePathFailures(
      references.map(({ schemaFile }) => schemaFile),
      "required artifact schema has invalid schema path",
    ),
    ...duplicateEntries(
      references.map(({ artifactPath }) => artifactPath),
      "required artifact schema duplicated artifact",
    ),
    ...duplicateEntries(
      references.map(({ schemaFile }) => schemaFile),
      "required artifact schema duplicated schema",
    ),
  ];
}

function specialSchemaReferenceFailures() {
  const schemaBackedArtifacts = new Set(
    schemaBackedRunArtifactSpecs().map((artifact) => artifact.path),
  );
  const references = specialArtifactSchemaReferences();
  return [
    ...schemaArtifactPathFailures(
      references.map(({ artifactPath }) => artifactPath),
      "special artifact schema has invalid artifact path",
    ),
    ...schemaFilePathFailures(
      references.map(({ schemaFile }) => schemaFile),
      "special artifact schema has invalid schema path",
    ),
    ...duplicateEntries(
      references.map(({ artifactPath }) => artifactPath),
      "special artifact schema duplicated artifact",
    ),
    ...duplicateEntries(
      references.map(({ schemaFile }) => schemaFile),
      "special artifact schema duplicated",
    ),
    ...references
      .filter(({ artifactPath }) => !schemaBackedArtifacts.has(artifactPath))
      .map(
        ({ artifactPath }) =>
          `special artifact schema mapping has no required schema-backed artifact: ${artifactPath}`,
      ),
  ];
}

function specialSchemaMappingFailures() {
  return specialArtifactSchemaReferences().flatMap(({ artifactPath, schemaFile }) => {
    const actual = schemaReferenceForArtifact(artifactPath)?.schemaFile;
    return actual === schemaFile
      ? []
      : [`special artifact schema mapping drift: ${artifactPath} must use ${schemaFile}`];
  });
}

function defaultSchemaMappingFailures() {
  const specialArtifacts = new Set(
    specialArtifactSchemaReferences().map(({ artifactPath }) => artifactPath),
  );
  return schemaBackedRunArtifactSpecs()
    .filter((artifact) => !specialArtifacts.has(artifact.path))
    .flatMap((artifact) => {
      const expected = `schemas/run.${artifact.path.replace(/\.jsonl?$/, "")}.schema.json`;
      const actual = schemaReferenceForArtifact(artifact.path)?.schemaFile;
      return actual === expected
        ? []
        : [`default artifact schema mapping drift: ${artifact.path} must use ${expected}`];
    });
}

function missingEntries(source, allowed, label) {
  return source.filter((entry) => !allowed.includes(entry)).map((entry) => `${label}: ${entry}`);
}

function duplicateEntries(entries, label) {
  const seen = new Set();
  const duplicates = new Set();
  for (const entry of entries) {
    if (seen.has(entry)) duplicates.add(entry);
    seen.add(entry);
  }
  return Array.from(duplicates).map((entry) => `${label}: ${entry}`);
}

function schemaFilePathFailures(schemaFiles, label) {
  return schemaFiles
    .filter((schemaFile) => !/^schemas\/run\..+\.schema\.json$/.test(schemaFile))
    .map((schemaFile) => `${label}: ${schemaFile}`);
}

function schemaArtifactPathFailures(artifactPaths, label) {
  return artifactPaths
    .filter((artifactPath) => !/^[a-z0-9][a-z0-9.-]*\.jsonl?$/.test(artifactPath))
    .map((artifactPath) => `${label}: ${artifactPath}`);
}
