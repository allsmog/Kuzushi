import { readFileSync } from "node:fs";
import { rustCanonicalRunArtifactSpecs } from "./rust-source-contracts.mjs";

const artifactContractSource = readFileSync(
  new URL("../crates/kuzushi-core/src/artifact_contract.rs", import.meta.url),
  "utf8",
);

export const requiredRunArtifactSpecs = rustArtifactSpecs("CANONICAL_RUN_ARTIFACTS");
export const requiredRunArtifacts = requiredRunArtifactSpecs.map((artifact) => artifact.path);

export const optionalRunArtifactSpecs = rustArtifactSpecs("OPTIONAL_RUN_ARTIFACTS");
export const optionalRunArtifacts = optionalRunArtifactSpecs.map((artifact) => artifact.path);

export const toolResultArtifactSpecs = rustArtifactSpecs("TOOL_RESULT_ARTIFACTS");
export const toolResultArtifacts = toolResultArtifactSpecs.map((artifact) => artifact.path);

export const toolInputArtifactSpecs = rustArtifactSpecs("TOOL_INPUT_ARTIFACTS");
export const toolInputArtifacts = toolInputArtifactSpecs.map((artifact) => artifact.path);

export function checkCanonicalRunArtifactInvariants() {
  return [
    ...artifactSpecInvariantFailures("canonical run artifact", requiredRunArtifactSpecs),
    ...artifactSpecInvariantFailures("optional run artifact", optionalRunArtifactSpecs),
    ...artifactSpecInvariantFailures("tool-result artifact", toolResultArtifactSpecs),
    ...artifactSpecInvariantFailures("tool-input artifact", toolInputArtifactSpecs),
    ...artifactInventoryOverlapFailures(),
  ];
}

export function checkCanonicalRunArtifactInvariantHelpers() {
  return [
    artifactSpecInvariantRegressionFailure(),
    artifactInventoryOverlapRegressionFailure(),
  ].filter(Boolean);
}

function rustArtifactSpecs(name) {
  const specs = rustCanonicalRunArtifactSpecs(artifactContractSource, name);
  if (specs === null || specs.length === 0) {
    throw new Error(`canonical artifact contract missing Rust ${name}`);
  }
  return specs;
}

function artifactSpecInvariantRegressionFailure() {
  const duplicateSpecs = [
    { path: "bad/path.json", label: "", kind: "xml" },
    { path: "bad/path.json", label: "duplicate", kind: "json" },
  ];
  const failures = [
    ...artifactSpecInvariantFailures("canonical run artifact", duplicateSpecs),
    ...artifactSpecInvariantFailures("optional run artifact", duplicateSpecs),
    ...artifactSpecInvariantFailures("tool-result artifact", duplicateSpecs),
    ...artifactSpecInvariantFailures("tool-input artifact", duplicateSpecs),
  ];
  const expected = [
    "canonical run artifact duplicates artifact bad/path.json",
    "canonical run artifact has invalid artifact path: bad/path.json",
    "canonical run artifact has invalid artifact label: bad/path.json",
    "canonical run artifact has invalid artifact kind: bad/path.json",
    "optional run artifact duplicates artifact bad/path.json",
    "tool-result artifact duplicates artifact bad/path.json",
    "tool-input artifact duplicates artifact bad/path.json",
  ];
  return includesAll(failures, expected)
    ? null
    : `canonical artifact spec invariant helper drift: got ${failures.join(", ")}`;
}

function artifactInventoryOverlapRegressionFailure() {
  const failures = artifactInventoryOverlapFailures({
    canonical: [{ path: "shared.json" }],
    optional: [{ path: "shared.json" }],
    toolResult: [{ path: "shared.json" }],
    toolInput: [{ path: "shared.json" }],
  });
  const expected =
    "artifact shared.json appears in multiple artifact inventories: canonical, optional, toolResult, toolInput";
  return failures.includes(expected)
    ? null
    : `canonical artifact inventory overlap helper drift: got ${failures.join(", ")}`;
}

function artifactSpecInvariantFailures(label, specs) {
  const paths = specs.map((artifact) => artifact.path);
  return [
    ...duplicateEntries(paths).map((artifact) => `${label} duplicates artifact ${artifact}`),
    ...specs.flatMap((artifact) => artifactShapeFailures(label, artifact)),
  ];
}

function artifactShapeFailures(label, artifact) {
  return [
    /^[a-z0-9][a-z0-9.-]*\.(jsonl?|md|sarif)$/.test(artifact.path)
      ? null
      : `${label} has invalid artifact path: ${artifact.path}`,
    artifact.label.trim() === artifact.label && artifact.label.length > 0
      ? null
      : `${label} has invalid artifact label: ${artifact.path}`,
    ["json", "jsonl", "markdown", "sarif"].includes(artifact.kind)
      ? null
      : `${label} has invalid artifact kind: ${artifact.path}`,
  ].filter(Boolean);
}

function artifactInventoryOverlapFailures(groups = currentArtifactInventories()) {
  const locationsByArtifact = artifactLocationsByPath(groups);
  return Object.entries(locationsByArtifact)
    .filter(([, locations]) => locations.length > 1)
    .map(
      ([artifact, locations]) =>
        `artifact ${artifact} appears in multiple artifact inventories: ${locations.join(", ")}`,
    );
}

function currentArtifactInventories() {
  return {
    canonical: requiredRunArtifactSpecs,
    optional: optionalRunArtifactSpecs,
    toolResult: toolResultArtifactSpecs,
    toolInput: toolInputArtifactSpecs,
  };
}

function artifactLocationsByPath(groups) {
  const locationsByArtifact = {};
  for (const [group, specs] of Object.entries(groups)) {
    for (const spec of specs) {
      locationsByArtifact[spec.path] = [...(locationsByArtifact[spec.path] ?? []), group];
    }
  }
  return locationsByArtifact;
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

function includesAll(actual, expected) {
  return expected.every((entry) => actual.includes(entry));
}
