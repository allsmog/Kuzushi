import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  optionalRunArtifactSpecs,
  optionalRunArtifacts,
  requiredRunArtifactSpecs,
  requiredRunArtifacts,
  toolResultArtifactSpecs,
  toolResultArtifacts,
} from "./canonical-run-artifacts.mjs";

const manifestFile = "crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs";
const artifactContractFile = "crates/kuzushi-core/src/artifact_contract.rs";

export function checkCanonicalManifestInventory(root) {
  const sourcePath = path.join(root, artifactContractFile);
  if (!existsSync(sourcePath)) return [`canonical manifest inventory: missing ${artifactContractFile}`];
  const actualSpecs = artifactSpecs(readFileSync(sourcePath, "utf8"), "CANONICAL_RUN_ARTIFACTS");
  const actual = actualSpecs.map((artifact) => artifact.path).sort();
  return [
    ...missingEntries(requiredRunArtifacts, actual, "canonical manifest missing required artifact"),
    ...missingEntries(actual, requiredRunArtifacts, "canonical manifest has uncontracted artifact"),
    ...duplicateEntries(actual).map((artifact) => `canonical manifest duplicates artifact ${artifact}`),
    ...fieldMismatches(actualSpecs, "label"),
    ...kindMismatches(actualSpecs),
  ];
}

export function checkOptionalAndToolResultArtifactInventory(root) {
  const sourcePath = path.join(root, artifactContractFile);
  if (!existsSync(sourcePath)) return [`optional/tool-result inventory: missing ${artifactContractFile}`];
  const source = readFileSync(sourcePath, "utf8");
  return [
    ...specInventoryFailures(
      optionalRunArtifactSpecs,
      artifactSpecs(source, "OPTIONAL_RUN_ARTIFACTS"),
      "optional run artifact inventory",
    ),
    ...specInventoryFailures(
      toolResultArtifactSpecs,
      artifactSpecs(source, "TOOL_RESULT_ARTIFACTS"),
      "tool-result artifact inventory",
    ),
  ];
}

export function checkReportReaderInventory(root) {
  const file = "crates/kuzushi-core/src/report/application.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`report reader inventory: missing ${file}`];
  const actualSpecs = reportReaderArtifactSpecs(root, readFileSync(sourcePath, "utf8"));
  return reportReaderExpectedSpecs().flatMap((expected) =>
    reportReaderMismatches(actualSpecs, expected),
  );
}

export function checkFailureFollowUpInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/run_failures.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`failure follow-up inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const required = stringArrayConstant(source, "FOLLOW_UP_RUN_FILES");
  const actualRequiredOrder = ["failures.json", ...toolResultArtifacts, ...required];
  const allowed = [...requiredRunArtifacts, ...toolResultArtifacts, "summary.json"];
  const expectedRequiredOrder = [
    "failures.json",
    ...toolResultArtifacts,
    "artifacts.json",
    "run.json",
    "summary.json",
  ];
  return [
    ...arrayOrderMismatch(
      actualRequiredOrder,
      expectedRequiredOrder,
      "failure follow-up required order drift",
    ),
    source.includes("TOOL_RESULT_ARTIFACTS")
      ? null
      : "failure follow-up must use TOOL_RESULT_ARTIFACTS",
    source.includes("OPTIONAL_RUN_ARTIFACTS")
      ? null
      : "optional failure follow-up must use OPTIONAL_RUN_ARTIFACTS",
    source.includes('push_existing_follow_up_path(paths, &dir, report_artifact_spec().leaf)')
      ? null
      : "optional failure follow-up must use report_artifact_spec().leaf",
    source.includes("dir.join(failure_artifact_spec().leaf)")
      ? null
      : "failure follow-up must use failure_artifact_spec().leaf",
    ...missingEntries(required, allowed, "failure follow-up has uncontracted artifact"),
  ].filter(Boolean);
}

export function checkFailureMissingArtifactInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/run_failures.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`failure missing-artifact inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const shared = artifactSpecs(readFileSync(path.join(root, artifactContractFile), "utf8"), "CANONICAL_RUN_ARTIFACTS")
    .map((artifact) => artifact.path);
  return [
    source.includes("CANONICAL_FAILURE_ARTIFACTS")
      ? "failure missing-artifact inventory must not keep a local canonical list"
      : null,
    source.includes("CANONICAL_RUN_ARTIFACTS")
      ? null
      : "failure missing-artifact inventory must use CANONICAL_RUN_ARTIFACTS",
    source.includes('*artifact != "failures.json"')
      ? null
      : "failure missing-artifact inventory must exclude failures.json",
    ...missingEntries(requiredRunArtifacts, shared, "canonical run artifact leaves missing artifact"),
    ...missingEntries(shared, requiredRunArtifacts, "canonical run artifact leaves has uncontracted artifact"),
  ].filter(Boolean);
}

export function checkCanonicalSnapshotInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/canonical_run_files.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`canonical snapshot inventory: missing ${file}`];
  const actual = tupleSpecs(
    constantBody(readFileSync(sourcePath, "utf8"), "JSON_SNAPSHOT_FILES"),
    "json",
  ).map((artifact) => artifact.path);
  const expected = requiredSnapshotJsonArtifacts();
  return [
    ...missingEntries(expected, actual, "canonical snapshot writer missing artifact"),
    ...missingEntries(actual, expected, "canonical snapshot writer has uncontracted artifact"),
  ];
}

export function checkCanonicalSpecialWriterInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/canonical_run_files.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`canonical special writer inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const actual = canonicalSpecialWriterArtifacts(source);
  const expected = requiredSpecialWriterArtifacts();
  return [
    ...missingEntries(expected, actual, "canonical special writer missing artifact"),
    ...missingEntries(actual, expected, "canonical special writer has uncontracted artifact"),
  ];
}

export function checkRunMetadataWriterInventory(root) {
  const file = "crates/kuzushi-core/src/run_artifacts/run_summary_store.rs";
  const sourcePath = path.join(root, file);
  if (!existsSync(sourcePath)) return [`run metadata writer inventory: missing ${file}`];
  const source = readFileSync(sourcePath, "utf8");
  const constants = stringConstants(source, ["RUN_METADATA_FILE", "LEGACY_SUMMARY_FILE"]);
  return [
    constants.RUN_METADATA_FILE === "run.json"
      ? null
      : "run metadata writer must own run.json",
    constants.LEGACY_SUMMARY_FILE === "summary.json"
      ? null
      : "legacy summary writer must keep summary.json",
    source.includes("write_run_summary_file(&dir.join(RUN_METADATA_FILE)")
      ? null
      : "run metadata writer must write RUN_METADATA_FILE",
    source.includes("write_run_summary_file(&dir.join(LEGACY_SUMMARY_FILE)")
      ? null
      : "run metadata writer must write LEGACY_SUMMARY_FILE",
  ].filter(Boolean);
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
  const sharedSpecs = artifactSpecs(
    readFileSync(path.join(root, artifactContractFile), "utf8"),
    "CANONICAL_RUN_ARTIFACTS",
  );
  return [
    ...stringArrayConstant(source, "CANONICAL_JSON_FILES").map((artifact) =>
      sharedArtifactSpec(sharedSpecs, artifact),
    ),
    ...stringArrayConstant(source, "CANONICAL_TEXT_FILES").map((artifact) =>
      sharedArtifactSpec(sharedSpecs, artifact),
    ),
    ...(source.includes("TOOL_RESULT_ARTIFACTS") ? toolResultArtifactSpecs : []),
    ...(source.includes("OPTIONAL_RUN_ARTIFACTS") ? optionalRunArtifactSpecs : []),
  ].filter(Boolean);
}

function sharedArtifactSpec(specs, artifact) {
  return specs.find((spec) => spec.path === artifact);
}

function tupleSpecs(body, kind) {
  if (body === null) return [];
  return [...body.matchAll(/\(\s*"([^"]+)"\s*,\s*"([^"]+)"/g)].map((match) => ({
    path: match[1],
    label: match[2],
    kind,
  }));
}

function stringArrayConstant(source, name) {
  const body = constantBody(source, name);
  if (body === null) return [];
  return [...body.matchAll(/"([^"]+)"/g)].map((match) => match[1]);
}

function stringConstants(source, names) {
  return Object.fromEntries(
    names.map((name) => [name, source.match(new RegExp(`const ${name}: &str = "([^"]+)"`))?.[1]]),
  );
}

function optionalTextSpecs(body) {
  if (body === null) return [];
  return [...body.matchAll(/\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"[^"]+"/g)].map((match) => ({
    path: match[1],
    label: match[2],
    kind: match[1].endsWith(".sarif") ? "sarif" : "markdown",
  }));
}

function reportReaderExpectedSpecs() {
  return [
    ...requiredRunArtifactSpecs.filter((artifact) => artifact.path !== "report.md"),
    ...optionalRunArtifactSpecs,
    ...toolResultArtifactSpecs,
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

function artifactSpecs(source, name) {
  const body = constantBody(source, name);
  if (body === null) return [];
  return [...body.matchAll(/leaf:\s*"([^"]+)"[\s\S]*?label:\s*"([^"]+)"[\s\S]*?kind:\s*"([^"]+)"/g)].map((match) => ({
    path: match[1],
    label: match[2],
    kind: match[3],
  }));
}

function specInventoryFailures(expected, actual, label) {
  const actualPaths = actual.map((artifact) => artifact.path).sort();
  const expectedPaths = expected.map((artifact) => artifact.path);
  return [
    ...missingEntries(expectedPaths, actualPaths, `${label} missing artifact`),
    ...missingEntries(actualPaths, expectedPaths, `${label} has uncontracted artifact`),
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

function constantBody(source, name) {
  const start = source.indexOf(`const ${name}`);
  if (start === -1) return null;
  const equals = source.indexOf("=", start);
  if (equals === -1) return null;
  const open = source.indexOf("[", equals);
  if (open === -1) return null;
  const close = source.indexOf("];", open);
  return close === -1 ? null : source.slice(open, close);
}

function missingEntries(source, allowed, label) {
  return source.filter((entry) => !allowed.includes(entry)).map((entry) => `${label}: ${entry}`);
}

function duplicateEntries(entries) {
  return entries.filter((entry, index) => entries.indexOf(entry) !== index);
}

function arrayOrderMismatch(actual, expected, label) {
  return actual.join("\n") === expected.join("\n")
    ? []
    : [`${label}: expected ${expected.join(", ")}`];
}

function fieldMismatches(actualSpecs, field) {
  return requiredRunArtifactSpecs.flatMap((expected) => {
    const actual = actualSpecs.find((artifact) => artifact.path === expected.path);
    return actual && actual[field] !== expected[field]
      ? [`canonical manifest artifact ${expected.path} must have ${field} ${expected[field]}`]
      : [];
  });
}

function kindMismatches(actualSpecs) {
  return fieldMismatches(actualSpecs, "kind");
}
