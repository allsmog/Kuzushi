import { readFileSync } from "node:fs";
import {
  artifactAliasFields,
  artifactKindAliasFields,
  artifactLabelAliasFields,
  artifactPathAliasFields,
} from "./canonical-run-artifacts.mjs";
import {
  rustArrayConstantBody,
  rustCanonicalRunArtifactSpecs,
  rustFunctionBody,
  rustStringArrayConstant,
  rustStringConstants,
} from "./rust-source-contracts.mjs";

export function checkRustSourceContractParsers() {
  return [
    ...checkStringArrayConstantParser(),
    ...checkStringSliceConstantParser(),
    ...checkArrayConstantBodyParser(),
    ...checkStringConstantsParser(),
    ...checkCanonicalArtifactSpecParser(),
    ...checkFunctionBodyParser(),
    ...checkSharedArtifactAliasExports(),
  ];
}

function checkArrayConstantBodyParser() {
  const source = `
const JSON_SNAPSHOT_FILES: &[(&str, &str)] = &[
    ("context.json", "empty context snapshot"),
    ("findings.json", "empty findings"),
];
`;
  const body = rustArrayConstantBody(source, "JSON_SNAPSHOT_FILES");
  return body?.includes('("context.json", "empty context snapshot")') &&
    body.includes('("findings.json", "empty findings")')
    ? []
    : ["rust source parser: array constant body parser drift"];
}

function checkStringConstantsParser() {
  const source = `
const LEGACY_SUMMARY_FILE: &str = "summary.json";
const RUN_METADATA_FILE: &str = "run.json";
`;
  const constants = rustStringConstants(source, ["RUN_METADATA_FILE", "LEGACY_SUMMARY_FILE"]);
  return constants.RUN_METADATA_FILE === "run.json" &&
    constants.LEGACY_SUMMARY_FILE === "summary.json"
    ? []
    : ["rust source parser: string constants parser drift"];
}

function checkStringArrayConstantParser() {
  const source = `
pub(crate) const ARTIFACT_PATH_KEYS: [&str; 3] = [
    "path",
    "file_path",
    "prompts_dir",
];
`;
  const aliases = rustStringArrayConstant(source, "ARTIFACT_PATH_KEYS");
  return sameList(aliases, ["path", "file_path", "prompts_dir"])
    ? []
    : ["rust source parser: string-array constant parser drift"];
}

function checkStringSliceConstantParser() {
  const source = `
const FOLLOW_UP_RUN_FILES: &[&str] = &["artifacts.json", "run.json", "summary.json"];
`;
  const aliases = rustStringArrayConstant(source, "FOLLOW_UP_RUN_FILES");
  return sameList(aliases, ["artifacts.json", "run.json", "summary.json"])
    ? []
    : ["rust source parser: string-slice constant parser drift"];
}

function checkCanonicalArtifactSpecParser() {
  const source = `
pub(crate) const CANONICAL_RUN_ARTIFACTS: [CanonicalRunArtifactSpec; 2] = [
    CanonicalRunArtifactSpec {
        leaf: "run.json",
        label: "run metadata",
        kind: "json",
    },
    CanonicalRunArtifactSpec { leaf: "report.md", label: "report", kind: "markdown" },
];
`;
  const specs = rustCanonicalRunArtifactSpecs(source, "CANONICAL_RUN_ARTIFACTS");
  const expected = [
    { path: "run.json", label: "run metadata", kind: "json" },
    { path: "report.md", label: "report", kind: "markdown" },
  ];
  return sameJson(specs, expected)
    ? []
    : ["rust source parser: canonical artifact spec parser drift"];
}

function checkFunctionBodyParser() {
  const body = rustFunctionBody("fn outer() { if true { call(); } }", "outer");
  return body === "{ if true { call(); } }"
    ? []
    : ["rust source parser: function-body parser drift"];
}

function checkSharedArtifactAliasExports() {
  const source = readFileSync(
    new URL("../crates/kuzushi-core/src/artifact_contract.rs", import.meta.url),
    "utf8",
  );
  const labels = rustStringArrayConstant(source, "ARTIFACT_LABEL_KEYS") ?? [];
  const paths = rustStringArrayConstant(source, "ARTIFACT_PATH_KEYS") ?? [];
  const kinds = rustStringArrayConstant(source, "ARTIFACT_KIND_KEYS") ?? [];
  const expectedCombined = [...labels, ...paths, ...kinds];
  return [
    sameList(artifactLabelAliasFields, labels)
      ? null
      : "rust source parser: shared label alias export drift",
    sameList(artifactPathAliasFields, paths)
      ? null
      : "rust source parser: shared path alias export drift",
    sameList(artifactKindAliasFields, kinds)
      ? null
      : "rust source parser: shared kind alias export drift",
    sameList(artifactAliasFields, expectedCombined)
      ? null
      : "rust source parser: combined artifact alias export drift",
  ].filter(Boolean);
}

function sameList(actual, expected) {
  return Array.isArray(actual) && sameJson(actual, expected);
}

function sameJson(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}
