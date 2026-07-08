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
  ];
}

function checkArrayConstantBodyParser() {
  const source = `
const JSON_FIXTURE_FILES: &[(&str, &str)] = &[
    ("alpha.json", "alpha fixture"),
    ("beta.json", "beta fixture"),
];
`;
  const body = rustArrayConstantBody(source, "JSON_FIXTURE_FILES");
  return body?.includes('("alpha.json", "alpha fixture")') &&
    body.includes('("beta.json", "beta fixture")')
    ? []
    : ["rust source parser: array constant body parser drift"];
}

function checkStringConstantsParser() {
  const source = `
const RUN_METADATA_FILE: &str = "run.json";
`;
  const constants = rustStringConstants(source, ["RUN_METADATA_FILE"]);
  return constants.RUN_METADATA_FILE === "run.json"
    ? []
    : ["rust source parser: string constants parser drift"];
}

function checkStringArrayConstantParser() {
  const source = `
pub(crate) const RUN_ARTIFACT_FIELDS: [&str; 3] = ["label", "path", "kind"];
`;
  const fields = rustStringArrayConstant(source, "RUN_ARTIFACT_FIELDS");
  return sameList(fields, ["label", "path", "kind"])
    ? []
    : ["rust source parser: string-array constant parser drift"];
}

function checkStringSliceConstantParser() {
  const source = `
const FOLLOW_UP_RUN_FILES: &[&str] = &["artifacts.json", "run.json"];
`;
  const aliases = rustStringArrayConstant(source, "FOLLOW_UP_RUN_FILES");
  return sameList(aliases, ["artifacts.json", "run.json"])
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

function sameList(actual, expected) {
  return Array.isArray(actual) && sameJson(actual, expected);
}

function sameJson(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}
