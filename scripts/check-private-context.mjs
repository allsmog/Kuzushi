#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const CANONICAL_WORKSPACE_IGNORE_POLICY =
  "*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n";

const REQUIRED_POLICY_PATH = "crates/kuzushi-cli/.kuzushi/.gitignore";
const CONTEXT_FIXTURES = new Set([
  "scripts/check-private-context.mjs",
  "scripts/check-private-context.test.mjs",
]);
export const PRIVATE_CONTEXT_TERMS = [
  ["rub", "rik"].join(""),
  ["c", "dm"].join(""),
  ["r", "sc"].join(""),
  ["r", "ba"].join(""),
  ["pol", "aris"].join(""),
  ["glass", "wing"].join(""),
  ["my", "thos"].join(""),
  ["shaya", "unnejad"].join(""),
];
const PRIVATE_NAMES = PRIVATE_CONTEXT_TERMS.slice(0, -1);
const SPARK_TERM = ["sp", "ark"].join("");
const PRIVATE_NAME_PREFIX = new RegExp(`(^|[^A-Za-z0-9])(${PRIVATE_NAMES.join("|")})`, "gi");
const PRIVATE_LONG_NAME_CAMEL = new RegExp(
  `(${PRIVATE_NAMES.filter((name) => name.length > 3)
    .map(caseInsensitivePattern)
    .join("|")})(?=[A-Z])`,
);
const PRIVATE_SHORT_NAME_CAMEL = new RegExp(
  `(${PRIVATE_NAMES.filter((name) => name.length === 3)
    .map(caseInsensitivePattern)
    .join("|")})(?=[A-Z][a-z])`,
);
const SPARK_NAME = new RegExp(`(^|[^A-Za-z0-9])${SPARK_TERM}(?=$|[^A-Za-z0-9])`, "i");
const PRIVATE_HOME_ACCOUNT = `${["shaya", "un"].join("")}[._-]?${["ne", "jad"].join("")}`;
const PRIVATE_HOME = new RegExp(`/(?:Users|home)/${PRIVATE_HOME_ACCOUNT}(?:/|$)`, "i");
const PUBLIC_SPARK_SPAN = new RegExp(
  `(?:apache ${SPARK_TERM}|openai(?: codex)? ${SPARK_TERM}|openai(?: oauth)? gpt-[0-9A-Za-z.-]+ codex ${SPARK_TERM}|${SPARK_TERM}[-_ ]java|${SPARK_TERM}\\.${SPARK_TERM}|jvm\\.${SPARK_TERM}|${SPARK_TERM}_glyphs)`,
  "gi",
);
const SPARK_ROUTE_CONTEXT = new RegExp(
  `(?:/${SPARK_TERM}\\.rs|\\bmod ${SPARK_TERM}\\b|\\b${SPARK_TERM}::|\\b${SPARK_TERM}_static_routes\\b|\\binspect_${SPARK_TERM}_route(?:_line)?\\b|\\b${SPARK_TERM}_route_method\\b|\\b${SPARK_TERM}_static_(?:route|filter)_method\\b)`,
  "gi",
);
const SPARK_JAVA_ROUTE_CALL = new RegExp(
  `(?:^|[^A-Za-z0-9])${SPARK_TERM}\\.(?:get|post|put|patch|delete|head|options|before|after)\\(`,
  "gi",
);
const OPENAI_SPARK_CATALOG = new RegExp(
  `(?:openai-(?:codex|oauth):)?gpt-[^\\s"']*codex-${SPARK_TERM}`,
  "i",
);
const OPENAI_SPARK_CATALOG_SPAN = new RegExp(OPENAI_SPARK_CATALOG.source, "gi");
const OPENAI_SPARK_ALIAS = new RegExp(
  `(?:\\blet ${SPARK_TERM}\\b|\\b${SPARK_TERM}\\.(?:provider|auth)\\b|resolve_model_selector\\("${SPARK_TERM}"\\)|\\|\\s*"${SPARK_TERM}"|OpenAI OAuth GPT-5\\.3 Codex ${SPARK_TERM}|Codex ${SPARK_TERM} catalog row|codex_oauth_selectors_expose_gpt_5_4_and_${SPARK_TERM}_without_legacy_provider_aliases)`,
  "gi",
);
const OPENAI_SPARK_MODEL_FILES = new Set([
  "crates/kuzushi-tui/src/app/settings/model_choices.rs",
  "crates/kuzushi-tui/src/app/settings/normalize_thinking_level/model_selectors.rs",
  "crates/kuzushi-tui/src/app/settings/tests.rs",
  "crates/kuzushi-tui/src/ui_view_models/config/tests.rs",
]);

export function scanRepository(root = process.cwd()) {
  const files = trackedFiles(root);
  const failures = requiredPolicyFailures(root, files);
  for (const file of files) {
    failures.push(...trackedFileFailures(root, file));
  }
  return failures;
}

function trackedFileFailures(root, file) {
  if (CONTEXT_FIXTURES.has(file)) return [];
  return [...workspaceStateFailures(file), ...trackedTextFailures(root, file)];
}

function workspaceStateFailures(file) {
  const stateFailure = trackedWorkspaceStateFailure(file);
  return stateFailure ? [stateFailure] : [];
}

function trackedTextFailures(root, file) {
  const bytes = readFileSync(path.join(root, file));
  return bytes.includes(0) ? [] : textContextFailures(file, bytes.toString("utf8"));
}

export function textContextFailures(file, source) {
  const failures = [];
  const pathFailure = lineContextFailure(file, file, source, "path");
  if (pathFailure) failures.push(pathFailure);
  for (const [index, line] of source.split("\n").entries()) {
    const failure = lineContextFailure(file, line, source, String(index + 1));
    if (failure) failures.push(failure);
  }
  return failures;
}

export function trackedWorkspaceStateFailure(file) {
  const marker = ".kuzushi/";
  const index = file.indexOf(marker);
  if (index < 0) return undefined;
  const relative = file.slice(index + marker.length);
  if (isTrackableWorkspaceState(relative)) return undefined;
  return `${file}: generated or private workspace state must not be tracked`;
}

export function workspacePolicyFailures(source) {
  return source === CANONICAL_WORKSPACE_IGNORE_POLICY
    ? []
    : ["workspace child ignore policy must match Kuzushi's canonical trackability contract"];
}

function lineContextFailure(file, line, source, location) {
  const forbidden = forbiddenPrivateName(line);
  if (forbidden) return `${file}:${location}: forbidden private name ${forbidden}`;
  if (PRIVATE_HOME.test(line)) return `${file}:${location}: private developer home path`;
  if (SPARK_NAME.test(line) && !allowedSparkContext(file, line, source)) {
    return `${file}:${location}: unapproved standalone integration label`;
  }
  return undefined;
}

function forbiddenPrivateName(line) {
  for (const match of line.matchAll(PRIVATE_NAME_PREFIX)) {
    const name = match[2];
    const suffix = line.slice((match.index ?? 0) + match[1].length + name.length);
    if (!isPublicPrefixOverlap(name, suffix)) return name;
  }
  return line.match(PRIVATE_LONG_NAME_CAMEL)?.[1] ?? line.match(PRIVATE_SHORT_NAME_CAMEL)?.[1];
}

function isPublicPrefixOverlap(name, suffix) {
  const normalized = name.toLowerCase();
  if (normalized === ["r", "ba"].join("")) {
    return /^c(?=$|[^A-Za-z0-9]|[A-Z])/i.test(suffix);
  }
  if (normalized === ["pol", "aris"].join("")) {
    return /^(?:e[ds]?|ing|ation(?:s)?)\b/i.test(suffix);
  }
  if (normalized === ["c", "dm"].join("")) {
    return /^a(?=$|[^A-Za-z0-9])/i.test(suffix);
  }
  return false;
}

function caseInsensitivePattern(term) {
  return [...term]
    .map((character) => `[${character.toLowerCase()}${character.toUpperCase()}]`)
    .join("");
}

function allowedSparkContext(file, line, source) {
  const patterns = [PUBLIC_SPARK_SPAN, OPENAI_SPARK_CATALOG_SPAN, SPARK_JAVA_ROUTE_CALL];
  if (file.includes("workspace/attack_surface/inspect_jvm_line/routes")) {
    patterns.push(SPARK_ROUTE_CONTEXT);
  }
  if (openAiSparkAliasContext(file, source)) patterns.push(OPENAI_SPARK_ALIAS);
  return !SPARK_NAME.test(maskMatches(line, patterns));
}

function openAiSparkAliasContext(file, source) {
  return OPENAI_SPARK_MODEL_FILES.has(file) && OPENAI_SPARK_CATALOG.test(source);
}

function maskMatches(line, patterns) {
  return patterns.reduce(
    (remainder, pattern) => remainder.replace(pattern, (match) => " ".repeat(match.length)),
    line,
  );
}

function isTrackableWorkspaceState(relative) {
  return (
    relative === ".gitignore" ||
    relative === "scope.toml" ||
    relative === "v3/config.toml" ||
    relative.startsWith("prompts/")
  );
}

function requiredPolicyFailures(root, files) {
  if (!files.includes(REQUIRED_POLICY_PATH)) {
    return [`${REQUIRED_POLICY_PATH}: canonical child ignore policy must be tracked`];
  }
  return workspacePolicyFailures(readFileSync(path.join(root, REQUIRED_POLICY_PATH), "utf8"));
}

function trackedFiles(root) {
  const bytes = execFileSync("git", ["-C", root, "ls-files", "-z"]);
  return bytes.toString("utf8").split("\0").filter(Boolean);
}

function main() {
  const failures = scanRepository();
  if (failures.length === 0) {
    process.stdout.write("Private-context check passed.\n");
    return;
  }
  process.stderr.write("Private-context check failed:\n");
  for (const failure of failures) process.stderr.write(`- ${failure}\n`);
  process.exitCode = 1;
}

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) main();
