#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const CANONICAL_WORKSPACE_IGNORE_POLICY =
  "*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n";

const REQUIRED_POLICY_PATH = "crates/kuzushi-cli/.kuzushi/.gitignore";
const CONTEXT_FIXTURES = new Set(["scripts/check-private-context.test.mjs"]);
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
const PRIVATE_ACCOUNT = PRIVATE_CONTEXT_TERMS.at(-1);
const SPARK_TERM = ["sp", "ark"].join("");
const FORBIDDEN_NAME = new RegExp(
  `(^|[^A-Za-z0-9_])(${PRIVATE_NAMES.join("|")})(?=$|[^A-Za-z0-9_])`,
  "i",
);
const SPARK_NAME = new RegExp(`(^|[^A-Za-z0-9_])${SPARK_TERM}(?=$|[^A-Za-z0-9_])`, "i");
const PRIVATE_HOME = new RegExp(`/(?:Users|home)/${PRIVATE_ACCOUNT}(?:/|$)`, "i");
const DIRECT_PUBLIC_SPARK_CONTEXT = new RegExp(
  `(?:codex[^\\n]*${SPARK_TERM}|${SPARK_TERM}[^\\n]*codex|${SPARK_TERM} java|${SPARK_TERM}\\.${SPARK_TERM}|jvm\\.${SPARK_TERM})`,
  "i",
);
const SPARK_JAVA_CONTEXT = new RegExp(`${SPARK_TERM} java`, "i");
const SPARK_ROUTE_CONTEXT = new RegExp(
  `(?:\\b${SPARK_TERM}[.:]|\\bmod ${SPARK_TERM}\\b|\\b${SPARK_TERM}_)`,
  "i",
);
const OPENAI_SPARK_CATALOG = new RegExp(
  `(?:openai-(?:codex|oauth):|gpt-[^\\s"']*codex-${SPARK_TERM})`,
  "i",
);
const OPENAI_SPARK_ALIAS = new RegExp(
  `(?:\\blet ${SPARK_TERM}\\b|\\b${SPARK_TERM}\\.(?:provider|auth)\\b|resolve_model_selector\\("${SPARK_TERM}"\\)|\\|\\s*"${SPARK_TERM}")`,
  "i",
);

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
  const forbidden = line.match(FORBIDDEN_NAME);
  if (forbidden) return `${file}:${location}: forbidden private name ${forbidden[2]}`;
  if (PRIVATE_HOME.test(line)) return `${file}:${location}: private developer home path`;
  if (SPARK_NAME.test(line) && !allowedSparkContext(file, line, source)) {
    return `${file}:${location}: unapproved standalone integration label`;
  }
  return undefined;
}

function allowedSparkContext(file, line, source) {
  if (DIRECT_PUBLIC_SPARK_CONTEXT.test(line)) return true;
  if (SPARK_JAVA_CONTEXT.test(source) && SPARK_ROUTE_CONTEXT.test(line)) {
    return true;
  }
  if (
    file.includes("workspace/attack_surface/inspect_jvm_line/routes") &&
    SPARK_ROUTE_CONTEXT.test(line)
  ) {
    return true;
  }
  return openAiSparkAliasContext(line, source);
}

function openAiSparkAliasContext(line, source) {
  return OPENAI_SPARK_CATALOG.test(source) && OPENAI_SPARK_ALIAS.test(line);
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
