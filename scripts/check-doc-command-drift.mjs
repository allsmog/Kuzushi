#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const repo = process.cwd();
const packageScripts = new Set(
  Object.keys(JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8")).scripts ?? {}),
);

const roots = [
  "README.md",
  "CONTRIBUTING.md",
  "ROADMAP.md",
  "docs",
  "examples",
  ".github",
  "AGENTS.md",
  "CLAUDE.md",
  "RELEASING.md",
];

const textExtensions = new Set([
  ".md",
  ".mjs",
  ".js",
  ".ts",
  ".json",
  ".jsonc",
  ".yml",
  ".yaml",
  ".sh",
  ".txt",
  ".mmd",
]);

const banned = [
  { label: "--preset", regex: /--preset\b/g, needsKuzushiContext: true },
  // --sarif was retired with the TS CLI and banned here; it is a real flag
  // again as of `kuzushi scan --sarif <path>` (Rust CLI), so it is allowed.
  { label: "--verify", regex: /--verify\b/g, needsKuzushiContext: true },
  { label: "--junit", regex: /--junit\b/g, needsKuzushiContext: true },
  { label: "--output", regex: /--output\b/g, needsKuzushiContext: true },
  { label: "--quality-gate", regex: /--quality-gate\b/g, needsKuzushiContext: true },
  { label: "--fail-on-tp", regex: /--fail-on-tp\b/g, needsKuzushiContext: true },
  { label: "--stream", regex: /--stream\b/g, needsKuzushiContext: true },
  { label: "kuzushi-ts", regex: /kuzushi-ts/g },
  { label: "pnpm dev:ts", regex: /pnpm dev:ts/g },
  { label: "scripts/kuzushi-dev", regex: /scripts\/kuzushi-dev/g },
  { label: "TypeScript/Ink", regex: /TypeScript\/Ink/g },
  { label: "kuzushi create-module", regex: /kuzushi\s+create-module/g },
];

const currentGuidanceFiles = [
  "AGENTS.md",
  "CLAUDE.md",
  "CONTRIBUTING.md",
  "docs/architecture/domain-boundaries.md",
  "docs/current-architecture.mmd",
  "docs/devex/new-contributor-map.md",
];

const modelGuidanceFiles = currentGuidanceFiles;

const packageScriptGuidanceFiles = ["CONTRIBUTING.md", ".github/PULL_REQUEST_TEMPLATE.md"];
const pnpmCommandsWithoutScripts = new Set(["exec", "install"]);

const staleSplitPathPatterns = [
  { label: "deleted TS Copilot core path", regex: /src\/copilot\/core\.ts/ },
  { label: "deleted TS core-sast path", regex: /src\/modules\/core-sast\.ts/ },
  { label: "deleted TS MCP bridge path", regex: /src\/modules\/mcp-bridge\.ts/ },
  { label: "deleted TS hidden DAG node path", regex: /src\/modules\/hidden-dag-node\.ts/ },
  { label: "deleted TS scan bootstrap path", regex: /src\/agents\/index\.ts/ },
  { label: "deleted TS scan pipeline path", regex: /src\/cli\/commands\/scan-pipeline\.ts/ },
  { label: "old modules.rs path", regex: /crates\/kuzushi-core\/src\/modules\.rs/ },
  { label: "old findings.rs path", regex: /crates\/kuzushi-core\/src\/findings\.rs/ },
  { label: "old scan.rs path", regex: /crates\/kuzushi-core\/src\/scan\.rs/ },
  { label: "old TUI app.rs path", regex: /crates\/kuzushi-tui\/src\/app\.rs/ },
  {
    label: "old TUI state_transitions.rs path",
    regex: /crates\/kuzushi-tui\/src\/app\/state_transitions\.rs/,
  },
  {
    label: "old TUI commands.rs path",
    regex: /crates\/kuzushi-tui\/src\/commands\.rs/,
  },
  { label: "old TUI renderer.rs path", regex: /crates\/kuzushi-tui\/src\/renderer\.rs/ },
  {
    label: "old TUI renderer/plain.rs path",
    regex: /crates\/kuzushi-tui\/src\/renderer\/plain\.rs/,
  },
  {
    label: "old core builtins execution path",
    regex: /(^|[^/\w.-])src\/modules\/registry\/with_v2_builtins\/execution\.rs/,
  },
  {
    label: "old traced runtime path",
    regex: /(^|[^/\w.-])src\/runtime\/traced_runtime\.rs/,
  },
];

const staleModelPathPatterns = [
  { label: "deleted TS model enforcement path", regex: /src\/agent-runtime\/enforcement\.ts/ },
];

const allowedContext =
  /\b(legacy|historical|removed|unsupported|not current|does not support|does not expose|do not use|do not add|do not resurrect|deleted|reference-only|preserved reference|retained TypeScript\/Ink references|old TypeScript|former TypeScript)\b/i;

const failures = [
  ...currentGuidanceFiles.flatMap((file) =>
    checkCurrentGuidancePaths(file, staleSplitPathPatterns),
  ),
  ...modelGuidanceFiles.flatMap((file) => checkCurrentGuidancePaths(file, staleModelPathPatterns)),
];

failures.push(...currentGuidanceFiles.flatMap(checkReferencedRepoPaths));
failures.push(...packageScriptGuidanceFiles.flatMap(checkPackageScriptReferences));
failures.push(...canonicalContributorFailures());
failures.push(...canonicalReadmeFailures());
failures.push(...canonicalRoadmapFailures());
failures.push(...canonicalProductFlowPrdFailures());
failures.push(...canonicalParityTestFailures());
failures.push(...canonicalDependencyPolicyFailures());

for (const file of roots.flatMap(walk)) {
  const rel = path.relative(repo, file);
  const text = readFileSync(file, "utf8");
  const lines = text.split(/\r?\n/);
  const header = lines.slice(0, 12).join("\n");
  const fileLabeledLegacy = allowedContext.test(header);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    for (const pattern of banned) {
      pattern.regex.lastIndex = 0;
      if (!pattern.regex.test(line)) continue;

      const context = lines
        .slice(Math.max(0, index - 4), Math.min(lines.length, index + 5))
        .join("\n");
      const hasKuzushiContext = /(^|[\s`'"|])kuzushi(\s|$)/i.test(context);
      const explicitlyAllowed = fileLabeledLegacy || allowedContext.test(context);

      if (pattern.needsKuzushiContext && !hasKuzushiContext) {
        continue;
      }
      if (explicitlyAllowed) {
        continue;
      }

      failures.push({
        file: rel,
        line: index + 1,
        pattern: pattern.label,
        text: line.trim(),
      });
    }
  }
}

if (failures.length > 0) {
  console.error("Stale Kuzushi public command examples found:");
  for (const failure of failures) {
    console.error(`- ${failure.file}:${failure.line} ${failure.pattern}: ${failure.text}`);
  }
  console.error(
    "\nFix the command, or label the surrounding section as legacy/historical/unsupported if it is not current operator guidance.",
  );
  process.exit(1);
}

console.log("doc command drift check passed");

function walk(root) {
  if (isHistoricalDoc(root)) return [];
  const abs = path.join(repo, root);
  return walkEntry(root, abs, safeStat(abs));
}

// docs/notes/ holds historical working notes and docs/PORT_PLAN.md is the
// upstream-port ledger; neither is current operator guidance.
function isHistoricalDoc(root) {
  return root === "docs/notes" || root.startsWith("docs/notes/") || root === "docs/PORT_PLAN.md";
}

function walkEntry(root, abs, stats) {
  if (stats === null) return [];
  if (stats.isFile()) return scannedFile(abs);
  if (!stats.isDirectory()) return [];
  return walkDirectory(root, abs);
}

function safeStat(abs) {
  try {
    return statSync(abs);
  } catch {
    return null;
  }
}

function scannedFile(abs) {
  return shouldScan(abs) ? [abs] : [];
}

function walkDirectory(root, abs) {
  const out = [];
  for (const entry of readdirSync(abs)) {
    if (entry === "node_modules" || entry === ".kuzushi") continue;
    out.push(...walk(path.join(root, entry)));
  }
  return out;
}

function shouldScan(file) {
  return textExtensions.has(path.extname(file));
}

function checkCurrentGuidancePaths(file, patterns) {
  const abs = path.join(repo, file);
  const lines = readFileSync(abs, "utf8").split(/\r?\n/);
  return lines.flatMap((line, index) => stalePathFailures(file, line, index, patterns));
}

function stalePathFailures(file, line, index, patterns) {
  return patterns
    .filter((pattern) => pattern.regex.test(line))
    .map((pattern) => ({
      file,
      line: index + 1,
      pattern: pattern.label,
      text: line.trim(),
    }));
}

function checkReferencedRepoPaths(file) {
  const abs = path.join(repo, file);
  const lines = readFileSync(abs, "utf8").split(/\r?\n/);
  const header = lines.slice(0, 12).join("\n");
  const fileLabeledLegacy = allowedContext.test(header);
  if (fileLabeledLegacy) return [];
  return lines.flatMap((line, index) => referencedPathFailures(file, lines, line, index));
}

function checkPackageScriptReferences(file) {
  const lines = readFileSync(path.join(repo, file), "utf8").split(/\r?\n/);
  const failures = [];
  let inShellBlock = false;
  for (let index = 0; index < lines.length; index += 1) {
    const fence = lines[index].match(/^\s*```([A-Za-z]*)/);
    if (fence) {
      inShellBlock = ["sh", "bash", "shell"].includes(fence[1]);
      continue;
    }
    failures.push(...missingPackageScriptFailures(file, lines[index], index, inShellBlock));
  }
  return failures;
}

function missingPackageScriptFailures(file, line, index, allowBare) {
  return pnpmScriptReferences(line, allowBare)
    .filter((script) => !pnpmCommandsWithoutScripts.has(script) && !packageScripts.has(script))
    .map((script) => ({
      file,
      line: index + 1,
      pattern: "missing package script",
      text: `pnpm ${script}`,
    }));
}

function pnpmScriptReferences(line, allowBare) {
  const scripts = [];
  const regex = /\bpnpm\s+(?:run\s+)?([A-Za-z0-9][A-Za-z0-9:._-]*)/g;
  for (const match of line.matchAll(regex)) {
    if (isCommandReference(line, match.index, allowBare)) scripts.push(match[1]);
  }
  return scripts;
}

function isCommandReference(line, index, allowBare) {
  const prefix = line.slice(0, index);
  return prefix.endsWith("`") || (allowBare && /^\s*(?:[$>]\s*)?$/.test(prefix));
}

function referencedPathFailures(file, lines, line, index) {
  const context = lines.slice(Math.max(0, index - 4), Math.min(lines.length, index + 5)).join("\n");
  if (allowedContext.test(context)) return [];
  return referencedRepoPaths(line)
    .map((reference) => missingRepoPathFailure(file, index, reference))
    .filter(Boolean);
}

function missingRepoPathFailure(file, index, reference) {
  if (reference.includes("*")) return null;
  if (safeStat(path.join(repo, reference)) !== null) return null;
  return {
    file,
    line: index + 1,
    pattern: "missing repo path",
    text: reference,
  };
}

function referencedRepoPaths(line) {
  const out = new Set();
  const regex = /(?:^|[\s`'"[(])((?:crates|src)\/[A-Za-z0-9._~:+@%/-]+)/g;
  for (const match of line.matchAll(regex)) {
    out.add(cleanReferencedPath(match[1]));
  }
  return [...out].filter(Boolean);
}

function cleanReferencedPath(value) {
  return value
    .replace(/::[A-Za-z0-9_:]+$/, "")
    .replace(/(?::\d+(?:-\d+)?)$/, "")
    .replace(/[),.;\]}]+$/, "");
}

function canonicalContributorFailures() {
  const file = "CONTRIBUTING.md";
  const text = readFileSync(path.join(repo, file), "utf8");
  return [
    requiredDocTextFailure(file, text, "pnpm dev -- --target", "Rust shell development command"),
    requiredDocTextFailure(file, text, "cargo test --workspace", "native workspace test command"),
    requiredDocTextFailure(
      file,
      text,
      "crates/kuzushi-core/src/modules/",
      "Rust built-in module path",
    ),
    forbiddenDocTextFailure(file, text, "run the CLI in dev mode (tsx)", "retired TSX runtime"),
    forbiddenDocTextFailure(file, text, "src/agents/tasks/", "retired agent-task path"),
    forbiddenDocTextFailure(file, text, "src/agents/index.ts", "retired agent registry path"),
  ].filter(Boolean);
}

function canonicalReadmeFailures() {
  const file = "README.md";
  const text = readFileSync(path.join(repo, file), "utf8");
  return [
    requiredDocTextFailure(file, text, "Published compatibility SDK source", "retained SDK role"),
    forbiddenDocTextFailure(file, text, "`src/agents/`", "deleted TS agents path"),
    forbiddenDocTextFailure(file, text, "scanner normalization", "deleted TS scanner runtime"),
  ].filter(Boolean);
}

function canonicalRoadmapFailures() {
  const file = "ROADMAP.md";
  const text = readFileSync(path.join(repo, file), "utf8");
  return [
    requiredDocTextFailure(file, text, "--fail-on <severity>", "implemented CI severity gate"),
    requiredDocTextFailure(file, text, "--sarif <path>", "implemented SARIF export"),
    requiredDocTextFailure(file, text, "kuzushi demo", "implemented offline demo"),
    forbiddenDocTextFailure(file, text, "registry = retired 0.20.0", "retired npm release claim"),
    forbiddenDocTextFailure(file, text, "repo is 0.24.0-alpha.0", "stale repository version"),
    forbiddenDocTextFailure(file, text, "`--ci` is output-format only", "stale CI gate claim"),
    forbiddenDocTextFailure(file, text, "CLI-unreachable", "stale SARIF reachability claim"),
    forbiddenDocTextFailure(file, text, "currently unstated", "stale privacy documentation claim"),
    forbiddenDocTextFailure(file, text, "today: silent 0 findings", "stale scan output claim"),
    forbiddenDocTextFailure(file, text, "1,529 LOC, 0 tests", "stale route-test claim"),
    requiredDocTextFailure(
      file,
      text,
      "workspace/inventory/tests.rs",
      "route inventory integration-test path",
    ),
  ].filter(Boolean);
}

function canonicalProductFlowPrdFailures() {
  const file = "docs/plans/product-flow-prd.md";
  const text = readFileSync(path.join(repo, file), "utf8");
  const required = productFlowRequiredText().map(([needle, label]) =>
    requiredDocTextFailure(file, text, needle, label),
  );
  const forbidden = productFlowForbiddenText().map(([needle, label]) =>
    forbiddenDocTextFailure(file, text, needle, label),
  );
  return [...required, ...forbidden].filter(Boolean);
}

function productFlowRequiredText() {
  return [
    ["Current-state reconciliation", "dated live-tree reconciliation marker"],
    ["Persistent strategy proposals", "shipped strategy queue capability"],
    ["Duplicate triage is fixed", "shipped triage behavior"],
    ["The earlier headless blockers are closed", "shipped headless parity"],
  ];
}

function productFlowForbiddenText() {
  return [
    ["The keyless first run is broken", "stale offline-onboarding claim"],
    ["You can't compose or save a strategy", "stale strategy-queue claim"],
    ["Triage re-triages duplicates with no verdict-skip", "stale triage claim"],
    ["`recon:import` is advertised but unreachable", "stale recon import claim"],
    ["HEAD already fails some workspace tests", "stale known-red test claim"],
  ];
}

function canonicalParityTestFailures() {
  const file = "crates/kuzushi-tui/tests/parity.rs";
  const text = readFileSync(path.join(repo, file), "utf8");
  return [
    requiredDocTextFailure(
      file,
      text,
      "cargo test -p kuzushi-tui --test parity`",
      "live parity test selector",
    ),
    forbiddenDocTextFailure(file, text, "--test parity -- --ignored", "stale ignored selector"),
  ].filter(Boolean);
}

function canonicalDependencyPolicyFailures() {
  const contributing = readFileSync(path.join(repo, "CONTRIBUTING.md"), "utf8");
  const workflow = readFileSync(path.join(repo, ".github/workflows/ci-full.yml"), "utf8");
  const policy = readFileSync(path.join(repo, "deny.toml"), "utf8");
  return [
    requiredDocTextFailure(
      "CONTRIBUTING.md",
      contributing,
      "cargo deny check advisories licenses bans sources",
      "complete dependency policy command",
    ),
    requiredDocTextFailure(
      ".github/workflows/ci-full.yml",
      workflow,
      "command: check advisories licenses bans sources",
      "complete dependency policy command",
    ),
    requiredDocTextFailure(
      "deny.toml",
      policy,
      'multiple-versions = "deny"',
      "fail-closed duplicate policy",
    ),
  ].filter(Boolean);
}

function requiredDocTextFailure(file, text, needle, label) {
  if (text.includes(needle)) return null;
  return { file, line: 1, pattern: `missing ${label}`, text: needle };
}

function forbiddenDocTextFailure(file, text, needle, label) {
  if (!text.includes(needle)) return null;
  return { file, line: 1, pattern: label, text: needle };
}
