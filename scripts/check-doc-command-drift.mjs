#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const repo = process.cwd();

const roots = [
  "README.md",
  "docs",
  "examples",
  "recipes",
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
  "docs/architecture/domain-boundaries.md",
  "docs/current-architecture.mmd",
  "docs/devex/new-contributor-map.md",
];

const modelGuidanceFiles = currentGuidanceFiles;

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

function referencedPathFailures(file, lines, line, index) {
  const context = lines
    .slice(Math.max(0, index - 4), Math.min(lines.length, index + 5))
    .join("\n");
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
  const regex = /(?:^|[\s`'"\[(])((?:crates|src)\/[A-Za-z0-9._~:+@%/-]+)/g;
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
