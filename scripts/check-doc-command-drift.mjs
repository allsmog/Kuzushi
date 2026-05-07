#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const repo = process.cwd();

const roots = [
  "README.md",
  "docs",
  "examples",
  "recipes",
  ".github/workflows/kuzushi-reference.yml",
  "AGENTS.md",
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
  { label: "--sarif", regex: /--sarif\b/g, needsKuzushiContext: true },
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

const allowedContext =
  /\b(legacy|historical|removed|unsupported|not current|does not support|does not expose|do not use|do not add|do not resurrect|deleted|reference-only|preserved reference|retained TypeScript\/Ink references|old TypeScript|former TypeScript)\b/i;

const failures = [];

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
      const hasKuzushiContext = /\bkuzushi\b/i.test(context);
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
    console.error(
      `- ${failure.file}:${failure.line} ${failure.pattern}: ${failure.text}`,
    );
  }
  console.error(
    "\nFix the command, or label the surrounding section as legacy/historical/unsupported if it is not current operator guidance.",
  );
  process.exit(1);
}

console.log("doc command drift check passed");

function walk(root) {
  const abs = path.join(repo, root);
  let stats;
  try {
    stats = statSync(abs);
  } catch {
    return [];
  }

  if (stats.isFile()) {
    return shouldScan(abs) ? [abs] : [];
  }

  if (!stats.isDirectory()) {
    return [];
  }

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
