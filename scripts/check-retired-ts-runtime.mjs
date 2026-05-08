#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const repo = process.cwd();

const retiredDirs = [
  "src/strategies",
  "src/governance",
  "src/jobs",
  "src/hooks",
  "src/intel",
  "src/scoring",
  "src/monorepo",
  "src/sessions",
  "src/migrations",
  "src/scheduler",
  "src/analysis-support",
  "src/crypto-behavioral",
  "src/poc-executor",
  "src/prompts",
  "src/discovery",
  "src/scanners",
  "src/knowledge",
];

const fixtureRoot = "reference/ts-runtime-island";
const sourceRoots = ["src", "scripts/pi-agent-core-bridge.mjs"];
const docRoots = [
  "README.md",
  "docs",
  "examples",
  "recipes",
  ".github/workflows/kuzushi-reference.yml",
  "AGENTS.md",
  "RELEASING.md",
];
const historicalDocPrefixes = [
  "docs/assessments/",
  "docs/data-model/",
  "docs/devex/",
  "docs/superpowers/",
  "docs/rust-migration-status.md",
  "docs/all-prompts.txt",
];

const sourceExtensions = new Set([".ts", ".tsx", ".js", ".mjs"]);
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

const failures = [];

for (const dir of retiredDirs) {
  if (existsSync(path.join(repo, dir))) {
    failures.push(`${dir} still exists under src; move it to ${fixtureRoot}/ or delete it.`);
  }
}

const sourceFiles = sourceRoots.flatMap((root) => walk(root, sourceExtensions));
for (const file of sourceFiles) {
  const rel = relative(file);
  if (rel.startsWith(`${fixtureRoot}/`)) continue;
  const text = readFileSync(file, "utf8");
  for (const specifier of importSpecifiers(text)) {
    const resolved = resolveImport(rel, specifier, sourceFiles);
    if (!resolved) continue;
    if (resolved.startsWith(`${fixtureRoot}/`)) {
      failures.push(`${rel} imports retired TS fixture ${resolved}`);
    }
  }
}

for (const file of docRoots.flatMap((root) => walk(root, textExtensions))) {
  const rel = relative(file);
  if (historicalDocPrefixes.some((prefix) => rel.startsWith(prefix))) continue;
  const text = readFileSync(file, "utf8");
  const lines = text.split(/\r?\n/);
  const fileIsHistorical = isHistorical(lines.slice(0, 12).join("\n"));
  lines.forEach((line, index) => {
    for (const retiredDir of retiredDirs) {
      if (!line.includes(retiredDir)) continue;
      const context = lines.slice(Math.max(0, index - 4), index + 5).join("\n");
      if (fileIsHistorical || isHistorical(context)) continue;
      failures.push(
        `${rel}:${index + 1} references ${retiredDir} without marking the context as historical/retired/reference-only.`,
      );
    }
  });
}

if (failures.length > 0) {
  console.error("Retired TypeScript runtime guardrail failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("retired TypeScript runtime guardrail passed");

function walk(root, extensions) {
  const abs = path.join(repo, root);
  let stats;
  try {
    stats = statSync(abs);
  } catch {
    return [];
  }

  if (stats.isFile()) {
    return extensions.has(path.extname(abs)) ? [abs] : [];
  }
  if (!stats.isDirectory()) return [];

  const out = [];
  for (const entry of readdirSync(abs)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".git") continue;
    out.push(...walk(path.join(root, entry), extensions));
  }
  return out;
}

function relative(file) {
  return path.relative(repo, file).replaceAll("\\", "/");
}

function importSpecifiers(text) {
  const specifiers = [];
  const patterns = [
    /import\s+(?:type\s+)?(?:[^'";]*?\s+from\s+)?["']([^"']+)["']/g,
    /export\s+(?:type\s+)?(?:[^'";]*?\s+from\s+)["']([^"']+)["']/g,
    /import\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const pattern of patterns) {
    let match = pattern.exec(text);
    while (match) {
      specifiers.push(match[1]);
      match = pattern.exec(text);
    }
  }
  return specifiers;
}

function resolveImport(from, specifier, sourceFiles) {
  if (!specifier.startsWith(".")) return undefined;
  const sourceSet = new Set(sourceFiles.map(relative));
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier));
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    `${base}.mjs`,
    base.replace(/\.js$/, ".ts"),
    base.replace(/\.js$/, ".tsx"),
    path.posix.join(base, "index.ts"),
    path.posix.join(base, "index.js"),
  ];
  return candidates.find((candidate) => sourceSet.has(candidate));
}

function isHistorical(text) {
  return /\b(retired|historical|legacy|reference-only|fixture|migration fixture|deleted|not current|unsupported|former TypeScript)\b/i.test(
    text,
  );
}
