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

const retiredUiPaths = [
  "src/cli/commands/shell.ts",
  "src/copilot/shell.ts",
  "src/ui/App.tsx",
  "src/ui/components",
  "src/ui/primitives",
  "src/ui/render.ts",
  "src/ui/setup.ts",
];
const retiredUiDependencies = ["ink", "react", "react-dom", "@types/react", "@types/react-dom"];
const retiredUiRuntimePackages = new Set(["ink", "react", "react-dom"]);
const retiredShellRouterPatterns = [
  { label: "ShellCommand type", regex: /\bShellCommand\b/ },
  { label: "SHELL_COMMAND_SPECS constant", regex: /\bSHELL_COMMAND_SPECS\b/ },
  { label: "shellCommandSpecs helper", regex: /\bshellCommandSpecs\b/ },
  { label: "parseShellCommand helper", regex: /\bparseShellCommand\b/ },
  { label: "handleShellCommand helper", regex: /\bhandleShellCommand\b/ },
  { label: "parse_command helper", regex: /\bparse_command\b/ },
  { label: "handle_command helper", regex: /\bhandle_command\b/ },
];
const deletedReferenceRoot = "reference/ts-runtime-island";
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
    failures.push(`${dir} still exists under src; port it to Rust or delete it.`);
  }
}

for (const uiPath of retiredUiPaths) {
  if (existsSync(path.join(repo, uiPath))) {
    failures.push(`${uiPath} still exists; interactive shell UI belongs in Rust Ratatui.`);
  }
}

if (existsSync(path.join(repo, deletedReferenceRoot))) {
  failures.push(
    `${deletedReferenceRoot} still exists; retired TypeScript runtime files must be deleted.`,
  );
}

failures.push(...tsxSourceFailures(), ...retiredUiDependencyFailures());

const sourceFiles = sourceRoots.flatMap((root) => walk(root, sourceExtensions));
failures.push(...retiredShellRouterFailures(sourceFiles), ...retiredUiImportFailures(sourceFiles));

for (const file of sourceFiles) {
  const rel = relative(file);
  const text = readFileSync(file, "utf8");
  for (const specifier of importSpecifiers(text)) {
    const resolved = resolveImport(rel, specifier, sourceFiles);
    if (!resolved) continue;
    if (retiredDirs.some((dir) => resolved.startsWith(`${dir}/`))) {
      failures.push(`${rel} imports retired TypeScript runtime file ${resolved}`);
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
    for (const retiredPath of [...retiredDirs, deletedReferenceRoot]) {
      if (!line.includes(retiredPath)) continue;
      const context = lines.slice(Math.max(0, index - 4), index + 5).join("\n");
      if (fileIsHistorical || isHistorical(context)) continue;
      failures.push(
        `${rel}:${index + 1} references ${retiredPath} without marking the context as historical/retired/deleted.`,
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
  const stats = statOrUndefined(abs);
  if (!stats) return [];
  if (stats.isFile()) return fileIfExtension(abs, extensions);
  return stats.isDirectory() ? walkDirectory(root, extensions) : [];
}

function walkDirectory(root, extensions) {
  const abs = path.join(repo, root);
  const out = [];
  for (const entry of readdirSync(abs)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".git") continue;
    out.push(...walk(path.join(root, entry), extensions));
  }
  return out;
}

function statOrUndefined(abs) {
  try {
    return statSync(abs);
  } catch {
    return undefined;
  }
}

function fileIfExtension(abs, extensions) {
  return extensions.has(path.extname(abs)) ? [abs] : [];
}

function relative(file) {
  return path.relative(repo, file).replaceAll("\\", "/");
}

function tsxSourceFailures() {
  return walk("src", new Set([".tsx"])).map(
    (file) => `${relative(file)} is a TSX source file; shell UI belongs in Rust Ratatui.`,
  );
}

function retiredUiDependencyFailures() {
  const pkg = JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8"));
  return ["dependencies", "devDependencies", "optionalDependencies"].flatMap((section) =>
    retiredUiDependencies
      .filter((name) => Object.hasOwn(pkg[section] ?? {}, name))
      .map((name) => `package.json ${section}.${name} must not reintroduce React/Ink UI.`),
  );
}

function retiredShellRouterFailures(files) {
  return files.flatMap((file) => {
    const rel = relative(file);
    if (!rel.startsWith("src/")) return [];
    const text = readFileSync(file, "utf8");
    return retiredShellRouterPatterns
      .filter(({ regex }) => regex.test(text))
      .map(
        ({ label }) =>
          `${rel} contains ${label}; shell command routing belongs in crates/kuzushi-tui.`,
      );
  });
}

function retiredUiImportFailures(files) {
  return files.flatMap((file) => {
    const rel = relative(file);
    const text = readFileSync(file, "utf8");
    return importSpecifiers(text)
      .filter((specifier) => retiredUiRuntimePackages.has(packageName(specifier)))
      .map((specifier) => `${rel} imports ${specifier}; shell UI belongs in Rust Ratatui.`);
  });
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

function packageName(specifier) {
  if (specifier.startsWith("@")) return specifier.split("/").slice(0, 2).join("/");
  return specifier.split("/")[0] ?? specifier;
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
  return /\b(retired|historical|legacy|deleted|not current|unsupported|former TypeScript)\b/i.test(
    text,
  );
}
