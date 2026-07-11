#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PARITY_TARGET = path.join(REPO_ROOT, "design", "PARITY_TARGET.md");
const MOCKUP_DIR = path.join(REPO_ROOT, "design", "mockups");

function parseArgs(argv) {
  const parsed = { bucket: "Implement", mockups: [] };
  for (let index = 0; index < argv.length; index += 1) {
    index = parseArg(parsed, argv, index);
  }
  return parsed;
}

function parseArg(parsed, argv, index) {
  const arg = argv[index];
  const handler = ARG_HANDLERS[arg];
  if (!handler) {
    throw new Error(`unknown argument: ${arg}`);
  }
  return handler(parsed, argv, index);
}

const ARG_HANDLERS = {
  "--runner": (parsed, _argv, index) => {
    parsed.runner = true;
    return index;
  },
  "--mockup": (parsed, argv, index) => {
    parsed.mockups.push(requireValue(argv, index + 1, argv[index]));
    return index + 1;
  },
  "--bucket": (parsed, argv, index) => {
    parsed.bucket = requireValue(argv, index + 1, argv[index]);
    return index + 1;
  },
  "--out-dir": (parsed, argv, index) => {
    parsed.outDir = requireValue(argv, index + 1, argv[index]);
    return index + 1;
  },
  "--status": (parsed, argv, index) => {
    parsed.status = requireValue(argv, index + 1, argv[index]);
    return index + 1;
  },
  "--verified": (parsed, _argv, index) => {
    parsed.verified = true;
    return index;
  },
  "--json": (parsed, _argv, index) => {
    parsed.json = true;
    return index;
  },
  "--all": (parsed, _argv, index) => {
    parsed.bucket = "all";
    return index;
  },
};

const args = parseArgs(process.argv.slice(2));

if (args.runner) {
  await runExtractor(args);
} else {
  forwardToTsx(process.argv.slice(2));
}

function requireValue(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function forwardToTsx(argv) {
  const script = fileURLToPath(import.meta.url);
  const child = spawnSync("pnpm", ["exec", "tsx", script, "--runner", ...argv], {
    cwd: REPO_ROOT,
    stdio: "inherit",
  });
  process.exit(child.status ?? 1);
}

async function runExtractor(options) {
  const targets = await selectedTargets(options);
  const temp = await mkdtemp(path.join(tmpdir(), "kuzushi-mockups-"));
  try {
    installJsxRuntime();
    await importWithPragma(path.join(MOCKUP_DIR, "_shared.jsx"), temp, "_shared.jsx");
    const rendered = {};
    for (const target of targets) {
      rendered[target.file] = await renderMockup(target, temp);
    }
    await writeOutputs(options, targets, rendered);
  } finally {
    await rm(temp, { force: true, recursive: true });
  }
}

async function selectedTargets(options) {
  if (options.mockups.length > 0) {
    return options.mockups.map((mockup) => ({
      bucket: "Implement",
      file: path.basename(mockup),
      note: "",
      target: "",
    }));
  }
  const targets = await readParityTargets();
  if (options.bucket === "all") return targets;
  return targets.filter((target) => target.bucket === options.bucket);
}

async function readParityTargets() {
  const body = await readFile(PARITY_TARGET, "utf8");
  return body
    .split("\n")
    .map((line) => {
      const match = line.match(
        /^\| `([^`]+\.jsx)` \| (Implement|Defer|Cut) \| ([^|]+) \| ([^|]+) \|$/,
      );
      if (!match) return null;
      return {
        file: match[1],
        bucket: match[2],
        target: match[3].trim(),
        note: match[4].trim(),
      };
    })
    .filter(Boolean);
}

function installJsxRuntime() {
  globalThis.window = globalThis;
  globalThis.h = (type, props, ...children) => {
    const flatChildren = children.flat(Number.POSITIVE_INFINITY).filter(isRenderable);
    if (typeof type === "function") {
      return type({ ...(props ?? {}), children: jsxChildren(flatChildren) });
    }
    return { type, props: props ?? {}, children: flatChildren };
  };
}

function isRenderable(child) {
  return child !== null && child !== undefined && child !== false && child !== true;
}

function jsxChildren(children) {
  if (children.length === 0) return undefined;
  if (children.length === 1) return children[0];
  return children;
}

async function renderMockup(target, temp) {
  const sourcePath = path.join(MOCKUP_DIR, target.file);
  const viewName = await viewExportName(sourcePath);
  await importWithPragma(sourcePath, temp, target.file);
  const view = globalThis[viewName];
  if (typeof view !== "function") {
    throw new Error(`${target.file} did not register window.${viewName}`);
  }
  return collectRows(view())
    .map((line) => line.trimEnd())
    .join("\n");
}

async function viewExportName(sourcePath) {
  const source = await readFile(sourcePath, "utf8");
  const assignment = source.match(/window\.([A-Za-z0-9_]+)\s*=/);
  if (assignment) return assignment[1];
  const declaration = source.match(/function\s+([A-Za-z0-9_]+)\s*\(/);
  if (declaration) return declaration[1];
  throw new Error(`could not identify exported view in ${sourcePath}`);
}

async function importWithPragma(sourcePath, temp, name) {
  const source = await readFile(sourcePath, "utf8");
  const targetPath = path.join(temp, name);
  await writeFile(targetPath, `/** @jsx h */\n${source}`);
  await import(pathToFileURL(targetPath).href);
}

function collectRows(node, rows = []) {
  if (Array.isArray(node)) return collectArrayRows(node, rows);
  if (!isCollectableNode(node)) return rows;
  if (isRow(node)) {
    rows.push(textOf(node));
    return rows;
  }
  return collectChildRows(node, rows);
}

function collectArrayRows(nodes, rows) {
  for (const child of nodes) collectRows(child, rows);
  return rows;
}

function collectChildRows(node, rows) {
  for (const child of childrenOf(node)) collectRows(child, rows);
  return rows;
}

function isCollectableNode(node) {
  return Boolean(node) && typeof node === "object";
}

function isRow(node) {
  return String(node.props?.className ?? "")
    .split(/\s+/)
    .includes("row");
}

function textOf(node) {
  if (Array.isArray(node)) return textOfArray(node);
  if (isEmptyTextNode(node)) return "";
  return textOfNonEmpty(node);
}

function textOfArray(nodes) {
  return nodes.map(textOf).join("");
}

function textOfNonEmpty(node) {
  if (isTextPrimitive(node)) return String(node);
  if (isElementNode(node)) return textOfChildren(node);
  return "";
}

function textOfChildren(node) {
  return childrenOf(node).map(textOf).join("");
}

function isEmptyTextNode(node) {
  return node === null || node === undefined || typeof node === "boolean";
}

function isTextPrimitive(node) {
  return typeof node === "string" || typeof node === "number";
}

function isElementNode(node) {
  return typeof node === "object";
}

function childrenOf(node) {
  const children = node.children ?? node.props?.children ?? [];
  return Array.isArray(children) ? children : [children];
}

async function writeOutputs(options, targets, rendered) {
  await writeRequestedFiles(options, targets, rendered);
  if (options.json) {
    writeJson(rendered);
    return;
  }
  writeDefaultOutput(options, targets, rendered);
}

async function writeRequestedFiles(options, targets, rendered) {
  if (options.outDir) await writeTextFiles(options.outDir, rendered);
  if (options.status)
    await writeStatus(options.status, targets, rendered, options.verified === true);
}

function writeJson(rendered) {
  process.stdout.write(`${JSON.stringify(rendered, null, 2)}\n`);
}

function writeDefaultOutput(options, targets, rendered) {
  if (options.outDir || options.status) return;
  process.stdout.write(`${rendered[targets[0].file] ?? ""}\n`);
}

async function writeTextFiles(outDir, rendered) {
  const absolute = path.resolve(REPO_ROOT, outDir);
  await rm(absolute, { force: true, recursive: true });
  await import("node:fs/promises").then(({ mkdir }) => mkdir(absolute, { recursive: true }));
  for (const [file, text] of Object.entries(rendered)) {
    await writeFile(path.join(absolute, file.replace(/\.jsx$/, ".txt")), `${text}\n`);
  }
}

async function writeStatus(statusPath, targets, rendered, verified) {
  const status = verified ? "pass" : "pending";
  const rows = targets.map((target) => {
    const lineCount = (rendered[target.file] ?? "").split("\n").filter(Boolean).length;
    return `| \`${target.file}\` | ${target.bucket} | ${status} | ${lineCount} | ${target.target} |`;
  });
  const body = [
    "# Kuzushi TUI Parity Status",
    "",
    "Generated by `node scripts/mockup-to-text.mjs --status design/PARITY_STATUS.md [--verified]`.",
    "",
    `- Mockups tracked: ${targets.length}`,
    verified
      ? `- Rust parity results: ${targets.length}/${targets.length} fixture-family contracts passed.`
      : "- Rust parity results: pending until `cargo test -p kuzushi-tui --test parity` is run.",
    "",
    "| Mockup | Bucket | Status | Mockup rows | Current target |",
    "| --- | --- | --- | ---: | --- |",
    ...rows,
    "",
  ].join("\n");
  await writeFile(path.resolve(REPO_ROOT, statusPath), body);
}
