#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { fixtureIsApproved, scanLine } from "./secret-scan-rules.mjs";

export { fixtureIsApproved, scanLine };

function parseNewLineStart(header) {
  const match = header.match(/\+(\d+)(?:,(\d+))?/);
  return match ? Number.parseInt(match[1], 10) : null;
}

export function scanDiff(diff, approvedPath = () => false) {
  const findings = [];
  const state = { currentPath: null, newLine: null };
  for (const rawLine of diff.split("\n")) {
    if (updateDiffLocation(rawLine, state)) continue;
    if (state.currentPath === null || state.newLine === null) continue;
    scanContentLine(rawLine, state, findings, approvedPath);
  }
  return findings;
}

function updateDiffLocation(rawLine, state) {
  if (rawLine.startsWith("+++ ")) {
    state.currentPath = rawLine === "+++ /dev/null" ? null : rawLine.replace(/^\+\+\+ b\//, "");
    return true;
  }
  if (!rawLine.startsWith("@@ ")) return false;
  state.newLine = parseNewLineStart(rawLine);
  return true;
}

function scanContentLine(rawLine, state, findings, approvedPath) {
  if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
    scanAddedLine(rawLine, state, findings, approvedPath);
    state.newLine += 1;
    return;
  }
  if (rawLine.startsWith("-") && !rawLine.startsWith("---")) return;
  if (!rawLine.startsWith("\\")) state.newLine += 1;
}

function scanAddedLine(rawLine, state, findings, approvedPath) {
  if (approvedPath(state.currentPath)) return;
  for (const rule of scanLine(rawLine.slice(1))) {
    findings.push({ path: state.currentPath, line: state.newLine, rule });
  }
}

const EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

function diffRange(base, head) {
  return /^0{40}$/.test(base) ? `${EMPTY_TREE_SHA}..${head}` : `${base}...${head}`;
}

export function diffForRange(base, head, cwd = process.cwd()) {
  const range = diffRange(base, head);
  const result = spawnSync(
    "git",
    [
      "diff",
      "--no-ext-diff",
      "--no-textconv",
      "--unified=0",
      "--no-color",
      "--diff-filter=ACMR",
      range,
      "--",
    ],
    { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const detail = result.stderr?.trim() || `git diff exited ${result.status}`;
    throw new Error(`secret scan could not establish diff range ${range}: ${detail}`);
  }
  return result.stdout;
}

export function parseArguments(argv, environment = process.env) {
  let base =
    environment.KUZUSHI_SECRET_SCAN_BASE_REF ?? environment.KUZUSHI_CRAP_RISK_BASE_REF ?? "HEAD^";
  let head = environment.KUZUSHI_SECRET_SCAN_HEAD_REF ?? "HEAD";
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--base") {
      base = argv[index + 1] ?? null;
      index += 1;
    } else if (arg === "--head") {
      head = argv[index + 1] ?? null;
      index += 1;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!base || !head) {
    throw new Error("secret scan requires non-empty base and head Git refs");
  }
  return { base, head };
}

export function diffForWorktree(base, cwd = process.cwd()) {
  const revision = /^0{40}$/.test(base) ? EMPTY_TREE_SHA : base;
  const tracked = checkedGitOutput(
    [
      "diff",
      "--no-ext-diff",
      "--no-textconv",
      "--unified=0",
      "--no-color",
      "--diff-filter=ACMR",
      revision,
      "--",
    ],
    cwd,
  );
  const names = checkedGitOutput(["ls-files", "--others", "--exclude-standard", "-z"], cwd)
    .split("\0")
    .filter(Boolean);
  const additions = names.map((name) =>
    checkedGitOutput(
      [
        "diff",
        "--no-index",
        "--no-ext-diff",
        "--no-textconv",
        "--unified=0",
        "--no-color",
        "--",
        "/dev/null",
        name,
      ],
      cwd,
      [0, 1],
    ),
  );
  return [tracked, ...additions].join("\n");
}

function checkedGitOutput(args, cwd, allowed = [0]) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (result.error) throw result.error;
  if (!allowed.includes(result.status))
    throw new Error(`secret scan could not read the working tree: git ${args[0]} failed`);
  return result.stdout;
}

function parseScanMode(argv) {
  const worktree = argv.includes("--worktree");
  if (worktree && argv.includes("--head"))
    throw new Error("--worktree cannot be combined with --head");
  return { worktree, ...parseArguments(argv.filter((arg) => arg !== "--worktree")) };
}

function escapeWorkflowCommand(value) {
  return value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}

export function formatFinding(finding, githubActions = process.env.GITHUB_ACTIONS === "true") {
  const message = `Potential ${finding.rule} found; credential value redacted`;
  if (!githubActions) {
    return `${finding.path}:${finding.line}: ${message}`;
  }
  const path = escapeWorkflowCommand(finding.path).replaceAll(",", "%2C").replaceAll(":", "%3A");
  return [
    `::error file=${path},line=${finding.line},title=Potential secret::`,
    escapeWorkflowCommand(message),
  ].join("");
}

export function run(argv = process.argv.slice(2)) {
  const { base, head, worktree } = parseScanMode(argv);
  const cwd = process.cwd();
  const diff = worktree ? diffForWorktree(base, cwd) : diffForRange(base, head, cwd);
  const findings = scanDiff(diff, (path) => fixtureIsApproved(path, cwd));
  if (findings.length === 0) {
    console.log(
      `Secret scan passed for ${base}...${worktree ? "working tree (including untracked files)" : head}.`,
    );
    return 0;
  }
  for (const finding of findings) {
    console.error(formatFinding(finding));
  }
  console.error(`Secret scan rejected ${findings.length} added credential pattern(s).`);
  return 1;
}

const invokedPath = process.argv[1]
  ? fileURLToPath(import.meta.url) === resolve(process.argv[1])
  : false;
if (invokedPath) {
  try {
    process.exitCode = run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Secret scan failed closed: ${message}`);
    process.exitCode = 1;
  }
}
