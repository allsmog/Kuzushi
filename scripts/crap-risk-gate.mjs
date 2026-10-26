#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { testCoversProductionFile } from "./crap-risk-test-mapping.mjs";
import {
  locallyChangedFunctions,
  vendoredTerminalBaseline,
} from "./vendored-terminal-baseline.mjs";

const root = execGit(["rev-parse", "--show-toplevel"], process.cwd()).trim() || process.cwd();
const threshold = Number(process.env.KUZUSHI_CRAP_RISK_THRESHOLD ?? "7");
const base = diffBase();
const allChanged = changedFiles();
const changedTests = changedTestFiles(allChanged);
const changed = changedCodeFiles(allChanged);
const failures = [];

for (const file of changed) {
  const abs = path.join(root, file);
  if (!existsSync(abs)) continue;
  const source = readFileSync(abs, "utf8");
  const production = productionSource(file, source);
  const hasFocusedChangedTest =
    changedTests.some((test) => testCoversProductionFile(file, test.file, test.source)) ||
    hasChangedInlineTest(file, source);
  const blocks = scoredFunctionBlocks(file, production);
  const logicalFileLines = localProductionLines(file, production, blocks);
  if (scoresWholeFile(file) && isProductionCode(file) && logicalFileLines > 300) {
    failures.push(`${file}: file has ${logicalFileLines} logical lines; limit is 300`);
  }
  for (const block of blocks) {
    const metrics = scoreBlock(file, block, hasFocusedChangedTest);
    if (metrics.complexity > 4) {
      failures.push(
        `${file}:${block.line} ${block.name} complexity ${metrics.complexity}; limit is 4`,
      );
    }
    if (metrics.lines > 40) {
      failures.push(
        `${file}:${block.line} ${block.name} has ${metrics.lines} logical lines; limit is 40`,
      );
    }
    if (metrics.risk >= threshold) {
      failures.push(
        `${file}:${block.line} ${block.name} CRAP-risk ${metrics.risk}; limit is < ${threshold}`,
      );
    }
  }
}

if (failures.length > 0) {
  console.error("Kuzushi CRAP-risk proxy gate failed:");
  for (const failure of failures.slice(0, 40)) {
    console.error(`- ${failure}`);
  }
  if (failures.length > 40) {
    console.error(`- ... ${failures.length - 40} more`);
  }
  console.error("Split branchy or long code, isolate side effects, or add focused tests.");
  process.exit(1);
}

console.log(`CRAP-risk proxy passed for ${changed.length} changed code file(s).`);

function changedFiles() {
  const explicit = process.env.KUZUSHI_CRAP_RISK_FILES;
  const files = explicit ? explicit.split(/\r?\n|,/) : changedFilesFromGit();
  return [...new Set(files.map((file) => normalize(file)).filter(Boolean))].sort();
}

function changedCodeFiles(files) {
  return files.filter(isTrackedCodeFile);
}

function changedTestFiles(files) {
  return files.filter(isTestFile).map((file) => ({
    file,
    source: existsSync(path.join(root, file)) ? readFileSync(path.join(root, file), "utf8") : "",
  }));
}

function hasChangedInlineTest(file, source) {
  if (!file.endsWith(".rs")) return false;
  const marker = source.split(/\r?\n/).findIndex((line) => line.includes("#[cfg(test)]"));
  if (marker < 0) return false;
  return changedLineRanges(file).some((range) => range.end >= marker + 1);
}

function productionSource(file, source) {
  if (!file.endsWith(".rs")) return source;
  return source.split(/^\s*#\[cfg\(test\)\]/m, 1)[0];
}

function changedFilesFromGit() {
  return [
    ...gitLines(["diff", "--name-only", "--diff-filter=ACMR"]),
    ...gitLines(["diff", "--cached", "--name-only", "--diff-filter=ACMR"]),
    ...gitLines(["ls-files", "--others", "--exclude-standard"]),
    ...gitLinesRequired(["diff", "--name-only", "--diff-filter=ACMR", base, "HEAD"]),
  ];
}

function diffBase() {
  const requested = process.env.KUZUSHI_CRAP_RISK_BASE_REF;
  if (/^0+$/.test(requested ?? "")) return emptyTreeBase();
  const selected = requested ?? "HEAD^";
  requireCommitBase(selected);
  return selected;
}

function emptyTreeBase() {
  const emptyTree = execGitRequired(["hash-object", "-t", "tree", "--stdin"], root, "").trim();
  if (emptyTree) return emptyTree;
  console.error("CRAP-risk gate cannot resolve Git's empty tree for a zero-SHA event base.");
  process.exit(1);
}

function requireCommitBase(base) {
  if (gitCommitResolves(base)) return;
  console.error(
    `CRAP-risk gate cannot resolve diff base "${base}" — the gate would silently check 0 files. ` +
      "Fetch more history (checkout with fetch-depth: 2 or 0) or set KUZUSHI_CRAP_RISK_BASE_REF.",
  );
  process.exit(1);
}

function gitCommitResolves(ref) {
  return git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]).trim().length > 0;
}

function functionBlocks(file, source) {
  const lines = source.split(/\r?\n/);
  if (file.endsWith(".rs")) return rustFunctionBlocks(lines, source);
  if (/\.(mjs|js|ts)$/.test(file)) return jsFunctionBlocks(lines, source);
  return [{ name: "<file>", line: 1, source }];
}

function scoredFunctionBlocks(file, source) {
  const upstream = vendoredTerminalBaseline(root, file);
  if (upstream !== null) {
    return locallyChangedFunctions(
      functionBlocks(file, source),
      functionBlocks(file, productionSource(file, upstream)),
    );
  }
  if (scoresWholeFile(file)) return functionBlocks(file, source);
  const changedLines = changedLineRanges(file);
  return functionBlocks(file, source).filter((block) => overlapsRanges(block, changedLines));
}

function localProductionLines(file, source, blocks) {
  if (vendoredTerminalBaseline(root, file) !== null) {
    return logicalLines(blocks.map((block) => block.source).join("\n")).length;
  }
  return logicalLines(source).length;
}

function scoresWholeFile(file) {
  return explicitFileListUsed() || isUntrackedFile(file) || isAddedFile(file);
}

function rustFunctionBlocks(lines, source) {
  const blocks = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const match = line.match(/^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)/);
    if (!match) continue;
    const block = collectBraceBlock(lines, index);
    blocks.push({ name: match[1], line: index + 1, endLine: block.endLine, source: block.source });
  }
  return blocks;
}

function jsFunctionBlocks(lines, source) {
  const blocks = [];
  const pattern =
    /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)|^\s*(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\(/;
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(pattern);
    if (!match) continue;
    const block = collectBraceBlock(lines, index);
    blocks.push({
      name: match[1] ?? match[2],
      line: index + 1,
      endLine: block.endLine,
      source: block.source,
    });
  }
  return blocks;
}

function collectBraceBlock(lines, start) {
  let depth = 0;
  let opened = false;
  const out = [];
  for (let index = start; index < lines.length; index += 1) {
    const line = lines[index];
    out.push(line);
    for (const char of stripStrings(line)) {
      const next = braceDepthAfter(char, depth, opened);
      depth = next.depth;
      opened = next.opened;
    }
    if (opened && depth <= 0) {
      return { source: out.join("\n"), endLine: index + 1 };
    }
  }
  return { source: out.join("\n"), endLine: start + out.length };
}

function braceDepthAfter(char, depth, opened) {
  if (char === "{") return { depth: depth + 1, opened: true };
  if (char === "}") return { depth: depth - 1, opened };
  return { depth, opened };
}

function scoreBlock(file, block, hasFocusedChangedTest) {
  const lines = logicalLines(block.source);
  const complexity = complexityScore(block.source);
  const sizeWeight = Math.max(0, Math.ceil((lines.length - 40) / 20));
  const sideEffectWeight = sideEffectScore(block.source);
  const coverageGap = isProductionCode(file) && !hasFocusedChangedTest ? 1 : 0;
  const centralityWeight = centralityScore(file);
  return {
    lines: lines.length,
    complexity,
    risk: complexity + sizeWeight + sideEffectWeight + coverageGap + centralityWeight,
  };
}

function complexityScore(source) {
  const branches = logicalLines(source).filter(isBranchLine);
  return 1 + branches.length;
}

function isBranchLine(line) {
  return /^(if|else if|match|for|while|loop|catch|case)\b/.test(line);
}

function sideEffectScore(source) {
  const text = stripComments(source);
  if (/\b(Command|spawn|spawnSync|execFileSync|fetch)\b/.test(text)) return 2;
  if (
    /\b(fs|File|OpenOptions|readFileSync|writeFileSync|env::|std::env|process\.env)\b/.test(text)
  ) {
    return 1;
  }
  return 0;
}

function centralityScore(file) {
  if (file.startsWith("bin/") || file.startsWith("scripts/")) return 1;
  if (/(^|\/)(main|lib)\.rs$/.test(file)) return 1;
  if (file.includes("/registry/") || file.includes("/runtime/") || file.includes("/renderer/"))
    return 1;
  return 0;
}

function logicalLines(source) {
  return stripComments(source)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split(/\r?\n/)
    .map((line) => line.replace(/\/\/.*$/, "").replace(/#.*$/, ""))
    .join("\n");
}

function stripStrings(line) {
  return line.replace(/"([^"\\]|\\.)*"/g, '""');
}

function isTrackedCodeFile(file) {
  return (
    !isTestFile(file) &&
    !file.startsWith("target/") &&
    !file.startsWith("dist/") &&
    !file.startsWith("coverage/") &&
    !file.startsWith("node_modules/") &&
    /\.(rs|mjs|js|ts)$/.test(file)
  );
}

function isProductionCode(file) {
  return !isTestFile(file) && !file.endsWith(".d.ts");
}

function isTestFile(file) {
  return (
    file.includes("/tests/") ||
    file.includes("_tests/") ||
    file.endsWith("/tests.rs") ||
    file.endsWith("_tests.rs") ||
    file.endsWith("/test_support.rs") ||
    file.includes("_test.") ||
    file.includes(".test.") ||
    file.includes("/snapshots/")
  );
}

function normalize(file) {
  return file.trim().replaceAll(path.sep, "/");
}

function explicitFileListUsed() {
  return Boolean(process.env.KUZUSHI_CRAP_RISK_FILES);
}

function isUntrackedFile(file) {
  return gitLines(["ls-files", "--others", "--exclude-standard", "--", file]).includes(file);
}

function isAddedFile(file) {
  const workingTreeAdd = gitLines([
    "diff",
    "--name-only",
    "--diff-filter=A",
    "HEAD",
    "--",
    file,
  ]).includes(file);
  return (
    workingTreeAdd ||
    gitLinesRequired(["diff", "--name-only", "--diff-filter=A", base, "HEAD", "--", file]).includes(
      file,
    )
  );
}

function overlapsRanges(block, ranges) {
  if (ranges.length === 0) return true;
  return ranges.some((range) => range.start <= block.endLine && block.line <= range.end);
}

function changedLineRanges(file) {
  let diff = git(["diff", "--unified=0", "HEAD", "--", file]);
  if (!diff.trim() && !explicitFileListUsed() && !isUntrackedFile(file)) {
    diff = gitRequired(["diff", "--unified=0", base, "HEAD", "--", file]);
  }
  return diff.split(/\r?\n/).map(parseAddedRange).filter(Boolean);
}

function parseAddedRange(line) {
  const match = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
  if (!match) return undefined;
  const start = Number(match[1]);
  const count = Number(match[2] ?? "1");
  const end = start + Math.max(count, 1) - 1;
  return { start, end };
}

function gitLines(args) {
  return git(args)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function gitLinesRequired(args) {
  return gitRequired(args)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function git(args) {
  return execGit(args, root);
}

function gitRequired(args) {
  return execGitRequired(args, root);
}

function execGit(args, cwd, input) {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", input });
  } catch {
    return "";
  }
}

function execGitRequired(args, cwd, input) {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      input,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (error) {
    const detail = error.stderr?.toString().trim() || error.message;
    console.error(`CRAP-risk gate Git command failed: git ${args.join(" ")}\n${detail}`);
    process.exit(1);
  }
}
