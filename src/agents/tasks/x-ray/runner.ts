import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type {
  AgentMessage,
  AgentQueryOptions,
  AgentRuntime,
  AgentRuntimeTool,
} from "../../../agent-runtime/types.js";
import { isPathWithinRoot, isRecord, toErrorMessage } from "../../../utils.js";
import {
  buildXRayPrompt,
  detectXRayRuntimeMode,
  loadXRaySkillPack,
  type XRayRuntimeMode,
  type XRaySkillPack,
} from "./skill-pack.js";

export interface XRayReportData {
  target: string;
  repoName: string;
  runtimeMode: XRayRuntimeMode;
  artifactPaths: {
    xRay: string;
    entryPoints: string;
    invariants: string;
    architectureSvg: string;
  };
  verdict: {
    tier?: string;
    summary: string;
  };
  entryPointCounts: {
    permissionless: number;
    roleGated: number;
    adminOnly: number;
    total: number;
  };
  invariantCounts: {
    global: number;
    integration: number;
    crossChain: number;
    economic: number;
    total: number;
  };
  costUsd: number;
}

export interface RunXRayReportParams {
  runtime: AgentRuntime;
  repoRoot: string;
  repoName: string;
  model: string;
  maxBudgetUsd?: number;
  effort?: AgentQueryOptions["effort"];
  signal?: AbortSignal;
  onOutput?: (line: string) => void;
}

export interface XRayToolGuard {
  repoRoot: string;
  skillDir: string;
  outputDir: string;
  checkTool(
    toolName: string,
    input: Record<string, unknown>,
  ):
    | { behavior: "allow" }
    | {
        behavior: "deny";
        message: string;
      };
  canUseTool: NonNullable<AgentQueryOptions["canUseTool"]>;
}

const CLAUDE_XRAY_TOOLS = ["Read", "Glob", "Grep", "Bash", "Write", "Task", "TodoWrite"];
const PI_AI_XRAY_TOOLS = ["Read", "Glob", "Grep", "Bash", "Write", "Task", "TodoWrite"];
const CODEX_XRAY_TOOLS = ["Bash", "Write"];

const REQUIRED_ARTIFACTS = {
  xRay: "x-ray.md",
  entryPoints: "entry-points.md",
  invariants: "invariants.md",
  architectureSvg: "architecture.svg",
} as const;

export async function runXRayReport(params: RunXRayReportParams): Promise<XRayReportData> {
  const repoRoot = path.resolve(params.repoRoot);
  const runtimeMode = detectXRayRuntimeMode(params.runtime.id);
  const skillPack = loadXRaySkillPack();
  const promptParts = buildXRayPrompt({
    runtimeMode,
    targetRoot: repoRoot,
    repoName: params.repoName,
    skillPack,
  });
  const guard = createXRayToolGuard({ repoRoot, skillDir: skillPack.skillDir });
  const abortController = relayAbort(params.signal);

  const options: AgentQueryOptions = {
    cwd: repoRoot,
    model: params.model,
    allowedTools: allowedToolsFor(runtimeMode),
    permissionMode: "dontAsk",
    maxBudgetUsd: params.maxBudgetUsd,
    abortController,
    effort: params.effort,
    taskId: "x-ray:run",
    systemPromptPrefix: promptParts.systemPromptPrefix,
    canUseTool: guard.canUseTool,
  };

  if (runtimeMode === "claude") {
    options.plugins = promptParts.plugins;
  } else if (runtimeMode === "pi-ai") {
    options.customTools = createXRayPiAiCustomTools({
      runtime: params.runtime,
      model: params.model,
      repoRoot,
      repoName: params.repoName,
      skillPack,
      guard,
      effort: params.effort,
      maxBudgetUsd: params.maxBudgetUsd,
    });
  }

  const result = await collectAgentRun(
    params.runtime.query({
      prompt: promptParts.prompt,
      options,
    }),
    params.onOutput,
  );

  if (result.executionError) {
    throw new Error(`X-Ray agent run failed: ${result.executionError}`);
  }

  return readXRayReportArtifacts({
    repoRoot,
    repoName: params.repoName,
    runtimeMode,
    costUsd: result.costUsd,
  });
}

export function readXRayReportArtifacts(params: {
  repoRoot: string;
  repoName?: string;
  runtimeMode?: XRayRuntimeMode;
  costUsd?: number;
}): XRayReportData {
  const repoRoot = path.resolve(params.repoRoot);
  const artifactDir = path.join(repoRoot, "x-ray");
  const paths = {
    xRay: path.join(artifactDir, REQUIRED_ARTIFACTS.xRay),
    entryPoints: path.join(artifactDir, REQUIRED_ARTIFACTS.entryPoints),
    invariants: path.join(artifactDir, REQUIRED_ARTIFACTS.invariants),
    architectureSvg: path.join(artifactDir, REQUIRED_ARTIFACTS.architectureSvg),
  };

  const missing = Object.values(paths).filter((candidate) => !existsSync(candidate));
  if (missing.length > 0) {
    throw new Error(`X-Ray report is missing required artifact(s): ${missing.join(", ")}`);
  }

  const xRayMarkdown = readFile(paths.xRay);
  const entryPointsMarkdown = readFile(paths.entryPoints);
  const invariantsMarkdown = readFile(paths.invariants);

  return {
    target: repoRoot,
    repoName: params.repoName ?? path.basename(repoRoot),
    runtimeMode: params.runtimeMode ?? "codex",
    artifactPaths: paths,
    verdict: parseVerdict(xRayMarkdown),
    entryPointCounts: parseEntryPointCounts(entryPointsMarkdown),
    invariantCounts: parseInvariantCounts(invariantsMarkdown),
    costUsd: params.costUsd ?? 0,
  };
}

export function createXRayToolGuard(params: { repoRoot: string; skillDir: string }): XRayToolGuard {
  const repoRoot = path.resolve(params.repoRoot);
  const skillDir = path.resolve(params.skillDir);
  const outputDir = path.join(repoRoot, "x-ray");

  const guard: XRayToolGuard = {
    repoRoot,
    skillDir,
    outputDir,
    checkTool(toolName, input) {
      if (toolName === "TodoWrite" || toolName === "Task") return { behavior: "allow" };
      if (toolName === "Write") return checkWrite(input, repoRoot, outputDir);
      if (toolName === "Read") return checkRead(input, repoRoot, skillDir);
      if (toolName === "Glob" || toolName === "Grep") return checkSearch(input, repoRoot, skillDir);
      if (toolName === "Bash") return checkBash(input, repoRoot, skillDir, outputDir);
      return { behavior: "deny", message: `X-Ray harness does not allow tool: ${toolName}` };
    },
    canUseTool(toolName, input) {
      return guard.checkTool(toolName, input);
    },
  };

  return guard;
}

export function createXRayPiAiCustomTools(params: {
  runtime: AgentRuntime;
  model: string;
  repoRoot: string;
  repoName: string;
  skillPack: XRaySkillPack;
  guard: XRayToolGuard;
  effort?: AgentQueryOptions["effort"];
  maxBudgetUsd?: number;
}): AgentRuntimeTool[] {
  let lastTodos: Array<Record<string, unknown>> = [];

  return [
    {
      name: "TodoWrite",
      description: "Update the X-Ray phase checklist.",
      parameters: {
        type: "object",
        properties: {
          todos: {
            type: "array",
            items: {
              type: "object",
              properties: {
                content: { type: "string" },
                status: { type: "string", enum: ["pending", "in_progress", "completed"] },
                id: { type: "string" },
              },
              required: ["content", "status"],
              additionalProperties: true,
            },
          },
        },
        required: ["todos"],
        additionalProperties: true,
      },
      execute(input) {
        const todos = Array.isArray(input["todos"])
          ? input["todos"].filter((todo): todo is Record<string, unknown> => isRecord(todo))
          : [];
        lastTodos = todos;
        const inProgress = todos.filter((todo) => todo["status"] === "in_progress");
        if (inProgress.length > 1) {
          throw new Error("TodoWrite accepts at most one in_progress X-Ray phase.");
        }
        return `Todo list updated (${lastTodos.length} item(s)).`;
      },
    },
    {
      name: "Task",
      description: "Run a bounded read-only X-Ray sub-analysis in the same target repository.",
      parameters: {
        type: "object",
        properties: {
          description: { type: "string" },
          prompt: { type: "string" },
          subagent_type: { type: "string" },
        },
        required: ["prompt"],
        additionalProperties: true,
      },
      async execute(input, options) {
        const prompt = readString(input, "prompt");
        if (!prompt) throw new Error("Task requires a prompt.");

        const result = await collectAgentRun(
          params.runtime.query({
            prompt: [
              "Run this bounded X-Ray sub-analysis and return concise findings for the parent agent.",
              `Repository: ${params.repoRoot}`,
              `Repo name: ${params.repoName}`,
              "Do not write files. Use at most 200 lines in your response.",
              "",
              prompt,
            ].join("\n"),
            options: {
              cwd: params.repoRoot,
              model: params.model,
              allowedTools: ["Read", "Glob", "Grep", "Bash"],
              permissionMode: "dontAsk",
              effort: params.effort,
              maxBudgetUsd: params.maxBudgetUsd,
              abortController: relayAbort(options.signal),
              systemPromptPrefix: [
                "You are a read-only helper for the vendored Pashov X-Ray skill.",
                `Local $SKILL_DIR: ${params.skillPack.skillDir}`,
                "Return only information useful for the parent X-Ray report.",
              ].join("\n"),
              canUseTool: params.guard.canUseTool,
            },
          }),
        );
        if (result.executionError) throw new Error(result.executionError);
        return truncateLines(
          result.resultText.trim() || "Task completed with no text output.",
          200,
        );
      },
    },
  ];
}

export function renderXRayReportSummary(data: XRayReportData): string {
  return [
    `x-ray:run complete for ${data.repoName} (${data.target})`,
    `  Runtime:      ${data.runtimeMode}`,
    `  Verdict:      ${data.verdict.tier ?? "unknown"}${data.verdict.summary ? ` - ${data.verdict.summary}` : ""}`,
    `  Entry points: ${data.entryPointCounts.total}`,
    `  Invariants:   ${data.invariantCounts.total}`,
    `  Cost:         $${data.costUsd.toFixed(4)}`,
    "",
    "Artifacts:",
    `  - ${data.artifactPaths.xRay}`,
    `  - ${data.artifactPaths.entryPoints}`,
    `  - ${data.artifactPaths.invariants}`,
    `  - ${data.artifactPaths.architectureSvg}`,
  ].join("\n");
}

function allowedToolsFor(runtimeMode: XRayRuntimeMode): string[] {
  if (runtimeMode === "claude") return [...CLAUDE_XRAY_TOOLS];
  if (runtimeMode === "pi-ai") return [...PI_AI_XRAY_TOOLS];
  return [...CODEX_XRAY_TOOLS];
}

async function collectAgentRun(
  stream: AsyncIterable<AgentMessage>,
  onOutput?: (line: string) => void,
): Promise<{ resultText: string; executionError: string | null; costUsd: number }> {
  const textParts: string[] = [];
  let resultText = "";
  let executionError: string | null = null;
  let costUsd = 0;

  for await (const message of stream) {
    if (message.type === "text-delta") {
      textParts.push(message.delta);
      continue;
    }
    if (message.type === "assistant") {
      const text = flattenAssistantContent(message.content);
      if (text.trim()) {
        textParts.push(text);
        onOutput?.(text);
      }
      continue;
    }
    if (message.type === "result") {
      costUsd = message.totalCostUsd ?? costUsd;
      if ("result" in message) {
        resultText = message.result;
      } else {
        executionError = message.errors.join("; ");
      }
    }
  }

  return {
    resultText: resultText || textParts.join(""),
    executionError,
    costUsd,
  };
}

function flattenAssistantContent(content: Array<Record<string, unknown>>): string {
  return content
    .map((block) => {
      if (typeof block["text"] === "string") return block["text"];
      if (typeof block["content"] === "string") return block["content"];
      return "";
    })
    .filter(Boolean)
    .join("\n");
}

function checkRead(
  input: Record<string, unknown>,
  repoRoot: string,
  skillDir: string,
): ReturnType<XRayToolGuard["checkTool"]> {
  const rawPath = readStringAny(input, ["path", "file_path", "filePath"]);
  if (!rawPath) return { behavior: "allow" };
  const candidate = resolveRepoRelative(repoRoot, rawPath);
  if (isPathWithinRoot(repoRoot, candidate) || isPathWithinRoot(skillDir, candidate)) {
    return { behavior: "allow" };
  }
  return {
    behavior: "deny",
    message: `X-Ray Read is limited to the target repository or vendored skill directory: ${rawPath}`,
  };
}

function checkSearch(
  input: Record<string, unknown>,
  repoRoot: string,
  skillDir: string,
): ReturnType<XRayToolGuard["checkTool"]> {
  const rawPath = readString(input, "path");
  if (!rawPath) return { behavior: "allow" };
  const candidate = resolveRepoRelative(repoRoot, rawPath);
  if (isPathWithinRoot(repoRoot, candidate) || isPathWithinRoot(skillDir, candidate)) {
    return { behavior: "allow" };
  }
  return {
    behavior: "deny",
    message: `X-Ray ${readString(input, "toolName") ?? "search"} path is outside the allowed roots: ${rawPath}`,
  };
}

function checkWrite(
  input: Record<string, unknown>,
  repoRoot: string,
  outputDir: string,
): ReturnType<XRayToolGuard["checkTool"]> {
  const rawPath = readStringAny(input, ["file_path", "path", "filePath"]);
  if (!rawPath) {
    return { behavior: "deny", message: "X-Ray Write requires a file path." };
  }
  const candidate = resolveRepoRelative(repoRoot, rawPath);
  if (isPathWithinRoot(outputDir, candidate)) return { behavior: "allow" };
  return {
    behavior: "deny",
    message: `X-Ray writes are only allowed under ${outputDir}: ${rawPath}`,
  };
}

function checkBash(
  input: Record<string, unknown>,
  repoRoot: string,
  skillDir: string,
  outputDir: string,
): ReturnType<XRayToolGuard["checkTool"]> {
  const command = readString(input, "command");
  if (!command) return { behavior: "deny", message: "X-Ray Bash requires a command." };
  const denied = explainDeniedBash(command, repoRoot, skillDir, outputDir);
  return denied ? { behavior: "deny", message: denied } : { behavior: "allow" };
}

function explainDeniedBash(
  command: string,
  repoRoot: string,
  skillDir: string,
  outputDir: string,
): string | null {
  const trimmed = command.trim();
  if (!trimmed) return "X-Ray Bash command is empty.";

  if (
    /^curl\s+-sf\s+https:\/\/raw\.githubusercontent\.com\/pashov\/skills\/main\/x-ray\/VERSION\s*$/.test(
      trimmed,
    )
  ) {
    return null;
  }

  for (const candidate of absolutePathsIn(trimmed)) {
    if (
      candidate.startsWith("/dev/") ||
      isPathWithinRoot(repoRoot, candidate) ||
      isPathWithinRoot(skillDir, candidate)
    ) {
      continue;
    }
    return `X-Ray Bash path is outside the target repo or skill directory: ${candidate}`;
  }

  for (const target of redirectionTargets(trimmed, repoRoot)) {
    if (target.startsWith("/dev/")) continue;
    if (!isPathWithinRoot(outputDir, target)) {
      return `X-Ray Bash redirection must write under ${outputDir}: ${target}`;
    }
  }

  const forbidden =
    /\b(rm|mv|cp|chmod|chown|sudo|ssh|scp|rsync|docker|kubectl|brew|apt|npm|pnpm|yarn|pip|wget)\b/;
  const forbiddenMatch = trimmed.match(forbidden);
  if (forbiddenMatch) {
    return `X-Ray Bash command is not in the deterministic allowlist: ${forbiddenMatch[1]}`;
  }

  if (/\bcurl\b/.test(trimmed)) {
    return "X-Ray Bash only allows curl for the upstream VERSION check.";
  }

  const normalizedSkillDir = escapeRegExp(skillDir);
  const scriptPattern = new RegExp(
    `${normalizedSkillDir}/scripts/(enumerate\\.sh|analyze_git_security\\.py|generate_svg\\.py)`,
  );
  if (scriptPattern.test(trimmed)) return null;
  if (
    /\b(scripts\/enumerate\.sh|scripts\/analyze_git_security\.py|scripts\/generate_svg\.py)\b/.test(
      trimmed,
    )
  ) {
    return null;
  }
  if (/\bforge\s+coverage\b/.test(trimmed)) return null;
  if (/\bnpx\s+hardhat\s+coverage\b/.test(trimmed)) return null;

  const allowedTokens = new Set([
    "awk",
    "bash",
    "cat",
    "cd",
    "echo",
    "find",
    "forge",
    "git",
    "grep",
    "head",
    "ls",
    "mkdir",
    "npx",
    "printf",
    "pwd",
    "python3",
    "rg",
    "sed",
    "sort",
    "tail",
    "test",
    "uniq",
    "wc",
  ]);

  const segments = trimmed
    .split(/&&|\|\||[;|]/)
    .map((part) => part.trim())
    .filter(Boolean);
  for (const segment of segments) {
    const token = segment.match(/^(?:\(|\s)*(?:env\s+)?([A-Za-z0-9_.-]+)/)?.[1];
    if (!token) continue;
    if (!allowedTokens.has(token)) {
      return `X-Ray Bash command is not in the deterministic allowlist: ${token}`;
    }
    if (token === "mkdir" && !segment.includes("x-ray")) {
      return "X-Ray Bash only allows mkdir for the x-ray artifact directory.";
    }
    if (
      token === "git" &&
      !/^git\s+(rev-parse|log|show|diff|status|ls-files|shortlog|rev-list|describe)\b/.test(segment)
    ) {
      return "X-Ray Bash git usage is limited to read-only inspection commands.";
    }
  }

  return null;
}

function absolutePathsIn(command: string): string[] {
  const matches = command.match(/(?:^|[\s"'(])((?:\/[A-Za-z0-9._~+-]+)+\/?)/g) ?? [];
  return matches
    .map((match) => match.trim().replace(/^["'(]/, ""))
    .filter((candidate) => candidate.startsWith("/"));
}

function redirectionTargets(command: string, repoRoot: string): string[] {
  const matches = [...command.matchAll(/(?:^|[^\d])>>?\s*(['"]?)([^'"&;|)\s]+)\1/g)];
  return matches
    .map((match) => match[2] ?? "")
    .filter((target) => target && !target.startsWith("&"))
    .map((target) => resolveRepoRelative(repoRoot, target));
}

function parseVerdict(markdown: string): XRayReportData["verdict"] {
  const section = extractHeadingSection(markdown, /x-ray verdict/i) ?? markdown;
  const tierMatch = section.match(/\b(FORTIFIED|HARDENED|ADEQUATE|READY|WATCH|FRAGILE|EXPOSED)\b/i);
  const summary =
    firstMeaningfulLine(cleanVerdictSummary(section)) ?? firstMeaningfulLine(markdown) ?? "";
  return {
    ...(tierMatch ? { tier: tierMatch[1]!.toUpperCase() } : {}),
    summary,
  };
}

function parseEntryPointCounts(markdown: string): XRayReportData["entryPointCounts"] {
  const summaryCounts = parseEntryPointSummaryCounts(markdown);
  if (summaryCounts) return summaryCounts;

  const permissionless = countEntriesInSection(markdown, /permissionless/i);
  const roleGated = countEntriesInSection(markdown, /role[- ]?gated|role gated/i);
  const adminOnly = countEntriesInSection(markdown, /admin[- ]?only|admin only/i);
  const sectionalTotal = permissionless + roleGated + adminOnly;
  const fallbackTotal = countEntryRows(markdown);
  const total = sectionalTotal > 0 ? sectionalTotal : fallbackTotal;
  return { permissionless, roleGated, adminOnly, total };
}

function parseInvariantCounts(markdown: string): XRayReportData["invariantCounts"] {
  const global = countUniqueTokens(markdown, /\bG-?\d+\b/gi);
  const integration = countUniqueTokens(markdown, /\bI-?\d+\b/gi);
  const crossChain = countUniqueTokens(markdown, /\bX-?\d+\b/gi);
  const economic = countUniqueTokens(markdown, /\bE-?\d+\b/gi);
  const total = global + integration + crossChain + economic || countInvariantHeadings(markdown);
  return { global, integration, crossChain, economic, total };
}

function countEntriesInSection(markdown: string, heading: RegExp): number {
  const section = extractHeadingSection(markdown, heading);
  return section ? countEntryRows(section) : 0;
}

function countEntryRows(markdown: string): number {
  const headingRows = (
    markdown.match(/^#{3,5}\s+(?!permissionless|role[- ]?gated|admin[- ]?only).+/gim) ?? []
  ).filter((line) => isLikelyEntryLabel(line.replace(/^#{3,5}\s+/, ""))).length;
  const tableRows = (markdown.match(/^\|\s*`?[^|\s][^|]*\|/gm) ?? []).filter((line) => {
    if (/^\|\s*-+/.test(line) || /\b(entry|permission|role|admin|aspect|detail)\b/i.test(line)) {
      return false;
    }
    const firstCell = line.split("|")[1]?.trim() ?? "";
    return isLikelyEntryLabel(firstCell);
  }).length;
  return Math.max(headingRows, tableRows);
}

function parseEntryPointSummaryCounts(markdown: string): XRayReportData["entryPointCounts"] | null {
  const summaryLines = markdown.split(/\r?\n/).map((line) => line.replace(/^>\s*/, "").trim());

  for (const summaryLine of summaryLines) {
    if (!/\b(entry points?|permissionless|role[- ]?gated|admin[- ]?only)\b/i.test(summaryLine)) {
      continue;
    }

    const total = readCount(summaryLine, /(\d+)\s+entry points?\b/i);
    const permissionless = readCount(summaryLine, /(\d+)\s+permissionless\b/i);
    const roleGated = readCount(summaryLine, /(\d+)\s+role[- ]?gated\b/i);
    const adminOnly = readCount(summaryLine, /(\d+)\s+admin[- ]?only\b/i);
    if (
      total === undefined &&
      permissionless === undefined &&
      roleGated === undefined &&
      adminOnly === undefined
    ) {
      continue;
    }

    const parsedPermissionless = permissionless ?? 0;
    const parsedRoleGated = roleGated ?? 0;
    const parsedAdminOnly = adminOnly ?? 0;
    return {
      permissionless: parsedPermissionless,
      roleGated: parsedRoleGated,
      adminOnly: parsedAdminOnly,
      total: total ?? parsedPermissionless + parsedRoleGated + parsedAdminOnly,
    };
  }

  return null;
}

function readCount(text: string, regex: RegExp): number | undefined {
  const match = text.match(regex);
  if (!match?.[1]) return undefined;
  const value = Number.parseInt(match[1], 10);
  return Number.isFinite(value) ? value : undefined;
}

function isLikelyEntryLabel(value: string): boolean {
  const normalized = value.replace(/[`*_]/g, "").trim();
  return /\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?\s*\(/.test(normalized);
}

function countInvariantHeadings(markdown: string): number {
  return (markdown.match(/^#{3,5}\s+.*invariant/gi) ?? []).length;
}

function extractHeadingSection(markdown: string, heading: RegExp): string | null {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((line) => /^#{1,3}\s+/.test(line) && heading.test(line));
  if (start === -1) return null;
  const level = lines[start]!.match(/^(#+)/)?.[1].length ?? 2;
  const end = lines.findIndex((line, index) => {
    if (index <= start) return false;
    const match = line.match(/^(#+)\s+/);
    return Boolean(match && match[1]!.length <= level);
  });
  return lines.slice(start + 1, end === -1 ? undefined : end).join("\n");
}

function countUniqueTokens(text: string, regex: RegExp): number {
  return new Set(
    (text.match(regex) ?? []).map((token) =>
      token.toUpperCase().replace(/^([GIEX])(\d+)$/u, "$1-$2"),
    ),
  ).size;
}

function firstMeaningfulLine(markdown: string): string | undefined {
  return markdown
    .split(/\r?\n/)
    .map((line) =>
      line
        .replace(/^#+\s*/, "")
        .replace(/^>\s*/, "")
        .replace(/\*\*/g, "")
        .replace(/^[-*]+\s*/, "")
        .replace(/^[\s:—-]+/, "")
        .trim(),
    )
    .find((line) => line.length > 0 && !/^[-|:]+$/.test(line));
}

function cleanVerdictSummary(markdown: string): string {
  return markdown.replace(/\b(FORTIFIED|HARDENED|ADEQUATE|READY|WATCH|FRAGILE|EXPOSED)\b/gi, "");
}

function readFile(filePath: string): string {
  try {
    return readFileSync(filePath, "utf8");
  } catch (err) {
    throw new Error(`Unable to read ${filePath}: ${toErrorMessage(err)}`);
  }
}

function readString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readStringAny(
  record: Record<string, unknown>,
  keys: readonly string[],
): string | undefined {
  for (const key of keys) {
    const value = readString(record, key);
    if (value) return value;
  }
  return undefined;
}

function resolveRepoRelative(repoRoot: string, candidate: string): string {
  return path.isAbsolute(candidate) ? path.resolve(candidate) : path.resolve(repoRoot, candidate);
}

function relayAbort(signal?: AbortSignal): AbortController | undefined {
  if (!signal) return undefined;
  const controller = new AbortController();
  if (signal.aborted) {
    controller.abort();
    return controller;
  }
  signal.addEventListener("abort", () => controller.abort(), { once: true });
  return controller;
}

function truncateLines(text: string, maxLines: number): string {
  const lines = text.split(/\r?\n/);
  if (lines.length <= maxLines) return text;
  return [...lines.slice(0, maxLines), `... (${lines.length - maxLines} lines omitted)`].join("\n");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export const __xRayRunnerInternals = {
  allowedToolsFor,
  collectAgentRun,
  parseVerdict,
  parseEntryPointCounts,
  parseInvariantCounts,
  explainDeniedBash,
};
