import type { AgentTask, TaskContext } from "../agents/types.js";
import type { ScannerConfig, ScannerPlugin, Finding } from "../scanners/types.js";
import { getTaskOutputMeta } from "../task-output-meta.js";
import { isRecord, normalizeCostUsd } from "../utils.js";

export interface ExecutedTaskResult {
  output: unknown;
  emittedFindings: Finding[];
  durationMs: number;
  costUsd: number;
}

export interface ExecutedScannerResult {
  findings: Finding[];
  durationMs: number;
  costUsd: number;
}

export async function executeAgentTask(
  task: AgentTask,
  input: unknown,
  context: TaskContext,
  config: ScannerConfig,
): Promise<ExecutedTaskResult> {
  const startedAt = Date.now();

  if (task.init) {
    await task.init(config);
  }

  const output = await task.run(input, context);

  return {
    output,
    emittedFindings: extractTaskFindings(task.outputKind, output),
    durationMs: Date.now() - startedAt,
    costUsd: normalizeCostUsd(getTaskOutputMeta(output)?.costUsd),
  };
}

export async function executeScannerPlugin(
  plugin: ScannerPlugin,
  repoRoot: string,
  input: Parameters<ScannerPlugin["scan"]>[1],
  config: ScannerConfig,
): Promise<ExecutedScannerResult> {
  const startedAt = Date.now();

  if (plugin.init) {
    await plugin.init(config);
  }

  const findings = await plugin.scan(repoRoot, input, config);

  return {
    findings,
    durationMs: Date.now() - startedAt,
    costUsd: normalizeCostUsd(getTaskOutputMeta(findings)?.costUsd),
  };
}

export function extractTaskFindings(
  outputKind: AgentTask["outputKind"],
  output: unknown,
): Finding[] {
  if (outputKind === "findings") {
    return asFindings(output);
  }

  if (outputKind === "threat-model") {
    if (!isRecord(output) || !Array.isArray(output["findings"])) {
      return [];
    }
    return asFindings(output["findings"]);
  }

  return [];
}

function asFindings(value: unknown): Finding[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const findings: Finding[] = [];
  for (const item of value) {
    if (!isRecord(item)) {
      continue;
    }

    const finding = asFinding(item);
    if (!finding) {
      continue;
    }

    findings.push(finding);
  }

  return findings;
}

function asFinding(item: Record<string, unknown>): Finding | null {
  const fingerprint = asString(item["fingerprint"]);
  const ruleId = asString(item["ruleId"]);
  const filePath = asString(item["filePath"]);
  const startLine = asNumber(item["startLine"]);
  const severity = asString(item["severity"]);
  const message = asString(item["message"]);

  if (!fingerprint || !ruleId || !filePath || !Number.isFinite(startLine) || !severity || !message) {
    return null;
  }

  return {
    scanner: asString(item["scanner"]) || "unknown",
    fingerprint,
    ruleId,
    filePath,
    startLine,
    severity,
    message,
    evidence: asNullableString(item["evidence"]),
    scannerConfidence: asString(item["scannerConfidence"]) || "MEDIUM",
    subcategory: asStringArray(item["subcategory"]),
    likelihood: asString(item["likelihood"]) || "MEDIUM",
    impact: asString(item["impact"]) || "MEDIUM",
    cwe: asStringArray(item["cwe"]),
    score: asNumber(item["score"]) || 0,
  };
}

function asString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  return "";
}

function asNullableString(value: unknown): string | null {
  if (typeof value === "string") {
    return value;
  }

  return null;
}

function asNumber(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((item) => String(item));
}
