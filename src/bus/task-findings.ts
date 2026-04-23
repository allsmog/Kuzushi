import { isHandoff } from "../agents/handoff.js";
import type { AgentTask } from "../agents/types.js";
import type {
  CorroboratingSignal,
  EngineProvenance,
  Finding,
  ProofState,
  SuppressionReason,
  TaintPathStep,
} from "../scanners/types.js";
import { isRecord } from "../utils.js";

/**
 * Extract `Finding[]` from a task's output, unwrapping `TaskHandoff`
 * envelopes and honouring the task's declared `outputKind`.
 *
 * - `findings` — treat the output itself as `Finding[]`.
 * - `threat-model` — look for a `.findings` array inside the output.
 * - Anything else — returns `[]` (tasks that produce threat models,
 *   verdicts, or reports emit findings separately via the bus).
 */
export function extractTaskFindings(
  outputKind: AgentTask["outputKind"],
  output: unknown,
): Finding[] {
  // Unwrap TaskHandoff envelope if present
  const unwrapped = isHandoff(output) ? output.output : output;

  if (outputKind === "findings") {
    return asFindings(unwrapped);
  }

  if (outputKind === "threat-model") {
    if (!isRecord(unwrapped) || !Array.isArray(unwrapped["findings"])) {
      return [];
    }
    return asFindings(unwrapped["findings"]);
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

  if (
    !fingerprint ||
    !ruleId ||
    !filePath ||
    !Number.isFinite(startLine) ||
    !severity ||
    !message
  ) {
    return null;
  }

  return {
    taskId: asString(item["taskId"]) || "unknown",
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
    adjustedScore: asOptionalNumber(item["adjustedScore"]),
    taintPath: asTaintPath(item["taintPath"]),
    proofState: asProofState(item["proofState"]),
    engineProvenance: asEngineProvenance(item["engineProvenance"]),
    corroboratingSignals: asCorroboratingSignals(item["corroboratingSignals"]),
    suppressionReasons: asSuppressionReasons(item["suppressionReasons"]),
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

function asOptionalNumber(value: unknown): number | undefined {
  const parsed = asNumber(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function asCorroboratingSignals(value: unknown): CorroboratingSignal[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const signals: CorroboratingSignal[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const fingerprint = asString(item["fingerprint"]);
    const ruleId = asString(item["ruleId"]);
    const filePath = asString(item["filePath"]);
    const startLine = asNumber(item["startLine"]);
    if (!fingerprint || !ruleId || !filePath || !Number.isFinite(startLine)) {
      continue;
    }
    signals.push({
      taskId: asString(item["taskId"]) || "unknown",
      fingerprint,
      ruleId,
      filePath,
      startLine,
      cwe: asStringArray(item["cwe"]),
      score: asNumber(item["score"]) || 0,
    });
  }

  return signals.length > 0 ? signals : undefined;
}

function asSuppressionReasons(value: unknown): SuppressionReason[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const reasons: SuppressionReason[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const id = asString(item["id"]);
    const description = asString(item["description"]);
    const kind = asString(item["kind"]);
    if (!id || !description || (kind !== "hard" && kind !== "soft")) {
      continue;
    }
    reasons.push({
      id,
      kind,
      description,
      scorePenalty: asOptionalNumber(item["scorePenalty"]),
    });
  }

  return reasons.length > 0 ? reasons : undefined;
}

function asTaintPath(value: unknown): TaintPathStep[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const steps: TaintPathStep[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const filePath = asString(item["filePath"]);
    const line = asNumber(item["line"]);
    if (!filePath || !Number.isFinite(line)) {
      continue;
    }
    steps.push({
      filePath,
      line,
      message: asOptionalStringFromRecord(item["message"]),
      snippet: asOptionalStringFromRecord(item["snippet"]),
    });
  }

  return steps.length > 0 ? steps : undefined;
}

function asProofState(value: unknown): ProofState | undefined {
  const raw = asString(value);
  switch (raw) {
    case "symbolic_only":
    case "execution_attempted":
    case "execution_confirmed":
    case "execution_rejected":
    case "inconclusive":
      return raw;
    default:
      return undefined;
  }
}

function asEngineProvenance(value: unknown): EngineProvenance[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }

  const entries: EngineProvenance[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const detail = asString(item["detail"]);
    const kind = asString(item["kind"]);
    if (!detail) {
      continue;
    }
    if (
      kind !== "semgrep" &&
      kind !== "codeql" &&
      kind !== "taint-analysis" &&
      kind !== "agentic" &&
      kind !== "dynamic"
    ) {
      continue;
    }
    entries.push({ kind, detail });
  }

  return entries.length > 0 ? entries : undefined;
}

function asOptionalStringFromRecord(value: unknown): string | undefined {
  const text = asString(value);
  return text || undefined;
}
