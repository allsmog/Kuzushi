import { createHash } from "node:crypto";
import path from "node:path";
import type { AgentMessage } from "../../agent-runtime/types.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TaintPathStep } from "../../scanners/types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { ExecutionContext } from "../types.js";
import { TAINT_IRIS_NEXT_ATTRIBUTION, TAINT_IRIS_NEXT_TUI_HEADER_LINES } from "./copy.js";
import { validateAgentCweSelections } from "./cwe-reference.js";
import type {
  TaintIrisNextAgentFinding,
  TaintIrisNextAgentOutput,
  TaintIrisNextAgentResult,
  TaintIrisNextAgentSelection,
  TaintIrisNextEvidence,
  TaintIrisNextEvidenceResult,
  TaintIrisNextPlan,
} from "./types.js";

export const TAINT_IRIS_NEXT_AGENT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["selectedCwes", "findings", "notes"],
  properties: {
    selectedCwes: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "cwe",
          "reason",
          "catalogSignals",
          "sourceSpec",
          "sinkSpec",
          "sanitizerSpec",
          "customCweRationale",
        ],
        properties: {
          cwe: { type: "string" },
          reason: { type: "string" },
          catalogSignals: { type: "array", items: { type: "string" } },
          sourceSpec: { type: "string" },
          sinkSpec: { type: "string" },
          sanitizerSpec: { type: "string" },
          customCweRationale: { type: "string" },
        },
      },
    },
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "title",
          "cwe",
          "severity",
          "confidence",
          "filePath",
          "startLine",
          "message",
          "sourceSinkTrace",
          "catalogSignals",
          "customCweRationale",
          "taintPath",
        ],
        properties: {
          title: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
          filePath: { type: "string" },
          startLine: { type: "integer" },
          message: { type: "string" },
          sourceSinkTrace: { type: "string" },
          catalogSignals: { type: "array", items: { type: "string" } },
          customCweRationale: { type: "string" },
          taintPath: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["filePath", "line", "message", "snippet"],
              properties: {
                filePath: { type: "string" },
                line: { type: "integer" },
                message: { type: "string" },
                snippet: { type: "string" },
              },
            },
          },
        },
      },
    },
    notes: { type: "array", items: { type: "string" } },
  },
} as const;

export function buildTaintIrisNextAgentPrompt(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
): string {
  return [
    ...TAINT_IRIS_NEXT_TUI_HEADER_LINES,
    "",
    TAINT_IRIS_NEXT_ATTRIBUTION,
    "",
    "You are Kuzushi's Taint IRIS Next agent. This is an agent-forward adaptation inspired by the IRIS paper, not the original IRIS implementation.",
    "",
    "## Objective",
    "Use the deterministic context, threat model, CWE catalog, and evidence bundles below to select relevant taint CWE themes and report only defensible findings.",
    "Do not invent a vulnerability class when a catalog CWE fits. If you use a non-catalog CWE, include customCweRationale.",
    "",
    "## Backend",
    `requested: ${plan.backend.requested}`,
    `selected: ${plan.backend.selected}`,
    `evidence tool: ${evidenceResult.tool}`,
    plan.backend.codeqlDbPath
      ? `existing CodeQL DB: ${plan.backend.codeqlDbPath}`
      : "existing CodeQL DB: none",
    "",
    "## Context Summary",
    renderContextSummary(plan),
    "",
    "## Threat Model Summary",
    renderThreatModelSummary(plan),
    "",
    plan.promptCatalog,
    "",
    "## Evidence Bundles",
    renderEvidenceBundles(evidenceResult.evidence),
    "",
    "## Contract",
    "- Select final CWE themes only from the CWE Candidate Catalog unless customCweRationale is present.",
    "- Cite catalogSignals for every selected CWE and every finding.",
    "- Refine sourceSpec, sinkSpec, and sanitizerSpec from the evidence and threat model.",
    "- Return strict JSON matching the schema: { selectedCwes, findings, notes }.",
    `- Return at most ${plan.caps.maxAgentFindings} findings.`,
    "- Findings must include filePath, startLine, sourceSinkTrace, catalogSignals, and taintPath.",
    "- Skip weak matches that are only keyword hits without a credible source-to-sink story.",
    "- If evidence bundles are non-empty but you select no CWEs, notes[0] must start with NO_SELECTION: and explain why the evidence is insufficient.",
  ].join("\n");
}

export async function runTaintIrisNextAgent(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
  ctx: ExecutionContext,
): Promise<TaintIrisNextAgentResult> {
  const prompt = buildTaintIrisNextAgentPrompt(plan, evidenceResult);
  const abortController = new AbortController();
  const abortFromContext = (): void => abortController.abort();
  if (ctx.signal?.aborted) abortController.abort();
  ctx.signal?.addEventListener("abort", abortFromContext, { once: true });

  const fingerprint = "taint-iris-next:agent";
  ctx.reportAgentActivity?.(fingerprint, "tool-start", {
    toolName: "IRIS Next Agent",
    summary: "selecting CWE themes from bounded evidence",
    index: 1,
    total: 1,
  });

  let structuredOutput: unknown;
  let resultText = "";
  let costUsd = 0;

  try {
    for await (const message of ctx.runtime.query({
      prompt,
      options: {
        cwd: plan.repoRoot,
        model: ctx.toolModel ?? ctx.modelOverride ?? ctx.config.model,
        allowedTools: ["Read", "Grep", "Glob"],
        permissionMode: "dontAsk",
        abortController,
        taskId: "taint-iris-next:hunt",
        fingerprint,
        phase: "scan",
        ...(plan.maxBudgetUsd !== undefined ? { maxBudgetUsd: plan.maxBudgetUsd } : {}),
        outputFormat: {
          type: "json_schema",
          schema: TAINT_IRIS_NEXT_AGENT_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 2,
        },
      },
    })) {
      if (ctx.signal?.aborted) break;
      forwardAgentActivity(ctx, fingerprint, message);
      if (message.type !== "result") continue;
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
        costUsd = message.totalCostUsd;
      }
      if ("result" in message) {
        resultText = message.result;
        structuredOutput = message.structuredOutput;
      }
    }
  } catch (error) {
    throw new Error(`[taint-iris-next] Agent error: ${toErrorMessage(error)}`);
  } finally {
    ctx.signal?.removeEventListener("abort", abortFromContext);
    ctx.reportAgentActivity?.(fingerprint, "tool-complete", {
      summary: "IRIS Next agent session complete",
      index: 1,
      total: 1,
      done: true,
    });
  }

  const rawOutput = structuredOutput ?? tryParseJson(resultText);
  const parsed = parseAgentOutput(rawOutput);
  const warnings: string[] = [];
  if (!isRecord(rawOutput)) {
    warnings.push("agent returned no structured JSON output");
  }
  if (evidenceResult.evidence.length > 0 && parsed.selectedCwes.length === 0) {
    const rationale = parsed.notes?.find((note) => note.trim().startsWith("NO_SELECTION:"));
    warnings.push(
      rationale ??
        `agent selected no CWEs from ${evidenceResult.evidence.length} evidence row(s) and did not provide a NO_SELECTION rationale`,
    );
  }
  const selectionValidation = validateAgentCweSelections(parsed.selectedCwes, plan.catalog);
  if (!selectionValidation.valid) {
    const rejected = selectionValidation.rejected
      .map((item) => `${item.cwe}: ${item.reason}`)
      .join("; ");
    throw new Error(`[taint-iris-next] Agent selected invalid CWEs: ${rejected}`);
  }

  const findings = normalizeAgentFindings(parsed.findings, plan, evidenceResult.evidence, warnings);
  return {
    selectedCwes: selectionValidation.accepted,
    findings: findings.slice(0, plan.caps.maxAgentFindings),
    rawOutput,
    warnings,
    costUsd,
  };
}

export function parseAgentOutput(raw: unknown): TaintIrisNextAgentOutput {
  if (!isRecord(raw)) return { selectedCwes: [], findings: [], notes: [] };
  const selectedCwes = Array.isArray(raw["selectedCwes"])
    ? raw["selectedCwes"]
        .map(parseSelection)
        .filter((item): item is TaintIrisNextAgentSelection => !!item)
    : [];
  const findings = Array.isArray(raw["findings"])
    ? raw["findings"].map(parseFinding).filter((item): item is TaintIrisNextAgentFinding => !!item)
    : [];
  const notes = Array.isArray(raw["notes"])
    ? raw["notes"].filter((item): item is string => typeof item === "string")
    : [];
  return { selectedCwes, findings, notes };
}

function normalizeAgentFindings(
  rawFindings: readonly TaintIrisNextAgentFinding[],
  plan: TaintIrisNextPlan,
  evidence: readonly TaintIrisNextEvidence[],
  warnings: string[],
): Finding[] {
  const catalogIds = new Set(plan.catalog.map((entry) => entry.cwe));
  const out: Finding[] = [];

  for (const item of rawFindings) {
    const cwe = item.cwe.trim().toUpperCase();
    if (!catalogIds.has(cwe) && !item.customCweRationale?.trim()) {
      warnings.push(`dropped finding with non-catalog CWE ${cwe} and no customCweRationale`);
      continue;
    }
    if (!item.title.trim() || !item.filePath.trim() || !item.message.trim()) continue;

    const severity = mapSeverity(item.severity);
    const confidence = mapConfidence(item.confidence);
    const normalizedPath = normalizePath(plan.repoRoot, item.filePath);
    const startLine = Math.max(1, Math.floor(Number(item.startLine) || 1));
    const relatedEvidence = evidence.filter((candidate) => candidate.cwe === cwe).slice(0, 4);
    const taintPath = normalizeTaintPath(item, plan.repoRoot, relatedEvidence);
    const fingerprint = createHash("sha256")
      .update(
        ["taint-iris-next", plan.repoRoot, cwe, normalizedPath, startLine, item.title].join("|"),
      )
      .digest("hex");

    out.push({
      taskId: "taint-iris-next",
      fingerprint,
      ruleId: `taint-iris-next/${cwe || "custom"}`,
      filePath: normalizedPath,
      startLine,
      severity,
      message: `[${cwe}] ${item.title}: ${item.message}`,
      evidence: item.sourceSinkTrace || renderEvidenceSummary(relatedEvidence),
      scannerConfidence: confidence,
      subcategory: [
        "taint",
        plan.catalog.find((entry) => entry.cwe === cwe)?.taintClass ?? "custom",
      ],
      likelihood: confidence,
      impact: severity === "ERROR" ? "HIGH" : severity === "WARNING" ? "MEDIUM" : "LOW",
      cwe: cwe ? [cwe] : [],
      score: scoreFindingMetadata({
        severity,
        likelihood: confidence,
        impact: severity === "ERROR" ? "HIGH" : severity === "WARNING" ? "MEDIUM" : "LOW",
        subcategory: ["taint"],
      }),
      taintPath: taintPath.length > 0 ? taintPath : undefined,
      proofState: "symbolic_only",
      engineProvenance: [
        {
          kind: "agentic",
          detail: `taint-iris-next agent-forward adaptation; backend=${plan.backend.selected}; cwe=${cwe}`,
        },
        {
          kind: plan.backend.selected === "codeql" ? "codeql" : "taint-analysis",
          detail: `evidence source=${plan.backend.selected}; bundled structural signals=${relatedEvidence.length}`,
        },
      ],
    });
  }

  return out;
}

function parseSelection(raw: unknown): TaintIrisNextAgentSelection | undefined {
  if (!isRecord(raw)) return undefined;
  const cwe = str(raw["cwe"]);
  if (!cwe) return undefined;
  return {
    cwe,
    reason: str(raw["reason"]) || undefined,
    signalCitations: stringArray(raw["signalCitations"]),
    catalogSignals: stringArray(raw["catalogSignals"]),
    sourceSpec: str(raw["sourceSpec"]) || undefined,
    sinkSpec: str(raw["sinkSpec"]) || undefined,
    sanitizerSpec: str(raw["sanitizerSpec"]) || undefined,
    customCweRationale: str(raw["customCweRationale"]) || undefined,
  };
}

function parseFinding(raw: unknown): TaintIrisNextAgentFinding | undefined {
  if (!isRecord(raw)) return undefined;
  const title = str(raw["title"]);
  const cwe = str(raw["cwe"]);
  const filePath = str(raw["filePath"]);
  const message = str(raw["message"]);
  if (!title || !cwe || !filePath || !message) return undefined;
  return {
    title,
    cwe,
    severity: mapAgentSeverity(str(raw["severity"])),
    confidence: mapAgentConfidence(str(raw["confidence"])),
    filePath,
    startLine: Math.max(1, Math.floor(Number(raw["startLine"]) || 1)),
    message,
    sourceSinkTrace: str(raw["sourceSinkTrace"]),
    catalogSignals: stringArray(raw["catalogSignals"]),
    customCweRationale: str(raw["customCweRationale"]) || undefined,
    taintPath: parseTaintPath(raw["taintPath"]),
  };
}

function parseTaintPath(raw: unknown): TaintIrisNextAgentFinding["taintPath"] {
  if (!Array.isArray(raw)) return [];
  const out: NonNullable<TaintIrisNextAgentFinding["taintPath"]> = [];
  for (const item of raw) {
    if (!isRecord(item)) continue;
    const filePath = str(item["filePath"]);
    if (!filePath) continue;
    out.push({
      filePath,
      line: Math.max(1, Math.floor(Number(item["line"]) || 1)),
      message: str(item["message"]) || undefined,
      snippet: str(item["snippet"]) || undefined,
    });
  }
  return out;
}

function normalizeTaintPath(
  item: TaintIrisNextAgentFinding,
  repoRoot: string,
  evidence: readonly TaintIrisNextEvidence[],
): TaintPathStep[] {
  const explicit = item.taintPath ?? [];
  if (explicit.length > 0) {
    return explicit.map((step) => ({
      filePath: normalizePath(repoRoot, step.filePath),
      line: Math.max(1, step.line),
      message: step.message,
      snippet: step.snippet,
    }));
  }
  return evidence.slice(0, 3).map((step) => ({
    filePath: step.filePath,
    line: step.line,
    message: `${step.role}: ${step.catalogSignal}`,
    snippet: step.snippet,
  }));
}

function renderContextSummary(plan: TaintIrisNextPlan): string {
  const context = plan.repoContext;
  if (!context) return "No context loaded.";
  return [
    `languages: ${context.languages.join(", ") || plan.languages.join(", ") || "unknown"}`,
    `frameworks: ${context.frameworks.join(", ") || "none"}`,
    `auth: ${context.authPatterns.join(", ") || "none"}`,
    `db/orm: ${context.ormOrDb.join(", ") || "none"}`,
    `entry points: ${context.entryPoints.slice(0, 12).join(", ") || "none"}`,
  ].join("\n");
}

function renderThreatModelSummary(plan: TaintIrisNextPlan): string {
  const threatModel = plan.threatModel;
  if (!threatModel) return "No threat model loaded.";
  const lines = [`threats: ${threatModel.threats.length}`];
  for (const threat of threatModel.threats.slice(0, 10)) {
    lines.push(
      `- ${threat.id}: ${threat.title} [${threat.impact}/${threat.likelihood}] CWE=${(threat.relatedCwe ?? []).join(", ") || "n/a"}`,
    );
  }
  return lines.join("\n");
}

function renderEvidenceBundles(evidence: readonly TaintIrisNextEvidence[]): string {
  if (evidence.length === 0) {
    return "No structural evidence matched. The agent should return no findings unless repository reads reveal a defensible path.";
  }
  const byCwe = new Map<string, TaintIrisNextEvidence[]>();
  for (const item of evidence) {
    const group = byCwe.get(item.cwe) ?? [];
    group.push(item);
    byCwe.set(item.cwe, group);
  }

  const lines: string[] = [];
  for (const [cwe, items] of byCwe) {
    lines.push(`### ${cwe} (${items[0]?.taintClass ?? "taint"})`);
    for (const item of items.slice(0, 16)) {
      lines.push(
        `- ${item.role} ${item.catalogSignal} @ ${item.filePath}:${item.line} [${item.language}, ${item.confidence}] ${item.snippet}`,
      );
    }
  }
  return lines.join("\n");
}

function renderEvidenceSummary(evidence: readonly TaintIrisNextEvidence[]): string | null {
  if (evidence.length === 0) return null;
  return evidence
    .map((item) => `${item.role} ${item.catalogSignal} at ${item.filePath}:${item.line}`)
    .join("\n");
}

function forwardAgentActivity(
  ctx: ExecutionContext,
  fingerprint: string,
  message: AgentMessage,
): void {
  if (message.type === "assistant") {
    for (const block of message.content) {
      const blockType = typeof block["type"] === "string" ? block["type"] : "";
      if (blockType === "tool_use") {
        ctx.reportAgentActivity?.(fingerprint, "tool-start", {
          toolName: str(block["name"]) || "tool",
          toolInput: isRecord(block["input"]) ? block["input"] : {},
        });
      } else if (blockType === "text") {
        const text = str(block["text"]);
        if (text) {
          ctx.reportAgentActivity?.(fingerprint, "reasoning", {
            summary: text.length > 180 ? `${text.slice(0, 177)}...` : text,
          });
        }
      }
    }
    return;
  }
  if (message.type === "tool-progress") {
    ctx.reportAgentActivity?.(fingerprint, "tool-progress", {
      toolName: message.toolName,
      elapsedSeconds: message.elapsedSeconds,
    });
    return;
  }
  if (message.type === "tool-summary") {
    ctx.reportAgentActivity?.(fingerprint, "tool-complete", { summary: message.summary });
    return;
  }
  if (message.type === "tool-result") {
    ctx.reportAgentActivity?.(fingerprint, "tool-complete", {
      summary: message.isError ? "tool result errored" : "tool result returned",
      toolName: message.toolUseId,
    });
  }
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const rel = path.relative(repoRoot, filePath);
  return rel.startsWith("..") ? filePath : rel || filePath;
}

function mapSeverity(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return "ERROR";
    case "medium":
      return "WARNING";
    default:
      return "INFO";
  }
}

function mapConfidence(confidence: string | undefined): string {
  switch ((confidence ?? "").toLowerCase()) {
    case "high":
      return "HIGH";
    case "low":
      return "LOW";
    default:
      return "MEDIUM";
  }
}

function mapAgentSeverity(severity: string): TaintIrisNextAgentFinding["severity"] {
  if (severity === "critical" || severity === "high" || severity === "low" || severity === "info") {
    return severity;
  }
  return "medium";
}

function mapAgentConfidence(confidence: string): "high" | "medium" | "low" {
  if (confidence === "high" || confidence === "low") return confidence;
  return "medium";
}

function str(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
