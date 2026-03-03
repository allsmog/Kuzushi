import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../../agent-runtime/index.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask, TaskContext } from "../../types.js";
import {
  resolveInvariantAnalysisConfig,
  INVARIANT_CHECK_SCHEMA,
  type Invariant,
  type InvariantDocument,
  type InvariantViolation,
} from "./types.js";

function buildCheckPrompt(invariants: Invariant[]): string {
  const invariantDescriptions = invariants.map((inv) =>
    `- [${inv.id}] (${inv.kind}) ${inv.scope.filePath}:${inv.scope.startLine}: "${inv.statement}" (confidence: ${inv.confidence}, security: ${inv.securityRelevance})`
  ).join("\n");

  return [
    "You are an invariant violation checker.",
    "Given the following invariants inferred from the codebase, check whether any code path violates them.",
    "",
    "## Invariants to check",
    invariantDescriptions,
    "",
    "## Instructions",
    "1. For each invariant, use Read to examine the scope file and callers/callees.",
    "2. Check: 'Does any code path violate this invariant?'",
    "3. If yes, report the violation with the violating file/line and a description of how the invariant is broken.",
    "4. Assess severity: ERROR for security-critical violations, WARNING for significant, INFO for minor.",
    "5. If possible, describe an attack scenario that exploits the violation.",
    "",
    "Only report violations you can verify in code. Do not report speculative violations.",
  ].join("\n");
}

function parseViolations(raw: unknown, confidenceThreshold: number): InvariantViolation[] {
  if (!isRecord(raw) || !Array.isArray(raw["violations"])) return [];

  const violations: InvariantViolation[] = [];
  for (const item of raw["violations"] as unknown[]) {
    if (!isRecord(item)) continue;
    const v = normalizeViolation(item);
    if (!v) continue;
    if (v.confidence < confidenceThreshold) continue;
    violations.push(v);
  }

  return violations;
}

function normalizeViolation(item: Record<string, unknown>): InvariantViolation | null {
  const invariantId = typeof item["invariantId"] === "string" ? item["invariantId"].trim() : "";
  const invariantStatement = typeof item["invariantStatement"] === "string" ? item["invariantStatement"].trim() : "";
  const violatingFilePath = typeof item["violatingFilePath"] === "string" ? item["violatingFilePath"].trim() : "";
  const violationDescription = typeof item["violationDescription"] === "string" ? item["violationDescription"].trim() : "";

  if (!invariantId || !violatingFilePath || !violationDescription) return null;

  const violatingStartLine = Math.max(1, Math.floor(Number(item["violatingStartLine"]) || 1));
  const severity = normalizeSeverity(item["severity"]);
  const confidence = normalizeUnitNumber(item["confidence"]);

  return {
    invariantId,
    invariantStatement,
    violatingFilePath,
    violatingStartLine,
    violationDescription,
    severity,
    confidence,
    cwe: typeof item["cwe"] === "string" ? item["cwe"].trim() || undefined : undefined,
    attackScenario: typeof item["attackScenario"] === "string" ? item["attackScenario"].trim() || undefined : undefined,
  };
}

function violationToFinding(
  violation: InvariantViolation,
  repoRoot: string,
  repoName: string,
): Finding {
  const filePath = normalizeFilePath(repoRoot, violation.violatingFilePath);
  const cweList = violation.cwe ? [violation.cwe] : [];
  const fingerprint = computeFingerprint(repoName, filePath, violation);

  const confidenceLabel = violation.confidence >= 0.8 ? "HIGH" : violation.confidence >= 0.5 ? "MEDIUM" : "LOW";

  return {
    scanner: "invariant-check",
    fingerprint,
    ruleId: `invariant/${violation.invariantId}${violation.cwe ? `/${violation.cwe}` : ""}`,
    filePath,
    startLine: violation.violatingStartLine,
    severity: violation.severity,
    message: `Invariant violation: "${violation.invariantStatement}" — ${violation.violationDescription}`,
    evidence: violation.attackScenario || null,
    scannerConfidence: confidenceLabel,
    subcategory: ["vuln"],
    likelihood: confidenceLabel,
    impact: violation.severity === "ERROR" ? "HIGH" : "MEDIUM",
    cwe: cweList,
    score: scoreFindingMetadata({
      severity: violation.severity,
      likelihood: confidenceLabel,
      impact: violation.severity === "ERROR" ? "HIGH" : "MEDIUM",
      subcategory: ["vuln"],
    }),
  };
}

function computeFingerprint(repoName: string, filePath: string, violation: InvariantViolation): string {
  const source = [repoName, "invariant-analysis", violation.invariantId, filePath, String(violation.violatingStartLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

function normalizeSeverity(value: unknown): "ERROR" | "WARNING" | "INFO" {
  if (typeof value !== "string") return "WARNING";
  const upper = value.toUpperCase();
  if (upper === "ERROR" || upper === "WARNING" || upper === "INFO") return upper;
  return "WARNING";
}

function normalizeUnitNumber(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

export const invariantCheckTask: AgentTask<ScanOpts, Finding[]> = {
  id: "invariant-check",
  displayName: "Invariant Violation Checker",
  outputKind: "findings",
  dependsOn: ["invariant-extract"],

  async run(_input, context): Promise<Finding[]> {
    const cfg = resolveInvariantAnalysisConfig(context.config);
    const doc = context.upstreamOutputs.get("invariant-extract") as InvariantDocument | undefined;

    if (!doc || doc.invariants.length === 0) {
      console.error("[invariant-check] No invariants to check");
      return [];
    }

    const securityInvariants = doc.invariants.filter(
      (inv) => inv.securityRelevance === "high" || inv.securityRelevance === "medium",
    );

    if (securityInvariants.length === 0) {
      console.error("[invariant-check] No security-relevant invariants to check");
      return [];
    }

    const prompt = buildCheckPrompt(securityInvariants);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";

    const tag = "[invariant-check]";
    console.error(`${tag} Checking ${securityInvariants.length} invariants (model=${cfg.checkModel})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model: cfg.checkModel,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: INVARIANT_CHECK_SCHEMA,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      console.error(`${tag} Error: ${toErrorMessage(error)}`);
      return [];
    }

    const parsed = structuredOutput ?? parseJson(resultText);
    const violations = parseViolations(parsed, cfg.confidenceThreshold);

    console.error(`${tag} Found ${violations.length} violations`);

    return violations.map((v) => violationToFinding(v, context.repoRoot, context.repoName));
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging an invariant violation finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Attack scenario: ${finding.evidence}` : "",
        "",
        "This finding was generated by inferring an invariant from the code and finding a path that violates it.",
        "Verify both that the invariant is correct AND that the violation is reachable.",
      ].filter(Boolean).join("\n"),
    };
  },
};

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return { violations: [] };
  }
}

export const __invariantCheckInternals = {
  buildCheckPrompt,
  parseViolations,
  normalizeViolation,
  violationToFinding,
  computeFingerprint,
};
