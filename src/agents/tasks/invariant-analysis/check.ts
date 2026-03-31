import { createHash } from "node:crypto";
import path from "node:path";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { createLogger } from "../../../logger.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask, TaskContext } from "../../types.js";
import { resolveTaskAllowedTools } from "../runtime-overrides.js";
import {
  resolveInvariantAnalysisConfig,
  INVARIANT_CHECK_SCHEMA,
  type Invariant,
  type InvariantDocument,
  type InvariantViolation,
} from "./types.js";

const log = createLogger({ stage: "invariant-check" });

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
    "Report violations with supporting evidence from the code. Include the specific file and line where the violation occurs. If you are uncertain, still report the violation but set confidence below 0.5.",
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

  if (!invariantId || !invariantStatement || !violatingFilePath || !violationDescription) return null;

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
    impact: violation.severity === "ERROR" ? "HIGH" : violation.severity === "INFO" ? "LOW" : "MEDIUM",
    cwe: cweList,
    score: scoreFindingMetadata({
      severity: violation.severity,
      likelihood: confidenceLabel,
      impact: violation.severity === "ERROR" ? "HIGH" : violation.severity === "INFO" ? "LOW" : "MEDIUM",
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
    const doc = asInvariantDocument(context.upstreamOutputs.get("invariant-extract"));

    if (doc === undefined) {
      throw new Error("[invariant-check] Upstream invariant-extract failed or produced no output");
    }
    if (doc.invariants.length === 0) {
      log.info("No invariants to check");
      return [];
    }

    const invariantsToCheck = cfg.securityOnly
      ? doc.invariants.filter(
          (inv) => inv.securityRelevance === "high" || inv.securityRelevance === "medium",
        )
      : doc.invariants;

    if (invariantsToCheck.length === 0) {
      log.info("No invariants to check after filtering");
      return [];
    }

    const runtime = context.runtime;
    const tag = "[invariant-check]";
    const batches = chunkArray(invariantsToCheck, cfg.checkBatchSize);

    log.info(`Checking ${invariantsToCheck.length} invariants in ${batches.length} batch(es) (model=${cfg.checkModel})`);

    const allViolations: InvariantViolation[] = [];
    let totalCostUsd = 0;

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      const prompt = buildCheckPrompt(batch);
      let structuredOutput: unknown;
      let resultText = "";
      let batchCostUsd = 0;

      try {
        for await (const message of runtime.query({
          prompt,
          options: {
            cwd: context.repoRoot,
            model: cfg.checkModel,
            allowedTools: resolveTaskAllowedTools(context),
            permissionMode: "dontAsk",
            outputFormat: {
              type: "json_schema",
              schema: INVARIANT_CHECK_SCHEMA,
              strict: true,
              retryInvalidStructuredOutput: 2,
            },
          },
        })) {
          if (message.type !== "result") continue;
          if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
            batchCostUsd = message.totalCostUsd;
          }
          if ("result" in message) {
            resultText = message.result;
            structuredOutput = message.structuredOutput;
          }
        }
      } catch (error) {
        throw new Error(`${tag} Batch ${i + 1}/${batches.length} error: ${toErrorMessage(error)}`);
      }

      const parsed = structuredOutput ?? parseJson(resultText, tag);
      const batchViolations = parseViolations(parsed, cfg.confidenceThreshold);
      totalCostUsd += batchCostUsd;

      log.info(`Batch ${i + 1}/${batches.length}: resultLen=${resultText.length} structured=${structuredOutput !== undefined} preThreshold=${countPreThreshold(parsed)} postThreshold=${batchViolations.length}`);

      allViolations.push(...batchViolations);
    }

    const violations = allViolations;
    log.info(`Found ${violations.length} violations total`);

    return attachTaskOutputMeta(
      violations.map((v) => violationToFinding(v, context.repoRoot, context.repoName)),
      { costUsd: totalCostUsd },
    );
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

function asInvariantDocument(value: unknown): InvariantDocument | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  if (!Array.isArray(value["invariants"]) || !isRecord(value["coverage"])) {
    return undefined;
  }

  const coverage = value["coverage"];

  return {
    version: typeof value["version"] === "string" ? value["version"] : "1.0",
    invariants: value["invariants"].flatMap((item) => {
      if (!isRecord(item) || !isRecord(item["scope"])) {
        return [];
      }

      const scope = item["scope"];
      const id = typeof item["id"] === "string" ? item["id"] : "";
      const statement = typeof item["statement"] === "string" ? item["statement"] : "";
      const derivedFrom = typeof item["derivedFrom"] === "string" ? item["derivedFrom"] : "";
      if (!id || !statement || !derivedFrom) {
        return [];
      }

      return [{
        id,
        kind: typeof item["kind"] === "string"
          ? item["kind"] as InvariantDocument["invariants"][number]["kind"]
          : "data-invariant",
        scope: {
          filePath: typeof scope["filePath"] === "string" ? scope["filePath"] : "",
          startLine: Math.max(1, Number(scope["startLine"]) || 1),
          endLine: Math.max(1, Number(scope["endLine"]) || 1),
          functionName: typeof scope["functionName"] === "string" ? scope["functionName"] : undefined,
          className: typeof scope["className"] === "string" ? scope["className"] : undefined,
        },
        statement,
        formalExpression: typeof item["formalExpression"] === "string" ? item["formalExpression"] : undefined,
        confidence: Number.isFinite(Number(item["confidence"])) ? Number(item["confidence"]) : 0,
        derivedFrom,
        securityRelevance: typeof item["securityRelevance"] === "string"
          ? item["securityRelevance"] as InvariantDocument["invariants"][number]["securityRelevance"]
          : "none",
        category: typeof item["category"] === "string" ? item["category"] : undefined,
      }];
    }),
    coverage: {
      filesAnalyzed: Math.max(0, Number(coverage["filesAnalyzed"]) || 0),
      functionsAnalyzed: Math.max(0, Number(coverage["functionsAnalyzed"]) || 0),
      invariantsFound: Math.max(0, Number(coverage["invariantsFound"]) || 0),
    },
  };
}

function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

function chunkArray<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

function countPreThreshold(raw: unknown): number {
  if (!isRecord(raw) || !Array.isArray(raw["violations"])) return 0;
  return (raw["violations"] as unknown[]).length;
}

export const __invariantCheckInternals = {
  buildCheckPrompt,
  parseViolations,
  normalizeViolation,
  violationToFinding,
  computeFingerprint,
};
