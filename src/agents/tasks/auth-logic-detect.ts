import { runStructuredAgentQuery, resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { Finding } from "../../scanners/types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskRuntime, resolveTaskModel } from "./runtime-overrides.js";
import { resolveThreatModelOutput } from "./threat-model-guidance.js";
import { getLogger } from "../../logger.js";
import { createHash } from "node:crypto";

const log = getLogger("auth-logic-detect");

const AUTH_LOGIC_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "filePath", "startLine", "severity", "description", "attackVector", "cwe"],
        properties: {
          title: { type: "string" },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          attackVector: { type: "string" },
          cwe: { type: "array", items: { type: "string" } },
          evidence: { type: "string" },
          missingControl: { type: "string" },
        },
      },
    },
  },
} as const;

/**
 * Auth Logic Detection task — reasons about authorization patterns
 * beyond what taint tracking can find. Consumes STRIDE threat model
 * + app model to probe authorization boundaries.
 *
 * Detects:
 * - Missing authorization checks on sensitive endpoints
 * - Inconsistent auth enforcement across similar routes
 * - Horizontal privilege escalation (user A accessing user B's data)
 * - Vertical privilege escalation (user → admin)
 * - Parameter tampering for privilege escalation
 * - Authorization bypass through wrapper functions
 */
export const authLogicDetectTask: AgentTask<unknown, Finding[]> = {
  id: "auth-logic-detect",
  displayName: "Authorization Logic Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build"],

  async run(_input, context): Promise<Finding[]> {
    const model = resolveTaskModel(context, "auth-logic-detect");
    const runtime = resolveTaskRuntime(context);

    // Gather upstream data
    const appModel = context.upstreamOutputs.get("app-model-build");
    const strideOutput = resolveThreatModelOutput(context.upstreamOutputs);

    if (!appModel && !strideOutput) {
      log.info("No app model or STRIDE output available — skipping auth logic detection");
      return [];
    }

    // Extract relevant STRIDE threats (elevation-of-privilege focus)
    const elevationThreats = extractElevationThreats(strideOutput);
    const routes = extractRoutes(appModel);
    const boundaries = extractBoundaries(appModel);

    if (routes.length === 0 && elevationThreats.length === 0) {
      log.info("No routes or elevation threats found — skipping");
      return [];
    }

    log.info(`Starting auth logic analysis (model=${model}, routes=${routes.length}, threats=${elevationThreats.length})`);

    const prompt = buildAuthLogicPrompt(routes, elevationThreats, boundaries, context.repoName);

    try {
      const { structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
        prompt,
        cwd: context.repoRoot,
        model,
        allowedTools: [...resolveDefaultReadOnlyTools(runtime)],
        runtimeOptions: { runtime },
        schema: AUTH_LOGIC_SCHEMA,
      });

      if (executionError || !isRecord(structuredOutput)) {
        log.warn(`Auth logic detection failed: ${executionError ?? "no output"}`);
        return [];
      }

      const rawFindings = Array.isArray(structuredOutput["findings"]) ? structuredOutput["findings"] : [];
      const findings: Finding[] = rawFindings
        .filter((f): f is Record<string, unknown> => isRecord(f) && typeof f["filePath"] === "string")
        .map((f) => {
          const filePath = String(f["filePath"]);
          const startLine = typeof f["startLine"] === "number" ? f["startLine"] : 1;
          const cweList = Array.isArray(f["cwe"]) ? f["cwe"].map(String) : ["CWE-862"];

          return {
            taskId: "auth-logic-detect",
            fingerprint: createHash("sha256").update([context.repoName, "auth-logic", filePath, String(f["title"]), String(startLine)].join("|")).digest("hex"),
            ruleId: "auth-logic/" + (String(f["title"] ?? "missing-authz")).toLowerCase().replace(/\s+/g, "-").slice(0, 50),
            filePath,
            startLine,
            severity: normalizeSeverity(f["severity"]),
            message: String(f["description"] ?? f["title"] ?? "Authorization logic flaw"),
            evidence: String(f["evidence"] ?? f["attackVector"] ?? ""),
            scannerConfidence: "HIGH",
            subcategory: ["authorization", "business-logic"],
            likelihood: "HIGH",
            impact: "HIGH",
            cwe: cweList,
            score: normalizeSeverity(f["severity"]) === "ERROR" ? 85 : 65,
            proofState: "symbolic_only",
            engineProvenance: [{ kind: "agentic", detail: "LLM-driven auth-logic-detect analysis" }],
          };
        });

      log.info(`Found ${findings.length} authorization logic findings`);
      return attachTaskOutputMeta(findings, { costUsd });
    } catch (error) {
      log.error(`Auth logic detection error: ${toErrorMessage(error)}`);
      return [];
    }
  },
};

function buildAuthLogicPrompt(
  routes: Array<Record<string, unknown>>,
  elevationThreats: Array<Record<string, unknown>>,
  boundaries: Array<Record<string, unknown>>,
  repoName: string,
): string {
  return [
    "You are an authorization logic security analyst. Analyze this application for authorization flaws.",
    "",
    "Focus on finding REAL authorization vulnerabilities, not theoretical ones:",
    "- Missing authorization checks on endpoints that should be restricted",
    "- Inconsistent auth enforcement (some admin endpoints check roles, others don't)",
    "- Horizontal privilege escalation (user A can access user B's resources)",
    "- Vertical privilege escalation (regular user can access admin functions)",
    "- Parameter tampering that bypasses authorization (e.g. admin=true, role=admin in request)",
    "- IDOR (Insecure Direct Object References) where object ownership isn't verified",
    "",
    "Use the Read, Glob, and Grep tools to examine the actual code. Don't guess — verify.",
    "For each finding, provide the exact file path and line number where the flaw exists.",
    "",
    `## Repository: ${repoName}`,
    "",
    "## Application Routes",
    routes.length > 0
      ? JSON.stringify(routes.slice(0, 50), null, 2)
      : "No routes extracted — use Glob/Grep to find route definitions.",
    "",
    "## STRIDE Elevation-of-Privilege Threats",
    elevationThreats.length > 0
      ? JSON.stringify(elevationThreats.slice(0, 20), null, 2)
      : "No elevation threats identified by STRIDE.",
    "",
    "## Trust Boundaries",
    boundaries.length > 0
      ? JSON.stringify(boundaries.slice(0, 20), null, 2)
      : "No trust boundaries identified.",
    "",
    "Investigate the code and return ONLY confirmed authorization flaws with evidence.",
  ].join("\n");
}

function extractElevationThreats(strideOutput: unknown): Array<Record<string, unknown>> {
  if (!isRecord(strideOutput)) return [];
  const doc = isRecord(strideOutput["document"]) ? strideOutput["document"] : strideOutput;
  const threats = Array.isArray(doc["threats"]) ? doc["threats"] : [];
  return threats.filter((t): t is Record<string, unknown> =>
    isRecord(t) && (t["category"] === "elevation-of-privilege" || t["category"] === "spoofing"),
  );
}

function extractRoutes(appModel: unknown): Array<Record<string, unknown>> {
  if (!isRecord(appModel)) return [];
  const routes = Array.isArray(appModel["routes"]) ? appModel["routes"] : [];
  return routes.filter((r): r is Record<string, unknown> => isRecord(r));
}

function extractBoundaries(appModel: unknown): Array<Record<string, unknown>> {
  if (!isRecord(appModel)) return [];
  const boundaries = Array.isArray(appModel["boundaries"]) ? appModel["boundaries"] : [];
  return boundaries.filter((b): b is Record<string, unknown> => isRecord(b));
}

function normalizeSeverity(value: unknown): "ERROR" | "WARNING" | "INFO" {
  if (typeof value === "string") {
    const upper = value.toUpperCase();
    if (upper === "ERROR" || upper === "CRITICAL" || upper === "HIGH") return "ERROR";
    if (upper === "WARNING" || upper === "MEDIUM") return "WARNING";
  }
  return "WARNING";
}
