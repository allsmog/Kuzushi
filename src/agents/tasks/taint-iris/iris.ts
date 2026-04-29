/**
 * taint-iris — IRIS-style taint analysis: LLM writes all CodeQL queries dynamically.
 *
 * For each CWE from taint-cwe-select, runs a full IRIS loop in a single Claude session:
 *   Step A: Write & run CodeQL extraction queries for CWE-relevant sources/sinks
 *   Step B: Label candidates (source/sink/sanitizer/none)
 *   Step C: Generate TaintTracking configuration, compile, run (iterate on failure)
 *   Step D: Interpret SARIF results, triage
 *
 * Language-agnostic: the LLM writes CodeQL for whatever language the database contains.
 * Framework-agnostic: the LLM knows gRPC, protobuf, GORM, Django, Express, etc.
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { createLogger } from "../../../logger.js";
import { coerceRepoContext } from "../../../repo-context.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TaintPathStep } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { DagNodeImpl, DagRunContext } from "../../types.js";
import {
  resolveTaskAllowedTools,
  resolveTaskModel,
  resolveTaskRuntime,
} from "../runtime-overrides.js";
import type { CweSelection, CweSelectOutput } from "./cwe-select.js";

const log = createLogger({ stage: "taint-iris" });

const IRIS_FINDING_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "title",
          "cwe",
          "severity",
          "filePath",
          "startLine",
          "message",
          "sourceSinkTrace",
        ],
        properties: {
          title: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
          filePath: { type: "string" },
          startLine: { type: "integer" },
          message: { type: "string" },
          sourceSinkTrace: { type: "string" },
          taintPath: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["filePath", "line"],
              properties: {
                filePath: { type: "string" },
                line: { type: "integer" },
                message: { type: "string" },
                snippet: { type: "string" },
              },
            },
          },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
          exploitPreconditions: { type: "string" },
        },
      },
    },
  },
} as const;

function resolveCodeqlDbPath(context: DagRunContext): string | null {
  // Check common locations for a pre-built CodeQL database
  const candidates = [
    path.join(context.repoRoot, ".kuzushi", "codeql-db"),
    path.join(context.repoRoot, ".codeql", "db"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

function buildIrisPrompt(
  cwes: CweSelection[],
  codeqlDbPath: string | null,
  repoContext: ReturnType<typeof coerceRepoContext>,
  options: { promptOverride?: string; cweLimitNotice?: string } = {},
): string {
  const cweList = cwes.map((c) => `- ${c.id}: ${c.name} (${c.reason})`).join("\n");
  const repoInfo = repoContext
    ? [
        `Languages: ${repoContext.languages.join(", ")}`,
        `Frameworks: ${repoContext.frameworks.join(", ")}`,
        `DB/ORM: ${repoContext.ormOrDb.join(", ")}`,
        `Entry points: ${repoContext.entryPoints.join(", ")}`,
      ].join("\n")
    : "No context available.";

  const codeqlSection = codeqlDbPath
    ? [
        `## CodeQL Database`,
        `A CodeQL database is available at: ${codeqlDbPath}`,
        `You can run queries with: codeql query run -d ${codeqlDbPath} /tmp/query.ql`,
        `You can analyze with: codeql database analyze ${codeqlDbPath} /tmp/query.ql --format=sarif-latest --output=/tmp/results.sarif`,
        "",
      ].join("\n")
    : "No CodeQL database available. Use grep-based manual tracing instead.";

  const prompt = [
    "You are an IRIS-style security analyst performing taint analysis on a codebase.",
    "Your goal: find exploitable data flow vulnerabilities by combining LLM reasoning with CodeQL.",
    "",
    "## Project",
    repoInfo,
    "",
    codeqlSection,
    "",
    "## CWE Classes to Analyze",
    cweList,
    "",
    "## Method (IRIS loop — repeat for each CWE)",
    "",
    "For EACH CWE class above, perform these steps:",
    "",
    "### Step A: Extract sink and source candidates",
    "Write a CodeQL query that extracts API calls relevant to this CWE from the project's dependencies.",
    "For example, for CWE-89 (SQL Injection), query for calls to database query/exec methods.",
    "For sources, query for entry points (HTTP handlers, gRPC handlers, CLI arg reads, etc.).",
    "Run the query. If it fails to compile, read the error and fix the query. Iterate until it works.",
    "",
    "### Step B: Label candidates",
    "Review the extraction results. For each candidate, classify as:",
    "- **source**: untrusted user input enters here",
    "- **sink**: dangerous operation — vulnerability occurs if tainted data reaches here",
    "- **sanitizer**: blocks taint flow (escaping, validation, parameterization)",
    "- **none**: not security-relevant for this CWE",
    "",
    "### Step C: Generate and run taint tracking query",
    "Write a CodeQL TaintTracking::Configuration (or DataFlow::Configuration) that:",
    "- Defines isSource() using your labeled sources",
    "- Defines isSink() using your labeled sinks",
    "- Optionally adds isAdditionalFlowStep() for framework-specific propagation",
    "  (e.g., protobuf field access, gRPC metadata flow, ORM query builders)",
    "- Optionally adds isSanitizer() for identified sanitizers",
    "",
    "Compile and run. If compilation fails, read the error and fix. If it runs but finds 0 results,",
    "investigate: are you missing propagation steps? Is the source granularity wrong?",
    "Add AdditionalFlowStep predicates and re-run. Try up to 3 iterations per CWE.",
    "",
    "### Step D: Interpret results",
    "Read the SARIF output (or query results). For each data flow path found:",
    "- Read the actual source code at each step",
    "- Determine if the path is exploitable (check for sanitizers, type constraints, dead code)",
    "- If true positive: record as a finding with source→sink trace",
    "- If false positive: explain why and skip",
    "",
    "## Output",
    "After analyzing ALL CWE classes, return your findings as structured JSON.",
    "Each finding needs: title, CWE, severity, file path, line number, description, source→sink trace,",
    "and a structured taintPath array with each step's filePath, line, message (role like 'source', 'step', 'sink'), and code snippet.",
  ];
  if (options.cweLimitNotice) {
    prompt.splice(2, 0, "", options.cweLimitNotice);
  }
  if (options.promptOverride?.trim()) {
    prompt.push("", "## Operator Prompt Override", options.promptOverride.trim());
  }
  return prompt.join("\n");
}

export const taintIrisTask: DagNodeImpl<ScanOpts, Finding[]> = {
  id: "taint-iris",
  displayName: "IRIS Taint Analysis",
  outputKind: "findings",
  dependsOn: ["taint-cwe-select", "context-gatherer"],

  condition(upstreamOutputs) {
    const cweOutput = upstreamOutputs.get("taint-cwe-select") as CweSelectOutput | undefined;
    return !!cweOutput?.cwes?.length;
  },

  async run(input, context): Promise<Finding[]> {
    const runtime = resolveTaskRuntime(context);
    const model = resolveTaskModel(context, "taint-iris");
    const params = (input ?? {}) as unknown as Record<string, unknown>;
    const taskConfig = {
      ...(context.config.taskConfig["taint-iris"] ?? {}),
      ...(context.config.taskConfig["taint-iris:hunt"] ?? {}),
    };
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const cweOutput = context.upstreamOutputs.get("taint-cwe-select") as
      | CweSelectOutput
      | undefined;
    const cwes = cweOutput?.cwes ?? [];

    if (cwes.length === 0) {
      log.info("No CWE classes selected — skipping IRIS taint analysis");
      return attachTaskOutputMeta([], { costUsd: 0 });
    }

    const maxCwes = readPositiveInteger(params["maxCwes"] ?? taskConfig["maxCwes"]);
    const selectedCwes = maxCwes ? cwes.slice(0, maxCwes) : cwes;
    const cweLimitNotice =
      maxCwes && cwes.length > selectedCwes.length
        ? `Analyzing first ${selectedCwes.length} of ${cwes.length} selected CWE classes.`
        : undefined;
    const promptOverride = readString(
      params["TAINT_IRIS_PROMPT"] ?? taskConfig["TAINT_IRIS_PROMPT"],
    );
    const maxBudgetUsd = readPositiveNumber(params["maxBudgetUsd"] ?? taskConfig["maxBudgetUsd"]);
    const abortController = context.signal ? new AbortController() : undefined;
    if (context.signal && abortController) {
      if (context.signal.aborted) abortController.abort();
      else context.signal.addEventListener("abort", () => abortController.abort(), { once: true });
    }

    const codeqlDbPath = resolveCodeqlDbPath(context);
    const prompt = buildIrisPrompt(selectedCwes, codeqlDbPath, repoContext, {
      ...(promptOverride ? { promptOverride } : {}),
      ...(cweLimitNotice ? { cweLimitNotice } : {}),
    });

    log.info(
      `Starting IRIS taint analysis for ${selectedCwes.length} CWE classes (model=${model}, codeql=${!!codeqlDbPath})`,
    );

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          allowedTools: [...resolveTaskAllowedTools(context), "Bash", "Write"],
          permissionMode: "dontAsk",
          ...(maxBudgetUsd ? { maxBudgetUsd } : {}),
          ...(abortController ? { abortController } : {}),
          outputFormat: {
            type: "json_schema",
            schema: IRIS_FINDING_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number") costUsd = message.totalCostUsd;
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      throw new Error(`[taint-iris] Agent error: ${toErrorMessage(error)}`);
    }

    const findings = parseFindings(
      structuredOutput ?? tryParseJson(resultText),
      context.repoRoot,
      context.repoName,
    );

    log.info(`IRIS analysis complete: ${findings.length} findings, $${costUsd.toFixed(2)}`);

    return attachTaskOutputMeta(findings, { costUsd });
  },
};

function parseFindings(raw: unknown, repoRoot: string, repoName: string): Finding[] {
  if (!isRecord(raw)) return [];
  const items = Array.isArray(raw["findings"]) ? raw["findings"] : [];
  const out: Finding[] = [];

  for (const item of items) {
    if (!isRecord(item)) continue;
    const title = str(item["title"]);
    const cwe = str(item["cwe"]);
    const filePath = str(item["filePath"]);
    const startLine = Math.max(1, Math.floor(Number(item["startLine"]) || 1));
    const message = str(item["message"]);
    const trace = str(item["sourceSinkTrace"]);
    const confidence = str(item["confidence"]) || "medium";

    if (!title || !filePath || !message) continue;

    const rawPath = Array.isArray(item["taintPath"]) ? item["taintPath"] : [];
    const taintPath: TaintPathStep[] = [];
    for (const step of rawPath) {
      if (!isRecord(step)) continue;
      const fp = str(step["filePath"]);
      const ln = Math.max(1, Math.floor(Number(step["line"]) || 1));
      if (!fp) continue;
      taintPath.push({
        filePath: normalizePath(repoRoot, fp),
        line: ln,
        message: str(step["message"]) || undefined,
        snippet: str(step["snippet"]) || undefined,
      });
    }

    const severity = mapSeverity(str(item["severity"]));
    const fingerprint = createHash("sha256")
      .update([repoName, "taint-iris", cwe, filePath, String(startLine), title].join("|"))
      .digest("hex");

    out.push({
      taskId: "taint-iris",
      fingerprint,
      ruleId: `taint-iris/${cwe || "unknown"}`,
      filePath: normalizePath(repoRoot, filePath),
      startLine,
      severity,
      message: `[${cwe}] ${title}: ${message}`,
      evidence: trace || null,
      scannerConfidence: confidence.toUpperCase() as "HIGH" | "MEDIUM" | "LOW",
      subcategory: ["vuln"],
      likelihood: confidence.toUpperCase(),
      impact: severity === "ERROR" ? "HIGH" : "MEDIUM",
      cwe: cwe ? [cwe] : [],
      score: scoreFindingMetadata({
        severity,
        likelihood: confidence.toUpperCase(),
        impact: severity === "ERROR" ? "HIGH" : "MEDIUM",
        subcategory: ["vuln"],
      }),
      taintPath: taintPath.length > 0 ? taintPath : undefined,
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "taint-analysis", detail: "IRIS CodeQL-backed taint analysis" }],
    });
  }

  return out;
}

function mapSeverity(s: string): string {
  switch (s.toLowerCase()) {
    case "critical":
    case "high":
      return "ERROR";
    case "medium":
      return "WARNING";
    default:
      return "INFO";
  }
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const rel = path.relative(repoRoot, filePath);
  return rel.startsWith("..") ? filePath : rel || filePath;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function readPositiveInteger(value: unknown): number | undefined {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 0;
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : undefined;
}

function readPositiveNumber(value: unknown): number | undefined {
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : 0;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}
