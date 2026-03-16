import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import {
  antiHallucinationModule,
  frameworkAwarenessModule,
} from "../../prompts/modules.js";
import { coerceRepoContext } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";

const log = createLogger({ stage: "nosql-injection" });

const NOSQL_INJECTION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["category", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale"],
        properties: {
          category: { type: "string", enum: ["query-operator-injection", "where-clause-injection", "regex-injection-nosql"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          apiOrFunction: { type: "string" },
          inputSource: { type: "string" },
        },
      },
    },
  },
} as const;

interface NosqlInjectionFinding {
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  apiOrFunction?: string;
  inputSource?: string;
}

interface NosqlInjectionConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): NosqlInjectionConfig {
  const raw = ctx.config.scannerConfig["nosql-injection"];
  const model = (isRecord(raw) && typeof raw["model"] === "string" && raw["model"].trim())
    ? raw["model"].trim()
    : ctx.config.model;
  const maxFindings = (isRecord(raw) && typeof raw["maxFindings"] === "number" && raw["maxFindings"] >= 1)
    ? Math.floor(raw["maxFindings"])
    : 50;
  return { model, maxFindings };
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, profileLines: string[] = []): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Sanitization libs: ${repoContext.sanitizationLibs.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  const frameworkGuidance = repoContext?.frameworks.length
    ? [
        "## Framework-specific guidance",
        "When analyzing framework code, account for built-in protections:",
        "- Mongoose: schema validation can prevent operator injection if strict mode is on",
        "- Mongoose: query helpers with lean() bypass middleware but schema validation still applies",
        "- Express + express-mongo-sanitize: strips $ and . from req.body/query/params",
        "- NestJS + class-validator: DTO validation can prevent object injection",
        "Do NOT flag uses that are protected by the framework's built-in defenses or sanitization middleware.",
        "",
      ]
    : [];

  return [
    "You are a senior application security engineer specializing in NoSQL injection vulnerabilities.",
    "You have deep expertise in MongoDB operator injection, Mongoose query manipulation, and",
    "document database security across Node.js, Python, Ruby, and Java applications.",
    "",
    "Your task: systematically identify NoSQL injection vectors where attacker-controlled input",
    "can manipulate database queries through operator injection, $where clauses, or regex patterns.",
    "",
    ...contextLines,
    ...frameworkGuidance,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to detect",
    "",
    "### query-operator-injection (CWE-943)",
    "MongoDB operator injection via user-controlled objects passed directly to query methods.",
    "If req.body or req.query is passed to find(), findOne(), updateOne(), deleteMany() etc. without",
    "sanitization, an attacker can inject operators like {$gt: ''}, {$ne: null}, {$regex: '.*'}.",
    "Common patterns: Model.find(req.body), collection.findOne({user: req.query.user}) where",
    "req.query.user could be {$ne: null}. Only flag when user input flows into a query filter",
    "without operator stripping or schema validation.",
    "",
    "### where-clause-injection (CWE-943)",
    "$where clauses with user-controlled JavaScript strings. The $where operator executes arbitrary JS",
    "on the MongoDB server. Patterns: collection.find({$where: userString}),",
    "Model.find().where('this.field == \"' + userInput + '\"'). Even concatenation with $where is dangerous.",
    "Only flag when the $where expression includes user-controlled data.",
    "",
    "### regex-injection-nosql (CWE-943)",
    "$regex queries with unescaped user input enabling ReDoS or data extraction.",
    "Patterns: collection.find({field: {$regex: userInput}}), Model.find({name: new RegExp(userInput)}).",
    "An attacker can inject regex metacharacters for ReDoS or use .* patterns for data enumeration.",
    "Only flag when user input is passed to $regex without escaping regex special characters.",
    "",
    "## Investigation methodology",
    "1. Use Grep to find MongoDB/Mongoose query calls (find, findOne, updateOne, aggregate, $where, $regex).",
    "2. Use Read to trace data flow from user input (req.body, req.query, req.params) to query sinks.",
    "3. Check for sanitization: express-mongo-sanitize, manual $ stripping, schema validation, DTO validation.",
    "4. Check for regex escaping when user input reaches $regex operators.",
    "5. Only report findings where you can verify the injection vector AND the attacker-controlled input path.",
    "",
    antiHallucinationModule({
      extra: [
        "If unsure whether input is attacker-controlled, do NOT report.",
        "Confidence HIGH only if source-to-sink is fully verified.",
        "Do NOT flag queries with hardcoded filter objects.",
        "Do NOT flag queries protected by express-mongo-sanitize or equivalent middleware.",
      ],
    }),
    frameworkAwarenessModule(repoContext),
    "",
    `Return at most ${maxFindings} findings, prioritized by severity and confidence.`,
    "Filter out any finding where your confidence would be below MEDIUM.",
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as NosqlInjectionFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const apiInfo = f.apiOrFunction ? ` [${f.apiOrFunction}]` : "";

    const finding: Finding = {
      scanner: "nosql-injection-detect",
      fingerprint,
      ruleId: `nosql-injection/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Potential NoSQL injection"}${apiInfo}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: f.confidence || "MEDIUM",
      impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity: f.severity,
        likelihood: f.confidence,
        impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
        cwe: cweList,
      }),
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}

function computeFingerprint(repoName: string, filePath: string, f: NosqlInjectionFinding): string {
  const source = [repoName, "nosql-injection", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const nosqlInjectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "nosql-injection-detect",
  displayName: "NoSQL Injection Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "nosql-injection-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[nosql-injection]";
    log.info(`Starting scan (model=${model})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          maxTurns: undefined,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: NOSQL_INJECTION_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
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
      throw new Error(`${tag} Agent error: ${toErrorMessage(error)}`);
    }

    return attachTaskOutputMeta(
      normalizeFindings(
        structuredOutput ?? parseJson(resultText, tag),
        context.repoRoot,
        context.repoName,
        maxFindings,
      ),
      { costUsd },
    );
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a NoSQL injection finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The database query actually exists at the reported location.",
        "2. The input to the query filter is genuinely attacker-controlled.",
        "3. No sanitization middleware, schema validation, or operator stripping prevents exploitation.",
      ].filter(Boolean).join("\n"),
    };
  },
};

function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

export const __nosqlInjectionInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
