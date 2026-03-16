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

const log = createLogger({ stage: "prototype-pollution" });

const PROTOTYPE_POLLUTION_SCHEMA = {
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
          category: { type: "string", enum: ["merge-pollution", "property-assignment", "constructor-prototype"] },
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

interface PrototypePollutionFinding {
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

interface PrototypePollutionConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): PrototypePollutionConfig {
  const raw = ctx.config.scannerConfig["prototype-pollution"];
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
        "- Express/Koa: body-parser does NOT protect against prototype pollution in nested objects",
        "- Lodash >=4.17.12: _.merge and _.defaultsDeep are patched against __proto__ but not constructor.prototype",
        "- jQuery: $.extend deep mode is vulnerable in older versions",
        "- Immer: uses Proxy-based immutability which prevents prototype pollution",
        "Do NOT flag uses that are protected by patched library versions or framework defenses.",
        "",
      ]
    : [];

  return [
    "You are a senior application security engineer specializing in prototype pollution vulnerabilities",
    "in JavaScript and TypeScript codebases. You have deep expertise in object manipulation attacks,",
    "prototype chain poisoning, and supply chain vectors that enable property injection.",
    "",
    "Your task: systematically identify prototype pollution vectors where attacker-controlled input",
    "can modify Object.prototype or other built-in prototypes through unsafe merge/extend/assign patterns.",
    "",
    ...contextLines,
    ...frameworkGuidance,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to detect",
    "",
    "### merge-pollution (CWE-1321)",
    "Deep merge or extend operations with user-controlled input that can inject __proto__ or constructor.prototype.",
    "Common sinks: _.merge, _.defaultsDeep, deepmerge, extend(true, ...), Object.assign with nested user objects,",
    "custom recursive merge functions. Only flag when the source object is attacker-controlled",
    "(request body, query params, deserialized JSON) and the merge is recursive/deep.",
    "",
    "### property-assignment (CWE-1321)",
    "Dynamic property access patterns where an attacker-controlled key can be `__proto__`, `constructor`,",
    "or `prototype`. Patterns: obj[userKey] = value, obj[a][b] = c where a or b is user-controlled,",
    "bracket notation chains from parsed paths (e.g., lodash _.set, dot-prop, flat). Only flag when",
    "the property key/path originates from user input without __proto__/constructor filtering.",
    "",
    "### constructor-prototype (CWE-1321)",
    "Direct prototype chain manipulation: Object.setPrototypeOf with user input,",
    "obj.__proto__ assignment, constructor.prototype modification, Object.create with user-supplied proto.",
    "Only flag when the prototype value or target is influenced by attacker-controlled data.",
    "",
    "## Investigation methodology",
    "1. Use Grep to find merge/extend/deepmerge calls, dynamic property access patterns like obj[key],",
    "   _.set, dot-prop, and __proto__/constructor references.",
    "2. Use Read to inspect each candidate callsite and trace the input source.",
    "3. Trace the input source: is the key or merged object attacker-controlled?",
    "4. Check for prototype pollution guards: hasOwnProperty checks, key filtering for __proto__/constructor,",
    "   Object.create(null) base objects, frozen prototypes.",
    "5. Only report findings where you can verify the unsafe merge/assignment AND the attacker-controlled input path.",
    "",
    antiHallucinationModule({
      extra: [
        "If unsure whether input is attacker-controlled, do NOT report.",
        "Confidence HIGH only if source-to-sink is fully verified.",
        "Do NOT flag Object.assign with only flat/non-nested objects.",
        "Do NOT flag property access with hardcoded keys.",
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
    const f = item as unknown as PrototypePollutionFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const apiInfo = f.apiOrFunction ? ` [${f.apiOrFunction}]` : "";

    const finding: Finding = {
      scanner: "prototype-pollution-detect",
      fingerprint,
      ruleId: `prototype-pollution/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Potential prototype pollution"}${apiInfo}`,
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

function computeFingerprint(repoName: string, filePath: string, f: PrototypePollutionFinding): string {
  const source = [repoName, "prototype-pollution", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const prototypePollutionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "prototype-pollution-detect",
  displayName: "Prototype Pollution Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "prototype-pollution-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[prototype-pollution]";
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
            schema: PROTOTYPE_POLLUTION_SCHEMA,
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
        `You are triaging a prototype pollution finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The merge/assignment operation actually exists at the reported location.",
        "2. The input key or object is genuinely attacker-controlled.",
        "3. No __proto__/constructor filtering or Object.create(null) guards prevent exploitation.",
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

export const __prototypePollutionInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
