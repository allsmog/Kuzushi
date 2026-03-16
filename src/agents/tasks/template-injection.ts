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

const log = createLogger({ stage: "template-injection" });

const TEMPLATE_INJECTION_SCHEMA = {
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
          category: { type: "string", enum: ["jinja2-ssti", "ejs-injection", "pug-injection", "handlebars-injection"] },
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

interface TemplateInjectionFinding {
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

interface TemplateInjectionConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): TemplateInjectionConfig {
  const raw = ctx.config.scannerConfig["template-injection"];
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
        "- Flask/Jinja2: render_template() with named files is safe; render_template_string() with user input is NOT",
        "- Django: auto-escaping is on by default but does NOT prevent SSTI via Template(user_input)",
        "- Express/EJS: res.render() with template files is safe; ejs.render(userString) is NOT",
        "- Handlebars: SafeString and escapeExpression provide XSS protection but not SSTI protection",
        "Do NOT flag template rendering with static file paths and safe context variables.",
        "",
      ]
    : [];

  return [
    "You are a senior application security engineer specializing in Server-Side Template Injection (SSTI)",
    "vulnerabilities. You have deep expertise in Jinja2, EJS, Pug, Handlebars, Twig, and other",
    "template engines, including RCE exploitation chains through template sandbox escapes.",
    "",
    "Your task: systematically identify template injection vectors where attacker-controlled input",
    "is passed into template compilation or rendering functions, enabling code execution on the server.",
    "",
    ...contextLines,
    ...frameworkGuidance,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to detect",
    "",
    "### jinja2-ssti (CWE-1336)",
    "Jinja2/Flask Server-Side Template Injection. Dangerous patterns:",
    "- render_template_string(user_input) or Template(user_input).render()",
    "- String formatting user input into template strings before rendering",
    "- f-strings or %-formatting injecting user data into Jinja2 template syntax",
    "Known exploitation: {{config}}, {{request.application.__globals__}}, {{lipsum.__globals__}}.",
    "Only flag when user input flows into the template string itself, NOT into template context variables.",
    "",
    "### ejs-injection (CWE-1336)",
    "EJS template injection. Dangerous patterns:",
    "- ejs.render(userInput) or ejs.compile(userInput) where the template string is user-controlled",
    "- Unescaped output tags <%- %> with user input (XSS vector, not full SSTI)",
    "- res.render() with user-controlled template path (path traversal to arbitrary template)",
    "- Template options injection via settings['view options'] manipulation",
    "Only flag when user input controls the template source or unescaped output includes raw user data.",
    "",
    "### pug-injection (CWE-1336)",
    "Pug (formerly Jade) template injection. Dangerous patterns:",
    "- pug.render(userInput) or pug.compile(userInput) with user-controlled template strings",
    "- Dynamic template compilation from user-supplied content",
    "- Unescaped interpolation !{userInput} in Pug templates",
    "Only flag when the template source string is influenced by user input.",
    "",
    "### handlebars-injection (CWE-1336)",
    "Handlebars template injection. Dangerous patterns:",
    "- Handlebars.compile(userInput) where template string is user-controlled",
    "- Custom helper registration that evaluates user input",
    "- Prototype pollution leading to template injection via __proto__.type = 'Program'",
    "- lookupProperty bypass via {{#with}} and custom helpers",
    "Only flag when user input controls the template source or helper definitions.",
    "",
    "## Investigation methodology",
    "1. Use Grep to find template engine imports and rendering calls (render_template_string, Template,",
    "   ejs.render, ejs.compile, pug.render, pug.compile, Handlebars.compile).",
    "2. Use Read to inspect each candidate and trace the template string source.",
    "3. Distinguish between safe patterns (static template files with context vars) and unsafe",
    "   patterns (user input in template string).",
    "4. Check for sandboxing (Jinja2 SandboxedEnvironment) or input validation.",
    "5. Only report findings where you can verify user input reaches the template compilation/rendering sink.",
    "",
    antiHallucinationModule({
      extra: [
        "If unsure whether input is attacker-controlled, do NOT report.",
        "Confidence HIGH only if source-to-sink is fully verified.",
        "Do NOT flag render_template() with static file names and safe context variables.",
        "Do NOT flag template rendering in test files or development-only code.",
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
    const f = item as unknown as TemplateInjectionFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const apiInfo = f.apiOrFunction ? ` [${f.apiOrFunction}]` : "";

    const finding: Finding = {
      scanner: "template-injection-detect",
      fingerprint,
      ruleId: `template-injection/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "ERROR",
      message: `${f.description || "Potential template injection (SSTI)"}${apiInfo}`,
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

function computeFingerprint(repoName: string, filePath: string, f: TemplateInjectionFinding): string {
  const source = [repoName, "template-injection", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const templateInjectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "template-injection-detect",
  displayName: "Template Injection Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "template-injection-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[template-injection]";
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
            schema: TEMPLATE_INJECTION_SCHEMA,
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
        `You are triaging a template injection (SSTI) finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The template rendering/compilation call actually exists at the reported location.",
        "2. The template string is genuinely attacker-controlled (not just context variables).",
        "3. No sandboxing (SandboxedEnvironment) or input validation prevents exploitation.",
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

export const __templateInjectionInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
