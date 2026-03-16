import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import { antiHallucinationModule } from "../../prompts/modules.js";
import { coerceRepoContext } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";

const log = createLogger({ stage: "dangerous-api" });

const DANGEROUS_API_SCHEMA = {
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
          category: { type: "string", enum: ["unsafe-deserialization", "unsafe-eval", "unsafe-subprocess", "unsafe-file-ops", "insecure-defaults", "unsafe-regex", "prototype-pollution", "nosql-injection", "template-injection", "ldap-injection", "xml-injection"] },
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

interface DangerousApiFinding {
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

interface DangerousApiConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): DangerousApiConfig {
  const raw = ctx.config.scannerConfig["dangerous-api"];
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
        "- Express/Koa: body-parser limits, helmet defaults, CSRF middleware",
        "- Django: auto-escaping templates, ORM parameterization, CSRF protection",
        "- Rails: strong parameters, CSRF tokens, parameterized queries by default",
        "- Spring: @RequestBody validation, CSRF protection, parameterized JdbcTemplate",
        "Do NOT flag uses that are protected by the framework's built-in defenses.",
        "",
      ]
    : [];

  return [
    "You are a senior application security engineer with 10+ years of experience auditing",
    "production codebases for dangerous API usage. You have deep expertise in unsafe deserialization,",
    "code injection, command injection, path traversal, and insecure defaults across multiple languages",
    "and frameworks.",
    "",
    "Your task: systematically identify dangerous API calls that accept attacker-controlled input",
    "without adequate validation or sanitization.",
    "",
    ...contextLines,
    ...frameworkGuidance,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to detect",
    "",
    "### unsafe-deserialization (CWE-502)",
    "Deserializing untrusted data: pickle.loads, yaml.unsafe_load, Java ObjectInputStream,",
    "PHP unserialize, JSON.parse with reviver on untrusted input, eval-based JSON parsing.",
    "Only flag when input source is attacker-controlled (request body, URL params, file upload, message queue).",
    "",
    "### unsafe-eval (CWE-94, CWE-95)",
    "Dynamic code execution: eval(), Function(), vm.runInNewContext, exec(), setTimeout/setInterval with strings,",
    "template injection (Jinja2, EJS, Pug with unescaped), Python exec/compile, Ruby instance_eval.",
    "Only flag when the evaluated string includes user-controlled data.",
    "",
    "### unsafe-subprocess (CWE-78)",
    "Shell command injection: child_process.exec with string concatenation, os.system, subprocess.call(shell=True),",
    "Runtime.exec with user input, backtick execution in Ruby/Perl.",
    "Do NOT flag subprocess.run([...]) with array arguments (safe) or hardcoded commands.",
    "",
    "### unsafe-file-ops (CWE-22, CWE-59)",
    "Path traversal / symlink attacks: fs.readFile/writeFile with user-controlled paths without path.resolve + startsWith check,",
    "open() with user input, file uploads without filename sanitization, directory listing without access control.",
    "",
    "### insecure-defaults (CWE-16)",
    "Dangerous default configurations: CORS allow-all (*), debug mode in production config,",
    "disabled CSRF protection, permissive CSP, missing secure/httpOnly on cookies, weak session config,",
    "TLS verification disabled, verbose error messages exposing internals.",
    "",
    "### unsafe-regex (CWE-1333)",
    "Regular expressions vulnerable to catastrophic backtracking when applied to user input.",
    "Only flag regex patterns with nested quantifiers (e.g., (a+)+, (a|b*)*, .*a.*b.*c) that process user-controlled strings.",
    "",
    "### prototype-pollution (CWE-1321)",
    "Deep merge/extend operations with user-controlled input:",
    "- `_.merge({}, userInput)`, `deepmerge(target, userInput)`, `Object.assign` with nested objects",
    "- Property access via `obj[userKey]` where userKey can be `__proto__`, `constructor.prototype`",
    "- Only flag when input source is attacker-controlled and target is a shared/global object",
    "",
    "### nosql-injection (CWE-943)",
    "MongoDB operator injection via user-controlled query objects:",
    "- `db.collection.find(req.body)` where body can contain `$gt`, `$ne`, `$regex`, `$where`",
    "- Mongoose queries with unsanitized user objects: `User.find(req.query)`",
    "- `$where` clause with user-controlled JavaScript strings",
    "",
    "### template-injection (CWE-1336)",
    "Server-side template injection (SSTI):",
    "- Jinja2: `render_template_string(user_input)`, `Template(user_input).render()`",
    "- EJS: `ejs.render(user_input)` or unescaped output `<%- userVar %>`",
    "- Pug/Jade: Dynamic template compilation with user input",
    "- Handlebars: `Handlebars.compile(userInput)` or helper injection",
    "",
    "### ldap-injection (CWE-90)",
    "User input concatenated into LDAP filter strings:",
    "- `(&(uid=${username})(password=${password}))` without escaping",
    "- Libraries: ldapjs, python-ldap, javax.naming.directory",
    "",
    "### xml-injection (CWE-611)",
    "XML External Entity (XXE) via unsafe XML parsing:",
    "- Parsers with external entities enabled by default",
    "- `libxml2` without `noent`, `lxml` without `resolve_entities=False`",
    "- Java: `DocumentBuilderFactory` without `setFeature(DISALLOW_DOCTYPE_DECL)`",
    "",
    "## Investigation methodology",
    "1. Use Glob to find files with relevant imports and API calls for each category.",
    "2. Use Read to inspect each candidate callsite.",
    "3. Trace the input source: is it attacker-controlled? (request params, headers, body, file upload, etc.)",
    "4. Check for sanitization, validation, allowlists, or other guards between source and sink.",
    "5. Only report findings where you can verify the dangerous API call AND the attacker-controlled input path.",
    "",
    antiHallucinationModule({
      extra: [
        "If unsure whether input is attacker-controlled, do NOT report.",
        "Confidence HIGH only if source-to-sink is fully verified.",
      ],
    }),
    "",
    `Return at most ${maxFindings} findings, prioritized by severity and confidence.`,
    "Filter out any finding where your confidence would be below MEDIUM.",
  ].join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as DangerousApiFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const apiInfo = f.apiOrFunction ? ` [${f.apiOrFunction}]` : "";

    const finding: Finding = {
      scanner: "dangerous-api-detect",
      fingerprint,
      ruleId: `dangerous-api/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Dangerous API usage"}${apiInfo}`,
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

function computeFingerprint(repoName: string, filePath: string, f: DangerousApiFinding): string {
  const source = [repoName, "dangerous-api", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const dangerousApiTask: AgentTask<ScanOpts, Finding[]> = {
  id: "dangerous-api-detect",
  displayName: "Dangerous API Surface Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "dangerous-api-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[dangerous-api]";
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
            schema: DANGEROUS_API_SCHEMA,
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
        `You are triaging a dangerous API usage finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The dangerous API call actually exists at the reported location.",
        "2. The input to the API is genuinely attacker-controlled.",
        "3. No sanitization, validation, or access control guards prevent exploitation.",
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

export const __dangerousApiInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
