import { createHash } from "node:crypto";
import path from "node:path";
import {
  antiHallucinationModule,
  frameworkAwarenessModule,
} from "../../prompts/modules.js";
import { coerceRepoContext, coerceFileIndex } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { FileIndex, RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";
import { preReadFilesForTask, type PreReadResult } from "./pre-read.js";
import { formatFileTreeForPrompt, formatPreReadForPrompt, formatPatternMatchesForPrompt } from "./pre-read-prompt.js";
import { buildThreatModelLeadsSection, resolveThreatModelOutput } from "./threat-model-guidance.js";
import {
  filterCategories,
  filterBlocks,
  CATEGORY_SCOPE_HEADER,
  type CategoryRelevance,
  type CategoryBlock,
} from "./category-filter.js";
import { buildApplicationModelSection, buildThreatScenarioEvidenceSection } from "./scenario-guidance.js";
import { resolveTaskAllowedTools, resolveTaskModel, resolveTaskPositiveInt, resolveTaskRuntime } from "./runtime-overrides.js";
import type { ToolPolicy } from "../../prompts/tool-policy.js";

const log = createLogger({ stage: "code-config-detect" });

const CODE_CONFIG_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["detectorId", "category", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale"],
        properties: {
          detectorId: { type: "string", enum: ["dangerous-api-detect", "auth-access-detect", "security-misconfig-detect"] },
          category: { type: "string" },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          apiOrFunction: { type: "string" },
          inputSource: { type: "string" },
          endpoint: { type: "string" },
          httpMethod: { type: "string" },
        },
      },
    },
  },
} as const;

interface CodeConfigFinding {
  detectorId: string;
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
  endpoint?: string;
  httpMethod?: string;
}

interface CodeConfigConfig {
  model: string;
  maxFindings: number;
}

type CodeConfigDetectorId =
  | "dangerous-api-detect"
  | "auth-access-detect"
  | "security-misconfig-detect";

const CODE_CONFIG_ANALYSIS_TOOL_POLICY: ToolPolicy = {
  allow: ["group:readonly", "group:analysis"],
};

function resolveConfig(
  ctx: TaskContext,
  configKey = "code-config-detect",
): CodeConfigConfig {
  const model = resolveTaskModel(ctx, configKey, "code-config-detect");
  const maxFindings = resolveTaskPositiveInt(ctx, configKey, "maxFindings", 50, "code-config-detect");
  return { model, maxFindings };
}

/* ------------------------------------------------------------------ */
/*  Category relevance mappings + prompt blocks                       */
/* ------------------------------------------------------------------ */

const CODE_CONFIG_RELEVANCE: CategoryRelevance[] = [
  // Part 1: Dangerous API
  { id: "unsafe-deserialization", always: true },
  { id: "unsafe-eval", always: true },
  { id: "unsafe-subprocess", always: true },
  { id: "unsafe-file-ops", always: true },
  { id: "insecure-defaults", always: true },
  { id: "unsafe-regex", always: true },
  { id: "prototype-pollution", languages: ["JavaScript", "TypeScript"] },
  { id: "nosql-injection", ormOrDbPattern: /mongo|mongoose|dynamo|cosmos|couchdb/i },
  { id: "template-injection", languages: ["JavaScript", "TypeScript", "Python", "Ruby", "PHP", "Java", "Kotlin"] },
  { id: "ldap-injection", languages: ["Java", "Kotlin", "Python", "PHP", "Ruby"] },
  { id: "xml-injection", languages: ["Java", "Kotlin", "Python", "PHP", "Ruby", "Go"] },
  // Part 2: Auth/Access
  { id: "unprotected-endpoint", always: true },
  { id: "missing-role-check", requiresAuth: true },
  { id: "idor", always: true },
  { id: "default-credentials", always: true },
  { id: "mass-assignment", languages: ["JavaScript", "TypeScript", "Ruby", "Python"] },
  { id: "jwt-claim-manipulation", requiresAuth: true },
  { id: "session-fixation", requiresAuth: true },
  { id: "horizontal-privesc", always: true },
  // Part 3: Security Misconfig
  { id: "debug-mode", always: true },
  { id: "missing-headers", always: true },
  { id: "insecure-cors", always: true },
  { id: "insecure-cookies", always: true },
  { id: "exposed-admin", always: true },
  { id: "verbose-errors", always: true },
  { id: "jwt-misconfiguration", requiresAuth: true },
  { id: "session-storage", requiresAuth: true },
  { id: "missing-rate-limit", always: true },
  { id: "exposed-endpoints", always: true },
  { id: "container-misconfig", fileTreePattern: /Dockerfile|docker-compose|\.dockerignore/i },
  { id: "cicd-misconfig", fileTreePattern: /\.github\/workflows|\.gitlab-ci|Jenkinsfile|\.circleci/i },
];

const DANGEROUS_API_BLOCKS: CategoryBlock[] = [
  { id: "unsafe-deserialization", lines: [
    "### unsafe-deserialization (CWE-502)",
    "Deserializing untrusted data: pickle.loads, yaml.unsafe_load, Java ObjectInputStream,",
    "PHP unserialize, JSON.parse with reviver on untrusted input, eval-based JSON parsing.",
    "Only flag when input source is attacker-controlled (request body, URL params, file upload, message queue).",
    "",
  ] },
  { id: "unsafe-eval", lines: [
    "### unsafe-eval (CWE-94, CWE-95)",
    "Dynamic code execution: eval(), Function(), vm.runInNewContext, setTimeout/setInterval with strings,",
    "template injection (Jinja2, EJS, Pug with unescaped), Python compile, Ruby instance_eval.",
    "Only flag when the evaluated string includes user-controlled data.",
    "",
  ] },
  { id: "unsafe-subprocess", lines: [
    "### unsafe-subprocess (CWE-78)",
    "Shell command injection: child_process.exec with string concatenation, os.system, subprocess.call(shell=True),",
    "Runtime.exec with user input, backtick execution in Ruby/Perl.",
    "Do NOT flag subprocess.run([...]) with array arguments (safe) or hardcoded commands.",
    "",
  ] },
  { id: "unsafe-file-ops", lines: [
    "### unsafe-file-ops (CWE-22, CWE-59)",
    "Path traversal / symlink attacks: fs.readFile/writeFile with user-controlled paths without path.resolve + startsWith check,",
    "open() with user input, file uploads without filename sanitization, directory listing without access control.",
    "",
  ] },
  { id: "insecure-defaults", lines: [
    "### insecure-defaults (CWE-16)",
    "Dangerous default configurations: CORS allow-all (*), debug mode in production config,",
    "disabled CSRF protection, permissive CSP, missing secure/httpOnly on cookies, weak session config,",
    "TLS verification disabled, verbose error messages exposing internals.",
    "",
  ] },
  { id: "unsafe-regex", lines: [
    "### unsafe-regex (CWE-1333)",
    "Regular expressions vulnerable to catastrophic backtracking when applied to user input.",
    "Only flag regex patterns with nested quantifiers that process user-controlled strings.",
    "",
  ] },
  { id: "prototype-pollution", lines: [
    "### prototype-pollution (CWE-1321)",
    "Deep merge/extend operations with user-controlled input:",
    "- `_.merge({}, userInput)`, `deepmerge(target, userInput)`, `Object.assign` with nested objects",
    "- Property access via `obj[userKey]` where userKey can be `__proto__`, `constructor.prototype`",
    "",
  ] },
  { id: "nosql-injection", lines: [
    "### nosql-injection (CWE-943)",
    "MongoDB operator injection via user-controlled query objects:",
    "- `db.collection.find(req.body)` where body can contain `$gt`, `$ne`, `$regex`, `$where`",
    "",
  ] },
  { id: "template-injection", lines: [
    "### template-injection (CWE-1336)",
    "Server-side template injection (SSTI):",
    "- Jinja2: `render_template_string(user_input)`, `Template(user_input).render()`",
    "- EJS: `ejs.render(user_input)` or unescaped output `<%- userVar %>`",
    "",
  ] },
  { id: "ldap-injection", lines: [
    "### ldap-injection (CWE-90)",
    "User input concatenated into LDAP filter strings without escaping.",
    "",
  ] },
  { id: "xml-injection", lines: [
    "### xml-injection (CWE-611)",
    "XML External Entity (XXE) via unsafe XML parsing with external entities enabled.",
    "",
  ] },
];

const AUTH_ACCESS_BLOCKS: CategoryBlock[] = [
  { id: "unprotected-endpoint", lines: [
    "### unprotected-endpoint (CWE-862)",
    "State-changing endpoint (POST/PUT/DELETE) without auth middleware.",
    "",
  ] },
  { id: "missing-role-check", lines: [
    "### missing-role-check (CWE-863)",
    "Admin/privileged endpoint accessible to regular users.",
    "",
  ] },
  { id: "idor", lines: [
    "### idor (CWE-639)",
    "Resource access using user-supplied ID without ownership validation.",
    "",
  ] },
  { id: "default-credentials", lines: [
    "### default-credentials (CWE-798)",
    "Hardcoded passwords in seed/migration/config files.",
    "",
  ] },
  { id: "mass-assignment", lines: [
    "### mass-assignment (CWE-915)",
    "Object spread or assign from request body to model without field filtering.",
    "",
  ] },
  { id: "jwt-claim-manipulation", lines: [
    "### jwt-claim-manipulation (CWE-345)",
    "JWT claims trusted without server-side validation.",
    "",
  ] },
  { id: "session-fixation", lines: [
    "### session-fixation (CWE-384)",
    "Session ID not regenerated after authentication state change.",
    "",
  ] },
  { id: "horizontal-privesc", lines: [
    "### horizontal-privesc (CWE-639)",
    "Resource access using user-supplied ID without verifying the requesting user owns the resource.",
    "",
  ] },
];

const SECURITY_MISCONFIG_BLOCKS: CategoryBlock[] = [
  { id: "debug-mode", lines: [
    "### debug-mode (CWE-489)",
    "DEBUG=True in production Django, Flask debug=True, Express morgan dev mode in production.",
    "",
  ] },
  { id: "missing-headers", lines: [
    "### missing-headers (CWE-16)",
    "Missing Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options headers.",
    "",
  ] },
  { id: "insecure-cors", lines: [
    "### insecure-cors (CWE-942)",
    "CORS with `*` origin combined with credentials, reflecting arbitrary Origin headers.",
    "",
  ] },
  { id: "insecure-cookies", lines: [
    "### insecure-cookies (CWE-614)",
    "Missing Secure flag, HttpOnly flag, or SameSite attribute on session cookies.",
    "",
  ] },
  { id: "exposed-admin", lines: [
    "### exposed-admin (CWE-200)",
    "Admin panels or debug endpoints accessible without authentication.",
    "",
  ] },
  { id: "verbose-errors", lines: [
    "### verbose-errors (CWE-209)",
    "Stack traces or detailed error messages with internal paths exposed to users.",
    "",
  ] },
  { id: "jwt-misconfiguration", lines: [
    "### jwt-misconfiguration (CWE-347)",
    "JWT with alg:none accepted, algorithm confusion, short/guessable JWT secret.",
    "",
  ] },
  { id: "session-storage", lines: [
    "### session-storage (CWE-539)",
    "Session data in localStorage, session tokens in URL, missing session expiration.",
    "",
  ] },
  { id: "missing-rate-limit", lines: [
    "### missing-rate-limit (CWE-307)",
    "Authentication endpoints without rate limiting.",
    "",
  ] },
  { id: "exposed-endpoints", lines: [
    "### exposed-endpoints (CWE-200)",
    "Debug/monitoring endpoints exposed without auth (/actuator/*, /metrics, /swagger-ui).",
    "",
  ] },
  { id: "container-misconfig", lines: [
    "### container-misconfig (CWE-250)",
    "Dockerfile running as root, privileged containers, host network mode.",
    "",
  ] },
  { id: "cicd-misconfig", lines: [
    "### cicd-misconfig (CWE-829)",
    "GitHub Actions script injection, secrets exposed in logs, overly permissive GITHUB_TOKEN.",
    "",
  ] },
];

function buildPrompt(
  repoContext: RepoContext | undefined,
  maxFindings: number,
  profileLines: string[] = [],
  fileIndex?: FileIndex,
  preRead?: PreReadResult,
  threatModelContext?: string,
  applicationModelContext?: string,
  scenarioContext?: string,
  detectorScope: CodeConfigDetectorId[] = [
    "dangerous-api-detect",
    "auth-access-detect",
    "security-misconfig-detect",
  ],
): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Sanitization libs: ${repoContext.sanitizationLibs.join(", ") || "unknown"}`,
        `- Auth patterns: ${repoContext.authPatterns.join(", ") || "unknown"}`,
        `- Entry points: ${repoContext.entryPoints.join(", ") || "unknown"}`,
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

  const included = filterCategories(CODE_CONFIG_RELEVANCE, repoContext, fileIndex);
  const isFiltered = repoContext != null && included.size < CODE_CONFIG_RELEVANCE.length;
  const enableDangerousApi = detectorScope.includes("dangerous-api-detect");
  const enableAuthAccess = detectorScope.includes("auth-access-detect");
  const enableSecurityMisconfig = detectorScope.includes("security-misconfig-detect");

  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, ["eval-exec", "auth-session", "config-security"]);

  const part1Lines = enableDangerousApi ? filterBlocks(DANGEROUS_API_BLOCKS, included) : [];
  const part2Lines = enableAuthAccess ? filterBlocks(AUTH_ACCESS_BLOCKS, included) : [];
  const part3Lines = enableSecurityMisconfig ? filterBlocks(SECURITY_MISCONFIG_BLOCKS, included) : [];

  return [
    "You are a senior application security engineer with 10+ years of experience auditing production",
    "codebases for dangerous API usage, authentication/authorization flaws, and security misconfigurations.",
    "You combine deep expertise in code-level vulnerabilities with configuration hardening knowledge.",
    "",
    "Your task: systematically identify dangerous API calls, auth/access control issues, and security",
    "misconfigurations across the codebase.",
    "",
    ...contextLines,
    ...frameworkGuidance,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    ...(threatModelContext ? [threatModelContext, ""] : []),
    ...(applicationModelContext ? [applicationModelContext] : []),
    ...(scenarioContext ? [scenarioContext] : []),
    ...(isFiltered ? CATEGORY_SCOPE_HEADER : []),
    ...(part1Lines.length > 0 ? [
      "# Part 1: Dangerous API Detection",
      "",
      "For dangerous API findings, set `detectorId: \"dangerous-api-detect\"` and `category` to the API category.",
      "",
      "## Categories to detect",
      "",
      ...part1Lines,
    ] : []),
    ...(part2Lines.length > 0 ? [
      "# Part 2: Auth/Access Control Detection",
      "",
      "For auth findings, set `detectorId: \"auth-access-detect\"` and `category` to the auth pattern.",
      "Include `endpoint` and `httpMethod` fields when applicable.",
      "",
      "## Phase 1: Map auth architecture",
      "Identify the auth patterns used (JWT, session, OAuth, etc.).",
      "Build a map of which route groups are protected, including router/app/controller-level middleware.",
      "",
      "## Phase 2: Find violations",
      "",
      ...part2Lines,
    ] : []),
    ...(part3Lines.length > 0 ? [
      "# Part 3: Security Misconfiguration Detection",
      "",
      "For misconfiguration findings, set `detectorId: \"security-misconfig-detect\"` and `category` to the config category.",
      "",
      ...part3Lines,
    ] : []),
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "## Investigation methodology",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Start by analyzing the pre-loaded files above for all three categories.",
          "2. Use Glob/Grep only for additional files not already provided.",
          "3. Use Read to inspect any additional candidate files.",
        ]
      : [
          "1. Use Glob to find files with relevant imports, API calls, middleware, config files.",
          "2. Use Read to inspect each candidate file.",
        ]),
    "3. Trace input sources for dangerous APIs: is it attacker-controlled?",
    "4. Check for sanitization, validation, allowlists, or other guards.",
    "5. Only report findings where you can verify the issue.",
    "",
    `Return at most ${maxFindings} findings total (all categories combined), prioritized by severity and confidence.`,
    "Filter out any finding where your confidence would be below MEDIUM.",
    "",
    antiHallucinationModule({
      extra: [
        "If unsure whether input is attacker-controlled, do NOT report.",
        "Confidence HIGH only if source-to-sink is fully verified or misconfiguration is confirmed in code.",
        "If unsure whether middleware protects a route, READ the middleware registration.",
        "Only report misconfigurations you can verify in code. Do not assume defaults.",
        "Account for framework defaults that may provide secure configuration automatically.",
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ].filter(Boolean).join("\n");
}

function normalizeFindings(
  raw: unknown,
  repoRoot: string,
  repoName: string,
  maxFindings: number,
  detectorScope?: Set<CodeConfigDetectorId>,
): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as CodeConfigFinding;
    if (!f.filePath?.trim()) continue;
    if (detectorScope && !detectorScope.has((f.detectorId || "dangerous-api-detect") as CodeConfigDetectorId)) {
      continue;
    }

    let scanner: string;
    let rulePrefix: string;
    let fingerprintPrefix: string;

    switch (f.detectorId) {
      case "auth-access-detect":
        scanner = "auth-access-detect";
        rulePrefix = "auth-access";
        fingerprintPrefix = "auth-access";
        break;
      case "security-misconfig-detect":
        scanner = "security-misconfig-detect";
        rulePrefix = "security-misconfig";
        fingerprintPrefix = "security-misconfig";
        break;
      default:
        scanner = "dangerous-api-detect";
        rulePrefix = "dangerous-api";
        fingerprintPrefix = "dangerous-api";
        break;
    }

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, fingerprintPrefix, f.category, filePath, f.startLine);

    const apiInfo = f.apiOrFunction ? ` [${f.apiOrFunction}]` : "";
    const endpointInfo = f.endpoint ? ` (${f.httpMethod ?? "?"} ${f.endpoint})` : "";
    const extraInfo = f.detectorId === "dangerous-api-detect" ? apiInfo
      : f.detectorId === "auth-access-detect" ? endpointInfo
      : "";

    const finding: Finding = {
      scanner,
      fingerprint,
      ruleId: `${rulePrefix}/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Security issue detected"}${extraInfo}`,
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

function computeFingerprint(repoName: string, prefix: string, category: string, filePath: string, startLine: number): string {
  const source = [repoName, prefix, category, filePath, String(startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const codeConfigDetectTask: AgentTask<ScanOpts, Finding[]> = {
  id: "code-config-detect",
  displayName: "Code & Config Security Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("code-config-detect", fileIndex, context.repoRoot);
    const profiles = context.securityProfiles
      ? [
          ...getProfilesForTask(context.securityProfiles, "code-config-detect"),
          ...getProfilesForTask(context.securityProfiles, "dangerous-api-detect"),
          ...getProfilesForTask(context.securityProfiles, "auth-access-detect"),
          ...getProfilesForTask(context.securityProfiles, "security-misconfig-detect"),
        ]
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const threatModelContext = buildThreatModelLeadsSection(
      "code-config-detect",
      resolveThreatModelOutput(context.upstreamOutputs),
      fileIndex,
      preRead,
    );
    const prompt = buildPrompt(repoContext, maxFindings, profileLines, fileIndex, preRead, threatModelContext);
    const runtime = resolveTaskRuntime(context);

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[code-config-detect]";
    log.info(`Starting scan (model=${model})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,

          allowedTools: resolveTaskAllowedTools(context),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: CODE_CONFIG_SCHEMA,
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
    if (finding.ruleId.startsWith("auth-access/")) {
      return {
        prompt: [
          `You are triaging an auth/access control finding in "${repoName}".`,
          "",
          `Rule: ${finding.ruleId}`,
          `File: ${finding.filePath}:${finding.startLine}`,
          `Message: ${finding.message}`,
          finding.evidence ? `Rationale: ${finding.evidence}` : "",
          "",
          "Verify the endpoint is truly unprotected or the access control is genuinely missing.",
          "Check for middleware applied at router/app level that might not be visible at the handler.",
        ].filter(Boolean).join("\n"),
      };
    }

    if (finding.ruleId.startsWith("security-misconfig/")) {
      return {
        prompt: [
          `You are triaging a security misconfiguration finding in "${repoName}".`,
          "",
          `Rule: ${finding.ruleId}`,
          `File: ${finding.filePath}:${finding.startLine}`,
          `Message: ${finding.message}`,
          finding.evidence ? `Rationale: ${finding.evidence}` : "",
          "",
          "Verify the misconfiguration is genuine and affects production environments.",
          "Check if there are compensating controls or if the setting only applies to development.",
        ].filter(Boolean).join("\n"),
      };
    }

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

export const __codeConfigDetectInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
  CODE_CONFIG_RELEVANCE,
};
