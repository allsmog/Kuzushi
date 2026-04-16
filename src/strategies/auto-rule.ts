import { spawn } from "node:child_process";
import path from "node:path";
import { resolveTaskModel, resolveTaskRuntime } from "../agents/tasks/runtime-overrides.js";
import type { TaskContext } from "../agents/types.js";
import { createLogger } from "../logger.js";
import type { Finding } from "../scanners/types.js";
import { toErrorMessage } from "../utils.js";
import type { GeneratedRule, StrategyEvidence } from "./types.js";

const log = createLogger({ stage: "auto-rule" });

const LANG_EXT_MAP: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".py": "python",
  ".go": "go",
  ".java": "java",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".rs": "rust",
  ".c": "c",
  ".cpp": "cpp",
};

const RULE_GENERATION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["rule"],
  properties: {
    rule: {
      type: "object",
      additionalProperties: false,
      required: ["kind", "ruleContent", "description", "vulnClass", "cweIds"],
      properties: {
        kind: { type: "string", enum: ["semgrep", "grep-pattern"] },
        ruleContent: { type: "string" },
        description: { type: "string" },
        vulnClass: { type: "string" },
        cweIds: { type: "array", items: { type: "string" } },
      },
    },
  },
} as const;

function detectLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return LANG_EXT_MAP[ext] ?? "generic";
}

/**
 * Extract a reusable Semgrep detection rule from a confirmed finding.
 * Uses an LLM call to generalize the specific finding into a pattern.
 */
export async function generateRule(
  finding: Finding,
  evidence: StrategyEvidence[] | undefined,
  context: TaskContext,
): Promise<GeneratedRule | null> {
  const runtime = resolveTaskRuntime(context);
  const model = resolveTaskModel(context, "multi-strategy");
  const cwd = context.scanPath ?? context.repoRoot;
  const language = detectLanguage(finding.filePath);

  const evidenceStr =
    evidence && evidence.length > 0
      ? [
          "## Evidence from analysis",
          ...evidence.map((e) => `- [${e.kind}] ${e.description}`),
          "",
        ].join("\n")
      : "";

  const prompt = [
    "You are a Semgrep rule engineer. A vulnerability was confirmed through verification.",
    "Generate a reusable Semgrep rule that catches this vulnerability pattern and similar variants.",
    "",
    "## Confirmed Finding",
    `File: ${finding.filePath}:${finding.startLine}`,
    `Rule: ${finding.ruleId}`,
    `CWE: ${finding.cwe.join(", ") || "unknown"}`,
    `Language: ${language}`,
    `Message: ${finding.message}`,
    finding.evidence ? `Evidence: ${finding.evidence}` : "",
    "",
    evidenceStr,
    "## Instructions",
    "1. Read the vulnerable code at the finding location to understand the exact pattern",
    "2. Identify what makes this code vulnerable — the dangerous sink and how untrusted input reaches it",
    "3. Generate a Semgrep YAML rule with these requirements:",
    "",
    "   **Pattern design:**",
    "   - Use `patterns` with `pattern` to match the vulnerable code shape",
    "   - Use `pattern-not` to exclude safe variants (parameterized queries, escaped output, sanitized input)",
    "   - Use `pattern-either` when multiple syntactic forms are vulnerable",
    "   - Prefer structural patterns over regex — Semgrep understands ASTs",
    "",
    "   **Rule metadata (REQUIRED):**",
    "   ```yaml",
    "   metadata:",
    "     category: security",
    "     confidence: HIGH",
    `     cwe: ["CWE-XXX"]  # Use actual CWE IDs`,
    '     subcategory: ["vuln"]',
    "   ```",
    "",
    `   **Rule ID format:** \`kuzushi.custom.<descriptive-name>\``,
    `   **Languages:** [${language}]`,
    "   **Severity:** ERROR for exploitable, WARNING for potential",
    "",
    "4. Identify abstraction points in the vulnerability pattern:",
    "   - What variable names, function forms, or library calls could vary?",
    "   - Could the same sink be reached via different APIs?",
    "   - Use Semgrep metavariables ($VAR, $FUNC, $EXPR) to capture these variations",
    "5. Prefer `pattern-either` with multiple concrete shapes over a single overly-broad pattern",
    "6. The rule should catch the FAMILY of this vulnerability, not just this exact instance",
    "7. Avoid overly broad rules — prefer precision over recall",
    "8. Return the COMPLETE valid Semgrep YAML including the `rules:` top-level key",
  ]
    .filter(Boolean)
    .join("\n");

  try {
    let structuredOutput: unknown;

    for await (const message of runtime.query({
      prompt,
      options: {
        cwd,
        model,
        allowedTools: ["Read", "Grep"],
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: RULE_GENERATION_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      },
    })) {
      if (message.type === "result" && "result" in message) {
        structuredOutput = message.structuredOutput;
      }
    }

    if (!structuredOutput || typeof structuredOutput !== "object") return null;
    const obj = structuredOutput as Record<string, unknown>;
    const rule = obj["rule"] as Record<string, unknown> | undefined;
    if (!rule) return null;

    const kind = rule["kind"] === "semgrep" ? "semgrep" : "grep-pattern";
    const ruleContent = String(rule["ruleContent"] ?? "");
    const description = String(rule["description"] ?? "");
    const vulnClass = String(rule["vulnClass"] ?? finding.cwe[0] ?? "unknown");
    const cweIds = Array.isArray(rule["cweIds"])
      ? rule["cweIds"].map((c) => String(c)).filter(Boolean)
      : finding.cwe;

    if (!ruleContent) return null;

    return {
      kind,
      vulnClass,
      cweIds,
      ruleContent,
      description,
      sourceFinding: {
        fingerprint: finding.fingerprint,
        filePath: finding.filePath,
        startLine: finding.startLine,
      },
    };
  } catch (error) {
    log.warn(`Rule generation failed: ${toErrorMessage(error)}`);
    return null;
  }
}

/**
 * Validate a generated rule by running Semgrep against the original finding location.
 * Returns true if the rule catches the finding.
 */
export async function validateRule(
  ruleFilePath: string,
  targetFile: string,
  targetLine: number,
  repoRoot: string,
  semgrepBin: string = "semgrep",
): Promise<boolean> {
  // Path traversal guard: target must resolve inside repoRoot
  const resolvedTarget = path.resolve(repoRoot, targetFile);
  const resolvedRoot = path.resolve(repoRoot);
  if (!resolvedTarget.startsWith(resolvedRoot + path.sep) && resolvedTarget !== resolvedRoot) {
    return false;
  }

  return new Promise((resolve) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 30_000);

    const proc = spawn(
      semgrepBin,
      ["--config", ruleFilePath, "--json", "--no-git-ignore", resolvedTarget],
      {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "ignore"],
        signal: ac.signal,
      },
    );

    const chunks: Buffer[] = [];
    proc.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        resolve(false);
        return;
      }
      try {
        const output = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
        const results = output?.results ?? [];
        const hit = results.some((r: Record<string, unknown>) => {
          const start = r["start"] as Record<string, unknown> | undefined;
          const line = Number(start?.["line"] ?? 0);
          return Math.abs(line - targetLine) <= 3;
        });
        resolve(hit);
      } catch {
        resolve(false);
      }
    });

    proc.on("error", () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

/**
 * Takes a validated rule and produces a more generalized variant using
 * metavariables and pattern-either. The generalized rule is broader but
 * still constrained by pattern-not exclusions.
 */
export async function generateGeneralizedRule(
  originalRule: GeneratedRule,
  finding: Finding,
  context: TaskContext,
): Promise<GeneratedRule | null> {
  if (originalRule.kind !== "semgrep") return null;

  const runtime = resolveTaskRuntime(context);
  const model = resolveTaskModel(context, "multi-strategy");
  const cwd = context.scanPath ?? context.repoRoot;

  const prompt = [
    "You are a Semgrep rule engineer. You have an existing rule that catches one specific vulnerability.",
    "Your task is to GENERALIZE it to catch a broader family of the same vulnerability class.",
    "",
    "## Original Rule",
    "```yaml",
    originalRule.ruleContent,
    "```",
    "",
    "## Source Finding",
    `File: ${finding.filePath}:${finding.startLine}`,
    `CWE: ${finding.cwe.join(", ")}`,
    `Vuln class: ${originalRule.vulnClass}`,
    "",
    "## Instructions",
    "1. Read the original rule and understand what specific code pattern it matches",
    "2. Identify what can vary while preserving the vulnerability:",
    "   - Variable names → replace with Semgrep metavariables ($VAR, $FUNC, $ARG)",
    "   - Specific function calls → generalize with `pattern-either` listing alternatives",
    "   - Literal values → use `...` ellipsis where the value doesn't matter",
    "3. Keep ALL `pattern-not` exclusions from the original (safe patterns must still be excluded)",
    "4. Add any NEW `pattern-not` exclusions for false-positive-prone generalizations",
    "5. Use the rule ID format: `kuzushi.custom.<original-name>-generalized`",
    "6. Return the COMPLETE valid Semgrep YAML including the `rules:` top-level key",
    "",
    "IMPORTANT: The generalized rule should catch MORE variants but NOT introduce false positives.",
    "If the original rule is already well-generalized, return it unchanged.",
  ].join("\n");

  try {
    let structuredOutput: unknown;

    for await (const message of runtime.query({
      prompt,
      options: {
        cwd,
        model,
        allowedTools: ["Read", "Grep"],
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: RULE_GENERATION_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      },
    })) {
      if (message.type === "result" && "result" in message) {
        structuredOutput = message.structuredOutput;
      }
    }

    if (!structuredOutput || typeof structuredOutput !== "object") return null;
    const obj = structuredOutput as Record<string, unknown>;
    const rule = obj["rule"] as Record<string, unknown> | undefined;
    if (!rule) return null;

    const ruleContent = String(rule["ruleContent"] ?? "");
    if (!ruleContent || ruleContent === originalRule.ruleContent) return null;

    return {
      kind: "semgrep",
      vulnClass: originalRule.vulnClass,
      cweIds: originalRule.cweIds,
      ruleContent,
      description: String(rule["description"] ?? originalRule.description),
      sourceFinding: originalRule.sourceFinding,
    };
  } catch (error) {
    log.warn(`Generalized rule generation failed: ${toErrorMessage(error)}`);
    return null;
  }
}
