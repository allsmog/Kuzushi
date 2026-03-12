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
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";

const SECRETS_DETECTION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["secretType", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale"],
        properties: {
          secretType: { type: "string", enum: ["api-key", "private-key", "password", "token", "connection-string"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
        },
      },
    },
  },
} as const;

interface SecretsDetectionFinding {
  secretType: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
}

interface SecretsDetectionConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): SecretsDetectionConfig {
  const raw = ctx.config.scannerConfig["secrets-detect"];
  const model = (isRecord(raw) && typeof raw["model"] === "string" && raw["model"].trim())
    ? raw["model"].trim()
    : ctx.config.model;
  const maxFindings = (isRecord(raw) && typeof raw["maxFindings"] === "number" && raw["maxFindings"] >= 1)
    ? Math.floor(raw["maxFindings"])
    : 100;
  return { model, maxFindings };
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, profileLines: string[] = []): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are a secrets detection specialist with deep expertise in identifying hardcoded credentials,",
    "API keys, and sensitive tokens in source code. You have reviewed hundreds of data breaches caused",
    "by leaked secrets and know how to distinguish real secrets from test fixtures and placeholders.",
    "",
    "Analyze the repository for hardcoded secrets and credentials. Only report findings where you",
    "have HIGH or MEDIUM confidence the secret is genuine — not a placeholder or test fixture.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Secret patterns to detect",
    "",
    "### api-key (CWE-798)",
    "- AWS access keys: starts with `AKIA` followed by 16 alphanumeric characters",
    "- GCP API keys: starts with `AIza` followed by 35 characters",
    "- Stripe keys: `sk_live_`, `pk_live_` prefixed strings",
    "- GitHub tokens: `ghp_`, `gho_`, `ghs_` prefixed strings",
    "- Generic API keys in config files or environment variable assignments",
    "",
    "### private-key (CWE-798)",
    "- RSA private keys: `BEGIN RSA PRIVATE KEY`",
    "- EC private keys: `BEGIN EC PRIVATE KEY`",
    "- PGP private keys: `BEGIN PGP PRIVATE KEY`",
    "- SSH private keys: `BEGIN OPENSSH PRIVATE KEY`",
    "",
    "### password (CWE-798)",
    "- Hardcoded passwords in connection strings or config",
    "- Password assignments in source code (e.g., `password = \"...\"`, `passwd: \"...\"`)",
    "",
    "### token (CWE-798)",
    "- JWT secrets hardcoded in source",
    "- OAuth tokens, bearer tokens in code",
    "- Session secrets, signing keys",
    "",
    "### connection-string (CWE-798)",
    "- Database URLs with embedded credentials: `mysql://user:pass@`, `postgresql://user:pass@`, `mongodb://user:pass@`",
    "- Redis URLs with passwords: `redis://:password@`",
    "",
    "## Instructions",
    "1. Use Glob to find config files (.env*, *.yml, *.yaml, *.json, *.toml, *.ini, *.conf)",
    "2. Use Grep to search for common secret patterns (AKIA, BEGIN.*PRIVATE KEY, password, secret, token)",
    "3. Use Read to inspect files with potential secrets",
    `4. Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report secrets you can verify exist in the actual code.",
        "Do NOT report test fixtures, example configs, documentation samples, or placeholder values.",
        "Strings like `YOUR_API_KEY`, `xxx`, `changeme`, `placeholder`, `example` are NOT real secrets.",
        "Files in `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`, `mocks/` are test fixtures — be extra skeptical.",
        "`.env.example` and `.env.sample` files contain placeholders, not real secrets.",
      ],
    }),
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as SecretsDetectionFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const finding: Finding = {
      scanner: "secrets-detect",
      fingerprint,
      ruleId: `secrets/${f.secretType || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "ERROR",
      message: `${f.description || "Potential hardcoded secret"}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: f.confidence || "MEDIUM",
      impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: ["CWE-798"],
      score: scoreFindingMetadata({
        severity: f.severity,
        likelihood: f.confidence,
        impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
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

function computeFingerprint(repoName: string, filePath: string, f: SecretsDetectionFinding): string {
  const source = [repoName, "secrets-detect", f.secretType, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const secretsDetectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "secrets-detect",
  displayName: "Secrets Detector",
  outputKind: "findings",
  dependsOn: [],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "secrets-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[secrets-detect]";
    console.error(`${tag} Starting scan (model=${model})`);

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
            schema: SECRETS_DETECTION_SCHEMA,
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
        `You are triaging a secrets detection finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify if the detected secret is a real credential or a placeholder/test fixture.",
        "Check if it's in a test file, example config, or documentation.",
        "Check if the value looks like a real secret (sufficient entropy, proper format).",
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

export const __secretsDetectionInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
