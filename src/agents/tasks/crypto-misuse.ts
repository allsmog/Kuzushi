import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import { coerceRepoContext } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { RepoContext, ScanOpts } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { getProfilesForTask, formatProfilesForPrompt } from "../../security-profiles.js";
import type { AgentTask, TaskContext } from "../types.js";

const CRYPTO_MISUSE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["category", "filePath", "startLine", "severity", "algorithmOrPattern", "recommendation", "cwe", "confidence", "rationale"],
        properties: {
          category: { type: "string", enum: ["hash-for-auth", "symmetric-cipher", "key-generation", "tls-config", "password-storage"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          algorithmOrPattern: { type: "string" },
          recommendation: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
        },
      },
    },
  },
} as const;

interface CryptoMisuseFinding {
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  algorithmOrPattern: string;
  recommendation: string;
  cwe: string;
  confidence: string;
  rationale: string;
}

interface CryptoMisuseConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): CryptoMisuseConfig {
  const raw = ctx.config.scannerConfig["crypto-misuse"];
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
        "",
      ]
    : [];

  return [
    "You are a senior cryptography engineer and security auditor with deep expertise in applied",
    "cryptographic protocols. You have reviewed hundreds of codebases for crypto misuse and know",
    "the difference between textbook vulnerabilities and real-world exploitable weaknesses.",
    "",
    "Analyze the repository for insecure cryptographic practices. Only report findings where you",
    "have HIGH or MEDIUM confidence the usage is genuinely insecure — not merely suboptimal.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to check",
    "",
    "### hash-for-auth (CWE-328)",
    "Bad: MD5, SHA1 for passwords/tokens. Good: bcrypt, scrypt, Argon2.",
    "",
    "### symmetric-cipher (CWE-327)",
    "Bad: ECB mode, DES, RC4, Blowfish. Good: AES-GCM, ChaCha20-Poly1305.",
    "",
    "### key-generation (CWE-330, CWE-798)",
    "Bad: Math.random(), hardcoded keys/secrets. Good: crypto.randomBytes(), KMS.",
    "",
    "### tls-config (CWE-295)",
    "Bad: Disabled cert verification, TLS < 1.2. Good: TLS 1.3, proper CA validation.",
    "",
    "### password-storage (CWE-916)",
    "Bad: Plaintext, unsalted, fast hash. Good: bcrypt/Argon2 with work factor.",
    "",
    "## Instructions",
    "1. Use Glob to find files with crypto imports (crypto, hashlib, javax.crypto, bcrypt, argon2, etc.)",
    "2. Use Read to inspect each file with crypto callsites.",
    "3. Classify each usage by category and safety.",
    `4. Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    "## Anti-hallucination constraints",
    "- Only report concrete misuse you can verify in code. Do not report secure patterns.",
    "- Do NOT infer or speculate about code you haven't read.",
    "- If a crypto library is used correctly per its documentation, do not flag it.",
    "- Confidence must reflect your actual certainty: HIGH only if misuse is unambiguous.",
    repoContext?.frameworks.length
      ? `- Account for framework defaults: ${repoContext.frameworks.join(", ")} may provide secure defaults.`
      : "",
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as CryptoMisuseFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const finding: Finding = {
      scanner: "crypto-misuse-detect",
      fingerprint,
      ruleId: `crypto-misuse/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.algorithmOrPattern || "Crypto misuse"}: ${f.rationale || "Potential cryptographic misuse"}`,
      evidence: f.recommendation || null,
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

function computeFingerprint(repoName: string, filePath: string, f: CryptoMisuseFinding): string {
  const source = [repoName, "crypto-misuse", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const cryptoMisuseTask: AgentTask<ScanOpts, Finding[]> = {
  id: "crypto-misuse-detect",
  displayName: "Crypto Misuse Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "crypto-misuse-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[crypto-misuse]";
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
            schema: CRYPTO_MISUSE_SCHEMA,
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
        `You are triaging a crypto misuse finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Recommendation: ${finding.evidence}` : "",
        "",
        "Verify the cryptographic usage is genuinely insecure in context.",
        "Check if there are compensating controls or if the usage is non-security-critical.",
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

export const __cryptoMisuseInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
