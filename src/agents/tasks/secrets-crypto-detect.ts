import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
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

const log = createLogger({ stage: "secrets-crypto-detect" });

const SECRETS_CRYPTO_SCHEMA = {
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
          detectorId: { type: "string", enum: ["secrets-detect", "crypto-misuse-detect"] },
          category: { type: "string" },
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

interface SecretsCryptoFinding {
  detectorId: string;
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
}

interface SecretsCryptoConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): SecretsCryptoConfig {
  const raw = ctx.config.scannerConfig["secrets-crypto-detect"];
  const model = (isRecord(raw) && typeof raw["model"] === "string" && raw["model"].trim())
    ? raw["model"].trim()
    : ctx.config.model;
  const maxFindings = (isRecord(raw) && typeof raw["maxFindings"] === "number" && raw["maxFindings"] >= 1)
    ? Math.floor(raw["maxFindings"])
    : 100;
  return { model, maxFindings };
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, profileLines: string[] = [], fileIndex?: FileIndex, preRead?: PreReadResult): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are a combined secrets detection and cryptography security specialist. You have deep expertise in",
    "identifying hardcoded credentials, API keys, and sensitive tokens, as well as insecure cryptographic",
    "practices in source code. You have reviewed hundreds of data breaches and crypto misuse incidents.",
    "",
    "Analyze the repository for both hardcoded secrets/credentials AND insecure cryptographic practices.",
    "Only report findings where you have HIGH or MEDIUM confidence the issue is genuine.",
    "",
    ...contextLines,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "# Part 1: Secrets Detection",
    "",
    "For secrets findings, set `detectorId: \"secrets-detect\"` and `category` to the secret type.",
    "",
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
    "### webhook-url (CWE-798)",
    "- Slack webhook URLs: `https://hooks.slack.com/services/T`",
    "- Discord webhooks: `https://discord.com/api/webhooks/`",
    "- Generic webhook URLs with embedded tokens",
    "",
    "### cloud-credential (CWE-798)",
    "- Azure: connection strings with `AccountKey=`, `SharedAccessKey=`",
    "- Heroku API keys: `HRKU-` prefix",
    "- Datadog API/APP keys: 32-character hex strings in config",
    "- Twilio: Account SID (`AC` + 32 hex) and Auth Token pairs",
    "",
    "### package-registry-token (CWE-798)",
    "- npm tokens: `npm_` prefix",
    "- PyPI tokens: `pypi-AgEIcH` prefix",
    "- NuGet API keys: `oy2` prefix",
    "- RubyGems: API keys in .gem/credentials",
    "",
    "## Entropy heuristic",
    "High-entropy strings (>4.0 bits/char Shannon entropy) in config files are likely real secrets.",
    "Low-entropy strings or dictionary words are likely placeholders. Use this as an additional signal.",
    "",
    "# Part 2: Cryptographic Misuse Detection",
    "",
    "For crypto findings, set `detectorId: \"crypto-misuse-detect\"` and `category` to the crypto category.",
    "",
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
    "### key-length (CWE-326)",
    "Bad: RSA key < 2048 bits, AES-128 where AES-256 is feasible, DSA keys < 2048.",
    "Check key generation parameters and constants.",
    "",
    "### ecb-mode (CWE-327)",
    "Bad: AES-ECB mode for anything beyond single-block encryption. Leaks patterns in data.",
    "Check cipher mode parameters: `AES/ECB`, `createCipheriv('aes-128-ecb', ...)`.",
    "",
    "### insecure-prng (CWE-338)",
    "Bad: Math.random() for security-sensitive values (tokens, session IDs, nonces, salts).",
    "Good: crypto.randomBytes(), crypto.getRandomValues(), secrets module.",
    "",
    "### timing-attack (CWE-208)",
    "Bad: String comparison (`===`, `==`, `strcmp`) for HMAC verification, password comparison,",
    "or token validation. Leaks length information via timing side-channel.",
    "Good: crypto.timingSafeEqual(), hmac.compare(), constant-time comparison libraries.",
    "",
    "### cert-validation (CWE-295)",
    "Bad: TLS certificate verification disabled (`rejectUnauthorized: false`, `verify=False`,",
    "`InsecureSkipVerify: true`), custom trust stores that accept self-signed certs in production.",
    "",
    formatFileTreeForPrompt(fileIndex),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    formatPatternMatchesForPrompt(fileIndex, ["secret-pattern", "crypto-import"]),
    "## Instructions",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Start by analyzing the pre-loaded files above for hardcoded secrets AND cryptographic misuse.",
          "2. Use Glob/Grep only for additional files not already provided.",
          "3. Use Read to inspect any additional files with potential issues.",
        ]
      : [
          "1. Use Glob to find config files (.env*, *.yml, *.yaml, *.json, *.toml, *.ini, *.conf) and files with crypto imports.",
          "2. Use Grep to search for common secret patterns and crypto API calls.",
          "3. Use Read to inspect files with potential secrets or crypto callsites.",
        ]),
    `4. Return at most ${maxFindings} findings total (both categories combined), prioritized by severity.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report secrets you can verify exist in the actual code.",
        "Do NOT report test fixtures, example configs, documentation samples, or placeholder values.",
        "Strings like `YOUR_API_KEY`, `xxx`, `changeme`, `placeholder`, `example` are NOT real secrets.",
        "Files in `test/`, `tests/`, `__tests__/`, `spec/`, `fixtures/`, `mocks/` are test fixtures — be extra skeptical.",
        "`.env.example` and `.env.sample` files contain placeholders, not real secrets.",
        "For crypto findings, only report genuinely insecure usage — not merely suboptimal.",
      ],
    }),
    frameworkAwarenessModule(repoContext),
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as SecretsCryptoFinding;
    if (!f.filePath?.trim()) continue;

    const isSecrets = f.detectorId === "secrets-detect";
    const scanner = isSecrets ? "secrets-detect" : "crypto-misuse-detect";
    const rulePrefix = isSecrets ? "secrets" : "crypto-misuse";
    const fingerprintPrefix = isSecrets ? "secrets-detect" : "crypto-misuse";

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, fingerprintPrefix, f.category, filePath, f.startLine);

    const finding: Finding = {
      scanner,
      fingerprint,
      ruleId: `${rulePrefix}/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || (isSecrets ? "ERROR" : "WARNING"),
      message: `${f.description || (isSecrets ? "Potential hardcoded secret" : "Potential cryptographic misuse")}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: f.confidence || "MEDIUM",
      impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: cweList.length > 0 ? cweList : (isSecrets ? ["CWE-798"] : []),
      score: scoreFindingMetadata({
        severity: f.severity,
        likelihood: f.confidence,
        impact: f.severity === "ERROR" ? "HIGH" : f.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
        cwe: cweList.length > 0 ? cweList : (isSecrets ? ["CWE-798"] : []),
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

export const secretsCryptoDetectTask: AgentTask<ScanOpts, Finding[]> = {
  id: "secrets-crypto-detect",
  displayName: "Secrets & Crypto Misuse Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("secrets-crypto-detect", fileIndex, context.repoRoot);
    const profiles = context.securityProfiles
      ? [
          ...getProfilesForTask(context.securityProfiles, "secrets-crypto-detect"),
          ...getProfilesForTask(context.securityProfiles, "secrets-detect"),
          ...getProfilesForTask(context.securityProfiles, "crypto-misuse-detect"),
        ]
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines, fileIndex, preRead);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[secrets-crypto-detect]";
    log.info(`Starting scan (model=${model})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model,
          maxTurns: context.config.taskMaxTurns ?? 15,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: SECRETS_CRYPTO_SCHEMA,
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
    if (finding.ruleId.startsWith("secrets/")) {
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
    }

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

export const __secretsCryptoDetectInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
