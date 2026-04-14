import { createHash } from "node:crypto";
import path from "node:path";
import {
  antiHallucinationModule,
  frameworkAwarenessModule,
} from "../../prompts/modules.js";
import {
  languageTuningModule,
  languageInvestigationModule,
  languageAntiHallucinationExtras,
} from "../../prompts/language-tuning.js";
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
import { resolveTaskAllowedTools, resolveTaskModel, resolveTaskPositiveInt, resolveTaskRuntime } from "./runtime-overrides.js";

const log = createLogger({ stage: "supply-chain" });

const SUPPLY_CHAIN_SCHEMA = {
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
          category: { type: "string", enum: ["postinstall-scripts", "lockfile-integrity", "internal-package-exposure"] },
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

interface SupplyChainFinding {
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

interface SupplyChainConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): SupplyChainConfig {
  const model = resolveTaskModel(ctx, "supply-chain");
  const maxFindings = resolveTaskPositiveInt(ctx, "supply-chain", "maxFindings", 50);
  return { model, maxFindings };
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, profileLines: string[] = [], fileIndex?: FileIndex, preRead?: PreReadResult): string {
  const patternMatchText = formatPatternMatchesForPrompt(fileIndex, []);

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
        "When analyzing supply chain risks, account for ecosystem-specific protections:",
        "- npm: --ignore-scripts flag, npm audit, package-lock.json integrity hashes",
        "- yarn: yarn.lock integrity, --frozen-lockfile in CI, yarn audit",
        "- pnpm: pnpm-lock.yaml, strict peer dependencies, side-effects-free by default",
        "- pip: pip --require-hashes, pipfile.lock, pip-audit",
        "Do NOT flag packages with verified integrity hashes in lockfiles.",
        "",
      ]
    : [];

  return [
    "You are a senior supply chain security engineer specializing in software composition analysis",
    "and dependency security. You have deep expertise in npm/yarn/pnpm ecosystem attacks,",
    "dependency confusion, typosquatting, and postinstall script exploitation.",
    "",
    "Your task: systematically identify supply chain risks in the repository's dependency configuration,",
    "lockfiles, and package manifest files.",
    "",
    ...contextLines,
    ...frameworkGuidance,
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "## Categories to detect",
    "",
    languageTuningModule({ taskId: "supply-chain", repoContext, frameworks: repoContext?.frameworks }) ||
    "### postinstall-scripts (CWE-829)",
    "npm/yarn/pnpm postinstall, preinstall, or install lifecycle scripts that download or execute",
    "external code. Dangerous patterns:",
    "- Scripts that use curl/wget to download and execute remote code",
    "- Scripts that spawn child processes to run downloaded binaries",
    "- Scripts that modify system files or environment variables",
    "- Dependencies with suspicious lifecycle scripts in their package.json",
    "Check both the repository's own package.json scripts AND key dependencies' postinstall scripts.",
    "Do NOT flag common build tools (node-gyp, esbuild, typescript) that use postinstall for compilation.",
    "",
    "### lockfile-integrity (CWE-829)",
    "Missing or inconsistent lockfile configurations that could allow dependency substitution.",
    "- Missing lockfile entirely (package-lock.json, yarn.lock, pnpm-lock.yaml)",
    "- Lockfile not matching package.json (dependency drift)",
    "- Missing integrity hashes in lockfile entries",
    "- .npmrc or .yarnrc configurations that disable integrity checks",
    "- CI/CD configurations that don't use --frozen-lockfile or equivalent",
    "",
    "### internal-package-exposure (CWE-829)",
    "Internal or private package names that could be claimed on the public npm registry,",
    "enabling dependency confusion attacks. Dangerous patterns:",
    "- @company-scope packages where the scope is not registered on npmjs.com",
    "- Unscoped internal package names that don't exist on the public registry",
    "- .npmrc pointing to private registry without scoped configuration",
    "- Package names in dependencies that match common internal naming patterns",
    "  (e.g., company-utils, internal-*, private-*) without scope protection",
    "",
    formatFileTreeForPrompt(fileIndex, patternMatchText.length > 0),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    patternMatchText,
    "## Investigation methodology",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Start by analyzing the pre-loaded files above for supply chain risks.",
          "2. Use Glob/Grep only for additional files not already provided.",
          "3. Use Read to inspect additional package manifest and lockfiles.",
          "4. Use Grep to search for internal package names in dependency lists.",
          "5. Check CI configuration files for lockfile enforcement (--frozen-lockfile, --ci).",
        ]
      : [
          "1. Use Glob to find package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, .npmrc, .yarnrc files.",
          "2. Use Read to inspect package.json scripts sections for dangerous lifecycle hooks.",
          "3. Use Read to check lockfile presence and integrity hash coverage.",
          "4. Use Grep to search for internal package names in dependency lists.",
          "5. Check CI configuration files for lockfile enforcement (--frozen-lockfile, --ci).",
        ]),
    `6. Return at most ${maxFindings} findings, prioritized by severity.`,
    "",
    antiHallucinationModule({
      extra: [
        "Only report supply chain risks you can verify from actual configuration files.",
        "Do NOT flag well-known build tools (node-gyp, esbuild, husky) for postinstall scripts.",
        "Do NOT flag missing lockfiles in library packages that intentionally omit them.",
        "Confidence HIGH only if the risk vector is clearly verified in the repository.",
        ...languageAntiHallucinationExtras({ taskId: "supply-chain", repoContext, frameworks: repoContext?.frameworks }),
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
    const f = item as unknown as SupplyChainFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, f.filePath);
    const cweList = f.cwe ? [f.cwe] : [];
    const fingerprint = computeFingerprint(repoName, filePath, f);

    const apiInfo = f.apiOrFunction ? ` [${f.apiOrFunction}]` : "";

    const finding: Finding = {
      taskId: "supply-chain-detect",
      fingerprint,
      ruleId: `supply-chain/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "WARNING",
      message: `${f.description || "Potential supply chain risk"}${apiInfo}`,
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

function computeFingerprint(repoName: string, filePath: string, f: SupplyChainFinding): string {
  const source = [repoName, "supply-chain", f.category, filePath, String(f.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

export const supplyChainTask: AgentTask<ScanOpts, Finding[]> = {
  id: "supply-chain-detect",
  displayName: "Supply Chain Detector",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<Finding[]> {
    const { model, maxFindings } = resolveConfig(context);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("supply-chain-detect", fileIndex, context.repoRoot);
    const profiles = context.securityProfiles
      ? getProfilesForTask(context.securityProfiles, "supply-chain-detect")
      : [];
    const profileLines = formatProfilesForPrompt(profiles);
    const prompt = buildPrompt(repoContext, maxFindings, profileLines, fileIndex, preRead);
    const runtime = resolveTaskRuntime(context);

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[supply-chain]";
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
            schema: SUPPLY_CHAIN_SCHEMA,
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
        `You are triaging a supply chain security finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The supply chain risk actually exists in the reported configuration file.",
        "2. The risk is genuine and not mitigated by other security controls.",
        "3. No lockfile enforcement, integrity checks, or scope protection prevents exploitation.",
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

export const __supplyChainInternals = {
  resolveConfig,
  buildPrompt,
  normalizeFindings,
  computeFingerprint,
};
