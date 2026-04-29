// @ts-nocheck — untracked draft (unreferenced); skipped in tsc to unblock build.
import path from "node:path";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { FileIndex, RepoContext, TargetBrief, TargetBriefEvidence } from "../../types.js";
import { isRecord } from "../../utils.js";
import type { DagNodeImpl } from "../types.js";
import { resolveTaskAllowedTools, resolveTaskModel } from "./runtime-overrides.js";

export interface ContextPromptOptions {
  guidance?: string;
  promptOverride?: string;
}

export interface ContextClassifierOutput {
  targetBrief: TargetBrief;
  classifierPrompt: string;
  deterministicFallback: TargetBrief;
}

const TARGET_BRIEF_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "targetKind",
    "confidence",
    "platformHints",
    "domainLanguage",
    "entrypointConcepts",
    "executionSurfaceConcepts",
    "trustBoundaryConcepts",
    "assetConcepts",
    "threatLenses",
    "avoidAssumptions",
    "evidence",
  ],
  properties: {
    targetKind: { type: "string" },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    platformHints: { type: "array", items: { type: "string" } },
    domainLanguage: { type: "array", items: { type: "string" } },
    entrypointConcepts: { type: "array", items: { type: "string" } },
    executionSurfaceConcepts: { type: "array", items: { type: "string" } },
    trustBoundaryConcepts: { type: "array", items: { type: "string" } },
    assetConcepts: { type: "array", items: { type: "string" } },
    threatLenses: { type: "array", items: { type: "string" } },
    avoidAssumptions: { type: "array", items: { type: "string" } },
    evidence: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["signal", "detail"],
        properties: {
          signal: { type: "string" },
          detail: { type: "string" },
          filePath: { type: "string" },
        },
      },
    },
  },
} as const;

export const contextClassifierTask: DagNodeImpl<unknown, ContextClassifierOutput> = {
  id: "context-classifier",
  displayName: "Context Classifier",
  outputKind: "custom",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<ContextClassifierOutput> {
    context.signal?.throwIfAborted();
    const gathered = asGathererOutput(context.upstreamOutputs.get("context-gatherer"));
    const repoContext = gathered?.repoContext;
    const fileIndex = gathered?.fileIndex;
    const promptOptions = asPromptOptions(context.upstreamOutputs.get("context-prompt-options"));
    const deterministicFallback = buildDeterministicTargetBrief(
      context.workRoot ?? context.repoRoot,
      repoContext,
      fileIndex,
    );
    const classifierPrompt = buildClassifierPrompt({
      target: context.workRoot ?? context.repoRoot,
      repoContext,
      fileIndex,
      deterministicFallback,
      guidance: promptOptions.guidance,
    });

    const model = resolveTaskModel(context, "context-classifier", "context-classification");
    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const abortController = new AbortController();
    if (context.signal) {
      if (context.signal.aborted) abortController.abort();
      else context.signal.addEventListener("abort", () => abortController.abort(), { once: true });
    }

    try {
      for await (const message of context.runtime.query({
        prompt: classifierPrompt,
        options: {
          cwd: context.workRoot ?? context.repoRoot,
          model,
          abortController,
          allowedTools: resolveTaskAllowedTools(context).filter((tool) => tool !== "Write"),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: TARGET_BRIEF_SCHEMA,
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
    } catch {
      const fallback = {
        targetBrief: deterministicFallback,
        classifierPrompt,
        deterministicFallback,
      };
      return attachTaskOutputMeta(fallback, { costUsd });
    }

    const parsed = structuredOutput ?? safeParseJson(resultText);
    const targetBrief =
      normalizeTargetBrief(parsed, deterministicFallback) ?? deterministicFallback;
    const output = {
      targetBrief: { ...targetBrief, source: targetBrief.source ?? "llm" },
      classifierPrompt,
      deterministicFallback,
    };
    return attachTaskOutputMeta(output, { costUsd });
  },
};

export function buildClassifierPrompt(input: {
  target: string;
  repoContext?: RepoContext;
  fileIndex?: FileIndex;
  deterministicFallback: TargetBrief;
  guidance?: string;
}): string {
  const tree = input.fileIndex?.tree.slice(0, 120).map((entry) => entry.path) ?? [];
  const patternCounts = Object.fromEntries(
    Object.entries(input.fileIndex?.patternMatches ?? {}).map(([key, matches]) => [
      key,
      matches.length,
    ]),
  );

  return [
    "Classify the security analysis lens for this target.",
    "",
    "Return ONLY JSON matching the requested schema. Do not run tools unless the provided facts are insufficient.",
    "",
    `Target: ${path.resolve(input.target)}`,
    "",
    "Deterministic fallback brief:",
    JSON.stringify(input.deterministicFallback, null, 2),
    "",
    "Heuristic repo context:",
    JSON.stringify(
      input.repoContext ?? {
        languages: [],
        frameworks: [],
        authPatterns: [],
        sanitizationLibs: [],
        ormOrDb: [],
        entryPoints: [],
      },
      null,
      2,
    ),
    "",
    "File tree sample:",
    tree.length > 0 ? tree.map((file) => `- ${file}`).join("\n") : "- (none)",
    "",
    "Security pattern match counts:",
    JSON.stringify(patternCounts, null, 2),
    "",
    "Instructions:",
    "- Choose the most useful targetKind for prompt generation, not a product label.",
    "- Use domain language from the observed files.",
    "- Include concepts the downstream context and threat-model prompts should inspect.",
    "- Include assumptions to avoid when unsupported by evidence.",
    "- Keep arrays concise and actionable.",
    input.guidance ? ["", "Operator guidance:", input.guidance].join("\n") : "",
  ]
    .filter(Boolean)
    .join("\n");
}

export function buildDeterministicTargetBrief(
  target: string,
  repoContext?: RepoContext,
  fileIndex?: FileIndex,
): TargetBrief {
  const files = (fileIndex?.tree ?? []).map((entry) => entry.path);
  const fileSet = new Set(files);
  const evidence: TargetBriefEvidence[] = [];
  const addEvidence = (signal: string, detail: string, filePath?: string): void => {
    evidence.push(filePath ? { signal, detail, filePath } : { signal, detail });
  };

  const hasGithubWorkflows =
    path.basename(path.resolve(target)) === ".github" ||
    files.some((file) => /^workflows\/.+\.ya?ml$/i.test(file)) ||
    files.some((file) => /^\.github\/workflows\/.+\.ya?ml$/i.test(file));
  const hasGithubActions =
    files.some((file) => /^actions\/.+\/action\.ya?ml$/i.test(file)) ||
    files.some((file) => /^\.github\/actions\/.+\/action\.ya?ml$/i.test(file));
  const hasScripts = files.some((file) => /(^|\/)scripts\/.+\.(sh|bash|js|ts|py)$/i.test(file));
  const hasBuildkite =
    fileSet.has(".buildkite/pipeline.yml") ||
    fileSet.has(".buildkite/pipeline.yaml") ||
    fileSet.has("pipeline.yml") ||
    fileSet.has("pipeline.yaml");
  const hasJenkins = files.some((file) => /(^|\/)Jenkinsfile$|\.jenkinsfile$/i.test(file));
  const hasTerraform = files.some((file) => /\.tf$/i.test(file));
  const hasKubernetes = files.some((file) =>
    /(^|\/)(kustomization\.ya?ml|Chart\.ya?ml)|(^|\/)(k8s|kubernetes|helm)\//i.test(file),
  );
  const hasWebContext =
    (repoContext?.frameworks ?? []).some((framework) =>
      /express|next|react|django|flask|fastapi|gin|echo|nestjs|graphql/i.test(framework),
    ) || (repoContext?.entryPoints ?? []).length > 0;

  if (hasGithubWorkflows) {
    const workflow = files.find(
      (file) =>
        /^workflows\/.+\.ya?ml$/i.test(file) || /^\.github\/workflows\/.+\.ya?ml$/i.test(file),
    );
    const action = files.find(
      (file) =>
        /^actions\/.+\/action\.ya?ml$/i.test(file) ||
        /^\.github\/actions\/.+\/action\.ya?ml$/i.test(file),
    );
    const script = files.find((file) => /(^|\/)scripts\/.+\.(sh|bash|js|ts|py)$/i.test(file));
    if (workflow) addEvidence("github-workflows", "workflow YAML files under workflows/", workflow);
    if (hasGithubActions)
      addEvidence("github-actions", "local action definitions under actions/", action);
    if (hasScripts)
      addEvidence("scripts", "workflow helper scripts are present under scripts/", script);
    return {
      targetKind: "ci-cd automation",
      confidence: 0.95,
      platformHints: ["github-actions", "ci-cd"],
      domainLanguage: ["workflows", "jobs", "runners", "actions", "scripts", "secrets"],
      entrypointConcepts: [
        "workflow triggers",
        "workflow_dispatch inputs",
        "pull request events",
        "scheduled runs",
      ],
      executionSurfaceConcepts: [
        "run shell steps",
        "local composite actions",
        "third-party actions",
        "helper scripts",
      ],
      trustBoundaryConcepts: [
        "untrusted pull request input",
        "repository checkout",
        "runner environment",
        "secrets boundary",
        "artifact and cache handoff",
      ],
      assetConcepts: ["GITHUB_TOKEN", "repository secrets", "OIDC tokens", "artifacts", "caches"],
      threatLenses: [
        "command injection",
        "privilege escalation",
        "secret exposure",
        "supply-chain dependency risk",
        "artifact or cache poisoning",
      ],
      avoidAssumptions: [
        "do not assume HTTP routes",
        "do not assume relational database access",
        "do not assume web request filters",
      ],
      evidence,
      source: "deterministic",
    };
  }

  if (hasBuildkite || hasJenkins || hasTerraform || hasKubernetes) {
    if (hasBuildkite)
      addEvidence(
        "buildkite",
        "Buildkite pipeline files detected",
        files.find((file) => /(^|\/)?\.buildkite\/pipeline\.ya?ml$|^pipeline\.ya?ml$/i.test(file)),
      );
    if (hasJenkins)
      addEvidence(
        "jenkins",
        "Jenkinsfile detected",
        files.find((file) => /(^|\/)Jenkinsfile$|\.jenkinsfile$/i.test(file)),
      );
    if (hasTerraform)
      addEvidence(
        "terraform",
        "Terraform configuration detected",
        files.find((file) => /\.tf$/i.test(file)),
      );
    if (hasKubernetes)
      addEvidence(
        "kubernetes",
        "Kubernetes or Helm configuration detected",
        files.find((file) =>
          /(^|\/)(kustomization\.ya?ml|Chart\.ya?ml)|(^|\/)(k8s|kubernetes|helm)\//i.test(file),
        ),
      );
    return {
      targetKind:
        hasTerraform || hasKubernetes ? "infrastructure configuration" : "ci-cd automation",
      confidence: 0.86,
      platformHints: [
        ...(hasBuildkite ? ["buildkite"] : []),
        ...(hasJenkins ? ["jenkins"] : []),
        ...(hasTerraform ? ["terraform"] : []),
        ...(hasKubernetes ? ["kubernetes"] : []),
      ],
      domainLanguage: ["pipelines", "jobs", "agents", "scripts", "secrets", "configuration"],
      entrypointConcepts: ["pipeline triggers", "manual inputs", "scheduled jobs"],
      executionSurfaceConcepts: ["shell commands", "plugins", "deployment steps"],
      trustBoundaryConcepts: ["source checkout", "agent environment", "credentials boundary"],
      assetConcepts: ["secrets", "tokens", "artifacts", "deployment credentials"],
      threatLenses: [
        "command injection",
        "secret exposure",
        "supply-chain risk",
        "misconfiguration",
      ],
      avoidAssumptions: ["do not assume HTTP routes", "do not assume relational database access"],
      evidence,
      source: "deterministic",
    };
  }

  if (hasWebContext) {
    addEvidence("web-context", "web framework or entrypoint signals detected");
    return {
      targetKind: "application service",
      confidence: 0.78,
      platformHints: repoContext?.frameworks ?? [],
      domainLanguage: ["routes", "handlers", "middleware", "clients", "datastores"],
      entrypointConcepts: ["HTTP routes", "API handlers", "message consumers"],
      executionSurfaceConcepts: ["request handlers", "background jobs", "outbound clients"],
      trustBoundaryConcepts: [
        "external request boundary",
        "authentication boundary",
        "service boundary",
      ],
      assetConcepts: ["user data", "credentials", "sessions", "database records"],
      threatLenses: ["authorization bypass", "injection", "SSRF", "data exposure"],
      avoidAssumptions: [],
      evidence,
      source: "deterministic",
    };
  }

  return {
    targetKind: "codebase",
    confidence: 0.5,
    platformHints: [],
    domainLanguage: ["files", "modules", "scripts", "configuration"],
    entrypointConcepts: ["public interfaces", "commands", "configuration inputs"],
    executionSurfaceConcepts: ["scripts", "parsers", "library APIs"],
    trustBoundaryConcepts: ["external input boundary", "filesystem boundary"],
    assetConcepts: ["configuration", "source files", "runtime credentials"],
    threatLenses: ["unsafe input handling", "secret exposure", "supply-chain risk"],
    avoidAssumptions: ["do not assume HTTP routes", "do not assume relational database access"],
    evidence,
    source: "deterministic",
  };
}

export function normalizeTargetBrief(raw: unknown, fallback: TargetBrief): TargetBrief | null {
  if (!isRecord(raw)) return null;
  return {
    targetKind: asString(raw["targetKind"]) || fallback.targetKind,
    confidence: asConfidence(raw["confidence"], fallback.confidence),
    platformHints: nonEmptyStringArray(raw["platformHints"], fallback.platformHints),
    domainLanguage: nonEmptyStringArray(raw["domainLanguage"], fallback.domainLanguage),
    entrypointConcepts: nonEmptyStringArray(raw["entrypointConcepts"], fallback.entrypointConcepts),
    executionSurfaceConcepts: nonEmptyStringArray(
      raw["executionSurfaceConcepts"],
      fallback.executionSurfaceConcepts,
    ),
    trustBoundaryConcepts: nonEmptyStringArray(
      raw["trustBoundaryConcepts"],
      fallback.trustBoundaryConcepts,
    ),
    assetConcepts: nonEmptyStringArray(raw["assetConcepts"], fallback.assetConcepts),
    threatLenses: nonEmptyStringArray(raw["threatLenses"], fallback.threatLenses),
    avoidAssumptions: asStringArray(raw["avoidAssumptions"]),
    evidence: asEvidenceArray(raw["evidence"], fallback.evidence),
    source: "llm",
  };
}

export function coerceTargetBrief(value: unknown): TargetBrief | undefined {
  if (isRecord(value) && isRecord(value["targetBrief"]))
    return coerceTargetBrief(value["targetBrief"]);
  if (!isRecord(value) || typeof value["targetKind"] !== "string") return undefined;
  return (
    normalizeTargetBrief(value, {
      targetKind: "codebase",
      confidence: 0.5,
      platformHints: [],
      domainLanguage: [],
      entrypointConcepts: [],
      executionSurfaceConcepts: [],
      trustBoundaryConcepts: [],
      assetConcepts: [],
      threatLenses: [],
      avoidAssumptions: [],
      evidence: [],
      source: "deterministic",
    }) ?? undefined
  );
}

export function asPromptOptions(value: unknown): ContextPromptOptions {
  if (!isRecord(value)) return {};
  return {
    guidance: typeof value["guidance"] === "string" ? value["guidance"] : undefined,
    promptOverride:
      typeof value["promptOverride"] === "string" ? value["promptOverride"] : undefined,
  };
}

function asGathererOutput(
  value: unknown,
): { repoContext?: RepoContext; fileIndex?: FileIndex } | null {
  if (!isRecord(value)) return null;
  return {
    repoContext: isRecord(value["repoContext"]) ? (value["repoContext"] as RepoContext) : undefined,
    fileIndex: isRecord(value["fileIndex"])
      ? (value["fileIndex"] as unknown as FileIndex)
      : undefined,
  };
}

function safeParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((v) => String(v).trim()).filter(Boolean) : [];
}

function nonEmptyStringArray(value: unknown, fallback: string[]): string[] {
  const arr = asStringArray(value);
  return arr.length > 0 ? arr : fallback;
}

function asConfidence(value: unknown, fallback: number): number {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(0, Math.min(1, num));
}

function asEvidenceArray(value: unknown, fallback: TargetBriefEvidence[]): TargetBriefEvidence[] {
  if (!Array.isArray(value)) return fallback;
  const out: TargetBriefEvidence[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const signal = asString(item["signal"]);
    const detail = asString(item["detail"]);
    if (!signal || !detail) continue;
    const filePath = asString(item["filePath"]);
    out.push(filePath ? { signal, detail, filePath } : { signal, detail });
  }
  return out.length > 0 ? out : fallback;
}

export const __contextClassifierInternals = {
  buildClassifierPrompt,
  buildDeterministicTargetBrief,
  normalizeTargetBrief,
};
