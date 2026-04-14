import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import { createLogger } from "../../../logger.js";
import type { Finding, TaintPathStep, TriageAgentConfig } from "../../../scanners/types.js";
import type { ScanOpts } from "../../../types.js";
import { isPathWithinRoot, isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask, TaskContext } from "../../types.js";
import {
  buildSystemsHuntArtifactDetail,
  extractSystemsHuntArtifactPath,
  writeSystemsHuntArtifact,
} from "./artifacts.js";
import type {
  RankedSystemsSurface,
  SystemsAnalysisStep,
  SystemsContextOutput,
  SystemsCorroborationStatus,
  SystemsHuntArtifact,
  SystemsHuntConfig,
  SystemsHuntLens,
  SystemsInvariant,
  SystemsInvariantOutput,
  SystemsSurfacePack,
  SystemsSurfaceKind,
  SystemsTriggerHypothesis,
  SystemsTriggerOutput,
} from "./types.js";
import {
  SYSTEMS_HUNT_LENSES,
  resolveSystemsHuntConfig,
} from "./types.js";
import { resolveTaskAllowedTools } from "../runtime-overrides.js";
import {
  formatSystemsSurfacePack,
  matchTriggerHypothesisToFinding,
} from "./helpers.js";

const log = createLogger({ stage: "systems-hunt" });

const LENS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "title",
          "cwe",
          "severity",
          "confidence",
          "filePath",
          "startLine",
          "message",
          "rationale",
          "triggerHypothesisIds",
          "violatedInvariant",
          "cheapVerifiable",
        ],
        properties: {
          title: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          message: { type: "string" },
          rationale: { type: "string" },
          triggerHypothesisIds: { type: "array", items: { type: "string" } },
          violatedInvariantIds: { type: "array", items: { type: "string" } },
          violatedInvariant: { type: "string" },
          triggerSequence: { type: "array", items: { type: "string" } },
          attackerControlledFields: { type: "array", items: { type: "string" } },
          memoryPrimitive: { type: "string" },
          hardeningNotes: { type: "array", items: { type: "string" } },
          cheapVerifiable: { type: "boolean" },
          analysisPath: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["filePath", "line", "role"],
              properties: {
                filePath: { type: "string" },
                line: { type: "integer", minimum: 1 },
                role: { type: "string" },
                snippet: { type: "string" },
              },
            },
          },
        },
      },
    },
  },
} as const;

const CORROBORATION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["status", "rationale", "coherentTrigger", "cheapVerifiable"],
  properties: {
    status: {
      type: "string",
      enum: ["survived", "counterexample-found", "insufficient-corroboration"],
    },
    rationale: { type: "string" },
    coherentTrigger: { type: "boolean" },
    cheapVerifiable: { type: "boolean" },
    guardLocations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["filePath", "line", "role"],
        properties: {
          filePath: { type: "string" },
          line: { type: "integer", minimum: 1 },
          role: { type: "string" },
          snippet: { type: "string" },
        },
      },
    },
    counterexampleNotes: { type: "array", items: { type: "string" } },
  },
} as const;

interface LensFinding {
  lens: SystemsHuntLens;
  title: string;
  cwe: string;
  severity: "ERROR" | "WARNING" | "INFO";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  filePath: string;
  startLine: number;
  message: string;
  rationale: string;
  triggerHypothesisIds: string[];
  violatedInvariantIds: string[];
  violatedInvariant: string;
  triggerSequence: string[];
  attackerControlledFields: string[];
  memoryPrimitive: string;
  hardeningNotes: string[];
  cheapVerifiable: boolean;
  analysisPath: SystemsAnalysisStep[];
}

interface CorroborationResult {
  status: "survived" | "counterexample-found" | "insufficient-corroboration";
  rationale: string;
  coherentTrigger: boolean;
  cheapVerifiable: boolean;
  guardLocations: SystemsAnalysisStep[];
  counterexampleNotes: string[];
  costUsd: number;
}

interface SurfaceAnalysisResult {
  findings: LensFinding[];
  costUsd: number;
}

interface MergedFinding {
  key: string;
  surface: RankedSystemsSurface;
  title: string;
  cwe: string[];
  severity: "ERROR" | "WARNING" | "INFO";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  filePath: string;
  startLine: number;
  message: string;
  lenses: Set<SystemsHuntLens>;
  rationales: string[];
  triggerHypothesisIds: Set<string>;
  violatedInvariantIds: Set<string>;
  violatedInvariant: string;
  triggerSequence: Set<string>;
  attackerControlledFields: Set<string>;
  memoryPrimitive: string;
  hardeningNotes: Set<string>;
  cheapVerifiable: boolean;
  analysisPath: SystemsAnalysisStep[];
}

export const systemsHuntTask: AgentTask<ScanOpts, Finding[]> = {
  id: "systems-hunt",
  displayName: "Systems Hunt",
  outputKind: "findings",
  dependsOn: ["systems-context-gatherer", "systems-invariant-extract", "systems-trigger-synth"],

  condition(upstreamOutputs) {
    const surfaceOutput = upstreamOutputs.get("systems-context-gatherer") as SystemsContextOutput | undefined;
    return (surfaceOutput?.surfaces.length ?? 0) > 0;
  },

  async run(_input, context): Promise<Finding[]> {
    const config = resolveSystemsHuntConfig(context);
    const surfaceOutput = context.upstreamOutputs.get("systems-context-gatherer") as SystemsContextOutput | undefined;
    const invariantOutput = context.upstreamOutputs.get("systems-invariant-extract") as SystemsInvariantOutput | undefined;
    const triggerOutput = context.upstreamOutputs.get("systems-trigger-synth") as SystemsTriggerOutput | undefined;
    const surfaces = surfaceOutput?.surfaces.slice(0, config.maxSurfaces) ?? [];
    const surfacePacks = surfaceOutput?.surfacePacks ?? [];
    const packBySurfaceId = new Map(surfacePacks.map((pack) => [pack.surfaceId, pack]));
    if (surfaces.length === 0) {
      return attachTaskOutputMeta([], { costUsd: 0 });
    }

    await mkdir(config.artifactRoot, { recursive: true });
    await mkdir(path.join(config.artifactRoot, "scratch"), { recursive: true });

    const results: SurfaceAnalysisResult[] = [];
    for (let index = 0; index < surfaces.length; index += config.maxConcurrentSurfaces) {
      const batch = surfaces.slice(index, index + config.maxConcurrentSurfaces);
      const batchResults = await Promise.all(batch.map((surface) =>
        analyzeSurface(
          surface,
          packBySurfaceId.get(surface.id),
          invariantOutput?.invariants ?? [],
          triggerOutput?.triggers ?? [],
          context,
          config,
          surfaceOutput,
        ),
      ));
      results.push(...batchResults);
    }

    const merged = mergeLensFindings(surfaces, results.flatMap((result) => result.findings));
    let totalCostUsd = results.reduce((sum, result) => sum + result.costUsd, 0);
    const findings: Finding[] = [];

    for (const value of merged.values()) {
      const relevantTriggers = (triggerOutput?.triggers ?? []).filter((trigger) => trigger.surfaceId === value.surface.id);
      const matchedTrigger = matchTriggerHypothesisToFinding({
        triggerHypothesisIds: [...value.triggerHypothesisIds],
        triggerSequence: [...value.triggerSequence],
        expectedPrimitive: value.memoryPrimitive,
        hypotheses: relevantTriggers,
      });
      const coherentTrigger = matchedTrigger.matchedIds.length > 0 || value.triggerSequence.size > 0;
      const corroboration = await corroborateFinding(
        value,
        packBySurfaceId.get(value.surface.id),
        relevantTriggers,
        coherentTrigger,
        context,
        config,
        surfaceOutput?.metadata.codeqlDbPath,
      );
      totalCostUsd += corroboration.costUsd;
      const emission = resolveEmissionDecision({
        lensCount: value.lenses.size,
        minLensAgreement: config.minLensAgreement,
        coherentTrigger,
        corroboration,
      });
      if (!emission.emit || !emission.corroborationStatus) {
        continue;
      }

      const fingerprint = createSystemsFindingFingerprint(context.repoName, value);
      const artifact: SystemsHuntArtifact = {
        fingerprint,
        title: value.title,
        cwe: value.cwe,
        severity: value.severity,
        filePath: value.filePath,
        startLine: value.startLine,
        surfaceId: value.surface.id,
        surfaceKind: value.surface.kind,
        lenses: [...value.lenses],
        triggerHypothesisIds: matchedTrigger.matchedIds,
        violatedInvariantIds: [...value.violatedInvariantIds],
        violatedInvariant: value.violatedInvariant,
        triggerSequence: [...value.triggerSequence],
        stateMachine: matchedTrigger.stateMachine,
        boundaryAssignments: matchedTrigger.boundaryAssignments,
        attackerControlledFields: [...value.attackerControlledFields],
        memoryPrimitive: value.memoryPrimitive,
        hardeningNotes: [...value.hardeningNotes],
        cheapVerifiable: emission.cheapVerifiable,
        reasoning: [value.rationales.join(" | "), corroboration.rationale].filter(Boolean).join(" | "),
        analysisPath: value.analysisPath,
        guardLocations: corroboration.guardLocations,
        counterexampleNotes: corroboration.counterexampleNotes,
        relatedFiles: packBySurfaceId.get(value.surface.id)?.relatedFiles ?? [value.surface.filePath],
        corroborationStatus: emission.corroborationStatus,
      };

      const artifactPath = await writeSystemsHuntArtifact(config.artifactRoot, artifact);
      const relativeArtifactPath = normalizeArtifactPath(context.repoRoot, artifactPath);
      findings.push({
        taskId: "systems-hunt",
        fingerprint,
        ruleId: buildRuleId(value.surface.kind, value.cwe),
        filePath: value.filePath,
        startLine: value.startLine,
        severity: value.severity,
        message: value.message,
        evidence: buildEvidenceSummary(artifact),
        scannerConfidence: value.confidence,
        subcategory: ["vuln"],
        likelihood: value.confidence,
        impact: value.severity === "ERROR" ? "HIGH" : value.severity === "WARNING" ? "MEDIUM" : "LOW",
        cwe: value.cwe,
        score: scoreFor(value.severity, value.confidence),
        taintPath: toTaintPath(value.analysisPath),
        proofState: "symbolic_only",
        engineProvenance: [
          { kind: "agentic", detail: `Systems hunt lenses: ${[...value.lenses].join(", ")}` },
          { kind: "agentic", detail: `Systems hunt corroboration: ${emission.corroborationStatus}` },
          { kind: "agentic", detail: buildSystemsHuntArtifactDetail(relativeArtifactPath) },
        ],
      });
    }

    return attachTaskOutputMeta(
      findings.sort((left, right) => right.score - left.score).slice(0, config.maxFindings),
      { costUsd: totalCostUsd },
    );
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    const artifactPath = extractSystemsHuntArtifactPath(finding);
    return {
      prompt: [
        `You are triaging a systems-code finding in "${repoName}".`,
        "This finding came from a low-level multi-lens hunt focused on protocol state,",
        "numeric boundary reasoning, unsafe memory operations, and missing mitigations.",
        artifactPath ? `First, Read the systems hunt artifact at ${artifactPath}.` : "First, inspect the supporting analysis path in the finding evidence.",
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Summary: ${finding.evidence}` : "",
        "",
        "Verify these questions explicitly:",
        "- Is the violated invariant real in the code, or already guarded elsewhere?",
        "- Can attacker-controlled packet fields, slice counts, or guest-controlled sizes reach this path?",
        "- Do compiler/runtime mitigations or hardening settings materially block exploitation?",
        "- If the bug is real, what is the concrete crash/corruption primitive?",
      ].filter(Boolean).join("\n"),
    };
  },
};

async function analyzeSurface(
  surface: RankedSystemsSurface,
  surfacePack: SystemsSurfacePack | undefined,
  invariants: SystemsInvariant[],
  triggers: SystemsTriggerHypothesis[],
  context: TaskContext,
  config: SystemsHuntConfig,
  surfaceOutput: SystemsContextOutput | undefined,
): Promise<SurfaceAnalysisResult> {
  const relevantInvariants = invariants.filter((invariant) => invariant.surfaceId === surface.id);
  const relevantTriggers = triggers.filter((trigger) => trigger.surfaceId === surface.id);
  const allowedTools = resolveTaskAllowedTools(context, undefined, [
    ...resolveTaskAllowedTools(context),
    "Bash",
    "Write",
  ]);
  const canUseTool = createSystemsHuntToolGuard(context.repoRoot, path.join(config.artifactRoot, "scratch"));

  const findings: LensFinding[] = [];
  let costUsd = 0;

  for (const lens of SYSTEMS_HUNT_LENSES) {
    const prompt = buildLensPrompt(
      surface,
      surfacePack,
      relevantInvariants,
      relevantTriggers,
      lens,
      config,
      surfaceOutput?.metadata.codeqlDbPath,
    );
    try {
      let structuredOutput: unknown;
      for await (const message of context.runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model: config.model,
          effort: config.effort,
          thinkingDisabled: config.thinkingDisabled,
          allowedTools,
          permissionMode: "dontAsk",
          canUseTool,
          outputFormat: {
            type: "json_schema",
            schema: LENS_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
          costUsd += message.totalCostUsd;
        }
        if ("result" in message) {
          structuredOutput = message.structuredOutput;
        }
      }
      findings.push(...parseLensOutput(lens, structuredOutput, context.repoRoot));
    } catch (error) {
      log.warn(`[systems-hunt/${surface.id}/${lens}] ${toErrorMessage(error)}`);
    }
  }

  return { findings, costUsd };
}

export function buildLensPrompt(
  surface: RankedSystemsSurface,
  surfacePack: SystemsSurfacePack | undefined,
  invariants: SystemsInvariant[],
  triggers: SystemsTriggerHypothesis[],
  lens: SystemsHuntLens,
  config: SystemsHuntConfig,
  codeqlDbPath?: string,
): string {
  const lensGuidance = lensInstructions(lens, surface.kind);
  const invariantLines = invariants.length > 0
    ? invariants.flatMap((invariant) => [
        `- [${invariant.id}] (${invariant.kind}) ${invariant.summary}`,
        `  Statement: ${invariant.statement}`,
        `  Rationale: ${invariant.rationale}`,
        `  Cheap verifiable: ${invariant.cheapVerifiable ? "yes" : "no"}`,
      ])
    : ["- No explicit invariants extracted; derive them from the code before reporting anything."];
  const triggerLines = triggers.length > 0
    ? triggers.flatMap((trigger) => [
        `- [${trigger.id}] Steps: ${trigger.orderedSteps.join(" -> ")}`,
        `  Preconditions: ${trigger.statePreconditions.join("; ") || "none"}`,
        `  Boundaries: ${Object.entries(trigger.boundaryAssignments).map(([key, value]) => `${key}=${value}`).join(", ") || "none"}`,
        `  Primitive: ${trigger.expectedPrimitive}`,
      ])
    : ["- No explicit trigger hypotheses extracted; derive a coherent sequence before reporting anything."];

  const codeqlSection = codeqlDbPath
    ? [
        "## Optional CodeQL assist",
        `If useful, you may inspect the existing CodeQL database at ${codeqlDbPath}.`,
        "Use it to validate value-range and control-flow hypotheses; do not rely on taint tracking.",
      ]
    : ["## Optional CodeQL assist", "No CodeQL database was discovered. Use repo reads and bounded Bash probes instead."];

  return [
    `You are running the ${lens} lens of a systems-code vulnerability hunt.`,
    `Budget: keep this surface investigation within ${config.maxTurnsPerSurface} turns.`,
    "",
    "## Surface",
    `surfaceId: ${surface.id}`,
    `Kind: ${surface.kind}`,
    `Location: ${surface.filePath}:${surface.startLine}`,
    `Reasons: ${surface.reasons.join("; ") || "none"}`,
    `Attacker-controlled fields: ${surface.attackerControlledFields.join(", ") || "unknown"}`,
    `Hardening signals: ${surface.hardeningSignals.join(", ") || "none"}`,
    `Evidence anchors: ${surface.evidence.slice(0, 4).map((signal) => `${signal.domain}@${signal.lineNumber}: ${signal.lineContent}`).join(" | ") || "none"}`,
    "",
    ...(surfacePack ? formatSystemsSurfacePack(surfacePack) : []),
    "",
    "## Extracted invariants",
    ...invariantLines,
    "",
    "## Trigger hypotheses",
    ...triggerLines,
    "",
    ...codeqlSection,
    "",
    `Scratch writes, if needed, must stay under ${config.artifactRootRelative}/scratch.`,
    "",
    lensGuidance,
    "",
    "## Output requirements",
    "Return only findings you can justify from actual code. Each finding must include:",
    "- triggerHypothesisIds referencing the coherent trigger sequence you relied on",
    "- violatedInvariant and violatedInvariantIds when available",
    "- triggerSequence describing the crafted interaction or boundary condition",
    "- attackerControlledFields and memoryPrimitive",
    "- hardeningNotes explaining whether mitigations are absent, partial, or bypassed",
    "- cheapVerifiable=true only when a single-turn bounded confirmation is realistic",
  ].join("\n");
}

function lensInstructions(
  lens: SystemsHuntLens,
  surfaceKind: SystemsSurfaceKind,
): string {
  switch (lens) {
    case "protocol-state":
      return [
        "## Lens guidance: protocol and state reasoning",
        "- Model packet ordering, option interactions, and state transitions explicitly.",
        "- Look for paths where two or more sequential packets/options create invalid state.",
        "- Check for null or stale state pointers reached only after semantic packet interactions.",
        surfaceKind === "rpc-handler" ? "- Pay special attention to authentication and RPC framing state across packets." : "",
      ].filter(Boolean).join("\n");
    case "arithmetic-sentinel":
      return [
        "## Lens guidance: arithmetic and sentinel reasoning",
        "- Analyze signed/unsigned comparisons, truncation, wraparound, and sentinel collisions.",
        "- Focus on counters that drive indexing, allocation, or early termination.",
        "- Force boundary values like 0, -1, 65535, UINT_MAX, and SIZE_MAX through the code.",
      ].join("\n");
    case "buffer-unsafe":
      return [
        "## Lens guidance: buffer and unsafe corruption reasoning",
        "- Track how copy length couples to stack/heap buffer size.",
        "- In Rust, inspect unsafe blocks, raw pointer arithmetic, from_raw_parts, get_unchecked, set_len, and FFI.",
        "- In C/C++, inspect memcpy/memmove/strcpy/sprintf-style paths and unchecked stack buffers.",
      ].join("\n");
    case "hardening-bypass":
      return [
        "## Lens guidance: hardening and mitigation reasoning",
        "- Determine whether the bug depends on missing canaries, fortify, panic guards, or isolation assumptions.",
        "- Distinguish 'bug exists' from 'bug is realistically corrupting memory under current hardening.'",
        "- Note partial mitigations that reduce reliability but do not eliminate the primitive.",
      ].join("\n");
  }
}

async function corroborateFinding(
  finding: MergedFinding,
  surfacePack: SystemsSurfacePack | undefined,
  triggers: SystemsTriggerHypothesis[],
  coherentTrigger: boolean,
  context: TaskContext,
  config: SystemsHuntConfig,
  codeqlDbPath?: string,
): Promise<CorroborationResult> {
  if (!config.enableCounterexamplePass) {
    return {
      status: "insufficient-corroboration",
      rationale: "Counterexample pass disabled.",
      coherentTrigger,
      cheapVerifiable: false,
      guardLocations: [],
      counterexampleNotes: [],
      costUsd: 0,
    };
  }

  const allowedTools = resolveTaskAllowedTools(context, undefined, [
    ...resolveTaskAllowedTools(context),
    "Bash",
    "Write",
  ]);
  const canUseTool = createSystemsHuntToolGuard(context.repoRoot, path.join(config.artifactRoot, "scratch"));
  let structuredOutput: unknown;
  let costUsd = 0;

  try {
    for await (const message of context.runtime.query({
      prompt: buildCorroborationPrompt(finding, surfacePack, triggers, config, codeqlDbPath),
      options: {
        cwd: context.repoRoot,
        model: config.model,
        effort: config.effort,
        thinkingDisabled: config.thinkingDisabled,
        allowedTools,
        permissionMode: "dontAsk",
        canUseTool,
        outputFormat: {
          type: "json_schema",
          schema: CORROBORATION_SCHEMA,
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
        structuredOutput = message.structuredOutput;
      }
    }
  } catch (error) {
    log.warn(`[systems-hunt/${finding.surface.id}/corroboration] ${toErrorMessage(error)}`);
    return {
      status: "insufficient-corroboration",
      rationale: "Counterexample pass failed.",
      coherentTrigger,
      cheapVerifiable: false,
      guardLocations: [],
      counterexampleNotes: [toErrorMessage(error)],
      costUsd: 0,
    };
  }

  return parseCorroborationOutput(structuredOutput, context.repoRoot, coherentTrigger, costUsd);
}

export function buildCorroborationPrompt(
  finding: MergedFinding,
  surfacePack: SystemsSurfacePack | undefined,
  triggers: SystemsTriggerHypothesis[],
  config: SystemsHuntConfig,
  codeqlDbPath?: string,
): string {
  const triggerLines = triggers.length > 0
    ? triggers.map((trigger) =>
      `- [${trigger.id}] ${trigger.orderedSteps.join(" -> ")} | Preconditions: ${trigger.statePreconditions.join("; ") || "none"} | Primitive: ${trigger.expectedPrimitive}`)
    : ["- No trigger hypotheses available."];

  return [
    "You are running the counterexample/corroboration pass for a systems-code finding.",
    `Budget: keep this corroboration within ${config.maxCorroborationTurns} turns.`,
    "",
    "Goal:",
    "- Disprove the finding if guards, resets, bounds checks, or hardening eliminate the primitive.",
    "- Otherwise confirm that the trigger sequence and violated invariant still hold after close reading.",
    "",
    `Finding: ${finding.title}`,
    `Location: ${finding.filePath}:${finding.startLine}`,
    `Lenses: ${[...finding.lenses].join(", ")}`,
    `Invariant: ${finding.violatedInvariant}`,
    `Trigger sequence: ${[...finding.triggerSequence].join(" -> ") || "none"}`,
    `Primitive: ${finding.memoryPrimitive}`,
    `Hardening notes: ${[...finding.hardeningNotes].join(" | ") || "none"}`,
    "",
    ...(surfacePack ? formatSystemsSurfacePack(surfacePack) : []),
    "",
    "## Trigger hypotheses",
    ...triggerLines,
    "",
    codeqlDbPath
      ? `Optional CodeQL database: ${codeqlDbPath}`
      : "No CodeQL database available; use repo reads and bounded Bash probes only.",
    "",
    "Return status=survived only if the bug still holds after searching for counterexamples.",
    "Return status=counterexample-found if a real guard, cap, state reset, or hardening mechanism blocks the trigger or primitive.",
    "Return status=insufficient-corroboration when you cannot disprove it, but you also cannot locally confirm it tightly enough.",
    "Only mark cheapVerifiable=true when you have identified a bounded local confirmation path.",
  ].join("\n");
}

export function parseCorroborationOutput(
  raw: unknown,
  repoRoot: string,
  coherentTriggerFallback: boolean,
  costUsd = 0,
): CorroborationResult {
  if (!isRecord(raw)) {
    return {
      status: "insufficient-corroboration",
      rationale: "Missing corroboration result.",
      coherentTrigger: coherentTriggerFallback,
      cheapVerifiable: false,
      guardLocations: [],
      counterexampleNotes: [],
      costUsd,
    };
  }

  const status = normalizeCorroborationStatus(raw["status"]);
  return {
    status,
    rationale: stringField(raw["rationale"]) || "No corroboration rationale provided.",
    coherentTrigger: typeof raw["coherentTrigger"] === "boolean" ? raw["coherentTrigger"] : coherentTriggerFallback,
    cheapVerifiable: raw["cheapVerifiable"] === true && status === "survived",
    guardLocations: normalizeAnalysisPath(repoRoot, raw["guardLocations"]),
    counterexampleNotes: stringArray(raw["counterexampleNotes"]),
    costUsd,
  };
}

export function resolveEmissionDecision(args: {
  lensCount: number;
  minLensAgreement: number;
  coherentTrigger: boolean;
  corroboration: CorroborationResult;
}): {
  emit: boolean;
  corroborationStatus?: SystemsCorroborationStatus;
  cheapVerifiable: boolean;
} {
  if (args.corroboration.status === "counterexample-found") {
    return { emit: false, cheapVerifiable: false };
  }
  if (args.corroboration.status === "survived") {
    return {
      emit: true,
      corroborationStatus: "survived",
      cheapVerifiable: args.corroboration.cheapVerifiable && args.corroboration.coherentTrigger,
    };
  }
  if (args.lensCount >= args.minLensAgreement && args.coherentTrigger) {
    return {
      emit: true,
      corroborationStatus: "lens-agreement-only",
      cheapVerifiable: false,
    };
  }
  return { emit: false, cheapVerifiable: false };
}

export function parseLensOutput(
  lens: SystemsHuntLens,
  raw: unknown,
  repoRoot: string,
): LensFinding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];
  const out: LensFinding[] = [];
  for (const item of raw["findings"]) {
    if (!isRecord(item)) continue;
    const title = stringField(item["title"]);
    const cwe = stringField(item["cwe"]);
    const severity = normalizeSeverity(item["severity"]);
    const confidence = normalizeConfidence(item["confidence"]);
    const filePath = normalizeRepoPath(repoRoot, stringField(item["filePath"]));
    const startLine = Math.max(1, Math.floor(Number(item["startLine"]) || 1));
    const message = stringField(item["message"]);
    const rationale = stringField(item["rationale"]);
    const violatedInvariant = stringField(item["violatedInvariant"]);
    if (!title || !cwe || !filePath || !message || !rationale || !violatedInvariant) continue;
    out.push({
      lens,
      title,
      cwe,
      severity,
      confidence,
      filePath,
      startLine,
      message,
      rationale,
      triggerHypothesisIds: stringArray(item["triggerHypothesisIds"]),
      violatedInvariantIds: stringArray(item["violatedInvariantIds"]),
      violatedInvariant,
      triggerSequence: stringArray(item["triggerSequence"]),
      attackerControlledFields: stringArray(item["attackerControlledFields"]),
      memoryPrimitive: stringField(item["memoryPrimitive"]) || "unknown",
      hardeningNotes: stringArray(item["hardeningNotes"]),
      cheapVerifiable: item["cheapVerifiable"] === true,
      analysisPath: normalizeAnalysisPath(repoRoot, item["analysisPath"]),
    });
  }
  return out;
}

export function mergeLensFindings(
  surfaces: RankedSystemsSurface[],
  findings: LensFinding[],
): Map<string, MergedFinding> {
  const surfaceByPath = new Map<string, RankedSystemsSurface>();
  for (const surface of surfaces) {
    surfaceByPath.set(surface.filePath, surface);
  }

  const merged = new Map<string, MergedFinding>();
  for (const finding of findings) {
    const key = `${finding.filePath}:${finding.startLine}:${finding.cwe}`;
    const surface = surfaceByPath.get(finding.filePath) ?? surfaces[0];
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        key,
        surface,
        title: finding.title,
        cwe: [finding.cwe],
        severity: finding.severity,
        confidence: finding.confidence,
        filePath: finding.filePath,
        startLine: finding.startLine,
        message: finding.message,
        lenses: new Set([finding.lens]),
        rationales: [finding.rationale],
        triggerHypothesisIds: new Set(finding.triggerHypothesisIds),
        violatedInvariantIds: new Set(finding.violatedInvariantIds),
        violatedInvariant: finding.violatedInvariant,
        triggerSequence: new Set(finding.triggerSequence),
        attackerControlledFields: new Set(finding.attackerControlledFields),
        memoryPrimitive: finding.memoryPrimitive,
        hardeningNotes: new Set(finding.hardeningNotes),
        cheapVerifiable: finding.cheapVerifiable,
        analysisPath: [...finding.analysisPath],
      });
      continue;
    }

    existing.cwe = [...new Set([...existing.cwe, finding.cwe])];
    existing.severity = maxSeverity(existing.severity, finding.severity);
    existing.confidence = maxConfidence(existing.confidence, finding.confidence);
    existing.lenses.add(finding.lens);
    existing.rationales.push(finding.rationale);
    for (const id of finding.triggerHypothesisIds) existing.triggerHypothesisIds.add(id);
    for (const id of finding.violatedInvariantIds) existing.violatedInvariantIds.add(id);
    for (const step of finding.triggerSequence) existing.triggerSequence.add(step);
    for (const field of finding.attackerControlledFields) existing.attackerControlledFields.add(field);
    for (const note of finding.hardeningNotes) existing.hardeningNotes.add(note);
    existing.cheapVerifiable ||= finding.cheapVerifiable;
    existing.analysisPath = mergeAnalysisPaths(existing.analysisPath, finding.analysisPath);
    if (existing.memoryPrimitive === "unknown" && finding.memoryPrimitive !== "unknown") {
      existing.memoryPrimitive = finding.memoryPrimitive;
    }
    if (finding.violatedInvariant.length > existing.violatedInvariant.length) {
      existing.violatedInvariant = finding.violatedInvariant;
    }
  }
  return merged;
}

export function createSystemsHuntToolGuard(
  repoRoot: string,
  scratchRoot: string,
): (
  toolName: string,
  args: Record<string, unknown>,
) => { behavior: "allow" } | { behavior: "deny"; message?: string } {
  return (toolName, args) => {
    if (toolName === "Write") {
      const filePath = resolvePathArg(repoRoot, args, ["file_path", "path"]);
      if (!filePath || !isPathWithinRoot(scratchRoot, filePath)) {
        return { behavior: "deny", message: "Write is limited to the systems-hunt scratch directory" };
      }
      return { behavior: "allow" };
    }

    if (toolName === "Read" || toolName === "Glob" || toolName === "Grep" || toolName === "GetFunctionBody" || toolName === "GetCallers" || toolName === "GetCallees" || toolName === "GoToDefinition" || toolName === "FindReferences" || toolName === "TypeAtPosition") {
      const filePath = resolvePathArg(repoRoot, args, ["file_path", "path"]);
      if (filePath && !isPathWithinRoot(repoRoot, filePath)) {
        return { behavior: "deny", message: "Analysis tools must stay inside the repository root" };
      }
      return { behavior: "allow" };
    }

    if (toolName === "Bash") {
      const command = typeof args["command"] === "string" ? args["command"] : "";
      const timeout = Number(args["timeout"] ?? 0);
      if (!isAllowedBashCommand(command)) {
        return { behavior: "deny", message: "Bash is limited to deterministic non-destructive analysis commands" };
      }
      if (timeout > 0 && timeout > 30_000) {
        return { behavior: "deny", message: "Bash timeout must be <= 30000 ms" };
      }
      return { behavior: "allow" };
    }

    return { behavior: "allow" };
  };
}

function isAllowedBashCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed) return false;
  if (/[;&`]|(?:\|\|)|(?:&&)|(?:>>)|(?:>)|\$\(/.test(trimmed)) {
    return false;
  }
  const words = splitShellWords(trimmed);
  if (!words || words.length === 0) return false;
  const binary = path.basename(words[0]);
  return new Set([
    "rg",
    "grep",
    "sed",
    "awk",
    "head",
    "tail",
    "wc",
    "cut",
    "sort",
    "uniq",
    "find",
    "ls",
    "file",
    "nm",
    "objdump",
    "readelf",
    "strings",
    "cargo",
    "rustc",
    "clang",
    "clang++",
    "gcc",
    "g++",
    "cc",
    "c++",
    "make",
    "cmake",
    "codeql",
  ]).has(binary);
}

function splitShellWords(command: string): string[] | null {
  const words: string[] = [];
  let current = "";
  let quote: "\"" | "'" | null = null;
  let escaping = false;

  for (const char of command) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }
    if (quote === "'") {
      if (char === "'") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "\\") {
      escaping = true;
      continue;
    }
    if (quote === "\"") {
      if (char === "\"") {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "'" || char === "\"") {
      quote = char;
      continue;
    }
    if (/\s/u.test(char)) {
      if (current) {
        words.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }

  if (escaping || quote) return null;
  if (current) words.push(current);
  return words;
}

function resolvePathArg(repoRoot: string, args: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = args[key];
    if (typeof value !== "string" || !value.trim()) continue;
    return path.resolve(repoRoot, value);
  }
  return undefined;
}

function buildRuleId(kind: SystemsSurfaceKind, cwe: string[]): string {
  const primary = cwe[0] ?? "CWE-unknown";
  return `systems-hunt/${primary.toLowerCase()}/${kind}`;
}

function buildEvidenceSummary(artifact: SystemsHuntArtifact): string {
  const triggers = artifact.triggerSequence.slice(0, 3).join(" -> ");
  const lenses = artifact.lenses.join(", ");
  return [
    `Lenses: ${lenses}`,
    `Corroboration: ${artifact.corroborationStatus}`,
    artifact.violatedInvariant ? `Invariant: ${artifact.violatedInvariant}` : "",
    triggers ? `Trigger: ${triggers}` : "",
    artifact.memoryPrimitive ? `Primitive: ${artifact.memoryPrimitive}` : "",
  ].filter(Boolean).join(" | ");
}

function scoreFor(severity: "ERROR" | "WARNING" | "INFO", confidence: "HIGH" | "MEDIUM" | "LOW"): number {
  const severityScore = severity === "ERROR" ? 50 : severity === "WARNING" ? 30 : 10;
  const confidenceScore = confidence === "HIGH" ? 30 : confidence === "MEDIUM" ? 20 : 10;
  return severityScore + confidenceScore;
}

function toTaintPath(steps: SystemsAnalysisStep[]): TaintPathStep[] | undefined {
  if (steps.length === 0) return undefined;
  return steps.map((step) => ({
    filePath: step.filePath,
    line: step.line,
    message: step.role,
    snippet: step.snippet,
  }));
}

function mergeAnalysisPaths(
  left: SystemsAnalysisStep[],
  right: SystemsAnalysisStep[],
): SystemsAnalysisStep[] {
  const merged = new Map<string, SystemsAnalysisStep>();
  for (const step of [...left, ...right]) {
    merged.set(`${step.filePath}:${step.line}:${step.role}`, step);
  }
  return [...merged.values()].sort((a, b) => {
    if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
    return a.line - b.line;
  });
}

function createSystemsFindingFingerprint(repoName: string, finding: MergedFinding): string {
  return createHash("sha256")
    .update([repoName, "systems-hunt", finding.filePath, String(finding.startLine), finding.cwe[0] ?? "none", finding.surface.kind].join("|"))
    .digest("hex");
}

function normalizeRepoPath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath).replace(/\\/g, "/");
  return relative.startsWith("..") ? filePath : relative || filePath;
}

function normalizeArtifactPath(repoRoot: string, filePath: string): string {
  return normalizeRepoPath(repoRoot, filePath);
}

function normalizeAnalysisPath(repoRoot: string, value: unknown): SystemsAnalysisStep[] {
  if (!Array.isArray(value)) return [];
  const out: SystemsAnalysisStep[] = [];
  for (const step of value) {
    if (!isRecord(step)) continue;
    const filePath = normalizeRepoPath(repoRoot, stringField(step["filePath"]));
    const line = Math.max(1, Math.floor(Number(step["line"]) || 1));
    const role = stringField(step["role"]);
    if (!filePath || !role) continue;
    out.push({
      filePath,
      line,
      role,
      snippet: stringField(step["snippet"]) || undefined,
    });
  }
  return out;
}

function normalizeSeverity(value: unknown): "ERROR" | "WARNING" | "INFO" {
  return value === "ERROR" || value === "WARNING" || value === "INFO" ? value : "WARNING";
}

function normalizeConfidence(value: unknown): "HIGH" | "MEDIUM" | "LOW" {
  return value === "HIGH" || value === "MEDIUM" || value === "LOW" ? value : "MEDIUM";
}

function normalizeCorroborationStatus(
  value: unknown,
): CorroborationResult["status"] {
  return value === "survived" || value === "counterexample-found" || value === "insufficient-corroboration"
    ? value
    : "insufficient-corroboration";
}

function maxSeverity(
  left: "ERROR" | "WARNING" | "INFO",
  right: "ERROR" | "WARNING" | "INFO",
): "ERROR" | "WARNING" | "INFO" {
  const order = ["INFO", "WARNING", "ERROR"];
  return order.indexOf(left) >= order.indexOf(right) ? left : right;
}

function maxConfidence(
  left: "HIGH" | "MEDIUM" | "LOW",
  right: "HIGH" | "MEDIUM" | "LOW",
): "HIGH" | "MEDIUM" | "LOW" {
  const order = ["LOW", "MEDIUM", "HIGH"];
  return order.indexOf(left) >= order.indexOf(right) ? left : right;
}

function stringField(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => stringField(entry)).filter(Boolean);
}

export const __systemsHuntInternals = {
  buildLensPrompt,
  buildCorroborationPrompt,
  parseLensOutput,
  parseCorroborationOutput,
  resolveEmissionDecision,
  mergeLensFindings,
  createSystemsHuntToolGuard,
};
