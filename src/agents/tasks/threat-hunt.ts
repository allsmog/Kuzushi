/**
 * Threat-driven hunt task — spawns one agent per DFD threat actor
 * (external-entity) with a CTF-framed prompt. Each agent explores the
 * codebase freely from that actor's perspective.
 *
 * Inspired by Nicholas Carlini's file-sweep approach demonstrated at
 * [un]prompted 2026, but driven by the Randori PASTA threat model
 * instead of blind file iteration.
 */
import { antiHallucinationModule } from "../../prompts/modules.js";
import {
  FINDING_SCHEMA,
  parseFindingOutput,
  selectFindings,
  type FindingOutput,
} from "../../scanners/normalize-findings.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { ScanOpts } from "../../types.js";
import { toErrorMessage } from "../../utils.js";
import { createLogger } from "../../logger.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskModel, resolveTaskRuntime, resolveTaskAllowedTools, resolveTaskPositiveInt } from "./runtime-overrides.js";
import { resolveThreatModelOutput } from "./threat-model-guidance.js";
import type { DfdElement, ThreatModelDocument } from "./threat-modeling/types.js";
import { isRecord } from "../../utils.js";

const log = createLogger({ stage: "threat-hunt" });

interface ThreatHuntConfig {
  model: string;
  maxFindings: number;
  maxActors: number;
  runsPerActor: number;
  maxConcurrentHunts: number;
}

function resolveConfig(ctx: TaskContext): ThreatHuntConfig {
  const model = resolveTaskModel(ctx, "threat-hunt");
  const maxFindings = resolveTaskPositiveInt(ctx, "threat-hunt", "maxFindings", 50);
  const maxActors = resolveTaskPositiveInt(ctx, "threat-hunt", "maxActors", 10);
  const runsPerActor = Math.min(resolveTaskPositiveInt(ctx, "threat-hunt", "runsPerActor", 1), 5);
  const maxConcurrentHunts = resolveTaskPositiveInt(ctx, "threat-hunt", "maxConcurrentHunts", 5);
  return { model, maxFindings, maxActors, runsPerActor, maxConcurrentHunts };
}

function extractActors(upstreamOutputs: Map<string, unknown>): DfdElement[] {
  const raw = resolveThreatModelOutput(upstreamOutputs);
  if (!isRecord(raw) || !isRecord(raw["document"])) return [];
  const doc = raw["document"] as unknown as ThreatModelDocument;
  if (!doc.dfd?.elements || !Array.isArray(doc.dfd.elements)) return [];
  return doc.dfd.elements.filter((el) => el.type === "external-entity");
}

function buildPrompt(actor: DfdElement): string {
  return [
    `You are competing in a CTF. You are simulating: ${actor.name}`,
    `Description: ${actor.description}`,
    `Trust zone: ${actor.trustZone}`,
    "",
    "Find exploitable security vulnerabilities in this codebase from this actor's perspective.",
    "Explore the codebase using the tools available to you.",
    "Only report findings with concrete evidence of exploitability.",
    "",
    antiHallucinationModule(),
  ].join("\n");
}

async function runActorHunt(
  actor: DfdElement,
  context: TaskContext,
  config: ThreatHuntConfig,
): Promise<FindingOutput> {
  const prompt = buildPrompt(actor);
  const runtime = resolveTaskRuntime(context);
  const tag = `[threat-hunt/${actor.name}]`;

  log.info(`${tag} Starting hunt (model=${config.model})`);

  let resultText = "";
  let structuredOutput: unknown = undefined;
  let costUsd = 0;
  let executionError: string | null = null;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: context.repoRoot,
      model: config.model,
      allowedTools: resolveTaskAllowedTools(context),
      permissionMode: "dontAsk",
      outputFormat: {
        type: "json_schema",
        schema: FINDING_SCHEMA,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    if (message.type === "tool-progress" || message.type === "tool-summary" || message.type === "assistant") {
      continue;
    }
    if (message.type !== "result") continue;

    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }
    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
      const durationSec = message.durationMs ? (message.durationMs / 1000).toFixed(1) : "?";
      log.info(`${tag} Complete in ${durationSec}s — ${message.numTurns} turns, $${message.totalCostUsd?.toFixed(4) ?? "?"}`);
      break;
    }
    executionError = (Array.isArray(message.errors) ? message.errors.join("; ") : "") || message.subtype || "unknown error";
  }

  if (executionError) {
    log.error(`${tag} Failed: ${executionError}`);
    return { findings: [], costUsd };
  }

  const parsed = structuredOutput != null || resultText
    ? parseFindingOutput(structuredOutput ?? resultText)
    : { findings: [] };
  return { findings: parsed.findings, costUsd };
}

async function run(_input: ScanOpts, context: TaskContext): Promise<Finding[]> {
  const config = resolveConfig(context);
  const actors = extractActors(context.upstreamOutputs);

  if (actors.length === 0) {
    log.info("[threat-hunt] No external entities in threat model DFD — skipping");
    return attachTaskOutputMeta([], { costUsd: 0 });
  }

  const capped = actors.slice(0, config.maxActors);
  const totalRuns = capped.length * config.runsPerActor;
  log.info(
    `[threat-hunt] Spawning ${totalRuns} hunts (${capped.length} actors x ${config.runsPerActor} runs, from ${actors.length} external entities)`,
  );

  // Build all hunt tasks, then execute with bounded concurrency to avoid
  // saturating API rate limits or exhausting OS resources.
  const huntTasks: Array<() => Promise<FindingOutput>> = [];
  for (const actor of capped) {
    for (let i = 0; i < config.runsPerActor; i++) {
      huntTasks.push(() =>
        runActorHunt(actor, context, config).catch((err) => {
          log.error(`[threat-hunt/${actor.name}] Error: ${toErrorMessage(err)}`);
          return { findings: [], costUsd: 0 } as FindingOutput;
        }),
      );
    }
  }

  const maxConcurrent = Math.min(totalRuns, config.maxConcurrentHunts);
  const results: FindingOutput[] = [];
  for (let i = 0; i < huntTasks.length; i += maxConcurrent) {
    const batch = huntTasks.slice(i, i + maxConcurrent);
    const batchResults = await Promise.all(batch.map((fn) => fn()));
    results.push(...batchResults);
  }

  // Merge all findings, dedup via selectFindings
  const merged: FindingOutput = {
    findings: results.flatMap((r) => r.findings),
    costUsd: results.reduce((sum, r) => sum + (r.costUsd ?? 0), 0),
  };

  const findings = selectFindings(
    merged,
    context.repoRoot,
    context.repoName,
    "HEAD",
    "threat-hunt",
    config.maxFindings,
  );

  return attachTaskOutputMeta(findings, { costUsd: merged.costUsd ?? 0 });
}

export const threatHuntTask: AgentTask<ScanOpts, Finding[]> = {
  id: "threat-hunt",
  displayName: "Threat-Driven Hunt",
  outputKind: "findings",
  dependsOn: ["threat-model-randori"],
  run,

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a finding from the threat-driven hunt in "${repoName}".`,
        "This finding was discovered by an agent simulating a specific threat actor.",
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Evidence: ${finding.evidence}` : "",
        "",
        "Verify the vulnerability is genuine and exploitable:",
        "- Trace the complete data flow from source to sink",
        "- Check for sanitization or framework protections",
        "- Confirm the code is reachable from the stated actor's trust zone",
      ].filter(Boolean).join("\n"),
    };
  },
};

// Exported for testing
export const __threatHuntInternals = {
  extractActors,
  buildPrompt,
  resolveConfig,
};
