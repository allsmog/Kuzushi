/**
 * Randori threat model task — runs the Randori PASTA plugin (S1-S4) via
 * Claude Code subprocess, reads the structured artifacts, and converts
 * them to Kuzushi's ThreatModelDocument format.
 *
 * Sole threat model provider — powered by the @kuzushi/randori-plugin dependency.
 */
import path from "node:path";
import { publishTaskActivity, publishTaskPhase } from "../../../bus/activity.js";
import { createLogger } from "../../../logger.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import { loadPersistentThreatModel } from "../../../threat-model-renderer.js";
import type { ScanOpts } from "../../../types.js";
import type { AgentTask } from "../../types.js";
import { resolveTaskAllowedTools } from "../runtime-overrides.js";
import { resolveThreatModelConfig } from "./config.js";
import { runRandoriPasta } from "./randori-runner.js";
import { resolveRandoriPluginPath } from "./resolve-randori.js";
import type { ThreatModelDocument } from "./types.js";

// Re-export so existing tests (and external callers) that import
// assessNarrativeArtifact from this module keep working.
export { assessNarrativeArtifact } from "./randori-runner.js";

const log = createLogger({ stage: "threat-model-randori" });

export const threatModelRandoriTask: AgentTask<
  ScanOpts,
  { document: ThreatModelDocument; findings: Finding[] }
> = {
  id: "threat-model-randori",
  displayName: "Randori PASTA Threat Model",
  outputKind: "threat-model",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<{ document: ThreatModelDocument; findings: Finding[] }> {
    context.signal?.throwIfAborted();
    const cfg = resolveThreatModelConfig(context.config);
    const pluginPath = resolveRandoriPluginPath();

    const previousModel = loadPersistentThreatModel(context.repoRoot);
    const artifactDir = path.join(".kuzushi", "runs", context.runId, "randori-output");

    log.info(
      `Starting Randori PASTA analysis (stages=${cfg.randoriStages.join(",")}, model=${cfg.model})`,
    );

    const taskId = "threat-model-randori";
    const publishPhase = (phase: string): void => {
      publishTaskPhase(context.bus, taskId, phase, { runId: context.runId });
    };
    const publishActivity = (description: string): void => {
      publishTaskActivity(context.bus, taskId, description, { runId: context.runId });
    };

    const result = await runRandoriPasta({
      runtime: context.runtime,
      repoRoot: context.repoRoot,
      repoName: context.repoName,
      pluginPath,
      model: cfg.model,
      allowedTools: [...resolveTaskAllowedTools(context), "Write"],
      stages: cfg.randoriStages,
      artifactDir,
      maxElements: cfg.maxElements,
      maxThreats: cfg.maxThreats,
      emitFindings: cfg.emitFindings,
      findingThreshold: cfg.findingThreshold,
      previousModel,
      logTag: "[threat-model-randori]",
      onPhase: publishPhase,
      onActivity: publishActivity,
      ...(context.signal ? { signal: context.signal } : {}),
    });

    return attachTaskOutputMeta(
      { document: result.document, findings: result.findings },
      { costUsd: result.costUsd },
    );
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    const strideMatch = finding.ruleId.match(/^threat-model\/([^/]+)/);
    const strideCategory = strideMatch?.[1] ?? "unknown";

    return {
      prompt: [
        `You are triaging a PASTA threat model finding in "${repoName}".`,
        "",
        `STRIDE Category: ${strideCategory}`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Message: ${finding.message}`,
        finding.evidence ? `\nEvidence:\n${finding.evidence}` : "",
        "",
        "This finding was identified through PASTA (Process for Attack Simulation and Threat Analysis).",
        "The threat model analyzed the application's data flow diagram, trust boundaries, and attack surface.",
        "",
        "Your task:",
        "1. Read the flagged code and surrounding context to verify the threat is real",
        "2. Check if existing mitigations (input validation, auth checks, TLS) address this threat",
        "3. For offensive/pentest tools: distinguish between DESIGN CHOICES (by_design) and actual bugs",
        "4. Provide a concrete attack scenario if the threat is valid",
      ]
        .filter(Boolean)
        .join("\n"),
    };
  },
};
