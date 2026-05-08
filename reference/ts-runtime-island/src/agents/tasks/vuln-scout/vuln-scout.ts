/**
 * Vuln Scout task — loads the vuln-scout whitebox pentesting plugin
 * into a Claude Code subprocess and lets the agent compose security
 * analysis skills (scan, verify, trace, threat-model, PoC development)
 * dynamically based on what it finds during exploration.
 *
 * Runs in parallel with other detection tasks as its own independent scanner.
 */

import { createLogger } from "../../../logger.js";
import { antiHallucinationModule } from "../../../prompts/modules.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import type { DagNodeImpl, DagRunContext } from "../../types.js";
import { runPluginFindingScanner } from "../plugin-finding-scanner.js";
import {
  resolveTaskAllowedTools,
  resolveTaskModel,
  resolveTaskPositiveInt,
  resolveTaskRuntime,
} from "../runtime-overrides.js";
import { resolveVulnScoutPlugin } from "./resolve-vuln-scout.js";

const log = createLogger({ stage: "vuln-scout" });

interface VulnScoutConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: DagRunContext): VulnScoutConfig {
  const model = resolveTaskModel(ctx, "vuln-scout");
  const maxFindings = resolveTaskPositiveInt(ctx, "vuln-scout", "maxFindings", 50);
  return { model, maxFindings };
}

export function buildVulnScoutPrompt(): string {
  return [
    "You are an expert whitebox penetration tester with access to vuln-scout security analysis skills.",
    "Perform a thorough security audit of this codebase using the skills available from your loaded plugins.",
    "",
    "Use the available scanning and analysis skills to:",
    "- Run static analysis to identify potential vulnerabilities (SAST patterns, taint analysis)",
    "- Trace data flows from user-controlled sources to dangerous sinks",
    "- Identify security misconfigurations, hardcoded secrets, and cryptographic failures",
    "- Check for OWASP Top 10 and API security issues",
    "- Verify findings rigorously — distinguish real vulnerabilities from false positives",
    "",
    "Explore the codebase thoroughly. Only report findings with concrete evidence of exploitability.",
    "",
    antiHallucinationModule(),
  ].join("\n");
}

// Backwards-compat alias for internal tests/callers.
const buildPrompt = buildVulnScoutPrompt;

async function run(_input: ScanOpts, context: DagRunContext): Promise<Finding[]> {
  const config = resolveConfig(context);
  const tag = "[vuln-scout]";

  let plugin: { type: "local"; path: string };
  try {
    plugin = resolveVulnScoutPlugin();
  } catch (err) {
    log.warn(`${tag} Vuln Scout plugin not available: ${toErrorMessage(err)} — skipping`);
    return attachTaskOutputMeta([], { costUsd: 0 });
  }

  log.info(`${tag} Starting pentest (model=${config.model})`);

  const result = await runPluginFindingScanner({
    runtime: resolveTaskRuntime(context),
    repoRoot: context.repoRoot,
    repoName: context.repoName,
    ref: "HEAD",
    scannerId: "vuln-scout",
    model: config.model,
    allowedTools: resolveTaskAllowedTools(context),
    plugins: [plugin],
    prompt: buildVulnScoutPrompt(),
    maxFindings: config.maxFindings,
    logTag: tag,
  });

  if (result.durationMs !== undefined && result.numTurns !== undefined) {
    const durationSec = (result.durationMs / 1000).toFixed(1);
    log.info(
      `${tag} Complete in ${durationSec}s — ${result.numTurns} turns, $${result.costUsd.toFixed(4)}`,
    );
  }

  return attachTaskOutputMeta(result.findings, { costUsd: result.costUsd });
}

export const vulnScoutTask: DagNodeImpl<ScanOpts, Finding[]> = {
  id: "vuln-scout",
  displayName: "Vuln Scout Pentest",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],
  run,

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a finding from the Vuln Scout whitebox pentest in "${repoName}".`,
        "This finding was discovered by an AI agent with access to vuln-scout's pentesting skills.",
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
        "- Confirm the code is reachable from an external entry point",
      ]
        .filter(Boolean)
        .join("\n"),
    };
  },
};

// Exported for testing
export const __vulnScoutInternals = {
  buildPrompt,
  resolveConfig,
};
