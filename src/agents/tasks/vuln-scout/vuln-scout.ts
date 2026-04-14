/**
 * Vuln Scout task — loads the vuln-scout whitebox pentesting plugin
 * into a Claude Code subprocess and lets the agent compose security
 * analysis skills (scan, verify, trace, threat-model, PoC development)
 * dynamically based on what it finds during exploration.
 *
 * Runs in parallel with other detection tasks as its own independent scanner.
 */
import { antiHallucinationModule } from "../../../prompts/modules.js";
import {
  FINDING_SCHEMA,
  parseFindingOutput,
  selectFindings,
} from "../../../scanners/normalize-findings.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import { createLogger } from "../../../logger.js";
import type { AgentTask, TaskContext } from "../../types.js";
import { resolveTaskModel, resolveTaskRuntime, resolveTaskAllowedTools } from "../runtime-overrides.js";
import { resolveTaskPositiveInt } from "../runtime-overrides.js";
import { resolveVulnScoutPlugin } from "./resolve-vuln-scout.js";

const log = createLogger({ stage: "vuln-scout" });

interface VulnScoutConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): VulnScoutConfig {
  const model = resolveTaskModel(ctx, "vuln-scout");
  const maxFindings = resolveTaskPositiveInt(ctx, "vuln-scout", "maxFindings", 50);
  return { model, maxFindings };
}

function buildPrompt(): string {
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

async function run(_input: ScanOpts, context: TaskContext): Promise<Finding[]> {
  const config = resolveConfig(context);
  const tag = "[vuln-scout]";

  let plugin: { type: "local"; path: string };
  try {
    plugin = resolveVulnScoutPlugin();
  } catch (err) {
    log.warn(`${tag} Vuln Scout plugin not available: ${toErrorMessage(err)} — skipping`);
    return attachTaskOutputMeta([], { costUsd: 0 });
  }

  const runtime = resolveTaskRuntime(context);
  const prompt = buildPrompt();

  log.info(`${tag} Starting pentest (model=${config.model})`);

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
      plugins: [plugin],
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
    throw new Error(`${tag} Failed: ${executionError}`);
  }

  const parsed = structuredOutput != null || resultText
    ? parseFindingOutput(structuredOutput ?? resultText)
    : { findings: [] };
  const findings = selectFindings(
    parsed,
    context.repoRoot,
    context.repoName,
    "HEAD",
    "vuln-scout",
    config.maxFindings,
  );

  return attachTaskOutputMeta(findings, { costUsd });
}

export const vulnScoutTask: AgentTask<ScanOpts, Finding[]> = {
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
      ].filter(Boolean).join("\n"),
    };
  },
};

// Exported for testing
export const __vulnScoutInternals = {
  buildPrompt,
  resolveConfig,
};
