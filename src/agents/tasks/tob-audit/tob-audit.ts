/**
 * Trail of Bits audit task — loads the forked trailofbits/skills plugin
 * into a Claude Code subprocess and lets the agent compose security
 * analysis skills (fp-check, variant-analysis, sharp-edges, insecure-defaults,
 * static-analysis, differential-review, etc.) dynamically based on what
 * it finds during exploration.
 *
 * Runs in parallel with other detection tasks as its own independent scanner.
 */

import { createLogger } from "../../../logger.js";
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
import type { AgentTask, TaskContext } from "../../types.js";
import {
  resolveTaskAllowedTools,
  resolveTaskModel,
  resolveTaskPositiveInt,
  resolveTaskRuntime,
} from "../runtime-overrides.js";
import { resolveTobPlugins } from "./resolve-tob-plugin.js";

const log = createLogger({ stage: "tob-audit" });

interface TobAuditConfig {
  model: string;
  maxFindings: number;
}

function resolveConfig(ctx: TaskContext): TobAuditConfig {
  const model = resolveTaskModel(ctx, "tob-audit");
  const maxFindings = resolveTaskPositiveInt(ctx, "tob-audit", "maxFindings", 50);
  return { model, maxFindings };
}

function buildPrompt(): string {
  return [
    "You are a senior security auditor with access to specialized security analysis skills.",
    "Audit this codebase for vulnerabilities using the security analysis skills available to you.",
    "",
    "Use the skills available from your loaded plugins to perform thorough analysis:",
    "- Look for insecure defaults and fail-open patterns",
    "- Identify sharp edges — error-prone APIs, dangerous configurations, and footgun designs",
    "- Trace data flows from user-controlled sources to dangerous sinks",
    "- Check for variant patterns when you find an issue",
    "- Verify your findings rigorously before reporting",
    "",
    "Explore the codebase thoroughly. Only report findings with concrete evidence of exploitability.",
    "",
    antiHallucinationModule(),
  ].join("\n");
}

async function run(_input: ScanOpts, context: TaskContext): Promise<Finding[]> {
  const config = resolveConfig(context);
  const tag = "[tob-audit]";

  let plugins: Array<{ type: "local"; path: string }>;
  try {
    plugins = resolveTobPlugins();
  } catch (err) {
    log.warn(`${tag} ToB skills plugins not available: ${toErrorMessage(err)} — skipping`);
    return attachTaskOutputMeta([], { costUsd: 0 });
  }

  const runtime = resolveTaskRuntime(context);
  const prompt = buildPrompt();

  log.info(`${tag} Starting audit (model=${config.model}, plugins=${plugins.length})`);

  let resultText = "";
  let structuredOutput: unknown;
  let costUsd = 0;
  let executionError: string | null = null;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: context.repoRoot,
      model: config.model,
      allowedTools: resolveTaskAllowedTools(context),
      permissionMode: "dontAsk",
      plugins,
      outputFormat: {
        type: "json_schema",
        schema: FINDING_SCHEMA,
        strict: true,
        retryInvalidStructuredOutput: 2,
      },
    },
  })) {
    if (
      message.type === "tool-progress" ||
      message.type === "tool-summary" ||
      message.type === "assistant"
    ) {
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
      log.info(
        `${tag} Complete in ${durationSec}s — ${message.numTurns} turns, $${message.totalCostUsd?.toFixed(4) ?? "?"}`,
      );
      break;
    }
    executionError =
      (Array.isArray(message.errors) ? message.errors.join("; ") : "") ||
      message.subtype ||
      "unknown error";
  }

  if (executionError) {
    throw new Error(`${tag} Failed: ${executionError}`);
  }

  const parsed =
    structuredOutput != null || resultText
      ? parseFindingOutput(structuredOutput ?? resultText)
      : { findings: [] };
  const findings = selectFindings(
    parsed,
    context.repoRoot,
    context.repoName,
    "HEAD",
    "tob-audit",
    config.maxFindings,
  );

  return attachTaskOutputMeta(findings, { costUsd });
}

export const tobAuditTask: AgentTask<ScanOpts, Finding[]> = {
  id: "tob-audit",
  displayName: "Trail of Bits Audit",
  outputKind: "findings",
  dependsOn: ["context-gatherer"],
  run,

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a finding from the Trail of Bits audit in "${repoName}".`,
        "This finding was discovered by an agent with access to ToB's security analysis skills.",
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
export const __tobAuditInternals = {
  buildPrompt,
  resolveConfig,
};
