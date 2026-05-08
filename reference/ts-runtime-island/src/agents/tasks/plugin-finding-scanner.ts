/**
 * Shared runner for Claude Code plugin-driven finding scanners.
 *
 * Both the Vuln Scout (whitebox pentest) and Trail of Bits (security audit)
 * pipeline tasks are structurally identical: spin up a Claude Code subprocess
 * with a domain plugin loaded, run a single structured-output query against
 * the FINDING_SCHEMA, and normalize the result. This runner is the single
 * source of truth for that flow so the pipeline tasks and the shell/run-mode
 * module wrappers stay in sync.
 */
import type { AgentRuntime } from "../../agent-runtime/types.js";
import {
  FINDING_SCHEMA,
  parseFindingOutput,
  selectFindings,
} from "../../scanners/normalize-findings.js";
import type { Finding } from "../../scanners/types.js";
import { forwardSubAgentMessage } from "./forward-subagent-output.js";

export interface PluginFindingScannerParams {
  runtime: AgentRuntime;
  /** Project/repo root used as cwd for the Claude subprocess. */
  repoRoot: string;
  /** Logical repo name for fingerprinting. */
  repoName: string;
  /** Git ref for fingerprinting (typically "HEAD"). */
  ref: string;
  /** Scanner identity — becomes the `taskId` on every finding. */
  scannerId: string;
  model: string;
  allowedTools: string[];
  plugins: Array<{ type: "local"; path: string }>;
  prompt: string;
  maxFindings: number;
  /** Log prefix (e.g. `"[vuln-scout]"`); purely cosmetic. */
  logTag?: string;
  signal?: AbortSignal;
  /**
   * Optional live-output sink — called once per sub-agent action the
   * Claude Code subprocess takes (tool_use headers, tool-progress
   * heartbeats). Typically bound to `ctx.reportOutput` so the operator
   * sees what the audit is doing mid-run under the `⏺` header.
   */
  onOutput?: (line: string) => void;
}

export interface PluginFindingScannerResult {
  findings: Finding[];
  costUsd: number;
  durationMs?: number;
  numTurns?: number;
}

export async function runPluginFindingScanner(
  params: PluginFindingScannerParams,
): Promise<PluginFindingScannerResult> {
  let resultText = "";
  let structuredOutput: unknown;
  let costUsd = 0;
  let durationMs: number | undefined;
  let numTurns: number | undefined;
  let executionError: string | null = null;

  for await (const message of params.runtime.query({
    prompt: params.prompt,
    options: {
      cwd: params.repoRoot,
      model: params.model,
      allowedTools: params.allowedTools,
      permissionMode: "dontAsk",
      plugins: params.plugins,
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
      // Forward sub-agent actions to the caller's live-tail sink, if any.
      // The subprocess runs blind otherwise — operators see only a spinner
      // for 30-60s while the audit loops through dozens of tool calls.
      forwardSubAgentMessage(message, params.onOutput);
      continue;
    }
    if (message.type !== "result") continue;

    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }
    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
      durationMs = message.durationMs;
      numTurns = message.numTurns;
      break;
    }
    executionError =
      (Array.isArray(message.errors) ? message.errors.join("; ") : "") ||
      message.subtype ||
      "unknown error";
  }

  if (executionError) {
    throw new Error(`${params.logTag ?? `[${params.scannerId}]`} Failed: ${executionError}`);
  }

  const parsed =
    structuredOutput != null || resultText
      ? parseFindingOutput(structuredOutput ?? resultText)
      : { findings: [] };

  const findings = selectFindings(
    parsed,
    params.repoRoot,
    params.repoName,
    params.ref,
    params.scannerId,
    params.maxFindings,
  );

  return { findings, costUsd, durationMs, numTurns };
}
