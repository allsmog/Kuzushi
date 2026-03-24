/**
 * Approval gate task — blocks pipeline until external approval.
 *
 * Used for human-in-the-loop workflows where the pipeline should
 * pause before proceeding to destructive or high-impact stages.
 *
 * Approval can be granted via:
 * - CLI stdin prompt (interactive mode)
 * - Timeout with configurable default action
 */

import type { AgentTask, TaskContext, TaskOutputKind } from "../types.js";
import type { KuzushiConfig } from "../../types.js";
import { createInterface } from "node:readline";
import { getLogger } from "../../logger.js";

export interface ApprovalGateInput {
  description?: string;
}

export interface ApprovalOutput {
  approved: boolean;
  approverNotes?: string;
  method: "cli" | "timeout" | "auto";
}

/** Default timeout for approval (5 minutes). */
const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;
const log = getLogger("approval-gate");

/**
 * Create an approval gate task with the given configuration.
 *
 * @param id - Task ID (e.g., "approval-before-verify")
 * @param displayName - Human-readable name
 * @param dependsOn - Upstream task dependencies
 * @param options - Gate behavior options
 */
export function createApprovalGate(
  id: string,
  displayName: string,
  dependsOn: string[],
  options?: {
    description?: string;
    timeoutMs?: number;
    defaultOnTimeout?: boolean;
    condition?: (upstreamOutputs: Map<string, unknown>, config: KuzushiConfig) => boolean;
  },
): AgentTask<ApprovalGateInput, ApprovalOutput> {
  return {
    id,
    displayName,
    outputKind: "custom" as TaskOutputKind,
    dependsOn,
    condition: options?.condition,
    promptMode: "none",

    async run(_input: ApprovalGateInput, context: TaskContext): Promise<ApprovalOutput> {
      const description = options?.description ?? `Pipeline requires approval to continue past "${displayName}"`;
      const timeoutMs = options?.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;
      const defaultOnTimeout = options?.defaultOnTimeout ?? false;

      // Emit approval-requested event
      await context.bus.publish({
        type: "task:approval-requested",
        meta: {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          runId: context.runId,
        },
        payload: {
          context: {
            runId: context.runId,
            repoRoot: context.repoRoot,
            scanPath: context.scanPath,
            repoName: context.repoName,
            dbPath: "",
          },
          taskId: id,
          description,
        },
      });

      // If stdin is not a TTY, auto-approve or auto-deny based on config
      if (!process.stdin.isTTY) {
        log.warn(
          { defaultOnTimeout },
          `Non-interactive mode: ${defaultOnTimeout ? "auto-approved" : "auto-denied"}`,
        );
        return {
          approved: defaultOnTimeout,
          method: "auto",
        };
      }

      // Interactive CLI prompt with timeout
      return promptForApproval(description, timeoutMs, defaultOnTimeout);
    },
  };
}

async function promptForApproval(
  description: string,
  timeoutMs: number,
  defaultOnTimeout: boolean,
): Promise<ApprovalOutput> {
  return new Promise<ApprovalOutput>((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
    });

    const timeoutAction = defaultOnTimeout ? "auto-approve" : "auto-deny";
    const timeoutSec = Math.round(timeoutMs / 1000);

    console.error(`\n${"─".repeat(60)}`);
    console.error(`APPROVAL REQUIRED: ${description}`);
    console.error(`(will ${timeoutAction} in ${timeoutSec}s)`);
    console.error(`${"─".repeat(60)}`);

    rl.question("Approve? [y/N] > ", (answer) => {
      clearTimeout(timer);
      rl.close();

      const approved = answer.trim().toLowerCase() === "y" || answer.trim().toLowerCase() === "yes";
      resolve({
        approved,
        method: "cli",
      });
    });

    const timer = setTimeout(() => {
      rl.close();
      console.error(`\n[approval-gate] Timeout reached, ${timeoutAction}`);
      resolve({
        approved: defaultOnTimeout,
        method: "timeout",
      });
    }, timeoutMs);
  });
}

/**
 * Pre-built approval gate that fires before verification stage.
 * Only activates when high-severity true positives are found.
 */
export const approvalBeforeVerification = createApprovalGate(
  "approval-before-verify",
  "Approval Gate: Before Verification",
  [],
  {
    description: "High-severity findings detected. Approve to proceed with exploitability verification.",
    condition: (upstreamOutputs) => {
      // Only require approval if there are findings to verify
      for (const [, output] of upstreamOutputs) {
        if (Array.isArray(output) && output.length > 0) {
          return true;
        }
      }
      return false;
    },
  },
);
