/**
 * Verify module — exploitability verification tool.
 *
 * Not a DagTool: `verify:finding` is a pure `ModuleTool` that operates on a
 * single stored finding by fingerprint. The underlying verification agent
 * (`verifyFindingWithAgent` at `src/verify.js`) does the PoC construction
 * and sandboxed execution directly — no scan DAG involved.
 *
 * Requires the finding to already have a triage verdict; run
 * `triage:run` first if that hasn't happened yet.
 */

import { defineModule, defineTool } from "../define.js";
import { storedToFinding } from "../sast/findings-bridge.js";
import { resolvePromptValue } from "../sast/prompts.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";

type Params = Record<string, unknown>;

export function createVerifyModule(): CopilotModule {
  const verifyFindingTool = defineTool<"verify">({
    name: "verify:finding",
    displayName: "Verify",
    formatInput(input) {
      const p = (input ?? {}) as Record<string, unknown>;
      return typeof p["fingerprint"] === "string"
        ? (p["fingerprint"] as string).slice(0, 12)
        : null;
    },
    renderResult(result) {
      const first = result.output.split("\n", 1)[0]?.trim();
      return first && first.length > 0 ? first : null;
    },
    description:
      "Verify exploitability of a triaged finding. Constructs a concrete PoC payload " +
      "and runs in a sandbox. Returns exploitability assessment + attack vector.",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: { type: "string", description: "Finding fingerprint to verify." },
        VERIFY_PROMPT: {
          type: "string",
          description: "Override the verify system prompt. Inline text or a path to .md/.txt.",
          "x-advanced": true,
        },
      },
      required: ["fingerprint"],
    },
    headless: true,
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const p = (input ?? {}) as Params;
      if (!ctx.workspace) {
        return { ok: false, output: "verify:finding needs an active workspace." };
      }
      const fingerprint = typeof p["fingerprint"] === "string" ? (p["fingerprint"] as string) : "";
      if (!fingerprint) {
        return { ok: false, output: "verify:finding requires a fingerprint." };
      }

      const db = ctx.workspace.rawDb() as import("better-sqlite3").Database;
      const { getStoredFinding } = await import("../../store.js");
      const stored = getStoredFinding(db, fingerprint);
      if (!stored) {
        return { ok: false, output: `[-] No finding with fingerprint '${fingerprint}'.` };
      }
      const finding = storedToFinding(stored);
      if (!finding) {
        return { ok: false, output: `[-] Failed to load finding '${fingerprint}'.` };
      }

      const triageResult = {
        fingerprint: stored.fingerprint,
        verdict: stored.verdict,
        confidence: stored.confidence,
        rationale: stored.rationale,
        verificationSteps: stored.verificationSteps,
        fixPatch: stored.fixPatch,
      };

      // Prompt override: prefer the unified `ctx.resolveOption` resolver
      // (shell `set VERIFY_PROMPT`/`setg` → taskConfig lookup). Fall back to
      // the input field if the caller passed it inline on the tool call.
      const rawPrompt =
        ctx.resolveOption?.<string>("VERIFY_PROMPT") ?? (p["VERIFY_PROMPT"] as string | undefined);
      const template = await resolvePromptValue(rawPrompt, ctx.cwd);

      const repoRoot = ctx.target ?? ctx.cwd;
      const repoName = repoRoot.split("/").pop() ?? "repo";
      const model = ctx.config.model;

      ctx.print?.status(`Verifying ${fingerprint}...`);

      const { verifyFindingWithAgent } = await import("../../verify.js");
      const outcome = await verifyFindingWithAgent(
        finding,
        triageResult as never,
        repoRoot,
        repoName,
        model,
        undefined,
        { runtime: ctx.runtime },
        template,
      );

      const verdict = outcome.result?.exploitable ? "VULNERABLE" : "not-exploitable";
      const output = [
        `[+] verify:finding complete`,
        `      ${verdict}`,
        outcome.result?.attackVector ? `      vector: ${outcome.result.attackVector}` : "",
        `      cost=$${outcome.costUsd.toFixed(4)}`,
      ]
        .filter(Boolean)
        .join("\n");

      return {
        ok: true,
        output,
        data: outcome.result,
        costUsd: outcome.costUsd,
      };
    },
  });

  return defineModule({
    id: "verify",
    displayName: "Exploit Verify",
    category: "offense",
    version: "0.17.2",
    description: "Exploitability verification — PoC construction and sandboxed execution.",
    rank: "good",
    references: [],
    notes: {
      stability: ["stable"],
      reliability: ["first-attempt"],
      sideEffects: ["sandbox execution", "costs LLM tokens"],
    },
    requires: [{ kind: "findings", minCount: 1 }],
    examples: ["# Verify a single finding\nuse verify\nset FINGERPRINT fp_a3b2c1\nrun"],
    tools: [verifyFindingTool],
  });
}
