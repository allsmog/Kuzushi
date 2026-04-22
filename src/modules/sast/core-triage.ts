/**
 * Triage sub-module — real implementation.
 *
 * Loads findings from the workspace DB, triages them via `triageFindingsBatch`
 * (the same code the SAST DAG's triage stage uses), and writes results back.
 * Supports single-finding, explicit list, or "all actionable" mode.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";
import { loadFindingsForTriage } from "./findings-bridge.js";
import { resolvePromptValue } from "./prompts.js";

type Params = Record<string, unknown>;

const triageRunTool: ModuleTool = {
  name: "triage:run",
  displayName: "Triage",
  formatInput(input) {
    const p = (input ?? {}) as Record<string, unknown>;
    if (typeof p["fingerprint"] === "string") return (p["fingerprint"] as string).slice(0, 12);
    if (Array.isArray(p["fingerprints"])) {
      const arr = p["fingerprints"] as unknown[];
      return `${arr.length} finding${arr.length === 1 ? "" : "s"}`;
    }
    return null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Triage one or more findings from the workspace DB. The triage agent reads the " +
    "code, traces dataflow, and classifies each with a verdict (tp/fp/needs_review/" +
    "by_design), confidence, rationale, and verification steps.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: { type: "string", description: "Single finding fingerprint to triage." },
      fingerprints: {
        type: "array",
        items: { type: "string" },
        description: "Multiple finding fingerprints to triage.",
      },
      batchSize: {
        type: "integer",
        default: 5,
        description: "Max findings per agent call (larger = cheaper but less accurate).",
      },
      TRIAGE_PROMPT: {
        type: "string",
        description: "Override the triage system prompt. Inline text or path to a .md/.txt file.",
        "x-advanced": true,
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const p = (input ?? {}) as Params;
    if (!ctx.workspace) {
      return { ok: false, output: "triage:run needs an active workspace." };
    }
    const db = ctx.workspace.rawDb() as import("better-sqlite3").Database;

    const fingerprints = collectFingerprints(p);
    const findings = loadFindingsForTriage(db, ctx.target, fingerprints);
    if (findings.length === 0) {
      return {
        ok: false,
        output:
          "[-] No findings match. Run a scanner first " +
          "(`use semgrep; run`) or pass explicit fingerprints.",
      };
    }

    const { triageFindingsBatch } = await import("../../triage.js");
    const template = await resolvePromptValue(p["TRIAGE_PROMPT"] as string, ctx.cwd);
    const repoRoot = ctx.target ?? ctx.cwd;
    const repoName = repoRoot.split("/").pop() ?? "repo";
    const batchSize = typeof p["batchSize"] === "number" ? (p["batchSize"] as number) : 5;

    ctx.print?.status(`Triaging ${findings.length} finding(s) in batches of ${batchSize}...`);

    const model = ctx.config.model;
    const { results, costUsd, missingFingerprints } = await triageFindingsBatch(
      findings,
      repoRoot,
      repoName,
      model,
      undefined,
      { runtime: ctx.runtime },
      batchSize,
      template,
    );

    const tp = [...results.values()].filter((r) => r.verdict === "tp").length;
    const fp = [...results.values()].filter((r) => r.verdict === "fp").length;
    const review = [...results.values()].filter((r) => r.verdict === "needs_review").length;

    const output = [
      `[+] Triaged ${results.size} of ${findings.length} findings`,
      `      tp=${tp}  fp=${fp}  needs_review=${review}`,
      `      cost=$${costUsd.toFixed(4)}`,
      missingFingerprints.length > 0
        ? `[!] ${missingFingerprints.length} findings missing from batch output`
        : "",
    ]
      .filter(Boolean)
      .join("\n");

    return {
      ok: true,
      output,
      data: {
        triaged: results.size,
        total: findings.length,
        tp,
        fp,
        needsReview: review,
        costUsd,
        missingFingerprints,
      },
      costUsd,
    };
  },
};

function collectFingerprints(p: Params): string[] | undefined {
  const single = typeof p["fingerprint"] === "string" ? [p["fingerprint"] as string] : [];
  const list = Array.isArray(p["fingerprints"])
    ? (p["fingerprints"] as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const combined = [...single, ...list];
  return combined.length > 0 ? combined : undefined;
}

export function createTriageModule(): CopilotModule {
  return {
    id: "triage",
    displayName: "AI Triage",
    category: "defense",
    version: "0.17.2",
    description: "LLM-driven triage of scanner findings with evidence-backed verdicts.",
    rank: "good",
    references: [{ type: "CWE", value: "general" }],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: ["costs LLM tokens"],
    },
    requires: [{ kind: "findings", minCount: 1 }],
    examples: [
      "# Triage every actionable finding\nuse triage\nrun",
      "# Triage one finding by fingerprint\nuse triage\nset FINGERPRINT fp_a3b2c1\nrun",
    ],
    tools: [triageRunTool],
  };
}
