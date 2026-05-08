/**
 * Triage module — LLM-driven triage of scanner findings.
 *
 * Not a DagTool: `triage:run` operates on findings stored in the workspace
 * DB and calls `triageFindingsBatch` directly. The scan pipeline's triage
 * pass is handled separately by the orchestrator's post-scan triage worker
 * (`src/bus/workers/triage-worker.ts`), not by this module.
 */

import { upsertRawFinding } from "../../store.js";
import { isRecord } from "../../utils.js";
import { defineModule, defineTool } from "../define.js";
import { loadFindingsForTriage } from "../sast/findings-bridge.js";
import { resolvePromptValue } from "../sast/prompts.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";

interface TriageRunInput {
  fingerprint?: string;
  fingerprints?: string[];
  batchSize?: number;
  TRIAGE_PROMPT?: string;
}

export function createTriageModule(): CopilotModule {
  const triageRunTool = defineTool<"triage">({
    name: "triage:run",
    displayName: "Triage",
    formatInput(input) {
      const p = parseTriageRunInput(input);
      if (p.fingerprint) return p.fingerprint.slice(0, 12);
      if (p.fingerprints) {
        return `${p.fingerprints.length} finding${p.fingerprints.length === 1 ? "" : "s"}`;
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
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const p = parseTriageRunInput(input);
      if (!ctx.workspace) {
        return { ok: false, output: "triage:run needs an active workspace." };
      }
      const db = ctx.workspace.rawDb() as import("better-sqlite3").Database;

      // Shell-mode hunt tools (carlini-threat-hunt, taint-iris, etc.) write
      // their findings to the `scan_findings` buffer table; only the scan
      // pipeline's report-worker normally drains that buffer into the
      // `findings` table that triage reads from. Without this promotion,
      // operators who run `use threat-hunt; run .` then `use triage; run .`
      // would see "no findings to triage" even though the hunt produced 30+.
      const fingerprints = collectFingerprints(p);
      const repoForPromote = ctx.target ?? ctx.cwd;
      promoteScanFindingsIfNeeded(db, repoForPromote);

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
      // Prompt override: prefer the unified `ctx.resolveOption` resolver
      // (shell `set TRIAGE_PROMPT`/`setg` → taskConfig lookup). Fall back
      // to the input field for inline calls.
      const rawPrompt = ctx.resolveOption?.<string>("TRIAGE_PROMPT") ?? p.TRIAGE_PROMPT;
      const template = await resolvePromptValue(rawPrompt, ctx.cwd);

      const repoRoot = ctx.target ?? ctx.cwd;
      const repoName = repoRoot.split("/").pop() ?? "repo";
      const batchSize = p.batchSize ?? 5;

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
  });

  return defineModule({
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
  });
}

function parseTriageRunInput(input: unknown): TriageRunInput {
  if (!isRecord(input)) return {};
  return {
    fingerprint: readStringField(input, "fingerprint"),
    fingerprints: readStringArrayField(input, "fingerprints"),
    batchSize: readNumberField(input, "batchSize"),
    TRIAGE_PROMPT: readStringField(input, "TRIAGE_PROMPT"),
  };
}

function collectFingerprints(p: TriageRunInput): string[] | undefined {
  const single = p.fingerprint ? [p.fingerprint] : [];
  const list = p.fingerprints ?? [];
  const combined = [...single, ...list];
  return combined.length > 0 ? combined : undefined;
}

function readStringField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function readNumberField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): number | undefined {
  const value = record[key];
  return typeof value === "number" ? value : undefined;
}

function readStringArrayField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): string[] | undefined {
  const value = record[key];
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === "string");
}

/**
 * Promote rows from the `scan_findings` buffer table into the canonical
 * `findings` table when the latter has fewer rows for the repo than the
 * former. Operates per-repo so we don't promote stale findings from other
 * targets in the same DB. Idempotent: existing rows in `findings` stay
 * untouched (upsertRawFinding skips when fingerprint+repo+ref already exist
 * with a real verdict — see scan_findings_store.ts and the INSERT_RAW
 * SQL guards).
 *
 * Why this lives here instead of in scan-mode bootstrap: the scan pipeline's
 * report-worker drains scan_findings during a normal scan run. Shell-mode
 * tools persist directly to scan_findings without the worker, so the
 * triage flow becomes the natural drain point.
 */
function promoteScanFindingsIfNeeded(db: import("better-sqlite3").Database, repo: string): void {
  let scanRows: Array<{ finding_json: string; run_id: string }>;
  try {
    scanRows = db
      .prepare(`SELECT finding_json, run_id FROM scan_findings ORDER BY run_id, ordinal`)
      .all() as Array<{ finding_json: string; run_id: string }>;
  } catch {
    // scan_findings table missing on first-run dbs — nothing to promote.
    return;
  }
  if (scanRows.length === 0) return;
  type RawFinding = Parameters<typeof upsertRawFinding>[1];
  for (const row of scanRows) {
    let finding: RawFinding | undefined;
    try {
      finding = JSON.parse(row.finding_json) as RawFinding;
    } catch {
      continue;
    }
    if (!finding) continue;
    try {
      upsertRawFinding(db, finding, repo, row.run_id);
    } catch {
      // Per-row failures are non-fatal — log via stderr would spam, so
      // silently skip and let the operator's empty-result diagnostic surface.
    }
  }
}
