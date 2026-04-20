/**
 * Findings sub-module — query the workspace findings/vulns database.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Verdict = "tp" | "fp" | "needs_review" | "by_design";

const findingsListTool: ModuleTool = {
  name: "findings:list",
  description:
    "Query vulnerabilities stored in the active workspace. Filter by severity, " +
    "verdict, file path, or name substring. Reads from the workspace's vulns table " +
    "(written by scanner sub-modules). Requires an active workspace.",
  inputSchema: {
    type: "object",
    properties: {
      severity: {
        type: "array",
        items: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        description: "Filter by severity levels.",
      },
      verdict: {
        type: "array",
        items: { type: "string", enum: ["tp", "fp", "needs_review", "by_design"] },
        description: "Filter by triage verdict (derived from check_code).",
      },
      name: { type: "string", description: "Substring match on finding name." },
      limit: { type: "number", default: 50, description: "Max findings to return." },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    if (!ctx.workspace || !ctx.workspaceId) {
      return {
        ok: false,
        output: "findings:list needs an active workspace. Try `workspace use <name>` first.",
      };
    }

    const rows = ctx.workspace.vulns.listForWorkspace(ctx.workspaceId);
    const severity = Array.isArray(params["severity"])
      ? (params["severity"] as Severity[])
      : undefined;
    const verdict = Array.isArray(params["verdict"]) ? (params["verdict"] as Verdict[]) : undefined;
    const name =
      typeof params["name"] === "string" ? (params["name"] as string).toLowerCase() : undefined;
    const limit = typeof params["limit"] === "number" ? (params["limit"] as number) : 50;

    const filtered = rows.filter((v) => {
      if (severity && (!v.severity || !severity.includes(v.severity as Severity))) return false;
      if (verdict) {
        const asVerdict = checkCodeToVerdict(v.checkCode);
        if (!verdict.includes(asVerdict)) return false;
      }
      if (name && !v.name.toLowerCase().includes(name)) return false;
      return true;
    });

    const slice = filtered.slice(0, limit);
    if (slice.length === 0) {
      return { ok: true, output: "  (no findings match)", data: { count: 0, findings: [] } };
    }

    const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
    const widths = {
      id: Math.max(2, ...slice.map((v) => v.id.slice(0, 8).length)),
      sev: Math.max(4, ...slice.map((v) => (v.severity ?? "").length)),
      chk: Math.max(5, ...slice.map((v) => (v.checkCode ?? "").length)),
      name: Math.max(4, ...slice.map((v) => v.name.length)),
    };
    const header = `  ${pad("Id", widths.id)}  ${pad("Sev", widths.sev)}  ${pad("Check", widths.chk)}  ${pad("Name", widths.name)}`;
    const sep = `  ${"-".repeat(widths.id)}  ${"-".repeat(widths.sev)}  ${"-".repeat(widths.chk)}  ${"-".repeat(widths.name)}`;
    const body = slice
      .map(
        (v) =>
          `  ${pad(v.id.slice(0, 8), widths.id)}  ${pad(v.severity ?? "", widths.sev)}  ${pad(v.checkCode ?? "", widths.chk)}  ${v.name}`,
      )
      .join("\n");
    const output = [
      header,
      sep,
      body,
      "",
      `  ${filtered.length} matching (showing ${slice.length})`,
    ].join("\n");

    return {
      ok: true,
      output,
      data: {
        count: filtered.length,
        findings: slice.map((v) => ({
          id: v.id,
          name: v.name,
          severity: v.severity,
          checkCode: v.checkCode,
          references: v.references,
        })),
      },
    };
  },
};

/** Translate a CheckCodeKind to Kuzushi's legacy Verdict enum. */
function checkCodeToVerdict(code: string | null): "tp" | "fp" | "needs_review" | "by_design" {
  switch (code) {
    case "vulnerable":
      return "tp";
    case "safe":
      return "fp";
    default:
      return "needs_review";
  }
}

export function createFindingsModule(): CopilotModule {
  return {
    id: "findings",
    displayName: "Findings",
    category: "governance",
    version: "0.17.2",
    description: "Read + filter previously stored findings from the workspace DB.",
    rank: "great",
    references: [],
    notes: { stability: ["stable"], reliability: ["reliable"], sideEffects: [] },
    tools: [findingsListTool],
  };
}
