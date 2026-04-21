/**
 * Variant Hunter — LLM-guided 1-day lateral spread from confirmed TPs.
 *
 * When triage confirms a vulnerability, the same bug pattern often exists
 * elsewhere: in sibling modules, in vendored dependencies, in forked code.
 * This module lifts a confirmed Finding into a portable semantic signature
 * and hunts for matching shapes across the repo tree, including vendored
 * paths (node_modules, vendor, third_party, deps) that default scans skip.
 *
 * Builds on the existing variant-analysis library used by the post-triage
 * bus worker, but exposes it as a shell/run-mode tool so researchers can
 * re-run it on-demand against a specific fingerprint and broaden scope.
 */

import path from "node:path";
import { analyzeVariants } from "../agents/tasks/variant-analysis.js";
import type { Finding } from "../scanners/types.js";
import type { TriageResult, Verdict } from "../types.js";
import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "./types.js";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async function loadFindingAndTriage(
  repoRoot: string,
  fingerprint: string,
): Promise<{ finding: Finding; triage: TriageResult; repoName: string } | string> {
  const { defaultDbPath, initDb, getStoredFinding } = await import("../store.js");
  const { resolveRepo } = await import("../cli/shared.js");

  const { root, name } = resolveRepo(repoRoot);
  const dbPath = defaultDbPath(root);

  let db: Awaited<ReturnType<typeof initDb>>;
  try {
    db = initDb(dbPath);
  } catch (err) {
    return `Could not open findings DB at ${dbPath}: ${err instanceof Error ? err.message : String(err)}`;
  }

  try {
    const record = getStoredFinding(db, fingerprint);
    if (!record) {
      return `No finding with fingerprint "${fingerprint}" in ${dbPath}.`;
    }

    const finding: Finding = {
      taskId: record.taskId,
      fingerprint: record.fingerprint,
      ruleId: record.ruleId,
      filePath: record.filePath,
      startLine: record.startLine,
      severity: record.severity,
      message: record.message,
      evidence: null,
      scannerConfidence: "MEDIUM",
      subcategory: ["vuln"],
      likelihood: "MEDIUM",
      impact: record.severity === "ERROR" ? "HIGH" : record.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: [],
      score: 0,
      proofState: record.proofState,
      engineProvenance: record.engineProvenance,
    };

    const triage: TriageResult = {
      fingerprint: record.fingerprint,
      verdict: record.verdict as Verdict,
      confidence: record.confidence,
      rationale: record.rationale,
      verificationSteps: record.verificationSteps,
      fixPatch: record.fixPatch,
    };

    return { finding, triage, repoName: name };
  } finally {
    db.close();
  }
}

function resolveModel(ctx: ToolExecutionContext, override?: string): string {
  if (override) return override;
  const variantConfig = ctx.config.taskConfig?.["variant-analysis"] as
    | Record<string, unknown>
    | undefined;
  if (variantConfig && typeof variantConfig.model === "string") return variantConfig.model;
  return ctx.config.model ?? "anthropic:claude-sonnet-4-6";
}

// ---------------------------------------------------------------------------
// variant:lift-pattern — extract a portable semantic signature from a finding
// ---------------------------------------------------------------------------

const VARIANT_SIGNATURE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["source", "sink", "missingGuard", "languages", "keywords", "description"],
  properties: {
    source: {
      type: "string",
      description:
        "Where untrusted data enters (e.g. 'HTTP request body', 'CLI argument', 'decoded header').",
    },
    sink: {
      type: "string",
      description:
        "The dangerous API or operation (e.g. 'child_process.exec', 'raw SQL concatenation', 'memcpy with attacker-controlled length').",
    },
    missingGuard: {
      type: "string",
      description:
        "The validation/sanitization that would have prevented the vulnerability (e.g. 'no allowlist on command', 'no bounds check on length field').",
    },
    languages: {
      type: "array",
      items: { type: "string" },
      description: "Languages this signature applies to.",
    },
    keywords: {
      type: "array",
      items: { type: "string" },
      description: "Identifier-level keywords a grep-based hunter should search for.",
    },
    description: {
      type: "string",
      description: "One-paragraph portable pattern description suitable for reuse.",
    },
  },
} as const;

const liftPatternTool: ModuleTool = {
  name: "variant:lift-pattern",
  displayName: "Lift Pattern",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    return typeof p?.["fingerprint"] === "string"
      ? (p["fingerprint"] as string).slice(0, 12)
      : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Lift a confirmed true-positive finding into a portable semantic signature " +
    "(source / sink / missing guard / keywords) that downstream hunters can use " +
    "to search other codebases for the same bug pattern. Reads the finding's code " +
    "context from the repository and returns a structured signature — it does NOT " +
    "hunt for variants itself (use variant:hunt for that).",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: {
        type: "string",
        description: "Fingerprint of the confirmed-TP finding to lift.",
      },
      target: {
        type: "string",
        description: "Repository path (defaults to the session target).",
      },
      model: {
        type: "string",
        description: "Model override for the lift query.",
      },
    },
    required: ["fingerprint"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const fingerprint = params.fingerprint as string | undefined;
    if (!fingerprint) {
      return { ok: false, output: "variant:lift-pattern requires a fingerprint." };
    }

    const target = (params.target as string) ?? ctx.target ?? ctx.cwd;
    const loaded = await loadFindingAndTriage(target, fingerprint);
    if (typeof loaded === "string") return { ok: false, output: loaded };
    const { finding } = loaded;

    const prompt = [
      "You are a senior security researcher. Extract a portable semantic signature",
      "for the confirmed vulnerability below so a downstream hunter can find the same",
      "pattern in other codebases.",
      "",
      "## Finding",
      `Rule: ${finding.ruleId}`,
      `File: ${finding.filePath}:${finding.startLine}`,
      `Severity: ${finding.severity}`,
      `Message: ${finding.message}`,
      "",
      "## Instructions",
      "1. Read the vulnerable code to extract the source, sink, and missing guard.",
      "2. Propose 4-10 grep-friendly keywords that would help a hunter narrow the search.",
      "3. Describe the pattern in one paragraph, language-agnostic where possible.",
      "4. Do NOT speculate — base the signature on code you have actually read.",
    ].join("\n");

    const { repoRoot } = await resolveRepoPaths(target);
    const model = resolveModel(ctx, params.model as string | undefined);

    ctx.reportActivity?.(`lifting pattern from ${fingerprint.slice(0, 12)} · ${model}`);

    let structuredOutput: unknown;
    let costUsd = 0;
    try {
      for await (const message of ctx.runtime.query({
        prompt,
        options: {
          cwd: repoRoot,
          model,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: VARIANT_SIGNATURE_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
          costUsd = message.totalCostUsd;
        }
        if ("result" in message && message.structuredOutput !== undefined) {
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `variant:lift-pattern error: ${msg}`, costUsd };
    }

    if (!structuredOutput) {
      return {
        ok: false,
        output: "variant:lift-pattern produced no structured output.",
        costUsd,
      };
    }

    const sig = structuredOutput as Record<string, unknown>;
    const lines = [
      `Variant signature for ${finding.ruleId} (${finding.filePath}:${finding.startLine}):`,
      `  Source:        ${String(sig.source ?? "")}`,
      `  Sink:          ${String(sig.sink ?? "")}`,
      `  Missing guard: ${String(sig.missingGuard ?? "")}`,
      `  Languages:     ${Array.isArray(sig.languages) ? (sig.languages as unknown[]).join(", ") : ""}`,
      `  Keywords:      ${Array.isArray(sig.keywords) ? (sig.keywords as unknown[]).join(", ") : ""}`,
      "",
      String(sig.description ?? ""),
    ];

    return {
      ok: true,
      output: lines.join("\n"),
      data: { fingerprint, signature: structuredOutput, finding },
      costUsd,
    };
  },
};

// ---------------------------------------------------------------------------
// variant:hunt — run variant analysis for a confirmed finding
// ---------------------------------------------------------------------------

const DEFAULT_VENDOR_PATHS = [
  "node_modules",
  "vendor",
  "third_party",
  "third-party",
  "deps",
  "external",
];

const huntTool: ModuleTool = {
  name: "variant:hunt",
  displayName: "Hunt Variants",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    return typeof p?.["fingerprint"] === "string"
      ? (p["fingerprint"] as string).slice(0, 12)
      : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Hunt for variants of a confirmed true-positive vulnerability across the repository. " +
    "Loads the finding and its triage rationale from the workspace DB, extracts the bug " +
    "pattern, then searches the codebase for other locations with the same missing guard. " +
    "With `includeVendored: true` (default), the search also covers node_modules, vendor, " +
    "third_party, deps, and external directories that normal scans skip.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: {
        type: "string",
        description: "Fingerprint of the confirmed-TP finding to hunt variants of.",
      },
      target: {
        type: "string",
        description: "Repository path (defaults to the session target).",
      },
      maxFindings: {
        type: "integer",
        default: 10,
        minimum: 1,
        maximum: 50,
        description: "Maximum variants to return (default 10).",
      },
      includeVendored: {
        type: "boolean",
        default: true,
        description:
          "When true (default), extend search scope to vendored/third-party directories.",
      },
      vendorPaths: {
        type: "array",
        items: { type: "string" },
        description:
          "Override the default vendored path list (node_modules, vendor, third_party, etc.).",
      },
      model: {
        type: "string",
        description: "Model override for the hunt query.",
      },
    },
    required: ["fingerprint"],
  },
  headless: true,
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const fingerprint = params.fingerprint as string | undefined;
    if (!fingerprint) {
      return { ok: false, output: "variant:hunt requires a fingerprint." };
    }

    const target = (params.target as string) ?? ctx.target ?? ctx.cwd;
    const loaded = await loadFindingAndTriage(target, fingerprint);
    if (typeof loaded === "string") return { ok: false, output: loaded };
    const { finding, triage, repoName } = loaded;

    if (triage.verdict !== "tp") {
      return {
        ok: false,
        output:
          `variant:hunt expects a confirmed TP — finding "${fingerprint}" has verdict "${triage.verdict}". ` +
          `Run triage first or force by passing the fingerprint of a known-true-positive finding.`,
      };
    }

    const { repoRoot } = await resolveRepoPaths(target);
    const maxFindings = Math.max(1, Math.min(50, Number(params.maxFindings) || 10));
    const includeVendored = params.includeVendored !== false;
    const vendorPaths =
      Array.isArray(params.vendorPaths) && params.vendorPaths.length > 0
        ? (params.vendorPaths as string[])
        : DEFAULT_VENDOR_PATHS;
    const model = resolveModel(ctx, params.model as string | undefined);

    const augmentedTriage: TriageResult = includeVendored
      ? {
          ...triage,
          rationale: [
            triage.rationale,
            "",
            "## Extended hunt scope (cross-module + vendored)",
            "Broaden the variant search to include vendored and third-party code under:",
            ...vendorPaths.map((p) => `  - ${p}/`),
            "Report variants in these directories with the same confidence bar (HIGH/MEDIUM only).",
          ].join("\n"),
        }
      : triage;

    ctx.reportActivity?.(`hunting variants in ${repoName} · max ${maxFindings}`);

    try {
      const result = await analyzeVariants(
        finding,
        augmentedTriage,
        repoRoot,
        repoName,
        model,
        maxFindings,
        ctx.runtime,
      );

      const summary = [
        `variant:hunt complete for ${finding.ruleId} (${finding.filePath}:${finding.startLine})`,
        `  Variants found: ${result.findings.length}`,
        `  Scope:          ${includeVendored ? "repo + vendored" : "repo only"}`,
        `  Cost:           $${result.costUsd.toFixed(4)}`,
      ];
      if (result.findings.length > 0) {
        summary.push("", "Top variants:");
        for (const v of result.findings.slice(0, 5)) {
          summary.push(`  - ${v.filePath}:${v.startLine} (${v.severity}) — ${v.message}`);
        }
      }

      return {
        ok: true,
        output: summary.join("\n"),
        data: {
          fingerprint,
          originalFinding: finding,
          variants: result.findings,
          scope: { includeVendored, vendorPaths: includeVendored ? vendorPaths : [] },
        },
        costUsd: result.costUsd,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `variant:hunt error: ${msg}` };
    }
  },
};

async function resolveRepoPaths(target: string): Promise<{ repoRoot: string; scanPath: string }> {
  const { resolveRepo } = await import("../cli/shared.js");
  const { root } = resolveRepo(target);
  return { repoRoot: root, scanPath: path.resolve(target) };
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createVariantHunterModule(): CopilotModule {
  return {
    id: "variant-hunter",
    displayName: "Variant Hunter",
    category: "offense",
    version: "0.1.0",
    description:
      "Lifts confirmed vulnerabilities into portable signatures and hunts cross-module " +
      "(including vendored dependencies) for the same bug pattern.",
    tools: [liftPatternTool, huntTool],
    events: {
      produces: ["scan:finding"],
      consumes: ["triage:complete"],
    },
    async init() {
      // No-op: module is stateless and uses the workspace DB on demand.
    },
    async dispose() {
      // No resources to release.
    },
  };
}

export const __variantHunterInternals = {
  DEFAULT_VENDOR_PATHS,
  VARIANT_SIGNATURE_SCHEMA,
  loadFindingAndTriage,
  resolveModel,
};
