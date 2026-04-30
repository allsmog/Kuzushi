/**
 * N-day diff hunter — fetch a CVE/GHSA advisory, extract the fix shape
 * from the patch diff, and hunt for pre-patch variants in the current repo.
 *
 * Inspired by n-day work on Chromium: reading upstream patches semantically
 * and structurally searching your tree for the pre-patch shape finds bugs
 * that rule-based scanners can't.
 */

import {
  type CveRecord,
  choosePrimaryPatchUrl,
  fetchCveOrAdvisory,
  fetchPatchText,
} from "../intel/cve-feed.js";
import { scoreFindingMetadata } from "../scanners/scoring.js";
import type { Finding } from "../scanners/types.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "./types.js";

// ndiff:fetch-cve

function readNdiffConfig(ctx: ExecutionContext): {
  offline: boolean;
  nvdApiKey?: string;
  githubToken?: string;
} {
  const cfg = ctx.config.taskConfig?.["ndiff-fetch"] as Record<string, unknown> | undefined;
  const offline = Boolean(cfg?.offline);
  const nvdApiKey = typeof cfg?.nvdApiKey === "string" ? (cfg.nvdApiKey as string) : undefined;
  const githubToken =
    typeof cfg?.githubToken === "string" ? (cfg.githubToken as string) : undefined;
  return { offline, nvdApiKey, githubToken };
}

const fetchCveTool: ModuleTool = {
  name: "ndiff:fetch-cve",
  displayName: "Fetch CVE",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    return typeof p?.["id"] === "string" ? (p["id"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Fetch a CVE or GitHub Security Advisory record, including description, CWEs, " +
    "affected products, and patch URLs. Accepts a CVE ID (CVE-YYYY-N...) or a GHSA " +
    "ID (GHSA-xxxx-xxxx-xxxx). In offline mode (set taskConfig.ndiff-fetch.offline = true) " +
    "returns fixture data only, never the network.",
  inputSchema: {
    type: "object",
    properties: {
      id: {
        type: "string",
        description: "CVE ID (CVE-YYYY-N...) or GHSA ID (GHSA-xxxx-xxxx-xxxx).",
      },
    },
    required: ["id"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const id = params.id as string | undefined;
    if (!id) return { ok: false, output: "ndiff:fetch-cve requires an `id`." };

    const cfg = readNdiffConfig(ctx);
    try {
      const record = await fetchCveOrAdvisory(id, {
        offline: cfg.offline,
        nvdApiKey: cfg.nvdApiKey,
        githubToken: cfg.githubToken,
      });
      if (!record) {
        return {
          ok: false,
          output: `No advisory found for "${id}" (offline=${cfg.offline}).`,
        };
      }
      return {
        ok: true,
        output: formatCveSummary(record),
        data: { record, primaryPatchUrl: choosePrimaryPatchUrl(record) },
      };
    } catch (err) {
      return {
        ok: false,
        output: `ndiff:fetch-cve error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  },
};

function formatCveSummary(record: CveRecord): string {
  const lines = [
    `${record.id} (${record.source.toUpperCase()})`,
    record.severity
      ? `  Severity: ${record.severity}${record.cvssScore ? ` (${record.cvssScore})` : ""}`
      : "",
    record.cwes.length > 0 ? `  CWEs:     ${record.cwes.join(", ")}` : "",
    record.publishedAt ? `  Published: ${record.publishedAt}` : "",
    "",
    record.description.trim(),
  ];
  if (record.patches.length > 0) {
    lines.push("", "Patches:");
    for (const p of record.patches.slice(0, 5)) {
      lines.push(`  - ${p.url}`);
    }
  }
  return lines.filter(Boolean).join("\n");
}

// ndiff:extract-fix-pattern

const FIX_PATTERN_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "fixShape",
    "vulnerableShape",
    "cwe",
    "languages",
    "keywords",
    "detectionQuery",
    "description",
    "confidence",
  ],
  properties: {
    fixShape: {
      type: "string",
      description:
        "One-sentence description of the code added by the patch (e.g. 'adds bounds check before indexed write').",
    },
    vulnerableShape: {
      type: "string",
      description: "One-sentence description of the pre-patch shape a hunter should look for.",
    },
    cwe: {
      type: "array",
      items: { type: "string" },
      description: "CWE IDs most relevant to this fix.",
    },
    languages: {
      type: "array",
      items: { type: "string" },
      description: "Languages this pattern applies to.",
    },
    keywords: {
      type: "array",
      items: { type: "string" },
      description: "Identifier-level keywords a grep hunter should use.",
    },
    detectionQuery: {
      type: "string",
      description:
        "A concrete ripgrep-style pattern or AST-grep sketch a hunter can use to narrow search.",
    },
    description: {
      type: "string",
      description: "One-paragraph human-readable pattern description.",
    },
    confidence: {
      type: "string",
      enum: ["HIGH", "MEDIUM", "LOW"],
      description:
        "How confident the analysis is that the extracted pattern is portable and searchable.",
    },
  },
} as const;

const extractFixPatternTool: ModuleTool = {
  name: "ndiff:extract-fix-pattern",
  displayName: "Extract Fix Pattern",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    if (typeof p?.["id"] === "string") return p["id"] as string;
    if (typeof p?.["patch"] === "string") return "<patch>";
    return null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Read a CVE patch diff and extract a portable fix-shape signature: what was " +
    "added to fix the bug, what the pre-patch code looked like, which CWEs apply, " +
    "and a concrete detection query a hunter can use to find unpatched variants. " +
    "Accepts either an advisory id (auto-fetches patch) or a raw patch text/URL. " +
    "Does NOT hunt — use ndiff:hunt-variants for that.",
  inputSchema: {
    type: "object",
    properties: {
      id: {
        type: "string",
        description: "CVE or GHSA ID — used to auto-fetch the patch if patchText is not supplied.",
      },
      patchText: {
        type: "string",
        description: "Raw patch/diff text. Takes precedence over auto-fetch.",
      },
      patchUrl: {
        type: "string",
        description: "URL to fetch the patch from (when id is not an NVD/GHSA entry).",
      },
      model: {
        type: "string",
        description: "Model override for the extract query.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const id = params.id as string | undefined;
    const explicitPatch = params.patchText as string | undefined;
    const explicitUrl = params.patchUrl as string | undefined;

    const cfg = readNdiffConfig(ctx);
    let record: CveRecord | null = null;
    let patchText = explicitPatch ?? "";
    let patchUrl = explicitUrl ?? "";

    if (!patchText) {
      if (!id && !patchUrl) {
        return {
          ok: false,
          output: "ndiff:extract-fix-pattern requires at least one of: id, patchText, or patchUrl.",
        };
      }
      if (id) {
        try {
          record = await fetchCveOrAdvisory(id, {
            offline: cfg.offline,
            nvdApiKey: cfg.nvdApiKey,
            githubToken: cfg.githubToken,
          });
        } catch (err) {
          return {
            ok: false,
            output: `Could not fetch ${id}: ${err instanceof Error ? err.message : String(err)}`,
          };
        }
        if (record && !patchUrl) {
          patchUrl = choosePrimaryPatchUrl(record) ?? "";
        }
      }
      if (patchUrl) {
        const fetched = await fetchPatchText(patchUrl, {
          offline: cfg.offline,
          githubToken: cfg.githubToken,
        });
        if (!fetched) {
          return {
            ok: false,
            output: `Could not fetch patch content from ${patchUrl}${cfg.offline ? " (offline mode)" : ""}.`,
          };
        }
        patchText = fetched;
      }
    }

    if (!patchText) {
      return {
        ok: false,
        output: "ndiff:extract-fix-pattern could not resolve any patch content to analyze.",
      };
    }

    const trimmed =
      patchText.length > 18000 ? `${patchText.slice(0, 18000)}\n... [truncated]` : patchText;
    const model = (params.model as string) ?? ctx.config.model ?? "anthropic:claude-sonnet-4-6";

    const prompt = [
      "You are a security researcher extracting a portable fix-shape signature from a CVE patch.",
      "Your goal: describe the added code (fix shape), the code it replaced (vulnerable shape),",
      "and a detection query that lets a hunter find unpatched variants in other codebases.",
      "",
      record
        ? `## Advisory\nID: ${record.id}\nCWEs: ${record.cwes.join(", ") || "(none listed)"}\n\n${record.description.trim()}`
        : "## Advisory\n(No structured advisory record supplied; infer from the patch.)",
      "",
      "## Patch diff",
      "```diff",
      trimmed,
      "```",
      "",
      "## Instructions",
      "1. Identify exactly what the patch added (a bounds check? an allowlist? a safe API swap?).",
      "2. Describe the pre-patch shape the same code had before the fix.",
      "3. Output CWE IDs, affected languages, grep-friendly keywords, and a concrete detection query.",
      "4. Set confidence to HIGH only if the fix shape is clearly portable; LOW for one-off refactors.",
      "5. Do NOT invent details the patch doesn't support.",
    ].join("\n");

    ctx.reportActivity?.(`extracting fix pattern ${record?.id ?? id ?? "(inline)"} · ${model}`);

    let structuredOutput: unknown;
    let costUsd = 0;
    try {
      for await (const message of ctx.runtime.query({
        prompt,
        options: {
          cwd: ctx.cwd,
          model,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: FIX_PATTERN_SCHEMA,
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
      return { ok: false, output: `ndiff:extract-fix-pattern error: ${msg}`, costUsd };
    }

    if (!structuredOutput) {
      return {
        ok: false,
        output: "ndiff:extract-fix-pattern produced no structured output.",
        costUsd,
      };
    }

    const fp = structuredOutput as Record<string, unknown>;
    const summary = [
      `Fix shape:         ${String(fp.fixShape ?? "")}`,
      `Vulnerable shape:  ${String(fp.vulnerableShape ?? "")}`,
      `CWEs:              ${Array.isArray(fp.cwe) ? (fp.cwe as unknown[]).join(", ") : ""}`,
      `Languages:         ${Array.isArray(fp.languages) ? (fp.languages as unknown[]).join(", ") : ""}`,
      `Keywords:          ${Array.isArray(fp.keywords) ? (fp.keywords as unknown[]).join(", ") : ""}`,
      `Detection query:   ${String(fp.detectionQuery ?? "")}`,
      `Confidence:        ${String(fp.confidence ?? "")}`,
      "",
      String(fp.description ?? ""),
    ].join("\n");

    return {
      ok: true,
      output: summary,
      data: { advisory: record, pattern: structuredOutput, patchUrl },
      costUsd,
    };
  },
};

// ndiff:hunt-variants

const VARIANT_HUNT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["variants"],
  properties: {
    variants: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["filePath", "startLine", "severity", "message", "confidence", "rationale"],
        properties: {
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          message: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          cwe: { type: "array", items: { type: "string" } },
        },
      },
    },
  },
} as const;

interface FixPattern {
  fixShape: string;
  vulnerableShape: string;
  cwe: string[];
  languages: string[];
  keywords: string[];
  detectionQuery: string;
  description: string;
  confidence: string;
}

const huntVariantsTool: ModuleTool = {
  name: "ndiff:hunt-variants",
  displayName: "Hunt CVE Variants",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    const pattern = p?.["pattern"] as Record<string, unknown> | undefined;
    const cwe =
      pattern && Array.isArray(pattern["cwes"]) ? (pattern["cwes"] as string[]).join(",") : null;
    return cwe ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Given a fix-shape signature (from ndiff:extract-fix-pattern), hunt the target " +
    "repository for pre-patch variants — code that still has the vulnerable shape. " +
    "Returns structured Finding records ready to feed into triage. Includes vendored " +
    "directories in scope when includeVendored is true (default).",
  inputSchema: {
    type: "object",
    properties: {
      pattern: {
        type: "object",
        description: "Fix pattern produced by ndiff:extract-fix-pattern.",
      },
      target: {
        type: "string",
        description: "Repository path (defaults to session target).",
      },
      maxFindings: {
        type: "integer",
        default: 15,
        minimum: 1,
        maximum: 100,
      },
      includeVendored: {
        type: "boolean",
        default: true,
        description: "Include node_modules/vendor/third_party/deps in the search.",
      },
      advisoryId: {
        type: "string",
        description: "Optional advisory ID recorded in the resulting Finding ruleId.",
      },
      model: {
        type: "string",
      },
    },
    required: ["pattern"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const pattern = params.pattern as FixPattern | undefined;
    if (!pattern || typeof pattern !== "object") {
      return { ok: false, output: "ndiff:hunt-variants requires a pattern object." };
    }
    const target = (params.target as string) ?? ctx.target ?? ctx.cwd;
    const maxFindings = Math.max(1, Math.min(100, Number(params.maxFindings) || 15));
    const includeVendored = params.includeVendored !== false;
    const advisoryId = (params.advisoryId as string) ?? "unknown";
    const model = (params.model as string) ?? ctx.config.model ?? "anthropic:claude-sonnet-4-6";

    const { resolveRepo } = await import("../cli/shared.js");
    const { root: repoRoot, name: repoName } = resolveRepo(target);

    const prompt = [
      "You are a senior security researcher hunting for pre-patch variants of a known CVE.",
      "The following fix-shape signature was extracted from the upstream patch.",
      "Your job: find code in the target repository that STILL has the vulnerable shape.",
      "",
      "## Fix-shape signature",
      `Fix shape:        ${pattern.fixShape}`,
      `Vulnerable shape: ${pattern.vulnerableShape}`,
      `CWEs:             ${(pattern.cwe ?? []).join(", ") || "(none)"}`,
      `Languages:        ${(pattern.languages ?? []).join(", ") || "(any)"}`,
      `Keywords:         ${(pattern.keywords ?? []).join(", ") || "(none)"}`,
      `Detection query:  ${pattern.detectionQuery ?? ""}`,
      "",
      pattern.description,
      "",
      "## Hunt methodology",
      "1. Use Grep with the supplied keywords and detection query.",
      "2. Read each candidate file and verify that the vulnerable shape is present AND the fix shape is absent.",
      "3. Report HIGH confidence only when you can clearly show the pre-patch structure in the code.",
      "4. Ignore test fixtures and files explicitly labeled 'mock' unless they are loaded in production.",
      includeVendored
        ? "5. Extend search to vendored code: node_modules/, vendor/, third_party/, deps/, external/."
        : "5. Restrict search to first-party source — skip node_modules/, vendor/, third_party/.",
      "",
      "## Anti-hallucination",
      "- Only report locations you have read.",
      "- Confidence must be HIGH or MEDIUM (skip LOW).",
      "- Skip files that already apply the fix shape.",
    ].join("\n");

    ctx.reportActivity?.(
      `hunting ${advisoryId} variants in ${repoName} · max ${maxFindings} · ${model}`,
    );

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
            schema: VARIANT_HUNT_SCHEMA,
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
      return { ok: false, output: `ndiff:hunt-variants error: ${msg}`, costUsd };
    }

    const findings = normalizeHuntResults(
      structuredOutput,
      advisoryId,
      pattern,
      repoName,
      maxFindings,
    );

    const summary = [
      `ndiff:hunt-variants complete (${advisoryId})`,
      `  Variants:   ${findings.length}`,
      `  Scope:      ${includeVendored ? "repo + vendored" : "repo only"}`,
      `  Cost:       $${costUsd.toFixed(4)}`,
    ];
    if (findings.length > 0) {
      summary.push("", "Top candidates:");
      for (const v of findings.slice(0, 5)) {
        summary.push(`  - ${v.filePath}:${v.startLine} (${v.severity}) — ${v.message}`);
      }
    }

    return {
      ok: true,
      output: summary.join("\n"),
      data: { advisoryId, pattern, findings },
      costUsd,
    };
  },
};

function normalizeHuntResults(
  raw: unknown,
  advisoryId: string,
  pattern: FixPattern,
  repoName: string,
  maxFindings: number,
): Finding[] {
  const record = (raw ?? {}) as Record<string, unknown>;
  const variants = Array.isArray(record.variants) ? record.variants : [];
  const out: Finding[] = [];
  for (const v of variants as Array<Record<string, unknown>>) {
    const filePath = typeof v.filePath === "string" ? v.filePath : null;
    const startLine = Number(v.startLine);
    if (!filePath || !Number.isFinite(startLine) || startLine < 1) continue;
    const confidence = typeof v.confidence === "string" ? v.confidence : "MEDIUM";
    if (confidence === "LOW") continue;
    const severity = typeof v.severity === "string" ? v.severity : "WARNING";
    const cwe = Array.isArray(v.cwe)
      ? (v.cwe as unknown[]).filter((c): c is string => typeof c === "string")
      : (pattern.cwe ?? []);
    const fingerprint = `ndiff/${advisoryId}/${filePath}:${startLine}`;
    const impact = severity === "ERROR" ? "HIGH" : severity === "INFO" ? "LOW" : "MEDIUM";
    const finding: Finding = {
      taskId: "n-day-diff-hunter",
      fingerprint,
      ruleId: `n-day/${advisoryId}`,
      filePath,
      startLine: Math.floor(startLine),
      severity,
      message:
        typeof v.message === "string"
          ? v.message
          : `Possible unpatched variant of ${advisoryId}: ${pattern.vulnerableShape}`,
      evidence: typeof v.rationale === "string" ? v.rationale : null,
      scannerConfidence: confidence,
      subcategory: ["n-day"],
      likelihood: confidence,
      impact,
      cwe,
      score: scoreFindingMetadata({
        severity,
        likelihood: confidence,
        impact,
        subcategory: ["n-day"],
      }),
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "agentic", detail: `n-day-diff-hunter(${advisoryId})` }],
    };
    out.push(finding);
    if (out.length >= maxFindings) break;
  }
  // Voltage the ruleId with repoName prefix for fingerprint uniqueness (best-effort)
  return out.map((f) => ({
    ...f,
    fingerprint: `${repoName}:${f.fingerprint}`,
  }));
}

// Module factory

export function createNDayDiffHunterModule(): CopilotModule {
  return {
    id: "ndiff",
    displayName: "N-day Diff Hunter",
    category: "intel",
    version: "0.1.0",
    description:
      "Fetch CVE/GHSA advisories, extract fix-shape signatures from patch diffs, " +
      "and hunt for pre-patch variants in the target repository.",
    tools: [fetchCveTool, extractFixPatternTool, huntVariantsTool],
    events: {
      produces: ["scan:finding"],
      consumes: [],
    },
    async init() {},
    async dispose() {},
  };
}

export const __nDayInternals = {
  FIX_PATTERN_SCHEMA,
  VARIANT_HUNT_SCHEMA,
  normalizeHuntResults,
  formatCveSummary,
  readNdiffConfig,
};
