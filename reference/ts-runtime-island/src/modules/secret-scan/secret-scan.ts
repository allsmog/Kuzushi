/**
 * `secret-scan` — committed-credential detection.
 *
 * Pure deterministic regex + entropy scanner. No LLM dependency, no
 * provider call — runs identically in shell, `kuzushi run`, and CI.
 *
 * The actual scanning lives in `./scan.ts` so the engine can be unit-
 * tested without going through the module shell. This file is the thin
 * `CopilotModule` wrapper that adapts the engine into a `ModuleTool`.
 *
 * Findings produced here use `taskId: "secret-scan"` and carry rule ids
 * shaped `secret-scan/<detector-id>`. Severity is `ERROR` for
 * unambiguous tokens (AWS access keys, GitHub PATs, PEM private keys),
 * `WARNING` for ambiguous-but-still-leaky shapes (JWTs, generic
 * password assignments).
 */

import path from "node:path";
import { defineModule, defineTool } from "../define.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";
import type { SecretDetector } from "./detectors.js";
import { type SecretScanOptions, scanForSecrets } from "./scan.js";

interface SecretScanInput {
  target?: string;
  maxFileBytes?: number;
  excludeDirs?: string[];
  binaryExts?: string[];
  maxFindings?: number;
  /**
   * Optional severity filter. Findings whose severity is NOT in the list
   * are dropped before returning. Operators who only want hard errors can
   * pass `["ERROR"]`.
   */
  severity?: ReadonlyArray<"ERROR" | "WARNING" | "INFO">;
}

const SEVERITY_VALUES = ["ERROR", "WARNING", "INFO"] as const;

function readDetectorOverride(ctx: ExecutionContext): ReadonlyArray<SecretDetector> | undefined {
  const cfg = ctx.config.taskConfig?.["secret-scan"] as
    | { detectors?: ReadonlyArray<SecretDetector> }
    | undefined;
  return cfg?.detectors;
}

const scanTool = defineTool<"secret-scan">({
  name: "secret-scan:scan",
  displayName: "Secret Scan",
  formatInput(input) {
    const p = (input ?? {}) as Record<string, unknown>;
    const target = typeof p["target"] === "string" ? (p["target"] as string) : null;
    return target ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Scan a directory tree for committed secrets and credentials. " +
    "Applies a curated regex pack (AWS, GitHub, Slack, Stripe, Google, " +
    "Anthropic/OpenAI, JWT, PEM private keys) plus an entropy gate on " +
    "ambiguous patterns. Skips binary files, common build/cache " +
    "directories, and files larger than a configurable cap. Returns the " +
    "findings as Finding[] in result.data; the matched secret is " +
    "redacted in the human-readable evidence line.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Directory to scan. Defaults to the active session target / cwd.",
      },
      maxFileBytes: {
        type: "integer",
        minimum: 1024,
        default: 2 * 1024 * 1024,
        description: "Maximum per-file byte cap (default 2 MiB).",
      },
      excludeDirs: {
        type: "array",
        items: { type: "string" },
        description:
          "Additional directory basenames to skip (merged with the built-in block-list).",
      },
      binaryExts: {
        type: "array",
        items: { type: "string" },
        description: "Additional extensions (with leading dot) to treat as binary and skip.",
      },
      maxFindings: {
        type: "integer",
        minimum: 1,
        maximum: 10000,
        default: 1000,
        description: "Stop after this many findings to bound runtime.",
      },
      severity: {
        type: "array",
        items: { type: "string", enum: SEVERITY_VALUES as unknown as string[] },
        description: "Severities to include in the result (default: all).",
      },
    },
  },
  headless: true,
  rank: "great",
  notes: {
    stability: ["stable"],
    reliability: ["reliable"],
    sideEffects: [],
  },
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as SecretScanInput;
    const target = params.target ?? ctx.target ?? ctx.cwd;
    const root = path.resolve(target);

    const opts: SecretScanOptions = {};
    if (params.maxFileBytes !== undefined) opts.maxFileBytes = params.maxFileBytes;
    if (params.excludeDirs) opts.excludeDirs = params.excludeDirs;
    if (params.binaryExts) opts.binaryExts = params.binaryExts;
    if (params.maxFindings !== undefined) opts.maxFindings = params.maxFindings;
    const detectorOverride = readDetectorOverride(ctx);
    if (detectorOverride) opts.detectors = detectorOverride;

    ctx.reportActivity?.(`secret-scan: walking ${root}`);

    let result: Awaited<ReturnType<typeof scanForSecrets>>;
    try {
      result = await scanForSecrets(root, opts, ctx.signal);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `secret-scan error: ${msg}` };
    }

    const filterSet = params.severity ? new Set(params.severity) : null;
    const findings = filterSet
      ? result.findings.filter((f) => filterSet.has(f.severity as (typeof SEVERITY_VALUES)[number]))
      : result.findings;

    const bySev = new Map<string, number>();
    for (const f of findings) bySev.set(f.severity, (bySev.get(f.severity) ?? 0) + 1);
    const sevSummary =
      findings.length === 0
        ? "no secrets detected"
        : [...bySev.entries()]
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([sev, n]) => `${n} ${sev.toLowerCase()}`)
            .join(", ");

    const lines = [
      `secret-scan: ${findings.length} finding${findings.length === 1 ? "" : "s"} (${sevSummary})`,
      `  Files scanned: ${result.filesScanned}`,
      `  Files skipped: ${result.filesSkipped}`,
      `  Target:        ${root}`,
    ];
    if (findings.length > 0) {
      lines.push("", "Top findings:");
      for (const f of findings.slice(0, 10)) {
        lines.push(`  - ${f.severity} · ${f.ruleId} · ${f.filePath}:${f.startLine}`);
      }
      if (findings.length > 10) {
        lines.push(`  … and ${findings.length - 10} more`);
      }
    }

    return {
      ok: true,
      output: lines.join("\n"),
      data: {
        findings,
        filesScanned: result.filesScanned,
        filesSkipped: result.filesSkipped,
        target: root,
      },
    };
  },
});

export function createSecretScanModule(): CopilotModule {
  return defineModule({
    id: "secret-scan",
    displayName: "Secret Scan",
    category: "defense",
    version: "0.1.0",
    description:
      "Deterministic regex + entropy scan for committed secrets " +
      "(AWS, GitHub, Slack, Stripe, Google, Anthropic/OpenAI, JWT, PEM).",
    rank: "great",
    references: [
      { type: "CWE", value: "CWE-798" },
      { type: "OWASP", value: "A02:2021 — Cryptographic Failures" },
    ],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: [],
    },
    tools: [scanTool],
    events: {
      produces: ["scan:finding"],
      consumes: [],
    },
    examples: ["use secret-scan", "set TARGET ./", "run"],
    async init() {
      // Stateless — detectors are imported at module load.
    },
    async dispose() {
      // No resources to release.
    },
  });
}
