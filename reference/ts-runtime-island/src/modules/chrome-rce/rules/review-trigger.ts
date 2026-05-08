/**
 * Rule 6 — chrome-rce:review-trigger
 *
 * A meta-rule. It does NOT detect a bug pattern in code — instead, it
 * surfaces a focusing finding when a PR diff touches one of a curated set
 * of paths that have been the source of multiple in-the-wild Chrome RCEs.
 *
 * Why not run all the time? In a full-repo Chromium scan, every Maglev
 * file would match and produce noise. The rule is only useful at PR time,
 * when the diff is small and we can use historical bug density as a hint
 * for code review focus.
 *
 * Behaviour:
 *   - If `input.diffBase` is unset → return `[]` (rule is opt-in to diff mode).
 *   - Otherwise → run `git diff --name-only <diffBase>...HEAD`, intersect
 *     the changed-files list with the `HOT_PATHS` table, and emit one
 *     finding per match.
 *
 * Anchor CVEs: see `../data/hot-paths.ts`.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import type { Finding } from "../../../scanners/types.js";
import type { ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import { defineDagTool } from "../../define.js";
import { requireDag } from "../../types.js";
import { HOT_PATHS, type HotPathEntry } from "../data/hot-paths.js";

const TASK_ID = "chrome-rce";

export const reviewTriggerDagTool = defineDagTool<"chrome-rce", ScanOpts, Finding[]>({
  name: "chrome-rce:review-trigger",
  displayName: "Chrome RCE hot-path review trigger",
  description:
    "Advisory finding when a PR diff touches a path with historical ITW Chrome RCEs " +
    "(V8 Maglev / V8 ARM64 codegen / V8 typer / Dawn wire-server). Opt-in to diff mode: " +
    "set --diff-base or scanOpts.diffBase to enable. Anchored to CVE-2024-7965, CVE-2025-6554, " +
    "CVE-2026-3910, CVE-2026-4675/4676/5281.",
  headless: true,
  rank: "good",
  notes: {
    stability: ["experimental"],
    reliability: ["fast"],
    sideEffects: [],
  },
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Path to the repository to scan.",
      },
      diffBase: {
        type: "string",
        description:
          "Git ref to diff against (e.g. 'main', 'HEAD~5'). When unset, the rule emits no findings.",
      },
    },
    required: ["target"],
  },
  dag: {
    outputKind: "findings",
    dependsOn: [],
  },
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    const target = typeof p?.["target"] === "string" ? (p["target"] as string) : null;
    const base = typeof p?.["diffBase"] === "string" ? (p["diffBase"] as string) : null;
    if (target && base) return `${target} · diff vs ${base}`;
    return target ?? null;
  },
  async run(input: ScanOpts, ctx): Promise<Finding[]> {
    const dag = requireDag(ctx);
    const repoRoot = dag.scanPath ?? dag.workRoot ?? dag.repoRoot;
    const diffBase = input.diffBase;

    if (!diffBase) {
      // Opt-in to diff mode: no diffBase → no findings. The rule produces
      // too much noise on a full repo scan otherwise.
      ctx.logger?.info(
        "chrome-rce:review-trigger skipped — no diffBase set. Pass --diff-base to enable.",
      );
      return [];
    }

    let changedFiles: string[];
    try {
      changedFiles = listChangedFiles(repoRoot, diffBase);
    } catch (err) {
      ctx.logger?.warn("chrome-rce:review-trigger failed to list changed files", {
        error: toErrorMessage(err),
        diffBase,
      });
      return [];
    }

    const findings: Finding[] = [];
    const seenFiles = new Set<string>();
    for (const file of changedFiles) {
      if (seenFiles.has(file)) continue;
      const entry = matchHotPath(file);
      if (!entry) continue;
      seenFiles.add(file);
      findings.push(buildHotPathFinding(file, entry));
    }
    return findings;
  },
});

function listChangedFiles(repoRoot: string, diffBase: string): string[] {
  // Verify the ref exists before diffing — avoids noisy errors on
  // monorepo subdirs that don't carry the expected branch in scope.
  execFileSync("git", ["rev-parse", "--verify", diffBase], {
    cwd: repoRoot,
    encoding: "utf-8",
    timeout: 5_000,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const filesRaw = execFileSync("git", ["diff", "--name-only", `${diffBase}...HEAD`], {
    cwd: repoRoot,
    encoding: "utf-8",
    timeout: 30_000,
  });
  return filesRaw.trim().split("\n").filter(Boolean);
}

function matchHotPath(file: string): HotPathEntry | undefined {
  // Order: prefer specific (pathEndsWith) over general (pathSubstring) so
  // a maglev-phi-representation-selector.cc hit gets the high-severity
  // entry, not the broader v8/src/maglev/ one.
  const exact = HOT_PATHS.find((e) => e.pathEndsWith && file.endsWith(e.pathEndsWith));
  if (exact) return exact;
  return HOT_PATHS.find((e) => e.pathSubstring && file.includes(e.pathSubstring));
}

function buildHotPathFinding(file: string, entry: HotPathEntry): Finding {
  const fingerprint = createHash("sha256")
    .update(`chrome-rce|${entry.ruleId}|${file}`)
    .digest("hex");
  return {
    taskId: TASK_ID,
    fingerprint,
    ruleId: entry.ruleId,
    filePath: file,
    startLine: 1,
    severity: entry.severity.toUpperCase(),
    message: entry.message,
    evidence: null,
    scannerConfidence: "MEDIUM",
    subcategory: ["chrome-rce", "path-watch", ...entry.anchorCves],
    likelihood: "LOW",
    impact: "HIGH",
    cwe: [],
    score: severityToScore(entry.severity),
    proofState: "symbolic_only",
    engineProvenance: [
      {
        kind: "agentic",
        detail: `chrome-rce hot-path advisory · anchored to ${entry.anchorCves.join(", ")}`,
      },
    ],
  };
}

function severityToScore(sev: HotPathEntry["severity"]): number {
  switch (sev) {
    case "high":
      return 0.6;
    case "medium":
      return 0.4;
  }
}
