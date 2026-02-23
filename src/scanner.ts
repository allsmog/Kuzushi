import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import type { RawFinding, ScanOpts } from "./types.js";

// Scoring tables — ported directly from kuzushi-practice
const SEVERITY_SCORE: Record<string, number> = { ERROR: 3, WARNING: 2, INFO: 1 };
const LIKELIHOOD_SCORE: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const IMPACT_SCORE: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const SUBCATEGORY_SCORE: Record<string, number> = { vuln: 2, audit: 1 };

/** Score a Semgrep finding by severity * likelihood * impact * subcategory. */
export function scoreFinding(finding: SemgrepResult): number {
  const extra = finding.extra ?? {};
  const meta = extra.metadata ?? {};
  const severity = SEVERITY_SCORE[extra.severity ?? "INFO"] ?? 1;
  const likelihood = LIKELIHOOD_SCORE[meta.likelihood ?? "LOW"] ?? 1;
  const impact = IMPACT_SCORE[meta.impact ?? "LOW"] ?? 1;
  const subcategories: string[] = meta.subcategory ?? ["audit"];
  const subcategory = Math.max(...subcategories.map((s) => SUBCATEGORY_SCORE[s] ?? 0), 1);
  return severity * likelihood * impact * subcategory;
}

/** Content-based fingerprint that survives line shifts. */
export function computeFingerprint(
  repoName: string,
  ref: string,
  finding: SemgrepResult,
): string {
  const extra = finding.extra ?? {};
  let matched = (extra.lines ?? "").trim();
  // Fall back to start_line when Semgrep OSS doesn't provide matched source
  if (!matched || matched === "requires login") {
    matched = String(finding.start?.line ?? "");
  }
  const s = `${repoName}|${ref}|${finding.check_id}|${finding.path}|${matched}|${extra.message ?? ""}`;
  return createHash("sha256").update(s).digest("hex");
}

/** Raw Semgrep JSON result shape (partial). */
export interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra?: {
    severity?: string;
    message?: string;
    lines?: string;
    metadata?: {
      confidence?: string;
      subcategory?: string[];
      likelihood?: string;
      impact?: string;
      cwe?: string[];
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
}

export interface SemgrepOutput {
  results: SemgrepResult[];
  errors?: unknown[];
}

/** Run the scanner binary and return parsed JSON output. */
export async function runSemgrep(
  repoRoot: string,
  opts: ScanOpts,
  scannerBin: string = "semgrep",
): Promise<SemgrepOutput> {
  const binName = scannerBin.split("/").pop() ?? "scanner";
  const args = [
    "--config", "auto",
    "--json",
    "--metrics", "on",
  ];

  for (const sev of opts.severity) {
    args.push("--severity", sev);
  }

  for (const pattern of opts.excludePatterns) {
    args.push("--exclude", pattern);
  }

  args.push(".");

  return new Promise((resolve, reject) => {
    const proc = spawn(scannerBin, args, {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const stdoutChunks: Buffer[] = [];

    proc.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
    proc.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write(`  [${binName}] ${chunk.toString()}`);
    });

    proc.on("close", (code) => {
      // semgrep: 0 = clean, 1 = findings exist, >1 = error
      if (code !== null && code > 1) {
        reject(new Error(`${binName} failed (exit ${code})`));
        return;
      }
      try {
        const json = JSON.parse(Buffer.concat(stdoutChunks).toString());
        resolve(json as SemgrepOutput);
      } catch (e) {
        reject(new Error(`Failed to parse ${binName} output: ${e}`));
      }
    });

    proc.on("error", (err) => {
      reject(new Error(`Failed to spawn ${binName}: ${err.message}`));
    });
  });
}

/** Rank, deduplicate, and select top findings for triage. */
export function selectFindings(
  semgrepOutput: SemgrepOutput,
  repoName: string,
  ref: string,
  maxFindings?: number,
): RawFinding[] {
  const results = semgrepOutput.results ?? [];
  const scored: Array<[number, SemgrepResult]> = results.map((f) => [
    scoreFinding(f),
    f,
  ]);
  scored.sort((a, b) => b[0] - a[0]);

  // Dedup by fingerprint — keep highest-scored instance
  const seen = new Map<string, [number, SemgrepResult]>();
  for (const [score, finding] of scored) {
    const fp = computeFingerprint(repoName, ref, finding);
    const existing = seen.get(fp);
    if (!existing || score > existing[0]) {
      seen.set(fp, [score, finding]);
    }
  }

  const deduped = [...seen.entries()]
    .sort((a, b) => b[1][0] - a[1][0])
    .slice(0, maxFindings);

  return deduped.map(([fp, [score, finding]]) => {
    const extra = finding.extra ?? {};
    const meta = extra.metadata ?? {};
    return {
      fingerprint: fp,
      ruleId: finding.check_id,
      filePath: finding.path,
      startLine: finding.start.line,
      severity: extra.severity ?? "UNKNOWN",
      message: extra.message ?? "",
      semgrepConfidence: meta.confidence ?? "UNKNOWN",
      subcategory: meta.subcategory ?? ["unknown"],
      likelihood: meta.likelihood ?? "UNKNOWN",
      impact: meta.impact ?? "UNKNOWN",
      cwe: meta.cwe ?? [],
      score,
    };
  });
}
