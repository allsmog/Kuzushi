import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import type { ScanOpts } from "../types.js";
import type { Finding } from "./types.js";
import { scoreFindingMetadata, detectParameterRiskBoost } from "./scoring.js";

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

/** Score a Semgrep finding by severity * likelihood * impact * subcategory. */
export function scoreSemgrepFinding(finding: SemgrepResult): number {
  const extra = finding.extra ?? {};
  const meta = extra.metadata ?? {};
  const messageText = extra.message ?? "";
  return scoreFindingMetadata({
    severity: extra.severity,
    likelihood: meta.likelihood,
    impact: meta.impact,
    subcategory: meta.subcategory,
    cwe: meta.cwe,
    parameterRiskBoost: detectParameterRiskBoost(messageText),
  });
}

/** Content-based fingerprint that survives line shifts. */
export function computeFingerprint(
  repoName: string,
  ref: string,
  finding: SemgrepResult,
): string {
  const extra = finding.extra ?? {};
  let matched = (extra.lines ?? "").trim();
  if (!matched || matched === "requires login") {
    matched = String(finding.start?.line ?? "");
  }
  const source = `${repoName}|${ref}|${finding.check_id}|${finding.path}|${matched}|${extra.message ?? ""}`;
  return createHash("sha256").update(source).digest("hex");
}

/** Run semgrep/opengrep and return parsed JSON output. */
export async function runSemgrep(
  repoRoot: string,
  opts: ScanOpts,
  scannerBin: string = "semgrep",
  configFlag: string | string[] = "auto",
): Promise<SemgrepOutput> {
  const binName = scannerBin.split("/").pop() ?? "scanner";
  const configs = Array.isArray(configFlag) ? configFlag : [configFlag];
  const args: string[] = [];
  for (const cfg of configs) {
    args.push("--config", cfg);
  }
  args.push("--json", "--metrics", "on");

  // Send all severities to Semgrep — let the scoring pipeline prioritize.
  // This ensures INFO-severity findings with high CWE multipliers are not
  // filtered before they can be scored.
  args.push("--severity", "ERROR", "--severity", "WARNING", "--severity", "INFO");

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
    let settled = false;

    proc.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
    proc.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write(`  [${binName}] ${chunk.toString()}`);
    });

    proc.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;

      // Semgrep/Opengrep exit code 1 means "findings were found", not a runtime failure.
      if (code !== null && code > 1) {
        reject(new Error(`${binName} failed (exit ${code})`));
        return;
      }

      try {
        const json = JSON.parse(Buffer.concat(stdoutChunks).toString());
        if (!json || typeof json !== "object" || !Array.isArray(json.results)) {
          resolve({ results: [], errors: [], paths: { scanned: [] } } as SemgrepOutput);
          return;
        }
        resolve(json as SemgrepOutput);
      } catch (err) {
        reject(new Error(`Failed to parse ${binName} output: ${err}`));
      }
    });

    proc.on("error", (err) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(new Error(`Failed to spawn ${binName}: ${err.message}`));
    });
  });
}

/** Rank, deduplicate, and select top findings. */
export function selectFindings(
  semgrepOutput: SemgrepOutput,
  repoName: string,
  ref: string,
  maxFindings?: number,
): Finding[] {
  const results = semgrepOutput.results ?? [];
  const scored: Array<[number, SemgrepResult]> = results.map((f) => [
    scoreSemgrepFinding(f),
    f,
  ]);
  scored.sort((a, b) => b[0] - a[0]);

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
      scanner: "semgrep",
      fingerprint: fp,
      ruleId: finding.check_id,
      filePath: finding.path,
      startLine: finding.start.line,
      severity: extra.severity ?? "INFO",
      message: extra.message ?? "",
      evidence: normalizeEvidence(extra.lines),
      scannerConfidence: meta.confidence ?? "LOW",
      subcategory: meta.subcategory ?? ["audit"],
      likelihood: meta.likelihood ?? "LOW",
      impact: meta.impact ?? "LOW",
      cwe: meta.cwe ?? [],
      score,
    };
  });
}

function normalizeEvidence(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed || null;
}
