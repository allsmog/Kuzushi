import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import type { ScanOpts } from "../types.js";
import { emitDiagnostic } from "../ui/output.js";
import { detectParameterRiskBoost, scoreFindingMetadata } from "./scoring.js";
import type { Finding } from "./types.js";

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
export function computeFingerprint(repoName: string, ref: string, finding: SemgrepResult): string {
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
  options: { signal?: AbortSignal } = {},
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

  // When scanPaths are provided (monorepo multi-path modules), pass all paths
  // as targets. Otherwise fall back to the single repoRoot.
  if (opts.scanPaths && opts.scanPaths.length > 0) {
    for (const p of opts.scanPaths) {
      args.push(p);
    }
  } else {
    args.push(repoRoot);
  }

  return new Promise((resolve, reject) => {
    const signal = options.signal;
    if (signal?.aborted) {
      reject(createAbortError(binName));
      return;
    }
    // Spawn detached so semgrep + semgrep-core get their own process
    // group. On parent exit/abort we then kill the whole group, which
    // reaps the long-running semgrep-core RPC backend that otherwise
    // outlives kuzushi (field-test issue #12 — orphan semgrep-core
    // observed running 16+ minutes after parent SIGTERM).
    const proc = spawn(scannerBin, args, {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });

    const stdoutChunks: Buffer[] = [];
    let settled = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;

    /** Kill the whole pgrp (semgrep + semgrep-core children). */
    const killGroup = (sig: NodeJS.Signals = "SIGTERM"): void => {
      try {
        if (typeof proc.pid === "number") process.kill(-proc.pid, sig);
      } catch {
        try {
          proc.kill(sig);
        } catch {
          /* already gone */
        }
      }
    };
    const onParentExit = (): void => {
      if (!settled) killGroup("SIGTERM");
    };
    process.once("exit", onParentExit);

    const cleanupAbort = () => {
      signal?.removeEventListener("abort", abort);
      process.removeListener("exit", onParentExit);
      if (killTimer) {
        clearTimeout(killTimer);
        killTimer = undefined;
      }
    };
    const abort = () => {
      if (settled) return;
      killGroup("SIGTERM");
      killTimer = setTimeout(() => {
        if (!settled) killGroup("SIGKILL");
      }, 1000);
    };
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();

    proc.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
    proc.stderr.on("data", (chunk: Buffer) => {
      if (signal?.aborted) return;
      const text = chunk.toString().trimEnd();
      if (text.length > 0) {
        emitDiagnostic(binName, text);
      }
    });

    proc.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanupAbort();

      if (signal?.aborted) {
        reject(createAbortError(binName));
        return;
      }

      // Semgrep/Opengrep exit code 1 means "findings were found", not a runtime failure.
      if (code !== null && code > 1) {
        // Exit 7 from semgrep is the registry/config-load failure path
        // (HTTP 403 / network unreachable / invalid config bundle).
        // Surface a concrete remediation hint — operators in sandboxed
        // environments otherwise have to read the source to learn that
        // the registry blocks tripped them up. Field-test issue #4.
        const hint =
          code === 7
            ? `\n  Hint: exit 7 typically means semgrep couldn't fetch its rule registry (HTTP 403 / unreachable). Override with a local ruleset:\n    git clone --depth=1 https://github.com/semgrep/semgrep-rules ~/.kuzushi-cache/semgrep-rules\n  Then in <repo>/.kuzushi/config.json set\n    {"taskConfig":{"semgrep":{"configFlag":["~/.kuzushi-cache/semgrep-rules/python", "..."]}}}\n  and re-run with --trust-repo-config.`
            : "";
        reject(new Error(`${binName} failed (exit ${code})${hint}`));
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
      cleanupAbort();
      if (signal?.aborted) {
        reject(createAbortError(binName));
        return;
      }
      reject(new Error(`Failed to spawn ${binName}: ${err.message}`));
    });
  });
}

function createAbortError(binName: string): Error {
  const err = new Error(`${binName} scan aborted`);
  err.name = "AbortError";
  return err;
}

/** Rank, deduplicate, and select top findings. */
export function selectFindings(
  semgrepOutput: SemgrepOutput,
  repoName: string,
  ref: string,
  maxFindings?: number,
): Finding[] {
  const results = semgrepOutput.results ?? [];
  const scored: Array<[number, SemgrepResult]> = results.map((f) => [scoreSemgrepFinding(f), f]);
  scored.sort((a, b) => b[0] - a[0]);

  const seen = new Map<string, [number, SemgrepResult]>();
  for (const [score, finding] of scored) {
    const fp = computeFingerprint(repoName, ref, finding);
    const existing = seen.get(fp);
    if (!existing || score > existing[0]) {
      seen.set(fp, [score, finding]);
    }
  }

  const deduped = [...seen.entries()].sort((a, b) => b[1][0] - a[1][0]).slice(0, maxFindings);

  return deduped.map(([fp, [score, finding]]) => {
    const extra = finding.extra ?? {};
    const meta = extra.metadata ?? {};
    return {
      taskId: "semgrep",
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
      proofState: "symbolic_only",
      engineProvenance: [{ kind: "semgrep", detail: "Semgrep static analysis rule match" }],
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
