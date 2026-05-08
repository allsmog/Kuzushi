/**
 * Run-metadata helpers — produce reproducibility metadata for `summary.json`
 * (per-run dir under `.kuzushi/runs/<runId>/summary.json`) and consume it
 * in replay/diff/prune flows.
 *
 * The schema is additive — old runs without `summary.json` continue to work
 * via the SQLite `pipeline_runs` row + (optional) `run.json`. New fields
 * here are never renamed or removed; bumping `schemaVersion` is reserved
 * for breaking changes and never silently flips behaviour.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import type { KuzushiConfig, ScanOpts } from "../types.js";

export const RUN_SUMMARY_SCHEMA_VERSION = 1;
export const RUN_SUMMARY_FILENAME = "summary.json";

export interface RunSummaryGitInfo {
  sha: string;
  branch?: string;
  dirty: boolean;
}

export interface RunSummaryPromptOverride {
  module: string;
  verb: string;
  sha256: string;
}

export interface RunSummaryHouseRule {
  module: string;
  sha256: string;
}

export interface RunSummaryReproducibility {
  kuzushiVersion: string;
  model: string;
  configHash: string;
  scanArgs: string[];
  envFingerprint: Record<string, string>;
  git?: RunSummaryGitInfo;
  promptOverrides: RunSummaryPromptOverride[];
  houseRules: RunSummaryHouseRule[];
  threatModelSha256?: string;
  loadedModules?: string[];
}

export interface RunSummaryFindingCounts {
  total: number;
  bySeverity: Record<string, number>;
  byVerdict: Record<string, number>;
}

export interface RunSummary {
  schemaVersion: number;
  runId: string;
  status: string;
  startedAt: string;
  completedAt?: string;
  durationMs?: number;
  totalCostUsd?: number;
  reproducibility: RunSummaryReproducibility;
  findings?: RunSummaryFindingCounts;
  repo: {
    root: string;
    name?: string;
  };
}

// ---------------------------------------------------------------------------
// Reproducibility primitives
// ---------------------------------------------------------------------------

/**
 * Stable JSON canonicalisation: sorts object keys recursively. Used for
 * the `configHash` so two configs that only differ in key-order produce
 * the same fingerprint.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return `{${parts.join(",")}}`;
}

export function sha256(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

export function hashConfig(config: KuzushiConfig): string {
  // Strip ephemeral fields (no fields strip today; reserved for future
  // `runtimeContext` / `_credentials` style additions).
  return `sha256:${sha256(canonicalJson(config as unknown))}`;
}

/**
 * Best-effort kuzushi package version. Reads from the host's package.json
 * via createRequire; falls back to "unknown" if not resolvable.
 */
export function readKuzushiVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../../package.json") as { version?: string };
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * Synchronous git probe — short SHA, branch, and dirty flag for the given
 * directory. Returns undefined when not a git repo or when git is missing.
 */
export function readGitInfo(repoRoot: string): RunSummaryGitInfo | undefined {
  if (!existsSync(repoRoot)) return undefined;
  const run = (args: string[]): string | undefined => {
    try {
      return execFileSync("git", args, {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "ignore"],
        encoding: "utf-8",
        timeout: 1500,
      }).trim();
    } catch {
      return undefined;
    }
  };
  const sha = run(["rev-parse", "HEAD"]);
  if (!sha) return undefined;
  const branch = run(["rev-parse", "--abbrev-ref", "HEAD"]);
  const dirtyOut = run(["status", "--porcelain"]);
  return {
    sha,
    branch: branch && branch !== "HEAD" ? branch : undefined,
    dirty: typeof dirtyOut === "string" && dirtyOut.length > 0,
  };
}

/**
 * Capture the relevant slice of env: any KUZUSHI_* var, plus presence
 * (not value) of common API-key style env. Never logs the actual key.
 */
export function readEnvFingerprint(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== "string" || v.length === 0) continue;
    if (k.startsWith("KUZUSHI_")) {
      out[k] = v.length > 64 ? `${v.slice(0, 60)}...` : v;
    } else if (/_API_KEY$|_TOKEN$/.test(k)) {
      out[k] = "<set>";
    }
  }
  return out;
}

/**
 * Walk `.kuzushi/prompts/<moduleId>/<verb>.md` and hash every file. Order
 * is alphabetical by `(module, verb)` for stability.
 */
export function readPromptOverrideFingerprints(dataDir: string): RunSummaryPromptOverride[] {
  const root = path.join(dataDir, "prompts");
  if (!existsSync(root)) return [];
  const out: RunSummaryPromptOverride[] = [];
  let modules: string[];
  try {
    modules = readdirSync(root).sort();
  } catch {
    return [];
  }
  for (const moduleDir of modules) {
    const modPath = path.join(root, moduleDir);
    let s: ReturnType<typeof statSync> | undefined;
    try {
      s = statSync(modPath);
    } catch {
      continue;
    }
    if (!s) continue;
    if (!s.isDirectory()) continue;
    let files: string[];
    try {
      files = readdirSync(modPath).sort();
    } catch {
      continue;
    }
    for (const file of files) {
      if (!file.endsWith(".md")) continue;
      const verb = file.slice(0, -3);
      try {
        const body = readFileSync(path.join(modPath, file));
        out.push({ module: moduleDir, verb, sha256: sha256(body) });
      } catch {
        // ignore unreadable
      }
    }
  }
  return out;
}

export function readHouseRulesFingerprints(dataDir: string): RunSummaryHouseRule[] {
  const root = path.join(dataDir, "house-rules");
  if (!existsSync(root)) return [];
  const out: RunSummaryHouseRule[] = [];
  let files: string[];
  try {
    files = readdirSync(root).sort();
  } catch {
    return [];
  }
  for (const file of files) {
    if (!file.endsWith(".md")) continue;
    const moduleId = file.slice(0, -3);
    try {
      const body = readFileSync(path.join(root, file));
      out.push({ module: moduleId, sha256: sha256(body) });
    } catch {
      // ignore unreadable
    }
  }
  return out;
}

export function readThreatModelDigest(dataDir: string): string | undefined {
  const file = path.join(dataDir, "threat-model.json");
  if (!existsSync(file)) return undefined;
  try {
    return sha256(readFileSync(file));
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Build the full reproducibility blob
// ---------------------------------------------------------------------------

export interface BuildReproOpts {
  config: KuzushiConfig;
  scanOpts: ScanOpts;
  repoRoot: string;
  /** Defaults to `<repoRoot>/.kuzushi`. */
  dataDir?: string;
  argv?: readonly string[];
  env?: NodeJS.ProcessEnv;
}

export function buildReproducibility(opts: BuildReproOpts): RunSummaryReproducibility {
  const dataDir = opts.dataDir ?? path.join(opts.repoRoot, ".kuzushi");
  const scanArgs = (opts.argv ?? process.argv.slice(2)).map(String);
  const env = opts.env ?? process.env;
  return {
    kuzushiVersion: readKuzushiVersion(),
    model: opts.config.model,
    configHash: hashConfig(opts.config),
    scanArgs,
    envFingerprint: readEnvFingerprint(env),
    git: readGitInfo(opts.repoRoot),
    promptOverrides: readPromptOverrideFingerprints(dataDir),
    houseRules: readHouseRulesFingerprints(dataDir),
    threatModelSha256: readThreatModelDigest(dataDir),
  };
}

// ---------------------------------------------------------------------------
// Finding counts (denormalised from findingsJson / live findings)
// ---------------------------------------------------------------------------

export function countFindingsBy(
  findings: ReadonlyArray<Record<string, unknown>>,
): RunSummaryFindingCounts {
  const bySeverity: Record<string, number> = {};
  const byVerdict: Record<string, number> = {};
  for (const f of findings) {
    const sev =
      (typeof f["displaySeverity"] === "string" && (f["displaySeverity"] as string)) ||
      (typeof f["severity"] === "string" && (f["severity"] as string).toLowerCase()) ||
      "unknown";
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    const verdict = typeof f["verdict"] === "string" ? (f["verdict"] as string) : "unknown";
    byVerdict[verdict] = (byVerdict[verdict] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byVerdict };
}

// ---------------------------------------------------------------------------
// Read summary.json (used by replay/diff)
// ---------------------------------------------------------------------------

export function readRunSummary(runDir: string): RunSummary | undefined {
  const file = path.join(runDir, RUN_SUMMARY_FILENAME);
  if (!existsSync(file)) return undefined;
  try {
    const raw = readFileSync(file, "utf-8");
    const parsed = JSON.parse(raw) as RunSummary;
    if (!parsed || typeof parsed !== "object") return undefined;
    if (typeof parsed.schemaVersion !== "number") return undefined;
    return parsed;
  } catch {
    return undefined;
  }
}
