import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import process from "node:process";

import { safeJsonStringify } from "./safe-json.js";

export interface RunReproducibilityMetadata {
  kuzushiVersion: string;
  nodeVersion: string;
  platform: string;
  arch: string;
  gitSha?: string;
  gitBranch?: string;
  gitDirty?: boolean;
  configHash: string;
  model?: string;
  scanArgs?: ReadonlyArray<string>;
  startedAt: string;
}

let cachedKuzushiVersion: string | undefined;

export function getKuzushiVersion(): string {
  if (cachedKuzushiVersion) return cachedKuzushiVersion;
  try {
    const req = createRequire(import.meta.url);
    const pkg = req("../../package.json") as { version?: string };
    cachedKuzushiVersion = pkg.version ?? "unknown";
  } catch {
    cachedKuzushiVersion = "unknown";
  }
  return cachedKuzushiVersion;
}

interface GitInfo {
  sha?: string;
  branch?: string;
  dirty?: boolean;
}

function gitExec(args: string[], cwd: string): string | null {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf-8",
      timeout: 3_000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

export function readGitInfo(cwd: string): GitInfo {
  const sha = gitExec(["rev-parse", "HEAD"], cwd) ?? undefined;
  const branch = gitExec(["rev-parse", "--abbrev-ref", "HEAD"], cwd) ?? undefined;
  const status = gitExec(["status", "--porcelain"], cwd);
  const dirty = status == null ? undefined : status.length > 0;
  return { sha: sha || undefined, branch: branch || undefined, dirty };
}

/**
 * Stable JSON canonicalisation: sort keys recursively so the resulting
 * string is byte-identical for semantically equal configs.
 */
function canonicalise(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalise);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = canonicalise(obj[key]);
    }
    return out;
  }
  return value;
}

export function hashConfig(config: unknown): string {
  const json = safeJsonStringify(canonicalise(config));
  return createHash("sha256").update(json).digest("hex");
}

export interface BuildRunMetadataOptions {
  repoRoot: string;
  config: unknown;
  model?: string;
  scanArgs?: ReadonlyArray<string>;
  startedAt?: string;
}

export function buildRunMetadata(opts: BuildRunMetadataOptions): RunReproducibilityMetadata {
  const gitInfo = readGitInfo(opts.repoRoot);
  return {
    kuzushiVersion: getKuzushiVersion(),
    nodeVersion: process.versions.node,
    platform: process.platform,
    arch: process.arch,
    gitSha: gitInfo.sha,
    gitBranch: gitInfo.branch,
    gitDirty: gitInfo.dirty,
    configHash: hashConfig(opts.config),
    model: opts.model,
    scanArgs: opts.scanArgs,
    startedAt: opts.startedAt ?? new Date().toISOString(),
  };
}
