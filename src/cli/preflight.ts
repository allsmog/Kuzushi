/**
 * Preflight — runtime environment checks beyond the static config schema.
 *
 * The config validator in src/config/validation.ts covers structural issues
 * (unknown backends, mutually-exclusive flags, invalid paths). This module
 * handles runtime preflight: API-key env vars, scanner binaries on PATH,
 * writable data dirs. Surfaced by `kuzushi config validate` and `kuzushi
 * doctor` so users see real blockers before they wait 10s into a scan.
 */

import { accessSync, constants, existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { parsePiAiModelSpec } from "../agent-runtime/model-spec.js";
import type { ConfigValidationIssue } from "../config/validation.js";
import { providerEnvVar, resolveActiveCredentials, resolveAmbientOauthToken } from "../config.js";
import type { KuzushiConfig } from "../types.js";

/** Return the first directory on PATH containing an executable named `bin`, or null. */
export function whichSync(bin: string): string | null {
  const pathVar = process.env.PATH ?? "";
  const pathExt = (process.env.PATHEXT ?? "").split(delimiter).filter(Boolean);
  const candidates = process.platform === "win32" && pathExt.length > 0 ? ["", ...pathExt] : [""];

  for (const dir of pathVar.split(delimiter)) {
    if (!dir) continue;
    for (const ext of candidates) {
      const full = join(dir, bin + ext);
      if (!existsSync(full)) continue;
      try {
        accessSync(full, constants.X_OK);
        return full;
      } catch {
        // exists but not executable — keep looking
      }
    }
  }
  return null;
}

export interface PreflightReport {
  issues: ConfigValidationIssue[];
  checks: PreflightCheck[];
}

export interface PreflightCheck {
  name: string;
  status: "ok" | "missing" | "skipped";
  detail?: string;
}

/**
 * Run preflight against the effective config. Returns both a list of issues
 * (for merging with the schema validator) and a per-check result table for
 * human-readable output (`kuzushi config validate`, `kuzushi doctor`).
 *
 * Only produces `error`-severity issues for conditions that will actually
 * break a scan (missing API key when using a hosted runtime, missing scanner
 * binary for a task that is enabled). Scanner binaries for disabled tasks
 * are surfaced as `warning`.
 */
export function runPreflight(config: KuzushiConfig, repoRoot: string): PreflightReport {
  const issues: ConfigValidationIssue[] = [];
  const checks: PreflightCheck[] = [];

  // ── Agent runtime credentials ──
  const credCheck = checkAgentRuntimeCredentials(config);
  checks.push(credCheck.check);
  if (credCheck.issue) issues.push(credCheck.issue);

  // ── Scanner binaries ──
  const enabledTasks = new Set((config.tasks ?? []).map((t) => t.toLowerCase()));
  for (const { task, bin, hint } of SCANNER_BINARIES) {
    const found = whichSync(bin);
    const enabled = enabledTasks.has(task);
    const status: PreflightCheck["status"] = found ? "ok" : enabled ? "missing" : "skipped";
    checks.push({
      name: `binary:${bin}`,
      status,
      detail: found
        ? found
        : enabled
          ? `${bin} not on PATH (required for ${task}). ${hint}`
          : `${bin} not on PATH (${task} not enabled in this config)`,
    });
    if (!found && enabled) {
      issues.push({
        severity: "error",
        path: `tasks.${task}`,
        message: `Scanner binary "${bin}" is required for task "${task}" but was not found on PATH.`,
        hint,
      });
    }
  }

  // ── Data directory writable ──
  const dataDir = join(repoRoot, ".kuzushi");
  const dataDirCheck: PreflightCheck = (() => {
    try {
      if (existsSync(dataDir)) {
        accessSync(dataDir, constants.W_OK);
        return { name: "data-dir", status: "ok", detail: dataDir };
      }
      // Parent must be writable if .kuzushi does not yet exist
      accessSync(repoRoot, constants.W_OK);
      return { name: "data-dir", status: "ok", detail: `${dataDir} (will be created)` };
    } catch {
      return {
        name: "data-dir",
        status: "missing",
        detail: `cannot write to ${dataDir} or its parent`,
      };
    }
  })();
  checks.push(dataDirCheck);
  if (dataDirCheck.status === "missing") {
    issues.push({
      severity: "error",
      path: "dataDir",
      message: `Kuzushi data directory is not writable: ${dataDir}`,
      hint: "Ensure the user running Kuzushi has write access to the repository root.",
    });
  }

  return { issues, checks };
}

const SCANNER_BINARIES: Array<{ task: string; bin: string; hint: string }> = [
  {
    task: "semgrep",
    bin: "semgrep",
    hint: "Install with `pip install semgrep` or see https://semgrep.dev/docs/getting-started/.",
  },
  {
    task: "codeql",
    bin: "codeql",
    hint: "Install via GitHub CLI (`gh extension install github/gh-codeql`) or the CodeQL releases page.",
  },
];

function checkAgentRuntimeCredentials(config: KuzushiConfig): {
  check: PreflightCheck;
  issue: ConfigValidationIssue | null;
} {
  const backend = config.agentRuntimeBackend ?? "pi-ai";
  const savedCredentials = resolveActiveCredentials(config);
  if (savedCredentials.apiKey?.trim()) {
    return {
      check: {
        name: "credentials",
        status: "ok",
        detail: `saved ${backend} provider credentials are configured`,
      },
      issue: null,
    };
  }

  let providerId = "anthropic";
  if (backend === "pi-ai") {
    try {
      providerId = parsePiAiModelSpec(config.model ?? "").provider;
    } catch {
      providerId = "";
    }
  } else if (backend === "claude") {
    providerId = "anthropic";
  } else {
    return {
      check: {
        name: "credentials",
        status: "skipped",
        detail: `backend "${backend}" manages its own credentials`,
      },
      issue: null,
    };
  }

  const envVar = providerId ? providerEnvVar(providerId) : undefined;
  if (!envVar) {
    return {
      check: {
        name: "credentials",
        status: "skipped",
        detail: `provider "${providerId || "unknown"}" does not require a known API-key env var`,
      },
      issue: null,
    };
  }

  const envKey = process.env[envVar];
  if (envKey && envKey.trim().length > 0) {
    return {
      check: {
        name: "credentials",
        status: "ok",
        detail: `${envVar} set`,
      },
      issue: null,
    };
  }

  // Inherited-auth mode: a discoverable OAuth token (env var, configured
  // file, or `~/.claude/...`) is treated as a valid credential.
  if (config.auth === "inherited" && providerId === "anthropic") {
    const ambient = resolveAmbientOauthToken(config);
    if (ambient) {
      return {
        check: {
          name: "credentials",
          status: "ok",
          detail: `inherited OAuth (${ambient.source})`,
        },
        issue: null,
      };
    }
  }

  return {
    check: {
      name: "credentials",
      status: "missing",
      detail: `${envVar} is not set and no saved provider credential was found.`,
    },
    issue: {
      severity: "error",
      path: "credentials",
      message: `${envVar} is not set.`,
      hint: `Run \`kuzushi auth\`, export ${envVar}, or pass --api-key to the scan/shell/run command.`,
    },
  };
}

export function formatPreflightCheck(check: PreflightCheck): string {
  const icon =
    check.status === "ok" ? "[ok]     " : check.status === "missing" ? "[MISSING]" : "[skipped]";
  const detail = check.detail ? ` — ${check.detail}` : "";
  return `${icon} ${check.name}${detail}`;
}
