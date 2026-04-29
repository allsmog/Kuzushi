/**
 * Resolve LLM API credentials from the layered Kuzushi config.
 *
 * Two sources are supported, in priority order:
 *
 *   1. `agentRuntimeConfig.<backend>.apiKey` — the literal key (plaintext in
 *      the config file; we warn about this in src/cli.ts#maybeWarnPlaintextApiKeyStorage).
 *
 *   2. `agentRuntimeConfig.<backend>.apiKeyFile` — a path to a file whose
 *      contents hold the key. Designed for secret-manager mount points: Docker
 *      secrets (`/run/secrets/anthropic`), Kubernetes secret volumes
 *      (`/var/run/secrets/.../token`), cloud-provider secret mounts,
 *      or a user-controlled file with `0600` permissions. This is the
 *      recommended way to use kuzushi in CI/CD without writing plaintext
 *      credentials into `~/.kuzushi/config.json`.
 *
 * If the file exists with world- or group-readable permissions we log a
 * warning once per process, because on shared hosts that's a practical
 * credential leak. We do not refuse to read — the file may live on a
 * tmpfs or other filesystem where POSIX perms are meaningless, and
 * blocking scans on a perms check would be worse than the warning.
 */

import { readFileSync, statSync } from "node:fs";
import { getLogger } from "./logger.js";
import type { AgentRuntimeCredentials } from "./types.js";

const log = getLogger("credentials");

/** One-time warning guard so a lax-perms file doesn't spam every run. */
const warnedPaths = new Set<string>();

/**
 * Read an API key from a file. Returns `undefined` on any failure
 * (missing file, unreadable, empty contents) rather than throwing, so
 * callers can fall through to the next resolution step.
 */
export function readApiKeyFromFile(filePath: string): string | undefined {
  let content: string;
  try {
    content = readFileSync(filePath, "utf8");
  } catch (err) {
    log.warn(
      `Could not read apiKeyFile "${filePath}": ${err instanceof Error ? err.message : String(err)}`,
    );
    return undefined;
  }

  const trimmed = content.trim();
  if (!trimmed) {
    log.warn(`apiKeyFile "${filePath}" exists but is empty`);
    return undefined;
  }

  // Best-effort perms check — warn (don't refuse) on world/group-readable files.
  try {
    const stat = statSync(filePath);
    const mode = stat.mode & 0o777;
    const worldOrGroupReadable = (mode & 0o044) !== 0;
    if (worldOrGroupReadable && !warnedPaths.has(filePath)) {
      warnedPaths.add(filePath);
      log.warn(
        `apiKeyFile "${filePath}" has permissive mode 0${mode.toString(8)}. ` +
          `Credential files should be owner-only (chmod 0600).`,
      );
    }
  } catch {
    // Perms check is informational only — never fail the scan over it.
  }

  return trimmed;
}

/**
 * Resolve the effective API key from an agent runtime config. Returns
 * `undefined` if neither `apiKey` nor `apiKeyFile` produce a usable key.
 *
 * This function mutates *a copy* of the config: the returned object has
 * `apiKey` populated from whichever source won, so downstream code that
 * only reads `.apiKey` keeps working without changes.
 */
export function resolveAgentRuntimeConfig(
  config: AgentRuntimeCredentials | undefined,
): AgentRuntimeCredentials | undefined {
  if (!config) return undefined;

  // Literal key takes precedence — this is the shape the Anthropic SDK
  // already understands and the shape most Kuzushi code paths already rely on.
  if (config.apiKey) return config;

  if (config.apiKeyFile) {
    const key = readApiKeyFromFile(config.apiKeyFile);
    if (key) {
      return { ...config, apiKey: key };
    }
  }

  return config;
}

/** Test/debug helper: clear the "already warned about lax perms" memo. */
export function __resetApiKeyWarnings(): void {
  warnedPaths.clear();
}
