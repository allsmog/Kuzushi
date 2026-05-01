/**
 * Persistence + auto-refresh for OAuth credentials.
 *
 * Stored separately from `agentRuntimeConfig` because:
 *   - Refresh tokens have a different blast radius (long-lived; never want
 *     them anywhere near a project-shared `config.json`).
 *   - Pi-ai's `OAuthCredentials` shape changes per provider; keeping it
 *     verbatim here avoids leaking pi-ai internals into our schema.
 *
 * File: `~/.kuzushi/oauth-credentials.json`, mode 0600. Always read from
 * the user's home (never the project) so refresh tokens don't follow
 * a repo around.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { refreshAnthropicToken } from "@mariozechner/pi-ai/oauth";
import { getLogger } from "./logger.js";
import { isRecord } from "./utils.js";

const log = getLogger("oauth-store");

/**
 * Pi-ai `OAuthCredentials` shape, restated here so the type isn't pulled
 * into Kuzushi consumers that don't depend on pi-ai. The unknown-key
 * passthrough mirrors pi-ai's `[key: string]: unknown` extension slot.
 */
export interface AnthropicOauthCredentials {
  /** Long-lived refresh token. Never log this. */
  refresh: string;
  /** Short-lived access token used as Authorization: Bearer. */
  access: string;
  /** Expiry as unix-ms. Pi-ai subtracts a 5-minute safety margin at write time. */
  expires: number;
  [key: string]: unknown;
}

export interface OAuthCredentialBag {
  anthropic?: AnthropicOauthCredentials;
}

const FILENAME = "oauth-credentials.json";

export function oauthCredentialsPath(home: string = os.homedir()): string {
  return path.join(home, ".kuzushi", FILENAME);
}

export function readOauthCredentials(home: string = os.homedir()): OAuthCredentialBag | undefined {
  const filePath = oauthCredentialsPath(home);
  if (!existsSync(filePath)) return undefined;
  try {
    const raw = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) return undefined;
    const out: OAuthCredentialBag = {};
    if (isAnthropicCreds(parsed["anthropic"])) {
      out.anthropic = parsed["anthropic"] as AnthropicOauthCredentials;
    }
    return out;
  } catch (err) {
    log.warn(`Could not read ${filePath}: ${String(err)}`);
    return undefined;
  }
}

function isAnthropicCreds(value: unknown): value is AnthropicOauthCredentials {
  if (!isRecord(value)) return false;
  return (
    typeof value["refresh"] === "string" &&
    typeof value["access"] === "string" &&
    typeof value["expires"] === "number"
  );
}

export function writeOauthCredentials(
  bag: OAuthCredentialBag,
  home: string = os.homedir(),
): string {
  const filePath = oauthCredentialsPath(home);
  const dir = path.dirname(filePath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(bag, null, 2)}\n`, {
    encoding: "utf-8",
    mode: 0o600,
  });
  // Best-effort re-chmod in case the file pre-existed with looser perms.
  try {
    chmodSync(filePath, 0o600);
  } catch {
    /* tmpfs etc. — ignore */
  }
  warnIfWorldReadable(filePath);
  return filePath;
}

const warnedPaths = new Set<string>();
function warnIfWorldReadable(filePath: string): void {
  try {
    const mode = statSync(filePath).mode & 0o777;
    if ((mode & 0o044) !== 0 && !warnedPaths.has(filePath)) {
      warnedPaths.add(filePath);
      log.warn(
        `${filePath} is mode 0${mode.toString(8)}; OAuth refresh tokens should be owner-only (chmod 0600).`,
      );
    }
  } catch {
    /* ignore */
  }
}

/**
 * Resolve a fresh Anthropic access token, refreshing transparently when
 * the stored access token is expired. Returns `undefined` when no OAuth
 * credentials are stored.
 *
 * This is the single seam pi-ai consults at query time so an 8-hour
 * shell session doesn't die on token expiry.
 */
export async function getFreshAnthropicAccessToken(): Promise<string | undefined> {
  const bag = readOauthCredentials();
  const creds = bag?.anthropic;
  if (!creds) return undefined;

  // Pi-ai's `loginAnthropic` and `refreshAnthropicToken` already bake in a
  // 5-minute safety margin, so a strict `now < expires` check is enough.
  if (Date.now() < creds.expires) return creds.access;

  log.info("Anthropic OAuth access token expired — refreshing");
  try {
    const next = await refreshAnthropicToken(creds.refresh);
    writeOauthCredentials({ ...(bag ?? {}), anthropic: next });
    return typeof next.access === "string" ? next.access : undefined;
  } catch (err) {
    log.warn(
      `Anthropic OAuth refresh failed: ${String(err)}. Re-run \`kuzushi auth\` to log in again.`,
    );
    return undefined;
  }
}

/** Test/debug helper: clear the per-process world-readable warning memo. */
export function __resetOauthStoreWarnings(): void {
  warnedPaths.clear();
}
