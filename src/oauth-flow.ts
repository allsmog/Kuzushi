/**
 * Kuzushi-side wrapper around pi-ai's OAuth login flows.
 *
 * Handles the bits pi-ai pushes onto the host application:
 *   - opening the auth URL in the operator's browser
 *   - prompting for a manual paste-back if the callback server isn't
 *     reachable (e.g. SSH, devcontainer, sandboxed runner)
 *   - persisting the resulting credentials to `~/.kuzushi/oauth-credentials.json`
 *
 * Returns the freshly-issued access token so callers can also export it
 * to `process.env.ANTHROPIC_OAUTH_TOKEN` for the running shell to pick
 * up without a restart.
 */

import { spawn } from "node:child_process";
import { loginAnthropic } from "@mariozechner/pi-ai/oauth";
import { getLogger } from "./logger.js";
import {
  type AnthropicOauthCredentials,
  oauthCredentialsPath,
  readOauthCredentials,
  writeOauthCredentials,
} from "./oauth-store.js";

const log = getLogger("oauth-flow");

export interface AnthropicLoginCallbacks {
  /**
   * Display the auth URL to the operator. Default opens the system
   * browser and writes the URL to stdout. Override to inject the URL
   * into a TUI.
   */
  onAuth?: (info: { url: string; instructions?: string }) => void;
  /** Inline progress messages from pi-ai (e.g. "exchanging code for token"). */
  onProgress?: (message: string) => void;
  /**
   * Paste-back prompt. Pi-ai calls this when the callback server can't
   * bind (sandboxed, port in use). The operator pastes the
   * `code#state` fragment from the redirect URL.
   */
  onManualCodeInput?: () => Promise<string>;
}

export interface AnthropicLoginResult {
  /** The fresh access token (Bearer-ready). Same as `credentials.access`. */
  accessToken: string;
  /** Full credential object as persisted. Refresh tokens included. */
  credentials: AnthropicOauthCredentials;
  /** Path of the credentials file the result was written to. */
  persistedTo: string;
}

/**
 * Run the Anthropic OAuth login flow and persist the result. Resolves to
 * the access token + on-disk path.
 *
 * @throws if pi-ai's flow fails (network, user cancel, invalid PKCE, etc.).
 */
export async function loginAnthropicAndPersist(
  callbacks: AnthropicLoginCallbacks = {},
): Promise<AnthropicLoginResult> {
  const onAuth =
    callbacks.onAuth ??
    ((info) => {
      const line = `Open this URL to authorize: ${info.url}`;
      process.stdout.write(`${line}\n`);
      tryOpenBrowser(info.url);
    });

  const onProgress = callbacks.onProgress ?? ((msg) => log.info(`[oauth] ${msg}`));

  const onManualCodeInput =
    callbacks.onManualCodeInput ??
    (async () => {
      throw new Error(
        "OAuth callback server unreachable and no manual paste-back handler was supplied. " +
          "Re-run from a terminal that can bind 127.0.0.1:53692.",
      );
    });

  const creds = await loginAnthropic({
    onAuth,
    onPrompt: async () => "",
    onProgress,
    onManualCodeInput,
  });

  // Pi-ai's OAuthCredentials shape is `{ refresh, access, expires, ... }`.
  // Coerce to our store's named type so consumers don't pull pi-ai's
  // type alias.
  const persistable: AnthropicOauthCredentials = {
    ...creds,
    refresh: String(creds["refresh"] ?? ""),
    access: String(creds["access"] ?? ""),
    expires: Number(creds["expires"] ?? 0),
  };

  if (!persistable.refresh || !persistable.access) {
    throw new Error("Anthropic OAuth flow returned no usable credentials");
  }

  const existing = readOauthCredentials() ?? {};
  const persistedTo = writeOauthCredentials({ ...existing, anthropic: persistable });
  log.info(`Anthropic OAuth credentials saved to ${persistedTo}`);

  // Make the token immediately available to the live process so the
  // running shell doesn't need a restart to pick it up.
  process.env["ANTHROPIC_OAUTH_TOKEN"] = persistable.access;
  process.env["ANTHROPIC_AUTH_TOKEN"] = persistable.access;

  return { accessToken: persistable.access, credentials: persistable, persistedTo };
}

/**
 * Best-effort browser opener. Spawns the platform's default URL handler
 * detached from the parent process; failures are non-fatal because the
 * URL is also printed to stdout.
 */
function tryOpenBrowser(url: string): void {
  if (process.env["KUZUSHI_DISABLE_BROWSER_OPEN"] === "1") return;
  const platform = process.platform;
  const cmd = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.unref();
    child.on("error", () => {
      /* ignore — URL is on stdout, the operator can copy it manually */
    });
  } catch {
    /* ignore */
  }
}

/** Re-export so callers don't need the store path constant directly. */
export { oauthCredentialsPath };
