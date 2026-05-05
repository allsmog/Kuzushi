/**
 * Kuzushi-side wrapper around pi-ai's OAuth login flows.
 *
 * Handles the bits pi-ai pushes onto the host application:
 *   - opening the auth URL in the operator's browser
 *   - prompting for a manual paste-back if the callback server isn't
 *     reachable (e.g. SSH, devcontainer, sandboxed runner)
 *   - persisting the resulting credentials to `~/.kuzushi/oauth-credentials.json`
 *
 * Returns the freshly-issued access token so callers can prime the live shell
 * without a restart.
 */

import { spawn } from "node:child_process";
import { loginAnthropic, loginOpenAICodex } from "@mariozechner/pi-ai/oauth";
import { getLogger } from "./logger.js";
import {
  type AnthropicOauthCredentials,
  type OpenAICodexOauthCredentials,
  oauthCredentialsPath,
  type ProviderOauthCredentials,
  readOauthCredentials,
  writeOauthCredentials,
} from "./oauth-store.js";

const log = getLogger("oauth-flow");

export interface OAuthLoginCallbacks {
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

export type AnthropicLoginCallbacks = OAuthLoginCallbacks;
export type OpenAICodexLoginCallbacks = OAuthLoginCallbacks;

export interface AnthropicLoginResult {
  /** The fresh access token (Bearer-ready). Same as `credentials.access`. */
  accessToken: string;
  /** Full credential object as persisted. Refresh tokens included. */
  credentials: AnthropicOauthCredentials;
  /** Path of the credentials file the result was written to. */
  persistedTo: string;
}

export interface OpenAICodexLoginResult {
  /** The fresh access token (Bearer-ready). Same as `credentials.access`. */
  accessToken: string;
  /** Full credential object as persisted. Refresh tokens included. */
  credentials: OpenAICodexOauthCredentials;
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
  const { persistable } = await runOAuthLogin({
    callbacks,
    login: loginAnthropic,
    providerLabel: "Anthropic",
  });

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
 * Run the OpenAI Codex OAuth login flow and persist the result. Use a model
 * like `openai-codex:gpt-5.4-mini` to consume the stored token.
 */
export async function loginOpenAICodexAndPersist(
  callbacks: OpenAICodexLoginCallbacks = {},
): Promise<OpenAICodexLoginResult> {
  const { persistable } = await runOAuthLogin({
    callbacks,
    login: loginOpenAICodex,
    providerLabel: "OpenAI Codex",
  });

  const existing = readOauthCredentials() ?? {};
  const persistedTo = writeOauthCredentials({ ...existing, "openai-codex": persistable });
  log.info(`OpenAI Codex OAuth credentials saved to ${persistedTo}`);

  return { accessToken: persistable.access, credentials: persistable, persistedTo };
}

async function runOAuthLogin<TCreds extends Record<string, unknown>>(opts: {
  callbacks: OAuthLoginCallbacks;
  login: (options: {
    onAuth: (info: { url: string; instructions?: string }) => void;
    onPrompt: (prompt: { message: string; placeholder?: string }) => Promise<string>;
    onProgress?: (message: string) => void;
    onManualCodeInput?: () => Promise<string>;
  }) => Promise<TCreds>;
  providerLabel: string;
}): Promise<{ creds: TCreds; persistable: ProviderOauthCredentials }> {
  const { callbacks, login, providerLabel } = opts;
  const onAuth =
    callbacks.onAuth ??
    ((info) => {
      const line = `Open this URL to authorize: ${info.url}`;
      process.stdout.write(`${line}\n`);
      tryOpenBrowser(info.url);
    });

  const onProgress = callbacks.onProgress ?? ((msg) => log.info(`[oauth] ${msg}`));

  const defaultManualPrompt =
    !callbacks.onManualCodeInput && process.stdin.isTTY ? createManualCodePrompt() : undefined;
  const onManualCodeInput = callbacks.onManualCodeInput ?? defaultManualPrompt?.promptManualCode;

  const loginOptions: Parameters<typeof login>[0] = {
    onAuth,
    onPrompt: defaultManualPrompt?.promptManualCode ?? (async () => ""),
    onProgress,
  };
  if (onManualCodeInput) loginOptions.onManualCodeInput = onManualCodeInput;

  const creds = await (async () => {
    try {
      return await login(loginOptions);
    } finally {
      defaultManualPrompt?.abort();
    }
  })();

  const persistable: ProviderOauthCredentials = {
    ...creds,
    refresh: String(creds["refresh"] ?? ""),
    access: String(creds["access"] ?? ""),
    expires: Number(creds["expires"] ?? 0),
  };

  if (!persistable.refresh || !persistable.access) {
    throw new Error(`${providerLabel} OAuth flow returned no usable credentials`);
  }

  return { creds, persistable };
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

function createManualCodePrompt(): {
  promptManualCode: () => Promise<string>;
  abort: () => void;
} {
  const controller = new AbortController();
  return {
    promptManualCode: () => promptManualCode(controller.signal),
    abort: () => controller.abort(),
  };
}

async function promptManualCode(signal: AbortSignal): Promise<string> {
  process.stdout.write(
    [
      "",
      "If the browser cannot reach the local callback, paste the final redirect URL here.",
      "You can also paste the code#state fragment.",
      "> ",
    ].join("\n"),
  );

  const rawMode =
    typeof process.stdin.setRawMode === "function" && process.stdin.isTTY
      ? process.stdin.isRaw
      : undefined;
  if (typeof process.stdin.setRawMode === "function" && process.stdin.isTTY) {
    process.stdin.setRawMode(false);
  }

  try {
    const readline = await import("node:readline/promises");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: process.stdin.isTTY,
    });
    try {
      return (await rl.question("", { signal })).trim();
    } finally {
      rl.close();
    }
  } finally {
    if (rawMode !== undefined && typeof process.stdin.setRawMode === "function") {
      process.stdin.setRawMode(rawMode);
    }
  }
}

/** Re-export so callers don't need the store path constant directly. */
export { oauthCredentialsPath };
