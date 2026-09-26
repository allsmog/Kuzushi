// Interactive OAuth login flows for the LangGraph bridge.
//
// The Rust shell (and `auth login <provider>`) spawns the bridge with
// `--oauth-login <provider> [method]` and inherited stdio, then blocks on the
// child. This module runs the browser/headless flow, writes the resulting
// `{ access, refresh, expires }` credential into the shared
// `oauth-credentials.json` bag, and exits 0 on success so the caller can detect
// readiness. It never reads the JSON request envelope — `--oauth-login` is
// dispatched before the bridge touches stdin.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import { createInterface } from "node:readline";
import { invalidProviderResponseError, providerHttpError } from "./errors.mjs";
import {
  oauthCredentialBag,
  oauthCredentialsPath,
  writeOauthCredentialBag,
} from "./model.mjs";

// Public OAuth client registrations for the Claude Code and Codex CLIs. These
// are not secrets (PKCE protects the flow); isolate them here so an operator can
// correct an endpoint without touching flow logic.
export const OAUTH_PROVIDERS = {
  anthropic: {
    storageKey: "anthropic",
    label: "anthropic",
    clientId: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
    authorizeUrl: "https://claude.ai/oauth/authorize",
    tokenUrl: "https://platform.claude.com/v1/oauth/token",
    scope: "user:profile user:inference user:sessions:claude_code user:mcp_servers",
    tokenRequestFormat: "json",
    // Claude's paste-code exchange rejects a request without the `state` that
    // was issued with the authorize URL (HTTP 400).
    tokenRequestIncludesState: true,
    redirectUri: "https://console.anthropic.com/oauth/code/callback",
    extraAuthorizeParams: { code: "true" },
    flow: "paste-code",
  },
  "openai-codex": {
    storageKey: "openai-codex",
    label: "openai",
    clientId: "app_EMoamEEZ73f0CkXaXp7hrann",
    authorizeUrl: "https://auth.openai.com/oauth/authorize",
    tokenUrl: "https://auth.openai.com/oauth/token",
    scope: "openid profile email offline_access",
    tokenRequestFormat: "form",
    redirectUri: "http://localhost:1455/auth/callback",
    callbackPort: 1455,
    callbackPath: "/auth/callback",
    extraAuthorizeParams: {},
    flow: "localhost",
  },
};

const PROVIDER_ALIASES = {
  openai: "openai-codex",
  "openai-codex": "openai-codex",
  codex: "openai-codex",
  anthropic: "anthropic",
  claude: "anthropic",
};

export function parseOauthLoginArgs(argv) {
  const flagIndex = argv.indexOf("--oauth-login");
  if (flagIndex === -1) return undefined;
  const providerArg = argv[flagIndex + 1];
  if (!providerArg) return undefined;
  return { providerArg, method: argv[flagIndex + 2] };
}

export function resolveProviderConfig(providerArg) {
  const key = PROVIDER_ALIASES[String(providerArg ?? "").trim().toLowerCase()];
  return key ? OAUTH_PROVIDERS[key] : undefined;
}

function base64url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function pkcePair() {
  const verifier = base64url(randomBytes(64));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function buildAuthorizeUrl(cfg, { challenge, state, redirectUri }) {
  const url = new URL(cfg.authorizeUrl);
  url.searchParams.set("client_id", cfg.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", cfg.scope);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  for (const [key, value] of Object.entries(cfg.extraAuthorizeParams ?? {})) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

// Accepts what a user can realistically paste: the bare code, Claude's
// `code#state` form, or the full redirect URL with `?code=...&state=...`.
export function parsePastedCode(raw) {
  const trimmed = String(raw ?? "").trim();
  if (!trimmed) return undefined;
  if (trimmed.includes("://")) return codeFromRedirectUrl(trimmed);
  const [code, state] = trimmed.split("#");
  return code ? { code, state: state || undefined } : undefined;
}

function codeFromRedirectUrl(raw) {
  try {
    const url = new URL(raw);
    const code = url.searchParams.get("code");
    return code ? { code, state: url.searchParams.get("state") || undefined } : undefined;
  } catch {
    return undefined;
  }
}

export function credentialFromTokenResponse(parsed, priorRefresh, now = Date.now()) {
  const access = nonEmpty(parsed?.access_token);
  if (!access) throw new Error("token response did not include an access_token");
  return {
    access,
    refresh: nonEmpty(parsed?.refresh_token) ?? priorRefresh,
    expires: now + Math.max(1, Number(parsed?.expires_in ?? 3600)) * 1000,
  };
}

export function mergeCredentialBag(bag, storageKey, credential) {
  return { ...bag, [storageKey]: credential };
}

function nonEmpty(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export function tokenExchangeBody(cfg, { code, state, verifier, redirectUri }) {
  const fields = {
    grant_type: "authorization_code",
    code,
    ...(cfg.tokenRequestIncludesState && state ? { state } : {}),
    redirect_uri: redirectUri,
    client_id: cfg.clientId,
    code_verifier: verifier,
  };
  if (cfg.tokenRequestFormat === "form") {
    return { headers: formHeaders(), body: new URLSearchParams(fields).toString() };
  }
  return { headers: jsonHeaders(), body: JSON.stringify(fields) };
}

function formHeaders() {
  return { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
}

function jsonHeaders() {
  return { "content-type": "application/json", accept: "application/json" };
}

export async function exchangeAuthorizationCode(cfg, params) {
  const { headers, body } = tokenExchangeBody(cfg, params);
  const response = await fetch(cfg.tokenUrl, { method: "POST", headers, body });
  if (!response.ok) throw oauthTokenHttpError(response.status, await response.text().catch(() => ""));
  return parseProviderTokenJson(await response.text());
}

// The RFC 6749 `error` code (invalid_grant, invalid_request, …) is a fixed
// vocabulary, never a secret; name it so a rejected login is diagnosable.
// Nothing else from the provider body is echoed.
export function oauthTokenHttpError(status, bodyText) {
  const error = providerHttpError(status);
  const code = oauthErrorCode(bodyText);
  if (code) error.message = error.message.replace(/\)\.$/, `: ${code}).`);
  return error;
}

function oauthErrorCode(bodyText) {
  try {
    const code = JSON.parse(String(bodyText).slice(0, 16_384))?.error;
    const value = typeof code === "string" ? code : code?.type;
    return typeof value === "string" && /^[a-z_]{1,64}$/.test(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function parseProviderTokenJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw invalidProviderResponseError();
  }
}

function saveCredential(cfg, credential) {
  const bag = oauthCredentialBag();
  const prior = bag[cfg.storageKey];
  const merged = mergeCredentialBag(bag, cfg.storageKey, {
    ...credential,
    refresh: credential.refresh ?? nonEmpty(prior?.refresh),
  });
  writeOauthCredentialBag(merged);
}

function openBrowser(url) {
  const opener = browserOpenerForPlatform(process.platform);
  if (!opener) return;
  try {
    const child = spawn(opener.command, [...opener.args, url], { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    // The URL is always printed too; a failed auto-open is non-fatal.
  }
}

function browserOpenerForPlatform(platform) {
  if (platform === "darwin") return { command: "open", args: [] };
  if (platform === "win32") return { command: "cmd", args: ["/c", "start", ""] };
  return { command: "xdg-open", args: [] };
}

function promptLine(question) {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function note(message) {
  process.stderr.write(`${message}\n`);
}

function announceAuthorizeUrl(cfg, url) {
  note(`\nAuthorize ${cfg.label} access by opening this URL in a browser:`);
  note(`  ${url}\n`);
}

async function runPasteCodeFlow(cfg) {
  const { verifier, challenge } = pkcePair();
  const state = base64url(randomBytes(32));
  const url = buildAuthorizeUrl(cfg, { challenge, state, redirectUri: cfg.redirectUri });
  announceAuthorizeUrl(cfg, url);
  openBrowser(url);
  const pasted = await promptLine("Paste the authorization code shown after you approve access: ");
  const parsed = parsePastedCode(pasted);
  if (!parsed) throw new Error("no authorization code was provided");
  if (parsed.state && parsed.state !== state) {
    throw new Error("authorization state does not match this login; restart the login");
  }
  const token = await exchangeAuthorizationCode(cfg, {
    code: parsed.code,
    state,
    verifier,
    redirectUri: cfg.redirectUri,
  });
  saveCredential(cfg, credentialFromTokenResponse(token));
}

async function runLocalhostFlow(cfg, { interactive = true } = {}) {
  const { verifier, challenge } = pkcePair();
  const state = base64url(randomBytes(32));
  const url = buildAuthorizeUrl(cfg, { challenge, state, redirectUri: cfg.redirectUri });
  if (!interactive) return runPasteRedirectFlow(cfg, { verifier, state, url });
  const callback = startCallbackServer(cfg, state);
  try {
    announceAuthorizeUrl(cfg, url);
    note("Waiting for the browser redirect to complete…");
    openBrowser(url);
    const code = await callback.code;
    const token = await exchangeAuthorizationCode(cfg, { code, verifier, redirectUri: cfg.redirectUri });
    saveCredential(cfg, credentialFromTokenResponse(token));
  } finally {
    callback.close();
  }
}

async function runPasteRedirectFlow(cfg, { verifier, state, url }) {
  announceAuthorizeUrl(cfg, url);
  note(
    "After approving, your browser is redirected to a localhost URL that may not load —" +
      " copy that full URL from the address bar and paste it here.",
  );
  const pasted = await promptLine("Paste the redirect URL (or the code): ");
  const parsed = parsePastedCode(pasted);
  if (!parsed) throw new Error("no authorization code was provided");
  if (parsed.state && parsed.state !== state) throw new Error("state mismatch in pasted redirect");
  const token = await exchangeAuthorizationCode(cfg, {
    code: parsed.code,
    verifier,
    redirectUri: cfg.redirectUri,
  });
  saveCredential(cfg, credentialFromTokenResponse(token));
}

function startCallbackServer(cfg, expectedState) {
  let settle;
  let fail;
  const code = new Promise((resolve, reject) => {
    settle = resolve;
    fail = reject;
  });
  const server = http.createServer((req, res) => handleCallbackRequest(cfg, expectedState, req, res, settle, fail));
  server.on("error", fail);
  server.listen(cfg.callbackPort, "127.0.0.1");
  return { code, close: () => server.close() };
}

function handleCallbackRequest(cfg, expectedState, req, res, settle, fail) {
  const requestUrl = new URL(req.url ?? "/", `http://localhost:${cfg.callbackPort}`);
  if (requestUrl.pathname !== cfg.callbackPath) {
    res.writeHead(404).end("not found");
    return;
  }
  const result = callbackResult(requestUrl, expectedState);
  res.writeHead(200, { "content-type": "text/html" }).end(callbackHtml(result));
  if (result.error) fail(new Error(result.error));
  else settle(result.code);
}

function callbackResult(requestUrl, expectedState) {
  const error = requestUrl.searchParams.get("error");
  if (error) return { error: `authorization denied: ${error}` };
  const code = requestUrl.searchParams.get("code");
  if (!code) return { error: "authorization callback was missing a code" };
  const state = requestUrl.searchParams.get("state");
  if (expectedState && state !== expectedState) return { error: "state mismatch in authorization callback" };
  return { code };
}

function callbackHtml(result) {
  const message = result.error
    ? `Login failed: ${result.error}`
    : "Login complete — you can close this tab and return to your terminal.";
  return `<!doctype html><meta charset="utf-8"><title>Kuzushi auth</title><body><p>${message}</p></body>`;
}

async function runFlow(cfg, method) {
  if (cfg.flow === "paste-code") return runPasteCodeFlow(cfg);
  const interactive = !isHeadlessMethod(method);
  return runLocalhostFlow(cfg, { interactive });
}

function isHeadlessMethod(method) {
  const normalized = String(method ?? "").trim().toLowerCase();
  return normalized === "headless" || normalized === "device";
}

export async function runOauthLogin({ providerArg, method }) {
  const cfg = resolveProviderConfig(providerArg);
  if (!cfg) {
    note(`unsupported oauth provider ${JSON.stringify(providerArg)} (expected openai or anthropic)`);
    return 1;
  }
  try {
    await runFlow(cfg, method);
    note(`\n${cfg.label} OAuth login complete; credentials stored at ${oauthCredentialsPath()}.`);
    return 0;
  } catch (error) {
    note(`\n${cfg.label} OAuth login failed: ${error?.message ?? String(error)}`);
    return 1;
  }
}
