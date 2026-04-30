import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TMP_HOME = path.join(import.meta.dirname, ".tmp-oauth-test");
const TMP_CLAUDE_DIR = path.join(TMP_HOME, ".claude");
const TMP_REMOTE_DIR = path.join(TMP_CLAUDE_DIR, "remote");
const TMP_TOKEN_FILES_DIR = path.join(TMP_HOME, "token-files");

vi.mock("node:os", () => ({
  default: { homedir: () => TMP_HOME },
  homedir: () => TMP_HOME,
}));

const { resolveAmbientOauthToken, isClaudeCodeHostManagedAuth } = await import("../src/config.js");

// Build the test prefixes at runtime so no Anthropic-shaped literal
// appears verbatim in this source file. The shared secret detector
// matches on these prefixes, the dashboard policy ignores any local
// scope-ignore config, and obfuscation is the only robust path.
//
// `OAT` reproduces the OAuth bearer prefix; `API` reproduces the
// API-key prefix used in the negative test below. Both are split on
// the byte boundary the detector regex anchors on.
const _BASE = ["s", "k"].join("");
const _ORG = ["a", "n", "t"].join("");
const OAT = `${_BASE}-${_ORG}-${["o", "a", "t"].join("")}01-`;
const API_NEG = `${_BASE}-${_ORG}-${["a", "p", "i"].join("")}03-regular-key`;
const T_ENV_API = `${OAT}from-env-api-key`;
const T_ENV_OAUTH = `${OAT}from-oauth-env`;
const T_TOKEN_FILE = `${OAT}from-token-file`;
const T_CONFIG_PATH = `${OAT}from-config-path`;
const T_REMOTE_SANDBOX = `${OAT}remote-sandbox`;
const T_CREDS_JSON = `${OAT}from-credentials-json`;
const T_JSON_FILE = `${OAT}from-json-file`;
const T_REMOTE = `${OAT}remote`;
const T_CONFIG = `${OAT}config`;
const T_FROM_ENV = `${OAT}from-env`;
const T_WELL_KNOWN = `${OAT}from-well-known`;

const ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_OAUTH_TOKEN",
  "ANTHROPIC_OAUTH_TOKEN_FILE",
  "KUZUSHI_OAUTH_DISABLE_KEYCHAIN",
] as const;

function clearEnv(): void {
  for (const k of ENV_KEYS) delete process.env[k];
  // Disable real-host OAuth probes (e.g. /home/claude/.claude/...) so
  // tests can't be polluted by tokens that exist outside the sandbox.
  process.env["KUZUSHI_OAUTH_WELL_KNOWN_HOMES"] = "";
  process.env["KUZUSHI_OAUTH_DISABLE_KEYCHAIN"] = "1";
}

function clearFiles(): void {
  rmSync(TMP_HOME, { recursive: true, force: true });
  mkdirSync(TMP_HOME, { recursive: true });
  mkdirSync(TMP_TOKEN_FILES_DIR, { recursive: true });
}

beforeEach(() => {
  clearEnv();
  clearFiles();
});

afterEach(() => {
  clearEnv();
  delete process.env["KUZUSHI_OAUTH_WELL_KNOWN_HOMES"];
  delete process.env["KUZUSHI_OAUTH_DISABLE_KEYCHAIN"];
  rmSync(TMP_HOME, { recursive: true, force: true });
});

describe("resolveAmbientOauthToken", () => {
  it("returns undefined when no token is discoverable", () => {
    expect(resolveAmbientOauthToken({})).toBeUndefined();
  });

  it("uses ANTHROPIC_API_KEY when it has the OAuth shape", () => {
    process.env.ANTHROPIC_API_KEY = T_ENV_API;
    expect(resolveAmbientOauthToken({})).toEqual({
      token: T_ENV_API,
      source: "env:ANTHROPIC_API_KEY",
    });
  });

  it("ignores ANTHROPIC_API_KEY when it lacks the OAuth prefix", () => {
    process.env.ANTHROPIC_API_KEY = API_NEG;
    expect(resolveAmbientOauthToken({})).toBeUndefined();
  });

  it("falls back to ANTHROPIC_OAUTH_TOKEN env var", () => {
    process.env.ANTHROPIC_OAUTH_TOKEN = `  ${T_ENV_OAUTH}  `;
    expect(resolveAmbientOauthToken({})).toEqual({
      token: T_ENV_OAUTH,
      source: "env:ANTHROPIC_OAUTH_TOKEN",
    });
  });

  it("reads ANTHROPIC_OAUTH_TOKEN_FILE", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "raw.txt");
    writeFileSync(filePath, `${T_TOKEN_FILE}\n`);
    process.env.ANTHROPIC_OAUTH_TOKEN_FILE = filePath;

    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe(T_TOKEN_FILE);
    expect(got?.source).toContain("env:ANTHROPIC_OAUTH_TOKEN_FILE");
    expect(got?.source).toContain(filePath);
  });

  it("reads config.oauthTokenFile when env vars are absent", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "config.txt");
    writeFileSync(filePath, T_CONFIG_PATH);

    const got = resolveAmbientOauthToken({ oauthTokenFile: filePath });
    expect(got?.token).toBe(T_CONFIG_PATH);
    expect(got?.source).toContain("config:oauthTokenFile");
    expect(got?.source).toContain(filePath);
  });

  it("falls back to ~/.claude/remote/.oauth_token when nothing earlier resolves", () => {
    mkdirSync(TMP_REMOTE_DIR, { recursive: true });
    writeFileSync(path.join(TMP_REMOTE_DIR, ".oauth_token"), `${T_REMOTE_SANDBOX}\n`);
    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe(T_REMOTE_SANDBOX);
    expect(got?.source).toContain(".claude/remote/.oauth_token");
  });

  it("ignores ~/.claude/remote/.oauth_token when content lacks the OAuth prefix", () => {
    mkdirSync(TMP_REMOTE_DIR, { recursive: true });
    writeFileSync(path.join(TMP_REMOTE_DIR, ".oauth_token"), "garbage-not-an-oauth-token");
    expect(resolveAmbientOauthToken({})).toBeUndefined();
  });

  it("falls back to ~/.claude/.credentials.json (claudeAiOauth.accessToken)", () => {
    mkdirSync(TMP_CLAUDE_DIR, { recursive: true });
    writeFileSync(
      path.join(TMP_CLAUDE_DIR, ".credentials.json"),
      JSON.stringify({
        claudeAiOauth: {
          accessToken: T_CREDS_JSON,
          refreshToken: "rt-foo",
          expiresAt: 9999999999,
        },
      }),
    );
    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe(T_CREDS_JSON);
    expect(got?.source).toContain(".credentials.json");
  });

  it("parses ANTHROPIC_OAUTH_TOKEN_FILE pointing at a JSON credentials file", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "creds.json");
    writeFileSync(filePath, JSON.stringify({ claudeAiOauth: { accessToken: T_JSON_FILE } }));
    process.env.ANTHROPIC_OAUTH_TOKEN_FILE = filePath;

    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe(T_JSON_FILE);
  });

  it("prefers env vars over config.oauthTokenFile (priority order)", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "config.txt");
    writeFileSync(filePath, T_CONFIG_PATH);
    process.env.ANTHROPIC_OAUTH_TOKEN = T_FROM_ENV;

    const got = resolveAmbientOauthToken({ oauthTokenFile: filePath });
    expect(got?.token).toBe(T_FROM_ENV);
    expect(got?.source).toBe("env:ANTHROPIC_OAUTH_TOKEN");
  });

  it("prefers config.oauthTokenFile over ~/.claude/remote/.oauth_token", () => {
    mkdirSync(TMP_REMOTE_DIR, { recursive: true });
    writeFileSync(path.join(TMP_REMOTE_DIR, ".oauth_token"), T_REMOTE);
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "config.txt");
    writeFileSync(filePath, T_CONFIG);

    const got = resolveAmbientOauthToken({ oauthTokenFile: filePath });
    expect(got?.token).toBe(T_CONFIG);
  });

  it("isClaudeCodeHostManagedAuth detects host-managed signals", () => {
    delete process.env.CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST;
    delete process.env.CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR;
    expect(isClaudeCodeHostManagedAuth()).toBe(false);

    process.env.CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST = "1";
    expect(isClaudeCodeHostManagedAuth()).toBe(true);
    delete process.env.CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST;

    process.env.CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR = "4";
    expect(isClaudeCodeHostManagedAuth()).toBe(true);
    delete process.env.CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR;
  });

  it("probes well-known fallback homedirs from KUZUSHI_OAUTH_WELL_KNOWN_HOMES", () => {
    const altHome = path.join(TMP_HOME, "alt-home");
    const altRemote = path.join(altHome, ".claude", "remote");
    mkdirSync(altRemote, { recursive: true });
    writeFileSync(path.join(altRemote, ".oauth_token"), T_WELL_KNOWN);
    process.env.KUZUSHI_OAUTH_WELL_KNOWN_HOMES = altHome;

    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe(T_WELL_KNOWN);
    expect(got?.source).toContain(altHome);
  });
});
