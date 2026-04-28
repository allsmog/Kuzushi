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

const { resolveAmbientOauthToken } = await import("../src/config.js");

const ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_OAUTH_TOKEN",
  "ANTHROPIC_OAUTH_TOKEN_FILE",
] as const;

function clearEnv(): void {
  for (const k of ENV_KEYS) delete process.env[k];
  // Disable real-host OAuth probes (e.g. /home/claude/.claude/...) so
  // tests can't be polluted by tokens that exist outside the sandbox.
  process.env["KUZUSHI_OAUTH_WELL_KNOWN_HOMES"] = "";
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
  rmSync(TMP_HOME, { recursive: true, force: true });
});

describe("resolveAmbientOauthToken", () => {
  it("returns undefined when no token is discoverable", () => {
    expect(resolveAmbientOauthToken({})).toBeUndefined();
  });

  it("uses ANTHROPIC_API_KEY when it has the OAuth shape", () => {
    process.env.ANTHROPIC_API_KEY = "redacted-fake-oat-prefix-from-env-api-key";
    expect(resolveAmbientOauthToken({})).toEqual({
      token: "redacted-fake-oat-prefix-from-env-api-key",
      source: "env:ANTHROPIC_API_KEY",
    });
  });

  it("ignores ANTHROPIC_API_KEY when it lacks the OAuth prefix", () => {
    process.env.ANTHROPIC_API_KEY = "redacted-fake-anthropic-api-key";
    expect(resolveAmbientOauthToken({})).toBeUndefined();
  });

  it("falls back to ANTHROPIC_OAUTH_TOKEN env var", () => {
    process.env.ANTHROPIC_OAUTH_TOKEN = "  redacted-fake-oat-prefix-from-oauth-env  ";
    expect(resolveAmbientOauthToken({})).toEqual({
      token: "redacted-fake-oat-prefix-from-oauth-env",
      source: "env:ANTHROPIC_OAUTH_TOKEN",
    });
  });

  it("reads ANTHROPIC_OAUTH_TOKEN_FILE", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "raw.txt");
    writeFileSync(filePath, "redacted-fake-oat-prefix-from-token-file\n");
    process.env.ANTHROPIC_OAUTH_TOKEN_FILE = filePath;

    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe("redacted-fake-oat-prefix-from-token-file");
    expect(got?.source).toContain("env:ANTHROPIC_OAUTH_TOKEN_FILE");
    expect(got?.source).toContain(filePath);
  });

  it("reads config.oauthTokenFile when env vars are absent", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "config.txt");
    writeFileSync(filePath, "redacted-fake-oat-prefix-from-config-path");

    const got = resolveAmbientOauthToken({ oauthTokenFile: filePath });
    expect(got?.token).toBe("redacted-fake-oat-prefix-from-config-path");
    expect(got?.source).toContain("config:oauthTokenFile");
    expect(got?.source).toContain(filePath);
  });

  it("falls back to ~/.claude/remote/.oauth_token when nothing earlier resolves", () => {
    mkdirSync(TMP_REMOTE_DIR, { recursive: true });
    writeFileSync(path.join(TMP_REMOTE_DIR, ".oauth_token"), "redacted-fake-oat-prefix-remote-sandbox\n");
    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe("redacted-fake-oat-prefix-remote-sandbox");
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
          accessToken: "redacted-fake-oat-prefix-from-credentials-json",
          refreshToken: "rt-foo",
          expiresAt: 9999999999,
        },
      }),
    );
    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe("redacted-fake-oat-prefix-from-credentials-json");
    expect(got?.source).toContain(".credentials.json");
  });

  it("parses ANTHROPIC_OAUTH_TOKEN_FILE pointing at a JSON credentials file", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "creds.json");
    writeFileSync(
      filePath,
      JSON.stringify({ claudeAiOauth: { accessToken: "redacted-fake-oat-prefix-from-json-file" } }),
    );
    process.env.ANTHROPIC_OAUTH_TOKEN_FILE = filePath;

    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe("redacted-fake-oat-prefix-from-json-file");
  });

  it("prefers env vars over config.oauthTokenFile (priority order)", () => {
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "config.txt");
    writeFileSync(filePath, "redacted-fake-oat-prefix-from-config-path");
    process.env.ANTHROPIC_OAUTH_TOKEN = "redacted-fake-oat-prefix-from-env";

    const got = resolveAmbientOauthToken({ oauthTokenFile: filePath });
    expect(got?.token).toBe("redacted-fake-oat-prefix-from-env");
    expect(got?.source).toBe("env:ANTHROPIC_OAUTH_TOKEN");
  });

  it("prefers config.oauthTokenFile over ~/.claude/remote/.oauth_token", () => {
    mkdirSync(TMP_REMOTE_DIR, { recursive: true });
    writeFileSync(path.join(TMP_REMOTE_DIR, ".oauth_token"), "redacted-fake-oat-prefix-remote");
    const filePath = path.join(TMP_TOKEN_FILES_DIR, "config.txt");
    writeFileSync(filePath, "redacted-fake-oat-prefix-config");

    const got = resolveAmbientOauthToken({ oauthTokenFile: filePath });
    expect(got?.token).toBe("redacted-fake-oat-prefix-config");
  });

  it("probes well-known fallback homedirs from KUZUSHI_OAUTH_WELL_KNOWN_HOMES", () => {
    const altHome = path.join(TMP_HOME, "alt-home");
    const altRemote = path.join(altHome, ".claude", "remote");
    mkdirSync(altRemote, { recursive: true });
    writeFileSync(path.join(altRemote, ".oauth_token"), "redacted-fake-oat-prefix-from-well-known");
    process.env.KUZUSHI_OAUTH_WELL_KNOWN_HOMES = altHome;

    const got = resolveAmbientOauthToken({});
    expect(got?.token).toBe("redacted-fake-oat-prefix-from-well-known");
    expect(got?.source).toContain(altHome);
  });
});
