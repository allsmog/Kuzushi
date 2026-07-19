import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { modelForRequest, oauthAccessToken } from "../../scripts/langgraph-bridge/model.mjs";

const originalOauthToken = process.env.ANTHROPIC_OAUTH_TOKEN;
const originalCredentials = process.env.KUZUSHI_OAUTH_CREDENTIALS;
const originalOpenAiKey = process.env.OPENAI_API_KEY;
const roots: string[] = [];

afterEach(() => {
  restoreEnv("ANTHROPIC_OAUTH_TOKEN", originalOauthToken);
  restoreEnv("KUZUSHI_OAUTH_CREDENTIALS", originalCredentials);
  restoreEnv("OPENAI_API_KEY", originalOpenAiKey);
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("LangGraph bridge OAuth authority", () => {
  it("reads only the credentials path resolved into the request", () => {
    const credentialsPath = credentialBag("file-token");
    process.env.KUZUSHI_OAUTH_CREDENTIALS = credentialBag("ambient-token");

    expect(oauthAccessToken({}, "anthropic")).toBeUndefined();
    expect(oauthAccessToken({ oauthCredentialsPath: credentialsPath }, "anthropic")).toBe(
      "file-token",
    );
  });

  it("uses OAuth environment tokens only when the request authorizes them", () => {
    process.env.ANTHROPIC_OAUTH_TOKEN = "environment-token";

    expect(oauthAccessToken({ oauthAllowEnvToken: false }, "anthropic")).toBeUndefined();
    expect(oauthAccessToken({ oauthAllowEnvToken: true }, "anthropic")).toBe("environment-token");
  });

  it("keeps an explicit API key ahead of an authorized OAuth bag", () => {
    const request = {
      model: "anthropic:claude-test",
      apiKey: "api-key",
      oauthCredentialsPath: credentialBag("oauth-token"),
    };

    expect(modelForRequest(request).authMode).not.toBe("oauth-file");
    expect(modelForRequest({ ...request, apiKey: undefined }).authMode).toBe("oauth-file");
  });

  it("keeps the OpenAI OAuth selector on OAuth when an API key is also present", () => {
    process.env.OPENAI_API_KEY = "ambient-api-key";
    const request = {
      model: "openai-codex:gpt-test",
      apiKey: "forwarded-api-key",
      oauthCredentialsPath: credentialBag("oauth-token", "openai-codex"),
    };

    expect(modelForRequest(request).authMode).toBe("oauth-file");
  });

  it("refuses the OpenAI OAuth selector when only an API key is available", () => {
    process.env.OPENAI_API_KEY = "ambient-api-key";

    expect(() =>
      modelForRequest({ model: "openai-codex:gpt-test", apiKey: "forwarded-api-key" }),
    ).toThrow(/authentication failed/i);
  });

  it("keeps the OpenAI API-key selector off the OAuth transport", () => {
    const request = {
      model: "openai:gpt-test",
      apiKey: "api-key",
      oauthCredentialsPath: credentialBag("oauth-token", "openai-codex"),
    };

    expect(modelForRequest(request).authMode).not.toBe("oauth-file");
  });
});

function credentialBag(access: string, provider = "anthropic") {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-oauth-test-"));
  roots.push(root);
  const file = join(root, "oauth.json");
  writeFileSync(file, JSON.stringify({ [provider]: { access, expires: Date.now() + 60_000 } }));
  return file;
}

function restoreEnv(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
