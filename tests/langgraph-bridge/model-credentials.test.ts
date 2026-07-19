import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import {
  modelForRequest,
  oauthAccessToken,
} from "../../scripts/langgraph-bridge/model.mjs";

const originalOauthToken = process.env.ANTHROPIC_OAUTH_TOKEN;
const originalCredentials = process.env.KUZUSHI_OAUTH_CREDENTIALS;
const roots: string[] = [];

afterEach(() => {
  restoreEnv("ANTHROPIC_OAUTH_TOKEN", originalOauthToken);
  restoreEnv("KUZUSHI_OAUTH_CREDENTIALS", originalCredentials);
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
    expect(oauthAccessToken({ oauthAllowEnvToken: true }, "anthropic")).toBe(
      "environment-token",
    );
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
});

function credentialBag(access: string) {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-oauth-test-"));
  roots.push(root);
  const file = join(root, "oauth.json");
  writeFileSync(file, JSON.stringify({ anthropic: { access, expires: Date.now() + 60_000 } }));
  return file;
}

function restoreEnv(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
