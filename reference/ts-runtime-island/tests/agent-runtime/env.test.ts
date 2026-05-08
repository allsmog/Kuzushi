import { describe, expect, it } from "vitest";
import { __test__, buildSubprocessEnv } from "../../src/agent-runtime/env.js";

describe("buildSubprocessEnv", () => {
  it("strips known credential-shaped variables", () => {
    const { env, stripped } = buildSubprocessEnv({
      PATH: "/usr/bin",
      HOME: "/home/x",
      AWS_SECRET_ACCESS_KEY: "secret",
      GITHUB_TOKEN: "ghp_xxx",
      DATABASE_URL: "postgres://...",
      OPENAI_API_KEY: "sk-...",
      MY_APP_PASSWORD: "p",
      SOME_CONFIG: "ok",
    });

    expect(env["PATH"]).toBe("/usr/bin");
    expect(env["HOME"]).toBe("/home/x");
    expect(env["SOME_CONFIG"]).toBe("ok");
    expect(env["AWS_SECRET_ACCESS_KEY"]).toBeUndefined();
    expect(env["GITHUB_TOKEN"]).toBeUndefined();
    expect(env["DATABASE_URL"]).toBeUndefined();
    expect(env["OPENAI_API_KEY"]).toBeUndefined();
    expect(env["MY_APP_PASSWORD"]).toBeUndefined();
    expect(stripped).toEqual(
      expect.arrayContaining([
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "DATABASE_URL",
        "OPENAI_API_KEY",
        "MY_APP_PASSWORD",
      ]),
    );
  });

  it("always allows ANTHROPIC_* and explicit Claude Code env vars through", () => {
    const { env, stripped } = buildSubprocessEnv({
      ANTHROPIC_API_KEY: "sk-ant-...",
      ANTHROPIC_OAUTH_TOKEN: "oauth",
      ANTHROPIC_BASE_URL: "https://example.invalid",
      CLAUDE_CODE_MAX_OUTPUT_TOKENS: "100000",
    });

    expect(env["ANTHROPIC_API_KEY"]).toBe("sk-ant-...");
    expect(env["ANTHROPIC_OAUTH_TOKEN"]).toBe("oauth");
    expect(env["ANTHROPIC_BASE_URL"]).toBe("https://example.invalid");
    expect(env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"]).toBe("100000");
    expect(stripped).toEqual([]);
  });

  it("merges extra entries on top of the parent env", () => {
    const { env } = buildSubprocessEnv(
      { PATH: "/usr/bin", ANTHROPIC_API_KEY: "old" },
      { ANTHROPIC_API_KEY: "new", CLAUDE_CODE_MAX_OUTPUT_TOKENS: "50000" },
    );

    expect(env["ANTHROPIC_API_KEY"]).toBe("new");
    expect(env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"]).toBe("50000");
    expect(env["PATH"]).toBe("/usr/bin");
  });

  it("does not return values in the stripped list (only names)", () => {
    const { stripped } = buildSubprocessEnv({
      AWS_SECRET_ACCESS_KEY: "this-must-not-appear-anywhere",
    });

    for (const name of stripped) {
      expect(name).not.toContain("this-must-not-appear-anywhere");
    }
  });

  it("classifies miscellaneous credential names correctly", () => {
    const { looksLikeCredential } = __test__;
    expect(looksLikeCredential("AWS_ACCESS_KEY_ID")).toBe(true);
    expect(looksLikeCredential("MY_APP_API_KEY")).toBe(true);
    expect(looksLikeCredential("STRIPE_SECRET_KEY")).toBe(true);
    expect(looksLikeCredential("SLACK_TOKEN")).toBe(true);
    expect(looksLikeCredential("HUGGINGFACE_TOKEN")).toBe(true);
    expect(looksLikeCredential("ANTHROPIC_API_KEY")).toBe(false);
    expect(looksLikeCredential("PATH")).toBe(false);
    expect(looksLikeCredential("HOME")).toBe(false);
    expect(looksLikeCredential("LANG")).toBe(false);
  });
});
