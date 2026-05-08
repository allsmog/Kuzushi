import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loginAnthropicMock = vi.hoisted(() => vi.fn());
const loginOpenAICodexMock = vi.hoisted(() => vi.fn());
const refreshAnthropicTokenMock = vi.hoisted(() => vi.fn());
const refreshOpenAICodexTokenMock = vi.hoisted(() => vi.fn());

vi.mock("@mariozechner/pi-ai/oauth", () => ({
  loginAnthropic: loginAnthropicMock,
  loginOpenAICodex: loginOpenAICodexMock,
  refreshAnthropicToken: refreshAnthropicTokenMock,
  refreshOpenAICodexToken: refreshOpenAICodexTokenMock,
}));

const { loginAnthropicAndPersist, loginOpenAICodexAndPersist, oauthCredentialsPath } = await import(
  "../src/oauth-flow.js"
);

let tmpHome: string;
let oldAnthropicOauthToken: string | undefined;
let oldAnthropicAuthToken: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(os.tmpdir(), "kuzushi-oauth-flow-"));
  oldAnthropicOauthToken = process.env["ANTHROPIC_OAUTH_TOKEN"];
  oldAnthropicAuthToken = process.env["ANTHROPIC_AUTH_TOKEN"];
  vi.spyOn(os, "homedir").mockReturnValue(tmpHome);
  loginAnthropicMock.mockReset();
  loginOpenAICodexMock.mockReset();
  loginAnthropicMock.mockResolvedValue({
    refresh: "refresh-token",
    access: "access-token",
    expires: 9_999_999_999_999,
  });
  loginOpenAICodexMock.mockResolvedValue({
    refresh: "codex-refresh-token",
    access: "codex-access-token",
    expires: 9_999_999_999_999,
    accountId: "acct_123",
  });
});

afterEach(() => {
  rmSync(tmpHome, { recursive: true, force: true });
  vi.restoreAllMocks();
  if (oldAnthropicOauthToken === undefined) {
    delete process.env["ANTHROPIC_OAUTH_TOKEN"];
  } else {
    process.env["ANTHROPIC_OAUTH_TOKEN"] = oldAnthropicOauthToken;
  }
  if (oldAnthropicAuthToken === undefined) {
    delete process.env["ANTHROPIC_AUTH_TOKEN"];
  } else {
    process.env["ANTHROPIC_AUTH_TOKEN"] = oldAnthropicAuthToken;
  }
});

describe("loginAnthropicAndPersist", () => {
  it("does not install a throwing manual callback in non-TTY contexts", async () => {
    const result = await loginAnthropicAndPersist();

    expect(result.accessToken).toBe("access-token");
    expect(loginAnthropicMock).toHaveBeenCalledOnce();
    const options = loginAnthropicMock.mock.calls[0]?.[0];
    expect(options.onManualCodeInput).toBeUndefined();
    await expect(options.onPrompt({ message: "Paste code" })).resolves.toBe("");
  });

  it("passes through an explicit manual code input handler", async () => {
    const onManualCodeInput = vi.fn(async () => "code#state");

    await loginAnthropicAndPersist({ onManualCodeInput });

    const options = loginAnthropicMock.mock.calls[0]?.[0];
    expect(options.onManualCodeInput).toBe(onManualCodeInput);
  });

  it("persists credentials and primes the live process env", async () => {
    await loginAnthropicAndPersist();

    const filePath = oauthCredentialsPath(tmpHome);
    expect(existsSync(filePath)).toBe(true);
    const stored = JSON.parse(readFileSync(filePath, "utf-8"));
    expect(stored.anthropic).toMatchObject({
      refresh: "refresh-token",
      access: "access-token",
      expires: 9_999_999_999_999,
    });
    expect(process.env["ANTHROPIC_OAUTH_TOKEN"]).toBe("access-token");
    expect(process.env["ANTHROPIC_AUTH_TOKEN"]).toBe("access-token");
  });
});

describe("loginOpenAICodexAndPersist", () => {
  it("persists Codex OAuth credentials under the pi-ai provider id", async () => {
    const result = await loginOpenAICodexAndPersist();

    expect(result.accessToken).toBe("codex-access-token");
    expect(loginOpenAICodexMock).toHaveBeenCalledOnce();
    const filePath = oauthCredentialsPath(tmpHome);
    const stored = JSON.parse(readFileSync(filePath, "utf-8"));
    expect(stored["openai-codex"]).toMatchObject({
      refresh: "codex-refresh-token",
      access: "codex-access-token",
      expires: 9_999_999_999_999,
      accountId: "acct_123",
    });
  });

  it("passes through an explicit Codex manual code input handler", async () => {
    const onManualCodeInput = vi.fn(async () => "code#state");

    await loginOpenAICodexAndPersist({ onManualCodeInput });

    const options = loginOpenAICodexMock.mock.calls[0]?.[0];
    expect(options.onManualCodeInput).toBe(onManualCodeInput);
  });
});
