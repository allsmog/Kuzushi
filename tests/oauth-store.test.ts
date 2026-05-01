/**
 * Unit tests for the OAuth credential store.
 *
 * Pi-ai's `refreshAnthropicToken` is mocked so the suite never touches
 * the network. The on-disk persistence + auto-refresh logic gets the
 * real exercise.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const refreshMock = vi.hoisted(() => vi.fn());
vi.mock("@mariozechner/pi-ai/oauth", () => ({
  refreshAnthropicToken: refreshMock,
}));

const {
  oauthCredentialsPath,
  readOauthCredentials,
  writeOauthCredentials,
  getFreshAnthropicAccessToken,
} = await import("../src/oauth-store.js");

let tmpHome: string;

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(os.tmpdir(), "kuzushi-oauth-store-"));
  refreshMock.mockReset();
  vi.spyOn(os, "homedir").mockReturnValue(tmpHome);
});

afterEach(() => {
  rmSync(tmpHome, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe("oauthCredentialsPath", () => {
  it("anchors to ~/.kuzushi/oauth-credentials.json", () => {
    expect(oauthCredentialsPath(tmpHome)).toBe(
      path.join(tmpHome, ".kuzushi", "oauth-credentials.json"),
    );
  });
});

describe("readOauthCredentials", () => {
  it("returns undefined when the file is missing", () => {
    expect(readOauthCredentials(tmpHome)).toBeUndefined();
  });

  it("parses a well-formed bag", () => {
    writeOauthCredentials(
      {
        anthropic: { refresh: "rt-1", access: "at-1", expires: 9_999_999_999_999 },
      },
      tmpHome,
    );
    const bag = readOauthCredentials(tmpHome);
    expect(bag?.anthropic?.refresh).toBe("rt-1");
    expect(bag?.anthropic?.access).toBe("at-1");
    expect(bag?.anthropic?.expires).toBe(9_999_999_999_999);
  });

  it("rejects an entry that's missing required fields", () => {
    writeOauthCredentials(
      // biome-ignore lint/suspicious/noExplicitAny: deliberately malformed input
      { anthropic: { refresh: "rt-only" } as any },
      tmpHome,
    );
    expect(readOauthCredentials(tmpHome)?.anthropic).toBeUndefined();
  });

  it("returns undefined when the file isn't valid JSON", () => {
    const filePath = oauthCredentialsPath(tmpHome);
    const dir = path.dirname(filePath);
    require("node:fs").mkdirSync(dir, { recursive: true });
    require("node:fs").writeFileSync(filePath, "{not json", "utf-8");
    expect(readOauthCredentials(tmpHome)).toBeUndefined();
  });
});

describe("writeOauthCredentials", () => {
  it("creates ~/.kuzushi when missing and writes 0600 mode", () => {
    const filePath = writeOauthCredentials(
      {
        anthropic: { refresh: "rt", access: "at", expires: 1 },
      },
      tmpHome,
    );
    expect(existsSync(filePath)).toBe(true);
    const mode = statSync(filePath).mode & 0o777;
    expect(mode).toBe(0o600);
    expect(JSON.parse(readFileSync(filePath, "utf-8"))).toEqual({
      anthropic: { refresh: "rt", access: "at", expires: 1 },
    });
  });
});

describe("getFreshAnthropicAccessToken", () => {
  it("returns undefined when no creds are stored", async () => {
    expect(await getFreshAnthropicAccessToken()).toBeUndefined();
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("returns the stored access token when not expired", async () => {
    writeOauthCredentials(
      {
        anthropic: { refresh: "rt", access: "fresh-at", expires: Date.now() + 60_000 },
      },
      tmpHome,
    );
    expect(await getFreshAnthropicAccessToken()).toBe("fresh-at");
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("calls refresh + persists when the access token has expired", async () => {
    writeOauthCredentials(
      {
        anthropic: { refresh: "rt-old", access: "stale-at", expires: Date.now() - 1_000 },
      },
      tmpHome,
    );
    refreshMock.mockResolvedValueOnce({
      refresh: "rt-new",
      access: "fresh-at",
      expires: Date.now() + 60_000,
    });

    const token = await getFreshAnthropicAccessToken();
    expect(token).toBe("fresh-at");
    expect(refreshMock).toHaveBeenCalledWith("rt-old");

    // Persisted refresh token must roll forward.
    const bag = readOauthCredentials(tmpHome);
    expect(bag?.anthropic?.refresh).toBe("rt-new");
    expect(bag?.anthropic?.access).toBe("fresh-at");
  });

  it("returns undefined and keeps stale creds when refresh fails", async () => {
    writeOauthCredentials(
      {
        anthropic: { refresh: "rt-broken", access: "stale-at", expires: Date.now() - 1_000 },
      },
      tmpHome,
    );
    refreshMock.mockRejectedValueOnce(new Error("network down"));

    expect(await getFreshAnthropicAccessToken()).toBeUndefined();
    const bag = readOauthCredentials(tmpHome);
    expect(bag?.anthropic?.access).toBe("stale-at");
  });
});
