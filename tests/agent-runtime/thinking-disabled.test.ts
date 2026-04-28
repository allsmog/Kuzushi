import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  _resetProxyBannerForTests,
  detectNonAnthropicProxy,
  warnIfNonAnthropicProxy,
} from "../../src/agent-runtime/claude.js";

describe("KUZUSHI_DISABLE_THINKING + non-Anthropic proxy detection", () => {
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    savedEnv.ANTHROPIC_BASE_URL = process.env.ANTHROPIC_BASE_URL;
    savedEnv.KUZUSHI_DISABLE_THINKING = process.env.KUZUSHI_DISABLE_THINKING;
    savedEnv.KUZUSHI_QUIET_PROXY_BANNER = process.env.KUZUSHI_QUIET_PROXY_BANNER;
    delete process.env.ANTHROPIC_BASE_URL;
    delete process.env.KUZUSHI_DISABLE_THINKING;
    delete process.env.KUZUSHI_QUIET_PROXY_BANNER;
    _resetProxyBannerForTests();
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  describe("detectNonAnthropicProxy", () => {
    it("returns null when ANTHROPIC_BASE_URL is unset", () => {
      expect(detectNonAnthropicProxy()).toBeNull();
    });

    it("returns null for api.anthropic.com", () => {
      process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com";
      expect(detectNonAnthropicProxy()).toBeNull();
    });

    it("returns null for any anthropic.com subdomain", () => {
      process.env.ANTHROPIC_BASE_URL = "https://staging.anthropic.com/v1";
      expect(detectNonAnthropicProxy()).toBeNull();
    });

    it("returns the host for an internal proxy", () => {
      process.env.ANTHROPIC_BASE_URL = "https://basecamp.stark.acme.com";
      expect(detectNonAnthropicProxy()).toBe("basecamp.stark.acme.com");
    });

    it("returns null for a malformed URL", () => {
      process.env.ANTHROPIC_BASE_URL = "not a url";
      expect(detectNonAnthropicProxy()).toBeNull();
    });
  });

  describe("warnIfNonAnthropicProxy", () => {
    function captureStderr(): { writes: string[]; stream: NodeJS.WriteStream } {
      const writes: string[] = [];
      const stream = {
        write: vi.fn((chunk: string | Buffer) => {
          writes.push(typeof chunk === "string" ? chunk : chunk.toString());
          return true;
        }),
      } as unknown as NodeJS.WriteStream;
      return { writes, stream };
    }

    it("emits no banner when no proxy is set", () => {
      const { writes, stream } = captureStderr();
      warnIfNonAnthropicProxy(stream);
      expect(writes).toEqual([]);
    });

    it("emits no banner for anthropic.com", () => {
      process.env.ANTHROPIC_BASE_URL = "https://api.anthropic.com";
      const { writes, stream } = captureStderr();
      warnIfNonAnthropicProxy(stream);
      expect(writes).toEqual([]);
    });

    it("emits a one-line banner for a non-Anthropic host", () => {
      process.env.ANTHROPIC_BASE_URL = "https://basecamp.stark.acme.com";
      const { writes, stream } = captureStderr();
      warnIfNonAnthropicProxy(stream);
      expect(writes).toHaveLength(1);
      expect(writes[0]).toContain("basecamp.stark.acme.com");
      expect(writes[0]).toContain("KUZUSHI_DISABLE_THINKING");
    });

    it("is idempotent — only emits once per process lifetime", () => {
      process.env.ANTHROPIC_BASE_URL = "https://internal.example.com";
      const { writes, stream } = captureStderr();
      warnIfNonAnthropicProxy(stream);
      warnIfNonAnthropicProxy(stream);
      warnIfNonAnthropicProxy(stream);
      expect(writes).toHaveLength(1);
    });

    it("respects KUZUSHI_QUIET_PROXY_BANNER opt-out", () => {
      process.env.ANTHROPIC_BASE_URL = "https://internal.example.com";
      process.env.KUZUSHI_QUIET_PROXY_BANNER = "1";
      const { writes, stream } = captureStderr();
      warnIfNonAnthropicProxy(stream);
      expect(writes).toEqual([]);
    });

    it("suppresses banner when KUZUSHI_DISABLE_THINKING is already set", () => {
      // Operator has already taken the recommended action — no need to nag.
      process.env.ANTHROPIC_BASE_URL = "https://internal.example.com";
      process.env.KUZUSHI_DISABLE_THINKING = "1";
      const { writes, stream } = captureStderr();
      warnIfNonAnthropicProxy(stream);
      expect(writes).toEqual([]);
    });
  });
});
