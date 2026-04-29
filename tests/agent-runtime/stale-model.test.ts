import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  _resetStaleModelBannerForTests,
  detectStaleModel,
  warnIfStaleModel,
} from "../../src/agent-runtime/claude.js";

describe("stale-model detection (C6)", () => {
  const savedQuiet = process.env.KUZUSHI_QUIET_STALE_MODEL_BANNER;

  beforeEach(() => {
    delete process.env.KUZUSHI_QUIET_STALE_MODEL_BANNER;
    _resetStaleModelBannerForTests();
  });

  afterEach(() => {
    if (savedQuiet === undefined) delete process.env.KUZUSHI_QUIET_STALE_MODEL_BANNER;
    else process.env.KUZUSHI_QUIET_STALE_MODEL_BANNER = savedQuiet;
  });

  describe("detectStaleModel", () => {
    it("returns null when model is undefined", () => {
      expect(detectStaleModel(undefined)).toBeNull();
    });

    it("returns null for the empty string", () => {
      expect(detectStaleModel("")).toBeNull();
    });

    it("returns null for the current Opus model", () => {
      expect(detectStaleModel("claude-opus-4-7")).toBeNull();
      expect(detectStaleModel("anthropic:claude-opus-4-7")).toBeNull();
    });

    it("returns the recommended replacement for stale Opus 4.6", () => {
      expect(detectStaleModel("claude-opus-4-6")).toBe("claude-opus-4-7");
    });

    it("strips the anthropic: provider prefix before lookup", () => {
      expect(detectStaleModel("anthropic:claude-opus-4-6")).toBe("claude-opus-4-7");
    });

    it("recognizes stale Sonnet and Haiku entries", () => {
      expect(detectStaleModel("claude-sonnet-4-5")).toBe("claude-sonnet-4-6");
      expect(detectStaleModel("claude-haiku-4-4")).toBe("claude-haiku-4-5");
    });

    it("returns null for an unknown model id", () => {
      expect(detectStaleModel("claude-zeta-9-9")).toBeNull();
    });
  });

  describe("warnIfStaleModel", () => {
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

    it("emits no banner when the model is current", () => {
      const { writes, stream } = captureStderr();
      warnIfStaleModel("claude-opus-4-7", stream);
      expect(writes).toEqual([]);
    });

    it("emits no banner when model is undefined", () => {
      const { writes, stream } = captureStderr();
      warnIfStaleModel(undefined, stream);
      expect(writes).toEqual([]);
    });

    it("emits a one-line banner naming the recommended replacement", () => {
      const { writes, stream } = captureStderr();
      warnIfStaleModel("anthropic:claude-opus-4-6", stream);
      expect(writes).toHaveLength(1);
      expect(writes[0]).toContain("claude-opus-4-6");
      expect(writes[0]).toContain("claude-opus-4-7");
      expect(writes[0]).toContain("KUZUSHI_QUIET_STALE_MODEL_BANNER");
    });

    it("only emits once per process lifetime (idempotent)", () => {
      const { writes, stream } = captureStderr();
      warnIfStaleModel("claude-opus-4-6", stream);
      warnIfStaleModel("claude-opus-4-6", stream);
      warnIfStaleModel("claude-sonnet-4-5", stream);
      expect(writes).toHaveLength(1);
    });

    it("can be silenced with KUZUSHI_QUIET_STALE_MODEL_BANNER=1", () => {
      process.env.KUZUSHI_QUIET_STALE_MODEL_BANNER = "1";
      const { writes, stream } = captureStderr();
      warnIfStaleModel("claude-opus-4-6", stream);
      expect(writes).toEqual([]);
    });
  });
});
