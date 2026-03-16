import { describe, it, expect, beforeEach } from "vitest";
import { LoopDetector } from "../../src/agent-runtime/loop-detector.js";
import { createHash } from "node:crypto";

function hash(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 16);
}

describe("LoopDetector", () => {
  let detector: LoopDetector;

  beforeEach(() => {
    detector = new LoopDetector();
  });

  describe("exact-repeat detection", () => {
    it("detects 3 identical consecutive calls", () => {
      const args = { file: "test.ts" };
      detector.recordCall("read", args, hash("result1"));
      detector.recordCall("read", args, hash("result1"));
      const result = detector.recordCall("read", args, hash("result1"));
      expect(result).not.toBeNull();
      expect(result!.pattern).toBe("exact-repeat");
      expect(result!.tool).toBe("read");
      expect(result!.count).toBe(3);
    });

    it("does not trigger below threshold", () => {
      const args = { file: "test.ts" };
      detector.recordCall("read", args, hash("result1"));
      const result = detector.recordCall("read", args, hash("result1"));
      expect(result).toBeNull();
    });

    it("resets when different tool is called", () => {
      const args = { file: "test.ts" };
      detector.recordCall("read", args, hash("result1"));
      detector.recordCall("read", args, hash("result1"));
      detector.recordCall("write", { content: "x" }, hash("result2"));
      const result = detector.recordCall("read", args, hash("result1"));
      expect(result).toBeNull();
    });
  });

  describe("ping-pong detection", () => {
    it("detects alternating pattern", () => {
      const argsA = { file: "a.ts" };
      const argsB = { file: "b.ts" };
      let result = null;
      for (let i = 0; i < 8; i++) {
        result = detector.recordCall(
          i % 2 === 0 ? "read" : "write",
          i % 2 === 0 ? argsA : argsB,
          hash(`result${i % 2}`),
        );
      }
      expect(result).not.toBeNull();
      expect(result!.pattern).toBe("ping-pong");
    });

    it("does not trigger with insufficient cycles", () => {
      const argsA = { file: "a.ts" };
      const argsB = { file: "b.ts" };
      let result = null;
      for (let i = 0; i < 4; i++) {
        result = detector.recordCall(
          i % 2 === 0 ? "read" : "write",
          i % 2 === 0 ? argsA : argsB,
          hash(`result${i % 2}`),
        );
      }
      expect(result).toBeNull();
    });
  });

  describe("expanding-loop detection", () => {
    it("detects monotonically increasing numeric arg", () => {
      detector.recordCall("read", { offset: 0 }, hash("r0"));
      detector.recordCall("read", { offset: 100 }, hash("r1"));
      const result = detector.recordCall("read", { offset: 200 }, hash("r2"));
      expect(result).not.toBeNull();
      expect(result!.pattern).toBe("expanding-loop");
    });

    it("does not trigger with decreasing values", () => {
      detector.recordCall("read", { offset: 200 }, hash("r0"));
      detector.recordCall("read", { offset: 100 }, hash("r1"));
      const result = detector.recordCall("read", { offset: 50 }, hash("r2"));
      // Should not detect expanding-loop (values are decreasing)
      expect(result?.pattern !== "expanding-loop" || result === null).toBe(true);
    });
  });

  describe("no-progress detection", () => {
    it("detects identical results from same tool", () => {
      const sameResult = hash("identical");
      detector.recordCall("search", { query: "a" }, sameResult);
      detector.recordCall("search", { query: "b" }, sameResult);
      const result = detector.recordCall("search", { query: "c" }, sameResult);
      expect(result).not.toBeNull();
      expect(result!.pattern).toBe("no-progress");
    });

    it("does not trigger with different results", () => {
      detector.recordCall("search", { query: "a" }, hash("r1"));
      detector.recordCall("search", { query: "b" }, hash("r2"));
      const result = detector.recordCall("search", { query: "c" }, hash("r3"));
      expect(result).toBeNull();
    });
  });

  describe("reset", () => {
    it("clears the detection window", () => {
      const args = { file: "test.ts" };
      detector.recordCall("read", args, hash("result1"));
      detector.recordCall("read", args, hash("result1"));
      detector.reset();
      const result = detector.recordCall("read", args, hash("result1"));
      expect(result).toBeNull(); // Only 1 call after reset
    });
  });
});
