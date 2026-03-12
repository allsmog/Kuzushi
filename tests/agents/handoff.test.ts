import { describe, it, expect } from "vitest";
import {
  createHandoff,
  isHandoff,
  getUpstreamOutput,
  getUpstreamHandoff,
  formatUpstreamInsights,
} from "../../src/agents/handoff.js";

describe("createHandoff", () => {
  it("creates a handoff envelope with defaults", () => {
    const handoff = createHandoff("test-task", { data: 42 });
    expect(handoff.__handoff).toBe(true);
    expect(handoff.taskId).toBe("test-task");
    expect(handoff.output).toEqual({ data: 42 });
    expect(handoff.insights).toEqual([]);
    expect(handoff.attentionPoints).toEqual([]);
    expect(handoff.confidence).toBe(1);
    expect(handoff.suggestedActions).toBeUndefined();
  });

  it("creates a handoff with custom options", () => {
    const handoff = createHandoff("test-task", "output", {
      insights: ["Found Express middleware"],
      attentionPoints: ["No auth on /api/admin"],
      suggestedActions: ["Check auth middleware"],
      confidence: 0.85,
    });
    expect(handoff.insights).toEqual(["Found Express middleware"]);
    expect(handoff.attentionPoints).toEqual(["No auth on /api/admin"]);
    expect(handoff.suggestedActions).toEqual(["Check auth middleware"]);
    expect(handoff.confidence).toBe(0.85);
  });

  it("clamps confidence to [0, 1]", () => {
    expect(createHandoff("t", null, { confidence: 1.5 }).confidence).toBe(1);
    expect(createHandoff("t", null, { confidence: -0.5 }).confidence).toBe(0);
  });
});

describe("isHandoff", () => {
  it("returns true for handoff objects", () => {
    expect(isHandoff(createHandoff("t", null))).toBe(true);
  });

  it("returns false for non-handoff values", () => {
    expect(isHandoff(null)).toBe(false);
    expect(isHandoff(undefined)).toBe(false);
    expect(isHandoff("string")).toBe(false);
    expect(isHandoff(42)).toBe(false);
    expect(isHandoff({ output: "foo" })).toBe(false);
    expect(isHandoff({ __handoff: false })).toBe(false);
  });
});

describe("getUpstreamOutput", () => {
  it("returns undefined for missing task", () => {
    const upstream = new Map<string, unknown>();
    expect(getUpstreamOutput(upstream, "missing")).toBeUndefined();
  });

  it("returns raw output when not wrapped", () => {
    const upstream = new Map<string, unknown>([["task-a", [1, 2, 3]]]);
    expect(getUpstreamOutput<number[]>(upstream, "task-a")).toEqual([1, 2, 3]);
  });

  it("unwraps handoff to return inner output", () => {
    const handoff = createHandoff("task-b", { value: "hello" });
    const upstream = new Map<string, unknown>([["task-b", handoff]]);
    expect(getUpstreamOutput<{ value: string }>(upstream, "task-b")).toEqual({ value: "hello" });
  });
});

describe("getUpstreamHandoff", () => {
  it("returns undefined for missing task", () => {
    const upstream = new Map<string, unknown>();
    expect(getUpstreamHandoff(upstream, "missing")).toBeUndefined();
  });

  it("returns undefined for raw output (not handoff)", () => {
    const upstream = new Map<string, unknown>([["task-a", "raw"]]);
    expect(getUpstreamHandoff(upstream, "task-a")).toBeUndefined();
  });

  it("returns the full handoff envelope", () => {
    const handoff = createHandoff("task-b", { val: 1 }, { insights: ["test"] });
    const upstream = new Map<string, unknown>([["task-b", handoff]]);
    const result = getUpstreamHandoff<{ val: number }>(upstream, "task-b");
    expect(result).toBeDefined();
    expect(result!.taskId).toBe("task-b");
    expect(result!.insights).toEqual(["test"]);
    expect(result!.output).toEqual({ val: 1 });
  });
});

describe("formatUpstreamInsights", () => {
  it("returns empty for no handoffs", () => {
    const upstream = new Map<string, unknown>([["task-a", "raw"]]);
    expect(formatUpstreamInsights(upstream, ["task-a"])).toEqual([]);
  });

  it("collects insights and attention points", () => {
    const h1 = createHandoff("t1", null, {
      insights: ["Express detected"],
      attentionPoints: ["No CSRF protection"],
    });
    const h2 = createHandoff("t2", null, {
      insights: ["PostgreSQL in use"],
    });
    const upstream = new Map<string, unknown>([["t1", h1], ["t2", h2]]);
    const result = formatUpstreamInsights(upstream, ["t1", "t2"]);
    expect(result).toContain("### Insights from t1");
    expect(result).toContain("- Express detected");
    expect(result).toContain("### Attention points from t1");
    expect(result).toContain("- No CSRF protection");
    expect(result).toContain("### Insights from t2");
    expect(result).toContain("- PostgreSQL in use");
  });

  it("skips non-existent deps", () => {
    const upstream = new Map<string, unknown>();
    expect(formatUpstreamInsights(upstream, ["t1", "t2"])).toEqual([]);
  });
});
