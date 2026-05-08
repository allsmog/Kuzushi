import type { Context as PiAiContext, ToolResultMessage } from "@mariozechner/pi-ai";
import { describe, expect, it } from "vitest";
import { maybeCompactContext } from "../../src/agent-runtime/context-compactor.js";

function toolResult(toolName: string, textLen: number, id?: string): ToolResultMessage {
  return {
    role: "toolResult",
    toolCallId: id ?? `${toolName}_${Math.random()}`,
    toolName,
    content: [{ type: "text", text: "x".repeat(textLen) }],
    isError: false,
    timestamp: Date.now(),
  };
}

function userMessage(text: string): PiAiContext["messages"][number] {
  return {
    role: "user",
    content: text,
    timestamp: Date.now(),
  } as PiAiContext["messages"][number];
}

function makeContext(messages: PiAiContext["messages"]): PiAiContext {
  return { messages } as PiAiContext;
}

describe("maybeCompactContext", () => {
  it("no-ops when input tokens are below threshold", () => {
    const ctx = makeContext([toolResult("Read", 10000), toolResult("Read", 10000)]);
    const result = maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 200_000, // 20% of cap — below default 75% threshold
    });
    expect(result.compacted).toBe(false);
    expect(result.compactedCount).toBe(0);
    // Messages unchanged.
    expect((ctx.messages[0] as ToolResultMessage).content[0]).toHaveProperty("text");
    expect(
      ((ctx.messages[0] as ToolResultMessage).content[0] as { text: string }).text.length,
    ).toBe(10000);
  });

  it("compacts old tool-results when input tokens cross threshold", () => {
    // 10 large tool-results in chronological order.
    const ctx = makeContext(
      Array.from({ length: 10 }, (_, i) => toolResult("Read", 20_000, `r${i}`)),
    );
    // Simulate 80% usage (above 75% threshold).
    const result = maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 800_000,
    });
    expect(result.compacted).toBe(true);
    expect(result.compactedCount).toBeGreaterThan(0);
    expect(result.estimatedFreedTokens).toBeGreaterThan(0);
  });

  it("keeps the last N tool-results intact (default 5)", () => {
    const ctx = makeContext(
      Array.from({ length: 10 }, (_, i) => toolResult("Read", 30_000, `r${i}`)),
    );
    maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 900_000,
    });
    // Last 5 should be unchanged (30k chars each).
    for (let i = 5; i < 10; i++) {
      const text = ((ctx.messages[i] as ToolResultMessage).content[0] as { text: string }).text;
      expect(text.length).toBe(30_000);
    }
    // At least one of the first 5 should be compacted (stub starts with "[").
    const firstFive = ctx.messages.slice(0, 5) as ToolResultMessage[];
    const compactedAny = firstFive.some((m) => {
      const t = (m.content[0] as { text: string }).text;
      return t.startsWith("[") && t.includes("elided for context budget");
    });
    expect(compactedAny).toBe(true);
  });

  it("custom keepLastN overrides the default", () => {
    const ctx = makeContext(
      Array.from({ length: 10 }, (_, i) => toolResult("Read", 20_000, `r${i}`)),
    );
    maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 900_000,
      keepLastN: 2,
    });
    // Last 2 must be intact.
    for (let i = 8; i < 10; i++) {
      expect(
        ((ctx.messages[i] as ToolResultMessage).content[0] as { text: string }).text.length,
      ).toBe(20_000);
    }
  });

  it("stops compacting once estimated tokens drop below target", () => {
    const ctx = makeContext(
      Array.from({ length: 10 }, (_, i) => toolResult("Read", 50_000, `r${i}`)),
    );
    const result = maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 800_000,
      target: 0.5, // stop when under 500k
    });
    // Shouldn't need to compact ALL 5 compactable entries — a few should suffice
    // since each 50k-char entry ≈ 12.5k tokens freed.
    expect(result.compactedCount).toBeGreaterThan(0);
    expect(result.compactedCount).toBeLessThanOrEqual(5);
  });

  it("does not touch non-tool-result messages", () => {
    const ctx = makeContext([
      userMessage("initial request"),
      toolResult("Read", 50_000, "r1"),
      userMessage("follow-up"),
      toolResult("Read", 50_000, "r2"),
    ]);
    maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 900_000,
      keepLastN: 0,
    });
    // User messages untouched.
    expect((ctx.messages[0] as { content: string }).content).toBe("initial request");
    expect((ctx.messages[2] as { content: string }).content).toBe("follow-up");
  });

  it("skips tool-results smaller than minContentChars", () => {
    const ctx = makeContext([
      toolResult("Read", 150), // below default 200-char minimum
      toolResult("Read", 50_000, "big"),
    ]);
    maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 900_000,
      keepLastN: 0,
    });
    // Tiny entry untouched.
    expect(
      ((ctx.messages[0] as ToolResultMessage).content[0] as { text: string }).text.length,
    ).toBe(150);
  });

  it("handles empty context and empty messages gracefully", () => {
    const empty = makeContext([]);
    const result = maybeCompactContext(empty, {
      contextWindow: 1_000_000,
      lastInputTokens: 900_000,
    });
    expect(result.compacted).toBe(false);
  });

  it("stub includes tool name and turn number when provided", () => {
    const ctx = makeContext(
      Array.from({ length: 10 }, (_, i) => toolResult("Grep", 30_000, `g${i}`)),
    );
    maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 900_000,
      turn: 17,
    });
    const firstStub = (ctx.messages[0] as ToolResultMessage).content[0] as { text: string };
    expect(firstStub.text).toContain("Grep");
    expect(firstStub.text).toContain("elided");
    expect(firstStub.text).toContain("turn 17");
  });

  it("preserves image content blocks while compacting text", () => {
    const imgResult: ToolResultMessage = {
      role: "toolResult",
      toolCallId: "img1",
      toolName: "Read",
      content: [
        { type: "text", text: "x".repeat(50_000) },
        {
          type: "image",
          data: "base64-data",
          mimeType: "image/png",
        } as unknown as { type: "image" },
      ],
      isError: false,
      timestamp: Date.now(),
    };
    const ctx = makeContext([
      imgResult,
      ...Array.from({ length: 6 }, (_, i) => toolResult("Read", 20_000, `r${i}`)),
    ]);
    maybeCompactContext(ctx, {
      contextWindow: 1_000_000,
      lastInputTokens: 900_000,
      keepLastN: 0,
    });
    // The image content should still be in the compacted entry.
    const compacted = ctx.messages[0] as ToolResultMessage;
    const hasImage = compacted.content.some((b) => (b as { type?: string }).type === "image");
    expect(hasImage).toBe(true);
    // And the text has been replaced with the stub.
    const textBlock = compacted.content.find((b) => (b as { type?: string }).type === "text") as
      | { text: string }
      | undefined;
    expect(textBlock?.text).toContain("elided");
  });
});
