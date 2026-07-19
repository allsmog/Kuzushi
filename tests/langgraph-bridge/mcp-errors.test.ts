import { describe, expect, it } from "vitest";
import {
  mcpConnectionFailureMessage,
  mcpToolTimeoutForRequest,
} from "../../scripts/langgraph-bridge/mcp.mjs";

describe("MCP connection error formatting", () => {
  it("normalizes the single-object callback shape", () => {
    const message = mcpConnectionFailureMessage(
      { name: "joern", error: new Error("spawn ENOENT") },
      undefined,
      { joern: { command: "kuzushi-mcp-joern" } },
    );

    expect(message).toContain("server joern");
    expect(message).toContain("command: kuzushi-mcp-joern");
    expect(message).toContain("spawn ENOENT");
    expect(message).not.toContain("[object Object]");
    expect(message).not.toContain("undefined");
  });

  it("normalizes the two-argument callback shape", () => {
    const message = mcpConnectionFailureMessage("treesitter", new Error("handshake failed"), {
      treesitter: { command: "kuzushi-mcp-treesitter" },
    });

    expect(message).toContain("server treesitter");
    expect(message).toContain("handshake failed");
  });

  it("uses the request-scoped MCP timeout with a bounded default", () => {
    expect(mcpToolTimeoutForRequest({})).toBe(60_000);
    expect(
      mcpToolTimeoutForRequest({ runtimeOptions: { mcpToolTimeoutMs: 12_345 } }),
    ).toBe(12_345);
    expect(() =>
      mcpToolTimeoutForRequest({ runtimeOptions: { mcpToolTimeoutMs: 0 } }),
    ).toThrow(/positive safe integer/);
  });
});
