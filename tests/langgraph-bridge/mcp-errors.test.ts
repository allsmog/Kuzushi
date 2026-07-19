import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  isMcpToolTimeoutError,
  mcpConnectionFailureMessage,
  mcpToolTimeoutForRequest,
  normalizeMcpToolError,
  withMcpClientCleanup,
} from "../../scripts/langgraph-bridge/mcp.mjs";

const execFileAsync = promisify(execFile);

describe("MCP connection error formatting", () => {
  afterEach(() => vi.useRealTimers());

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
    expect(mcpToolTimeoutForRequest({ runtimeOptions: { mcpToolTimeoutMs: 12_345 } })).toBe(12_345);
    expect(() => mcpToolTimeoutForRequest({ runtimeOptions: { mcpToolTimeoutMs: 0 } })).toThrow(
      /positive safe integer/,
    );
  });

  it("marks MCP timeouts without retaining their raw message as public text", () => {
    const sentinel = "provider-secret-sentinel";
    const normalized = normalizeMcpToolError(
      new Error(`MCP error -32001: Request timed out: ${sentinel}`),
    );

    expect(isMcpToolTimeoutError(normalized)).toBe(true);
    expect(normalized.message).toBe("MCP tool request timed out");
    expect(normalized.message).not.toContain(sentinel);
  });

  it("does not relabel unrelated MCP failures as timeouts", () => {
    const failure = new Error("MCP tool returned invalid output");

    expect(normalizeMcpToolError(failure)).toBe(failure);
    expect(isMcpToolTimeoutError(failure)).toBe(false);
  });

  it("keeps a computed timeout spend receipt when MCP cleanup rejects", async () => {
    const receipt = {
      ok: true,
      stopReason: "mcp_tool_timeout",
      cost_usd: 0.02,
      model_calls: 1,
    };
    let closeCalls = 0;

    const result = await withMcpClientCleanup(
      async () => receipt,
      async () => {
        closeCalls += 1;
        throw new Error("MCP cleanup timed out");
      },
    );

    expect(result).toBe(receipt);
    expect(closeCalls).toBe(1);
  });

  it("keeps a computed timeout spend receipt when MCP cleanup never settles", async () => {
    vi.useFakeTimers();
    const receipt = { ok: true, stopReason: "mcp_tool_timeout", cost_usd: 0.02 };
    const result = withMcpClientCleanup(
      async () => receipt,
      () => new Promise(() => {}),
      25,
    );

    await vi.advanceTimersByTimeAsync(25);

    await expect(result).resolves.toBe(receipt);
  });

  it("flushes the receipt and exits despite a live transport handle", async () => {
    const helper = new URL("../../scripts/langgraph-bridge/process-exit.mjs", import.meta.url);
    const receipt = { ok: true, stopReason: "mcp_tool_timeout", cost_usd: 0.02 };
    const childScript = [
      `import { writeBridgeResponseAndExit } from ${JSON.stringify(helper.href)};`,
      "setInterval(() => {}, 60_000);",
      `await writeBridgeResponseAndExit(${JSON.stringify(receipt)}, 0);`,
    ].join("\n");

    const result = await execFileAsync(
      process.execPath,
      ["--input-type=module", "--eval", childScript],
      {
        timeout: 2_000,
      },
    );

    expect(JSON.parse(result.stdout)).toEqual(receipt);
  });
});
