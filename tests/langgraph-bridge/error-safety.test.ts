import { describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { bridgeErrorResponse } from "../../scripts/langgraph-bridge/errors.mjs";

describe("bridge-visible error serialization", () => {
  it("suppresses arbitrary error messages and nested model content", () => {
    const sentinel = "raw-bridge-model-response-sentinel";
    const error = new Error(sentinel, { cause: new Error(`nested ${sentinel}`) });

    const response = bridgeErrorResponse(error);
    const serialized = JSON.stringify(response);

    expect(response).toEqual({
      ok: false,
      error: "Bridge operation failed; raw error details were suppressed.",
      errorClass: "bridge_internal",
    });
    expect(serialized).not.toContain(sentinel);
  });

  it("retains only a classified failure and bounded HTTP status", () => {
    const sentinel = "raw-provider-body-sentinel";
    const error = Object.assign(new Error(sentinel), { status: 429 });

    const response = bridgeErrorResponse(error);

    expect(response).toEqual({
      ok: false,
      error: "Provider rate limited the request (HTTP 429).",
      errorClass: "rate_limited",
      status: 429,
    });
    expect(JSON.stringify(response)).not.toContain(sentinel);
  });

  it("classifies MCP timeouts separately from retryable provider timeouts", () => {
    const error = Object.assign(new Error("MCP tool request timed out"), {
      name: "McpToolTimeoutError",
      code: "KUZUSHI_MCP_TOOL_TIMEOUT",
    });

    expect(bridgeErrorResponse(error)).toEqual({
      ok: false,
      error: "MCP tool request timed out.",
      errorClass: "mcp_timeout",
    });
  });
});
