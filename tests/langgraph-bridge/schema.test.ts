import { describe, expect, it } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import {
  LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
  validateBridgeRequest,
} from "../../scripts/langgraph-bridge/schema.mjs";

describe("LangGraph bridge protocol validation", () => {
  it("accepts the current protocol version", () => {
    const request = { protocolVersion: LANGGRAPH_BRIDGE_PROTOCOL_VERSION, prompt: "hello" };

    expect(validateBridgeRequest(request)).toBe(request);
  });

  it("rejects missing protocol versions", () => {
    expect(() => validateBridgeRequest({ prompt: "hello" })).toThrow(/protocolVersion <missing>/);
  });

  it("rejects unsupported protocol versions", () => {
    expect(() => validateBridgeRequest({ protocolVersion: 999, prompt: "hello" })).toThrow(
      /expected 1/,
    );
  });
});
