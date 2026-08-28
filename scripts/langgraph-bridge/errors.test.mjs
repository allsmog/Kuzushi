import assert from "node:assert/strict";
import test from "node:test";
import { BridgePublicError, bridgeErrorResponse } from "./errors.mjs";
import { modelOptions } from "./model.mjs";

test("adaptive-thinking temperature validation has an actionable safe class", () => {
  const error = new Error("temperature is not compatible with adaptive thinking");
  error.name = "InvocationParamCompatibilityError";

  const response = bridgeErrorResponse(error);

  assert.equal(response.errorClass, "sdk_client_validation");
  assert.match(response.error, /incompatible client-side invocation parameters/);
  assert.equal(
    response.detail,
    "temperature is incompatible with adaptive thinking; omit the pinned temperature",
  );
});

test("adaptive-thinking models omit a caller-pinned temperature", () => {
  const adaptive = modelOptions({ model: "anthropic:claude-opus-4-7", temperature: 0 });
  const datedAdaptive = modelOptions({
    model: "vertex-anthropic:claude-opus-4-7-20260801",
    temperature: 0,
  });
  const ordinary = modelOptions({ model: "anthropic:claude-sonnet-4-5", temperature: 0 });

  assert.equal(adaptive.temperature, undefined);
  assert.equal(datedAdaptive.temperature, undefined);
  assert.equal(ordinary.temperature, 0);
});

test("production error responses omit credential-bearing provider detail", () => {
  const response = bridgeErrorResponse(
    new Error(
      "Authorization: Bearer sk-live-secret-sentinel token=raw-token-secret api_key=raw-api-secret",
    ),
  );
  const serialized = JSON.stringify(response);

  assert.equal(serialized.includes("sk-live-secret-sentinel"), false);
  assert.equal(serialized.includes("raw-token-secret"), false);
  assert.equal(serialized.includes("raw-api-secret"), false);
});

test("arbitrary provider detail is omitted even when it contains no secret pattern", () => {
  const response = bridgeErrorResponse(
    new Error("proprietary source excerpt without a recognizable credential"),
  );

  assert.equal(response.detail, undefined);
  assert.equal(JSON.stringify(response).includes("proprietary source excerpt"), false);
});

test("provider SDK missing-key shapes are classified as authentication", () => {
  for (const message of [
    "Missing credentials. Please pass an apiKey",
    "Anthropic API key not found",
  ]) {
    const response = bridgeErrorResponse(new Error(message));
    assert.equal(response.errorClass, "authentication");
    assert.equal(response.error, "Provider authentication failed.");
    assert.equal(JSON.stringify(response).includes(message), false);
  }
});

test("typed MCP startup failures expose only actionable canonical guidance", () => {
  const error = new BridgePublicError("mcp_unavailable", undefined, {
    cause: new Error("spawn kuzushi-mcp-treesitter ENOENT at /private/target"),
  });

  const response = bridgeErrorResponse(error);

  assert.equal(response.errorClass, "mcp_unavailable");
  assert.match(response.error, /cargo build --workspace/);
  assert.equal(response.detail, undefined);
  assert.equal(JSON.stringify(response).includes("/private/target"), false);
});
