import assert from "node:assert/strict";
import test from "node:test";
import { BridgePublicError, bridgeErrorResponse, providerResponseError } from "./errors.mjs";
import { modelOptions } from "./model.mjs";
import { oauthModelForRequest } from "./oauth-models.mjs";

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

const MODEL_UNAVAILABLE_DETAIL =
  "The selected model is unavailable for this provider or account. Choose an available model explicitly.";

for (const provider of ["openai-codex", "anthropic"]) {
  test(`${provider} exposes only canonical guidance for an unsupported selected model`, async (t) => {
    const payload = { detail: "The 'selected-model' model is not supported for this account. PRIVATE_SOURCE" };
    t.mock.method(globalThis, "fetch", async () =>
      new Response(JSON.stringify(payload), { status: 400 }));
    const model = oauthModelForRequest(provider, "selected-model", "fixture-token", {});
    await assert.rejects(() => model.invoke([]), (error) => {
      const response = bridgeErrorResponse(error);
      assert.equal(response.errorClass, "provider_rejected");
      assert.equal(response.status, 400);
      assert.equal(response.detail, MODEL_UNAVAILABLE_DETAIL);
      assert.equal(JSON.stringify(response).includes("PRIVATE_SOURCE"), false);
      assert.equal(error.message.includes("PRIVATE_SOURCE"), false);
      return true;
    });
  });
}

test("model rejection supports structured provider codes and nested messages", async () => {
  for (const payload of [
    { error: { code: "model_not_found", message: "PRIVATE_SOURCE" } },
    { error: { message: "Model 'selected-model' is not supported for this account." } },
  ]) {
    const error = await providerResponseError(new Response(JSON.stringify(payload), { status: 404 }));
    assert.equal(bridgeErrorResponse(error).detail, MODEL_UNAVAILABLE_DETAIL);
    assert.equal(bridgeErrorResponse(error).status, 404);
  }
});

test("unknown or malformed rejection bodies retain HTTP status without inventing model unavailability", async () => {
  for (const body of [
    "not json", "null", "[]", JSON.stringify({ detail: 123 }),
    JSON.stringify({ detail: "Parameter temperature is not supported for this model. PRIVATE_SOURCE" }),
    JSON.stringify({ detail: "Invalid tool schema. PRIVATE_SOURCE" }),
    JSON.stringify({ detail: "No recognized cause. PRIVATE_SOURCE" }),
    JSON.stringify({ detail: "x".repeat(20_000) }),
  ]) {
    const response = bridgeErrorResponse(await providerResponseError(new Response(body, { status: 400 })));
    assert.equal(response.status, 400);
    assert.equal(response.errorClass, "provider_rejected");
    assert.equal(response.detail, undefined);
    assert.equal(JSON.stringify(response).includes("PRIVATE_SOURCE"), false);
  }
});

test("error-body parsing preserves auth and availability classes", async () => {
  for (const [status, errorClass] of [[401, "authentication"], [429, "rate_limited"], [503, "provider_unavailable"]]) {
    const payload = JSON.stringify({ error: { code: "model_not_found" } });
    const response = bridgeErrorResponse(await providerResponseError(new Response(payload, { status })));
    assert.equal(response.errorClass, errorClass);
    assert.equal(response.status, status);
    assert.equal(response.detail, undefined);
  }
  const unreadable = { status: 400, text: async () => { throw new Error("PRIVATE_SOURCE"); } };
  const response = bridgeErrorResponse(await providerResponseError(unreadable));
  assert.equal(response.status, 400);
  assert.equal(response.detail, undefined);
});

test("arbitrary errors cannot inject even canonical model-unavailable guidance", () => {
  const error = new Error("unknown");
  error.status = 400;
  error.detail = MODEL_UNAVAILABLE_DETAIL;
  assert.equal(bridgeErrorResponse(error).detail, undefined);
});
