import assert from "node:assert/strict";
import test from "node:test";
import { oauthModelForRequest } from "./oauth-models.mjs";

function openAiOauthModel() {
  return oauthModelForRequest("openai-codex", "gpt-test", "access", {});
}

function aiMessage(toolCalls) {
  return {
    _getType: () => "ai",
    content: "",
    tool_calls: toolCalls,
  };
}

function toolMessage(toolCallId) {
  return {
    _getType: () => "tool",
    content: "tool result",
    tool_call_id: toolCallId,
  };
}

function assertInvalidProviderResponse(invoke) {
  assert.throws(invoke, (error) => {
    assert.equal(error?.name, "BridgePublicError");
    assert.equal(error?.errorClass, "provider_response_invalid");
    assert.equal(error?.message, "Provider returned an invalid response.");
    return true;
  });
}

test("OpenAI OAuth history rejects tool calls without an explicit correlation id", () => {
  const model = openAiOauthModel();

  for (const invalidId of [undefined, "", "   ", 42]) {
    assertInvalidProviderResponse(() =>
      model.body([
        aiMessage([
          {
            id: invalidId,
            name: "Read",
            args: { path: "README.md" },
            type: "tool_call",
          },
        ]),
      ]),
    );
  }
});

test("OpenAI OAuth history never substitutes the tool name for a missing correlation id", () => {
  const model = openAiOauthModel();

  assertInvalidProviderResponse(() =>
    model.body([
      aiMessage([
        {
          name: "Read",
          args: { path: "README.md" },
          type: "tool_call",
        },
      ]),
    ]),
  );
});

test("OpenAI OAuth tool results require the matching correlation id", () => {
  const model = openAiOauthModel();

  for (const invalidId of [undefined, "", "   ", 42]) {
    assertInvalidProviderResponse(() => model.body([toolMessage(invalidId)]));
  }
});

test("OpenAI OAuth history preserves explicit tool-call correlation identity", () => {
  const model = openAiOauthModel();
  const body = model.body([
    aiMessage([
      {
        id: "provider-call-1",
        name: "Read",
        args: { path: "README.md" },
        type: "tool_call",
      },
    ]),
    toolMessage("provider-call-1"),
  ]);

  assert.equal(body.input.length, 2);
  assert.deepEqual(body.input[0], {
    type: "function_call",
    call_id: "provider-call-1",
    name: "Read",
    arguments: JSON.stringify({ path: "README.md" }),
  });
  assert.deepEqual(body.input[1], {
    type: "function_call_output",
    call_id: "provider-call-1",
    output: "tool result",
  });
});
