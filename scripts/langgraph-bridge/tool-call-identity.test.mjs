import assert from "node:assert/strict";
import test from "node:test";
import { messagesForNextStep } from "./next-step-messages.mjs";
import { oauthModelForRequest } from "./oauth-models.mjs";

function anthropicOauthModel() {
  return oauthModelForRequest("anthropic", "claude-test", "access", {});
}

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

test("Anthropic OAuth history preserves the assistant tool-use block that a tool result references", () => {
  const model = anthropicOauthModel();
  const body = model.body([
    aiMessage([
      {
        id: "anthropic-tool-1",
        name: "read_file",
        args: { path: "README.md" },
        type: "tool_call",
      },
    ]),
    toolMessage("anthropic-tool-1"),
  ]);

  assert.deepEqual(body.messages[0], {
    role: "assistant",
    content: [
      {
        type: "tool_use",
        id: "anthropic-tool-1",
        name: "read_file",
        input: { path: "README.md" },
      },
    ],
  });
  assert.equal(body.messages[1].role, "user");
  assert.equal(body.messages[1].content[0].type, "tool_result");
  assert.equal(body.messages[1].content[0].tool_use_id, "anthropic-tool-1");
});

test("Anthropic OAuth history rejects tool calls without explicit correlation identity", () => {
  const model = anthropicOauthModel();

  for (const invalidId of [undefined, "", "   ", 42]) {
    assertInvalidProviderResponse(() =>
      model.body([
        aiMessage([
          {
            id: invalidId,
            name: "read_file",
            args: { path: "README.md" },
            type: "tool_call",
          },
        ]),
      ]),
    );
  }
});

test("Anthropic OAuth history rejects malformed replayed tool names and input objects", () => {
  const model = anthropicOauthModel();

  for (const invalidName of [undefined, "", "   ", 42]) {
    assertInvalidProviderResponse(() =>
      model.body([
        aiMessage([
          {
            id: "anthropic-tool-1",
            name: invalidName,
            args: {},
            type: "tool_call",
          },
        ]),
      ]),
    );
  }

  for (const invalidArgs of [undefined, null, [], "path", 1, true]) {
    assertInvalidProviderResponse(() =>
      model.body([
        aiMessage([
          {
            id: "anthropic-tool-1",
            name: "read_file",
            args: invalidArgs,
            type: "tool_call",
          },
        ]),
      ]),
    );
  }
});

test("Anthropic OAuth tool results require the matching correlation id", () => {
  const model = anthropicOauthModel();

  for (const invalidId of [undefined, "", "   ", 42]) {
    assertInvalidProviderResponse(() => model.body([toolMessage(invalidId)]));
  }
});

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

test("next-step history converts Rust tool-use and tool-result blocks into correlated LangChain messages", () => {
  const messages = messagesForNextStep([
    {
      role: "assistant",
      content: [
        {
          type: "tool_use",
          id: "next-step-call-1",
          name: "read_file",
          input: { path: "README.md" },
        },
      ],
    },
    {
      role: "user",
      content: [
        {
          type: "tool_result",
          tool_use_id: "next-step-call-1",
          content: "repository evidence",
          is_error: false,
        },
      ],
    },
  ]);

  assert.equal(messages.length, 2);
  assert.equal(messages[0]._getType(), "ai");
  assert.deepEqual(messages[0].tool_calls, [
    {
      id: "next-step-call-1",
      name: "read_file",
      args: { path: "README.md" },
      type: "tool_call",
    },
  ]);
  assert.equal(messages[1]._getType(), "tool");
  assert.equal(messages[1].tool_call_id, "next-step-call-1");
  assert.equal(messages[1].content, "repository evidence");
});

test("next-step Rust history remains correlated through Anthropic and OpenAI OAuth serialization", () => {
  const messages = messagesForNextStep([
    {
      role: "assistant",
      content: [
        {
          type: "tool_use",
          id: "next-step-call-2",
          name: "read_file",
          input: { path: "README.md" },
        },
      ],
    },
    {
      role: "user",
      content: [
        {
          type: "tool_result",
          tool_use_id: "next-step-call-2",
          content: "tool output",
        },
      ],
    },
  ]);

  const anthropic = anthropicOauthModel().body(messages);
  assert.equal(anthropic.messages[0].content[0].type, "tool_use");
  assert.equal(anthropic.messages[0].content[0].id, "next-step-call-2");
  assert.equal(anthropic.messages[1].content[0].type, "tool_result");
  assert.equal(anthropic.messages[1].content[0].tool_use_id, "next-step-call-2");

  const openai = openAiOauthModel().body(messages);
  assert.deepEqual(openai.input[0], {
    type: "function_call",
    call_id: "next-step-call-2",
    name: "read_file",
    arguments: JSON.stringify({ path: "README.md" }),
  });
  assert.deepEqual(openai.input[1], {
    type: "function_call_output",
    call_id: "next-step-call-2",
    output: "tool output",
  });
});

test("next-step history fails closed instead of fabricating missing tool correlation identity", () => {
  assertInvalidProviderResponse(() =>
    messagesForNextStep([
      {
        role: "assistant",
        content: [{ type: "tool_use", name: "read_file", input: {} }],
      },
    ]),
  );

  assertInvalidProviderResponse(() =>
    messagesForNextStep([
      {
        role: "user",
        content: [{ type: "tool_result", content: "orphan output" }],
      },
    ]),
  );
});