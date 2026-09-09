import assert from "node:assert/strict";
import test from "node:test";
import { HumanMessage } from "@langchain/core/messages";
import { oauthModelForRequest } from "./oauth-models.mjs";

for (const effort of ["low", "medium", "high", "xhigh"]) {
  test(`OpenAI OAuth sends selected ${effort} reasoning through tool binding`, async (t) => {
    let body;
    t.mock.method(globalThis, "fetch", async (_url, init) => {
      body = JSON.parse(init.body);
      return new Response('data: {"type":"response.output_text.done","text":"ready"}\n\n');
    });
    const model = oauthModelForRequest("openai-codex", "gpt-5.5", "test-token", {
      thinkingLevel: effort,
    }).bindTools([]);
    await model.invoke([new HumanMessage("Hello")]);
    assert.deepEqual(body.reasoning, { effort });
    assert.equal(body.model, "gpt-5.5");
  });
}

test("OpenAI OAuth leaves reasoning absent when no effort was selected", () => {
  const model = oauthModelForRequest("openai-codex", "gpt-5.5", "test-token", {});
  assert.equal(Object.hasOwn(model.body([]), "reasoning"), false);
});

test("OpenAI OAuth accepts the bridge compatibility spelling without overriding selection", () => {
  const model = oauthModelForRequest("openai-codex", "gpt-5.5", "test-token", {
    thinking_level: "high",
  });
  assert.deepEqual(model.body([]).reasoning, { effort: "high" });
});
