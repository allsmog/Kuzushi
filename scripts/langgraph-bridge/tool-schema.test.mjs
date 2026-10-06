import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { HumanMessage } from "@langchain/core/messages";
import { DynamicStructuredTool } from "@langchain/core/tools";
import { z as z3 } from "zod/v3";
import { z as z4 } from "zod/v4";
import { oauthModelForRequest } from "./oauth-models.mjs";
import { bridgeToolsForNextStep } from "./schema.mjs";

const inputSchema = {
  type: "object",
  properties: {
    path: { type: "string", description: "Path relative to the target", minLength: 1 },
    limit: { type: "integer", minimum: 1, maximum: 30, enum: [1, 10, 30] },
    scope: { type: ["string", "null"], enum: ["local", null] },
    filters: { type: "array", items: { $ref: "#/$defs/filter" }, maxItems: 3 },
  },
  required: ["path"],
  additionalProperties: false,
  $defs: {
    filter: {
      type: "object",
      properties: { match: { anyOf: [{ type: "string" }, { type: "integer" }] } },
      required: ["match"],
      additionalProperties: false,
    },
  },
};

for (const alias of ["inputSchema", "input_schema"]) {
  test(`next-step declarations preserve canonical JSON Schema from ${alias}`, () => {
    const [tool] = bridgeToolsForNextStep({
      tools: [{ name: "workspace:read", description: "Read target evidence", [alias]: inputSchema }],
    });
    assert.deepEqual(JSON.parse(JSON.stringify(tool.schema)), inputSchema);
    assert.equal(tool.name, "workspace:read");
    assert.equal(tool.description, "Read target evidence");
  });
}

for (const provider of ["openai-codex", "anthropic"]) {
  test(`${provider} sends canonical next-step schemas over the HTTP boundary`, async (t) => {
    const tools = bridgeToolsForNextStep({ tools: [{ name: "Read", inputSchema }] });
    const body = await requestBody(t, provider, tools);
    assert.deepEqual(providerSchema(provider, body.tools[0]), inputSchema);
    assert.equal(body.model, "selected-model");
    if (provider === "openai-codex") {
      assert.equal(body.tools[0].strict, false);
      assert.equal(body.store, false);
      assert.equal(body.stream, true);
    } else {
      assert.deepEqual(body.tools[0].cache_control, { type: "ephemeral" });
    }
  });

  for (const [version, z] of [["v3", z3], ["v4", z4]]) {
    test(`${provider} converts local Zod ${version} tools before HTTP serialization`, async (t) => {
      const schema = z.object({
        path: z.string().min(1).describe("Relative path"),
        line: z.number().int().min(1).max(30).optional(),
        filter: z.object({ kind: z.enum(["source", "test"]).nullable() }),
      }).strict();
      const tool = new DynamicStructuredTool({
        name: "Read", description: "Read evidence", schema, func: async () => "unused",
      });
      const body = await requestBody(t, provider, [tool]);
      const actual = providerSchema(provider, body.tools[0]);
      assert.equal(actual.type, "object");
      assert.equal(actual.properties.path.description, "Relative path");
      assert.equal(actual.properties.path.minLength, 1);
      assert.equal(actual.properties.line.type, "integer");
      assert.equal(actual.properties.line.minimum, 1);
      assert.equal(actual.properties.line.maximum, 30);
      assert.deepEqual(actual.required, ["path", "filter"]);
      assert.equal(actual.additionalProperties, false);
      assert.ok(actual.properties.filter.properties.kind);
      assert.equal(JSON.stringify(actual).includes('"def"'), false);
      assert.equal(JSON.stringify(actual).includes('"_def"'), false);
      assert.equal(tool.schema, schema);
      assert.equal(schema.safeParse({ path: "ok", line: 31, filter: { kind: null } }).success, false);
      assert.equal(schema.safeParse({ path: "ok", filter: { kind: null } }).success, true);
    });
  }
}

for (const provider of ["openai-codex", "anthropic"]) {
  test(`${provider} next-step entrypoint preserves schema and returns the correlated call`, (t) => {
    const root = mkdtempSync(join(tmpdir(), "kuzushi-tool-schema-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const credentials = join(root, "oauth.json");
    writeFileSync(credentials, JSON.stringify({ [provider]: { access: "fixture-token", expires: Date.now() + 600_000 } }));
    const fixture = join(root, "provider.mjs");
    writeFileSync(fixture, nextStepProviderFixture(provider));
    const request = {
      protocolVersion: 1, type: "next-step", cwd: root,
      model: `${provider}:selected-model`, systemPrompt: "Read target evidence.",
      messages: [{ role: "user", content: "Read the target file." }],
      tools: [{ name: "Read", description: "Read evidence", inputSchema }],
      oauthCredentialsPath: credentials, oauthAllowEnvToken: false,
      apiKeyEnv: "KUZUSHI_TEST_NO_API_KEY", maxTokens: 64,
    };
    const bridge = fileURLToPath(new URL("../langgraph-bridge.mjs", import.meta.url));
    const result = spawnSync(process.execPath, ["--import", fixture, bridge], {
      input: JSON.stringify(request), encoding: "utf8", timeout: 20_000,
      env: { PATH: process.env.PATH, LANG: "en_US.UTF-8" },
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const response = JSON.parse(result.stdout);
    assert.equal(response.ok, true);
    assert.equal(response.step, "tool_call");
    assert.deepEqual(response.call, {
      name: "Read", input: { path: "example.txt" }, callId: "schema-call-1",
    });
  });
}

function nextStepProviderFixture(provider) {
  return `
import assert from "node:assert/strict";
globalThis.fetch = async (_url, init) => {
  const body = JSON.parse(init.body);
  const schema = body.tools[0].parameters ?? body.tools[0].input_schema;
  assert.deepEqual(schema, ${JSON.stringify(inputSchema)});
  assert.equal(body.model, "selected-model");
  if (${JSON.stringify(provider)} === "anthropic") {
    return new Response(JSON.stringify({
      content: [{ type: "tool_use", id: "schema-call-1", name: "Read", input: { path: "example.txt" } }]
    }));
  }
  assert.equal(body.tools[0].strict, false);
  const event = { type: "response.output_item.done", item: {
    type: "function_call", call_id: "schema-call-1", name: "Read", arguments: '{"path":"example.txt"}'
  } };
  return new Response("data: " + JSON.stringify(event) + "\\n\\n");
};
`;
}

function providerSchema(provider, tool) {
  return provider === "openai-codex" ? tool.parameters : tool.input_schema;
}

async function requestBody(t, provider, tools) {
  let body;
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    body = JSON.parse(init.body);
    return provider === "anthropic"
      ? new Response(JSON.stringify({ content: [{ type: "text", text: "ok" }] }))
      : new Response('data: {"type":"response.output_text.done","text":"ok"}\n\n');
  });
  const model = oauthModelForRequest(provider, "selected-model", "fixture-token", {}).bindTools(tools);
  await model.invoke([new HumanMessage("Read the target evidence.")]);
  return body;
}
