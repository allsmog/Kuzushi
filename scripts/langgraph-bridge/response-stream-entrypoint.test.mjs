import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

for (const type of ["next-step", "query", "next-step-preflight"]) {
  test(`${type} entrypoint frames the authoritative result and retains model selection`, (t) => {
    const { root, fixture, request } = setup(t);
    request.type = type;
    const result = run(fixture, request);
    assert.equal(result.status, 0, result.stderr);
    const frames = parseFrames(result.stdout);
    const terminal = frames.at(-1);
    assert.equal(terminal.type, "result");
    assert.equal(terminal.result.ok, true);
    if (type === "next-step-preflight") {
      assert.equal(frames.length, 1);
    } else {
      assert.equal(frames[0].type, "reset");
      assert.equal(frames.filter((frame) => frame.type === "text").map((frame) => frame.text).join(""), "Visible response");
      assert.equal(terminal.result.text, "Visible response");
    }
    assert.equal(result.stderr.includes("PRIVATE_REASONING"), false);
    assert.equal(result.stdout.includes(root), false);
  });
}

test("entrypoint frames terminal error after partial provider stream without promoting it to success", (t) => {
  const { fixture, request } = setup(t, false);
  const result = run(fixture, request);
  assert.equal(result.status, 1);
  const frames = parseFrames(result.stdout);
  assert.equal(frames[1].text, "Visible response");
  assert.equal(frames.at(-1).result.ok, false);
  assert.equal(frames.at(-1).result.text, undefined);
});

function setup(t, complete = true) {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-response-stream-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const credentials = join(root, "oauth.json");
  writeFileSync(credentials, JSON.stringify({ "openai-codex": { access: "fixture-token" } }));
  const fixture = join(root, "provider.mjs");
  writeFileSync(fixture, `
import assert from 'node:assert/strict';
globalThis.fetch = async (_url, init) => {
  const body = JSON.parse(init.body);
  assert.equal(body.model, 'gpt-5.5');
  assert.deepEqual(body.reasoning, { effort: 'medium' });
  const events = [
    {type:'response.reasoning_text.delta', delta:'PRIVATE_REASONING'},
    {type:'response.output_text.delta', delta:'Visible response'},
    ...(${complete} ? [{type:'response.output_text.done',text:'Visible response'}, {type:'response.completed',response:{status:'completed',usage:{input_tokens:2,output_tokens:3}}}] : [])
  ];
  return new Response(events.map(value => 'data: '+JSON.stringify(value)+'\\n\\n').join(''));
};
`);
  const request = {
    protocolVersion: 1, type: "next-step", responseEvents: "text-v1", cwd: root,
    model: "openai-codex:gpt-5.5", thinkingLevel: "medium", systemPrompt: "Local response test.",
    messages: [{ role: "user", content: "Local test" }], prompt: "Local test", tools: [],
    toolPolicy: { tools: [], mcps: false }, oauthCredentialsPath: credentials,
    oauthAllowEnvToken: false, apiKeyEnv: "KUZUSHI_TEST_NO_API_KEY", maxTokens: 64,
  };
  return { root, fixture, request };
}

function run(fixture, request) {
  const bridge = fileURLToPath(new URL("../langgraph-bridge.mjs", import.meta.url));
  return spawnSync(process.execPath, ["--import", fixture, bridge], {
    input: JSON.stringify(request), encoding: "utf8", timeout: 10_000,
    env: { PATH: process.env.PATH, LANG: "en_US.UTF-8" },
  });
}

function parseFrames(text) {
  return text.trimEnd().split("\n").map((line) => {
    assert.equal(line[0], "\x1e");
    return JSON.parse(line.slice(1));
  });
}
