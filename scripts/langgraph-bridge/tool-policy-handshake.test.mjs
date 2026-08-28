import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { fileToolsForRequest } from "./file-tools.mjs";
import {
  acknowledgeToolPolicy,
  authorizeExecutingQuery,
  READ_ONLY_ASK_POLICY_ID,
  READ_ONLY_ASK_POLICY_PROTOCOL_VERSION,
  READ_ONLY_ASK_TOOLS,
} from "./tool-policy-handshake.mjs";

function request(overrides = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "kuzushi-ask-policy-")));
  return {
    cwd: root,
    authorization: {
      protocolVersion: READ_ONLY_ASK_POLICY_PROTOCOL_VERSION,
      policyId: READ_ONLY_ASK_POLICY_ID,
      policy: {
        profile: READ_ONLY_ASK_POLICY_ID,
        tools: [...READ_ONLY_ASK_TOOLS],
        mcps: false,
        mcpReadRoots: [root],
        ...overrides,
      },
    },
  };
}

test("read-only Ask acknowledgement reports the exact mounted authority", () => {
  const policyRequest = request();
  const result = acknowledgeToolPolicy(policyRequest);

  assert.equal(result.ok, true);
  assert.deepEqual(result.acknowledgement, expectedReceipt(policyRequest));
});

test("write and shell tool probes are not mounted", () => {
  const policyRequest = request();
  const mounted = new Set(
    fileToolsForRequest({ toolPolicy: policyRequest.authorization.policy }).map((tool) => tool.name),
  );

  assert.equal(mounted.has("Write"), false);
  assert.equal(mounted.has("Shell"), false);
  assert.equal(mounted.has("Bash"), false);
});

test("unknown policy ids and MCP attachment fail closed", () => {
  const unknown = request();
  unknown.authorization.policyId = "ask.unknown.v9";
  assert.throws(() => acknowledgeToolPolicy(unknown), /unknown Ask tool-policy id/);
  assert.throws(() => acknowledgeToolPolicy(request({ mcps: true })), /cannot mount MCP/);
});

test("the executing query acknowledges the exact policy it mounts", () => {
  const query = request();
  query.toolPolicy = query.authorization.policy;

  assert.deepEqual(authorizeExecutingQuery(query), expectedReceipt(query));
});

test("the executing query refuses a policy changed after authorization", () => {
  const query = request();
  query.toolPolicy = { ...query.authorization.policy, tools: ["Read", "Write"] };

  assert.throws(
    () => authorizeExecutingQuery(query),
    /executing Ask tool policy differs from its authorization/,
  );
});

test("the executing query refuses a read root outside its target", () => {
  const query = request();
  const outside = realpathSync(mkdtempSync(join(tmpdir(), "kuzushi-ask-outside-")));
  query.authorization.policy.mcpReadRoots = [outside];
  query.toolPolicy = query.authorization.policy;

  assert.throws(
    () => authorizeExecutingQuery(query),
    /read root must match the canonical execution target/,
  );
});

test("authorized bridge query denies model-requested Write, Shell, and Bash calls", () => {
  const query = authorizedProbeRequest();
  const root = query.cwd;
  const sentinel = join(root, "sentinel.txt");
  const created = join(root, "created-by-probe.txt");
  const original = Buffer.from("operator-owned sentinel\n");
  writeFileSync(sentinel, original);

  const response = runBridgeWithDeniedToolProbe(query, sentinel, created);

  assert.equal(response.ok, true);
  assert.equal(response.text, "all denied probes observed");
  assert.deepEqual(response.toolPolicyAcknowledgement, expectedReceipt(query));
  assert.deepEqual(readFileSync(sentinel), original);
  assert.equal(existsSync(created), false);
});

function expectedReceipt(policyRequest) {
  return {
    protocolVersion: READ_ONLY_ASK_POLICY_PROTOCOL_VERSION,
    policyId: READ_ONLY_ASK_POLICY_ID,
    effectiveTools: [...READ_ONLY_ASK_TOOLS],
    readRoots: [...policyRequest.authorization.policy.mcpReadRoots],
    writeShellToolsMounted: false,
    mcpToolsMounted: false,
  };
}

function authorizedProbeRequest() {
  const query = request();
  const credentials = join(query.cwd, "oauth.json");
  writeFileSync(credentials, JSON.stringify({ anthropic: { access: "test-oauth-token" } }));
  return {
    ...query,
    protocolVersion: 1,
    model: "anthropic:claude-test",
    prompt: "Probe the requested tools, then report the result.",
    systemPrompt: "Test read-only authorization.",
    maxTokens: 256,
    apiKeyEnv: "KUZUSHI_TEST_DEFINITELY_MISSING_ANTHROPIC_KEY",
    oauthCredentialsPath: credentials,
    oauthAllowEnvToken: false,
    toolPolicy: query.authorization.policy,
  };
}

function runBridgeWithDeniedToolProbe(query, sentinel, created) {
  const fixture = join(query.cwd, "fake-model-preload.mjs");
  writeFileSync(fixture, deniedToolProbeModel(sentinel, created));
  const bridge = fileURLToPath(new URL("../langgraph-bridge.mjs", import.meta.url));
  const result = spawnSync(process.execPath, ["--import", fixture, bridge], {
    input: JSON.stringify(query),
    encoding: "utf8",
    env: { ...process.env },
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function deniedToolProbeModel(sentinel, created) {
  const calls = [
    { name: "Write", input: { file_path: sentinel, content: "mutated" } },
    { name: "Shell", input: { command: `printf mutated > ${sentinel}` } },
    { name: "Bash", input: { command: `touch ${created}` } },
  ];
  return `
let turn = 0;
const calls = ${JSON.stringify(calls)};
globalThis.fetch = async (_url, options) => {
  const body = JSON.parse(options.body);
  if (turn > 0) {
    const expected = \`Unknown tool \${calls[turn - 1].name}\`;
    const observed = body.messages.some((message) =>
      Array.isArray(message.content) && message.content.some((part) =>
        part.type === "tool_result" && part.content === expected));
    if (!observed) throw new Error(\`missing denied-tool result: \${expected}\`);
  }
  const content = turn < calls.length
    ? [{ type: "tool_use", id: \`probe-\${turn}\`, ...calls[turn] }]
    : [{ type: "text", text: "all denied probes observed" }];
  turn += 1;
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify({
      content,
      stop_reason: turn <= calls.length ? "tool_use" : "end_turn",
    }),
  };
};
`;
}
