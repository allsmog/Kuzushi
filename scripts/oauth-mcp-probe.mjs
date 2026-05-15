#!/usr/bin/env node
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
// Reproduce the bridge's multi-turn agent loop with real MCP tools.
import { Agent } from "@earendil-works/pi-agent-core";
import { getModel } from "@earendil-works/pi-ai";

const credsPath = path.join(homedir(), ".kuzushi", "oauth-credentials.json");
const creds = JSON.parse(readFileSync(credsPath, "utf8"));
const token = creds.anthropic.access;

const requestedModel = process.argv[2] ?? process.env.KUZUSHI_MODEL;
if (!requestedModel) {
  console.error(
    "Usage: node scripts/oauth-mcp-probe.mjs <anthropic-model-id> [reasoning] [structured]",
  );
  console.error("Set an explicit model argument or KUZUSHI_MODEL; no fallback is chosen.");
  process.exit(1);
}
if (requestedModel.includes(":") && !requestedModel.startsWith("anthropic:")) {
  console.error(`Expected an Anthropic model for this probe, got ${requestedModel}`);
  process.exit(1);
}
const modelId = requestedModel.replace(/^anthropic:/, "");
const reasoning = (process.argv[3] || "off") === "off" ? undefined : process.argv[3];
console.error(`[probe] model=${modelId} reasoning=${reasoning ?? "off"}`);

const servers = {
  "tree-sitter": "/home/user/Kuzushi/target/release/kuzushi-mcp-treesitter",
  joern: "/home/user/Kuzushi/target/release/kuzushi-mcp-joern",
  codeql: "/home/user/Kuzushi/target/release/kuzushi-mcp-codeql",
};

const handles = {};
async function spawnHandle(label, bin) {
  const child = spawnProbeServer(bin);
  const handle = createHandle(child);
  child.stdout.on("data", (chunk) => handleStdoutChunk(handle, chunk));
  await mcpRequest(handle, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "p", version: "0" },
  });
  const list = await mcpRequest(handle, "tools/list");
  handle.tools = list.tools;
  handle.send = (method, params) => mcpRequest(handle, method, params);
  return handle;
}

function spawnProbeServer(bin) {
  const child = spawn(bin, [], {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: "/tmp/targets/demo-repo",
  });
  child.stderr.on("data", () => {}); // drain
  return child;
}

function createHandle(child) {
  child.stdout.setEncoding("utf8");
  return { child, buf: "", pending: new Map(), nextId: 1, tools: [] };
}

function handleStdoutChunk(handle, chunk) {
  handle.buf += chunk;
  while (handle.buf.indexOf("\n") >= 0) {
    const idx = handle.buf.indexOf("\n");
    const line = handle.buf.slice(0, idx).trim();
    handle.buf = handle.buf.slice(idx + 1);
    handleStdoutLine(handle, line);
  }
}

function handleStdoutLine(handle, line) {
  if (!line) return;
  try {
    const data = JSON.parse(line);
    const pending = handle.pending.get(data.id);
    if (!pending) return;
    handle.pending.delete(data.id);
    settleMcpResponse(pending, data);
  } catch {}
}

function settleMcpResponse(pending, data) {
  if (data.error) {
    pending.reject(new Error(JSON.stringify(data.error)));
    return;
  }
  pending.resolve(data.result);
}

function mcpRequest(handle, method, params) {
  return new Promise((resolve, reject) => {
    const id = handle.nextId++;
    handle.pending.set(id, { resolve, reject });
    const body = { jsonrpc: "2.0", id, method };
    if (params !== undefined) body.params = params;
    handle.child.stdin.write(`${JSON.stringify(body)}\n`);
  });
}

for (const [label, bin] of Object.entries(servers)) {
  handles[label] = await spawnHandle(label, bin);
  console.error(`[probe] ${label}: ${handles[label].tools.length} tools`);
}

const tools = [];
for (const h of Object.values(handles)) {
  for (const t of h.tools) {
    const safeName = t.name.replace(/[^a-zA-Z0-9_]/g, "_");
    tools.push({
      name: safeName,
      description: t.description,
      parameters: t.inputSchema ?? { type: "object", additionalProperties: true },
      execute: async (_id, params) => {
        const startedAt = Date.now();
        const result = await h.send("tools/call", { name: t.name, arguments: params ?? {} });
        const text = result?.content?.[0]?.text
          ? String(result.content[0].text)
          : JSON.stringify(result);
        console.error(`[probe] ${t.name} -> ${Date.now() - startedAt}ms ${text.length}B`);
        return { content: [{ type: "text", text }], details: result };
      },
    });
  }
}
console.error(`[probe] total tools advertised: ${tools.length}`);

const model = getModel("anthropic", modelId);
const baseSystemPrompt =
  "You are a code-analysis test agent. Use tree_sitter_node_at on main.c lines 5, 9, 10, 15 (separate calls), then tree_sitter:callers for handle_request and snprintf, then summarize.";

const structuredOutputContract = [
  "",
  "Structured output contract:",
  "Return only strict JSON for `analysis`. Do not include markdown fences, prose, or trailing commentary.",
  "Required JSON schema:",
  JSON.stringify(
    { type: "object", properties: { summary: { type: "string" } }, required: ["summary"] },
    null,
    2,
  ),
].join("\n");

const useStructuredOutput = process.argv[4] === "structured";
const systemPrompt = useStructuredOutput
  ? `${baseSystemPrompt}\n${structuredOutputContract}`
  : baseSystemPrompt;
console.error("[probe] structuredOutput:", useStructuredOutput);

const agent = new Agent({
  initialState: {
    systemPrompt,
    model,
    tools,
    messages: [],
    thinkingLevel: reasoning ?? "off",
  },
  beforeToolCall: async () => undefined,
  getApiKey: async () => token,
});

let text = "";
agent.subscribe((event) => {
  if (event?.type === "message_update" && event.assistantMessageEvent?.type === "text_delta") {
    text += event.assistantMessageEvent.delta ?? "";
  }
});

console.error("[probe] prompting...");
const startedAt = Date.now();
await agent.prompt(
  "Run all four node_at calls (lines 5, 9, 10, 15) in parallel as a batch, then run both callers calls (handle_request, snprintf) in parallel as a batch, then summarize.",
);
console.error("[probe] done in", Date.now() - startedAt, "ms");
console.error("[probe] errorMessage:", agent.state.errorMessage);
console.error("[probe] text:", text.slice(0, 500));
console.error("[probe] usage:", JSON.stringify(agent.state.usage)?.slice(0, 200));

for (const h of Object.values(handles)) h.child.kill();
