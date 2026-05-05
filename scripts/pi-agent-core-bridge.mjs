#!/usr/bin/env node
import process from "node:process";

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    data += chunk;
  }
  return data;
}

function providerEnvName(provider) {
  return `${provider.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_API_KEY`;
}

function parseModelSpec(spec) {
  const idx = spec.indexOf(":");
  if (idx <= 0 || idx === spec.length - 1) {
    throw new Error(`model must use provider:model syntax, got ${JSON.stringify(spec)}`);
  }
  return [spec.slice(0, idx), spec.slice(idx + 1)];
}

function extractTextFromState(agent) {
  const messages = agent?.state?.messages;
  if (!Array.isArray(messages)) return "";
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const message = messages[i];
    if (message?.role !== "assistant" && message?.type !== "assistant") continue;
    const content = message.content;
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
      return content
        .map((part) => {
          if (typeof part === "string") return part;
          if (typeof part?.text === "string") return part.text;
          if (typeof part?.content === "string") return part.content;
          return "";
        })
        .join("");
    }
  }
  return "";
}

function maybeParseJson(text) {
  if (!text) return undefined;
  const trimmed = text.trim();
  const fence = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  const candidate = fence ? fence[1].trim() : trimmed;
  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1));
      } catch {
        return undefined;
      }
    }
    return undefined;
  }
}

function subscribeText(agent, onText) {
  if (typeof agent?.subscribe !== "function") return;
  agent.subscribe((event) => {
    if (event?.type !== "message_update") return;
    const assistantEvent = event.assistantMessageEvent;
    if (assistantEvent?.type === "text_delta" && typeof assistantEvent.delta === "string") {
      onText(assistantEvent.delta);
    }
  });
}

async function runAgent(AgentCtor, model, request) {
  const agent = new AgentCtor({
    initialState: {
      systemPrompt: request.systemPrompt,
      model,
      tools: [],
      messages: [],
      thinkingLevel: "low",
    },
    getApiKey: async (provider) =>
      request.apiKey ??
      process.env[request.apiKeyEnv] ??
      process.env[providerEnvName(provider)] ??
      process.env.OPENAI_API_KEY,
  });

  let text = "";
  subscribeText(agent, (delta) => {
    text += delta;
  });

  if (typeof agent.prompt === "function") {
    const result = await agent.prompt(request.prompt);
    if (typeof result === "string") text += result;
  } else if (typeof agent.run === "function") {
    const result = await agent.run(request.prompt);
    if (typeof result === "string") text += result;
  } else if (typeof agent.followUp === "function") {
    const promptMessage = {
      role: "user",
      content: [{ type: "text", text: request.prompt }],
    };
    agent.followUp(promptMessage);
  } else {
    throw new Error("Unsupported pi-agent-core Agent API: no prompt/run/followUp method found");
  }

  if (typeof agent.waitForIdle === "function") {
    await agent.waitForIdle();
  }

  if (!text.trim()) {
    text = extractTextFromState(agent);
  }

  return text.trim();
}

async function main() {
  const request = JSON.parse(await readStdin());
  const [{ Agent, default: DefaultAgent }, { getModel }] = await Promise.all([
    import("@mariozechner/pi-agent-core"),
    import("@mariozechner/pi-ai"),
  ]);
  const AgentCtor = Agent ?? DefaultAgent;
  if (!AgentCtor) throw new Error("@mariozechner/pi-agent-core did not export Agent");

  const [provider, modelId] = parseModelSpec(request.model);
  const model = getModel(provider, modelId);
  const text = await runAgent(AgentCtor, model, request);

  process.stdout.write(
    JSON.stringify({
      ok: true,
      text,
      structured: maybeParseJson(text),
    }),
  );
}

main().catch((error) => {
  process.stdout.write(
    JSON.stringify({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    }),
  );
  process.exitCode = 1;
});
