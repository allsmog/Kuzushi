#!/usr/bin/env node
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
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

function normalizeThinkingLevel(value) {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
  if (!normalized) return undefined;
  if (normalized === "xhigh" || normalized === "xtrahigh" || normalized === "extrahigh") {
    return "xhigh";
  }
  if (normalized === "high") return "high";
  if (normalized === "medium" || normalized === "med") return "medium";
  if (normalized === "low") return "low";
  return undefined;
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
  const thinkingLevel =
    normalizeThinkingLevel(request.thinkingLevel) ??
    normalizeThinkingLevel(process.env.KUZUSHI_THINKING_LEVEL) ??
    normalizeThinkingLevel(process.env.KUZUSHI_REASONING_EFFORT) ??
    "low";
  const agent = new AgentCtor({
    initialState: {
      systemPrompt: request.systemPrompt,
      model,
      tools: [],
      messages: [],
      thinkingLevel,
    },
    getApiKey: async (provider) =>
      (await getFreshOAuthAccessTokenForProvider(provider)) ??
      providerAuthToken(provider) ??
      configuredProviderApiKey(provider, request) ??
      process.env[providerEnvName(provider)] ??
      (provider === "openai" ? process.env.OPENAI_API_KEY : undefined),
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

function oauthCredentialsPath(home = os.homedir()) {
  return path.join(home, ".kuzushi", "oauth-credentials.json");
}

function readOauthCredentials(home = os.homedir()) {
  const filePath = oauthCredentialsPath(home);
  if (!existsSync(filePath)) return {};
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeOauthCredentials(bag, home = os.homedir()) {
  const filePath = oauthCredentialsPath(home);
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(bag, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    chmodSync(filePath, 0o600);
  } catch {
    /* ignore */
  }
  return filePath;
}

function isProviderCreds(value) {
  return (
    value &&
    typeof value === "object" &&
    typeof value.refresh === "string" &&
    typeof value.access === "string" &&
    typeof value.expires === "number"
  );
}

function normalizeOAuthProvider(provider) {
  const normalized = String(provider ?? "")
    .trim()
    .toLowerCase();
  if (normalized === "anthropic" || normalized === "claude") return "anthropic";
  if (normalized === "openai-codex" || normalized === "codex") return "openai-codex";
  throw new Error("auth login supports providers: openai-codex, anthropic");
}

async function loadOAuthModule() {
  try {
    return await import("@mariozechner/pi-ai/oauth");
  } catch (error) {
    throw new Error(
      `Could not load @mariozechner/pi-ai/oauth for OAuth login/refresh: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

async function getFreshOAuthAccessTokenForProvider(provider) {
  if (provider !== "anthropic" && provider !== "openai-codex") return undefined;
  const bag = readOauthCredentials();
  const creds = bag[provider];
  if (!isProviderCreds(creds)) return undefined;
  if (Date.now() < creds.expires) return creds.access;

  try {
    const oauth = await loadOAuthModule();
    const refresh =
      provider === "anthropic" ? oauth.refreshAnthropicToken : oauth.refreshOpenAICodexToken;
    if (typeof refresh !== "function") return undefined;
    const next = await refresh(creds.refresh);
    if (!isProviderCreds(next)) return undefined;
    writeOauthCredentials({ ...bag, [provider]: next });
    return next.access;
  } catch {
    return undefined;
  }
}

function providerAuthToken(provider) {
  if (provider === "anthropic") {
    return process.env.ANTHROPIC_AUTH_TOKEN ?? process.env.ANTHROPIC_OAUTH_TOKEN;
  }
  return undefined;
}

function configuredProviderApiKey(provider, request) {
  const providerEnv = providerEnvName(provider);
  if (request.apiKeyEnv === providerEnv) return request.apiKey;
  if (request.apiKeyEnv && request.apiKeyEnv !== "OPENAI_API_KEY") return request.apiKey;
  return undefined;
}

async function runOAuthLogin(rawProvider) {
  const provider = normalizeOAuthProvider(rawProvider);
  const oauth = await loadOAuthModule();
  const login = provider === "anthropic" ? oauth.loginAnthropic : oauth.loginOpenAICodex;
  if (typeof login !== "function") {
    throw new Error(`@mariozechner/pi-ai/oauth does not expose a login flow for ${provider}`);
  }

  const creds = await login({
    onAuth: (info) => {
      process.stdout.write(`Open this URL to authorize ${provider}: ${info.url}\n`);
      tryOpenBrowser(info.url);
    },
    onPrompt: async () => promptManualCode(),
    onManualCodeInput: async () => promptManualCode(),
    onProgress: (message) => process.stdout.write(`[oauth] ${message}\n`),
  });
  const persistable = {
    ...creds,
    refresh: String(creds?.refresh ?? ""),
    access: String(creds?.access ?? ""),
    expires: Number(creds?.expires ?? 0),
  };
  if (!persistable.refresh || !persistable.access) {
    throw new Error(`${provider} OAuth flow returned no usable credentials`);
  }
  const bag = readOauthCredentials();
  const filePath = writeOauthCredentials({ ...bag, [provider]: persistable });
  process.stdout.write(`${provider} OAuth credentials saved to ${filePath}\n`);
}

function tryOpenBrowser(url) {
  if (process.env.KUZUSHI_DISABLE_BROWSER_OPEN === "1") return;
  const command =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.unref();
  } catch {
    /* URL is printed for manual use. */
  }
}

async function promptManualCode() {
  process.stdout.write(
    "\nIf the browser cannot reach the local callback, paste the final redirect URL or code#state fragment.\n> ",
  );
  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: process.stdin.isTTY,
  });
  try {
    return (await rl.question("")).trim();
  } finally {
    rl.close();
  }
}

async function main() {
  if (process.argv[2] === "--oauth-login") {
    await runOAuthLogin(process.argv[3] ?? "openai-codex");
    return;
  }

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
