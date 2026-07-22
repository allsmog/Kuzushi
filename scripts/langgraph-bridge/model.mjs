import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { AnthropicVertex } from "@anthropic-ai/vertex-sdk";
import { ChatAnthropic } from "@langchain/anthropic";
import { AIMessage, SystemMessage, ToolMessage } from "@langchain/core/messages";
import { ChatOpenAI } from "@langchain/openai";
import { oauthModelForRequest } from "./oauth-models.mjs";

export function parseModelSpec(spec) {
  const value = String(spec ?? "");
  const idx = value.indexOf(":");
  if (idx <= 0 || idx === value.length - 1) {
    throw new Error(`model must use provider:model syntax, got ${JSON.stringify(value)}`);
  }
  return [value.slice(0, idx), value.slice(idx + 1)];
}

export function modelForRequest(request) {
  const [provider, modelName] = parseModelSpec(request.model);
  const oauthModel = oauthModelForProvider(request, provider, modelName);
  if (oauthModel) return oauthModel;
  const model = apiModelForProvider(request, provider, modelName);
  if (!model) {
    throw new Error(`LangGraph bridge does not support provider ${JSON.stringify(provider)}`);
  }
  return model;
}

function apiModelForProvider(request, provider, modelName) {
  const options = modelOptions(request);
  if (provider === "openai" || provider === "openai-codex") {
    return new ChatOpenAI({
      model: modelName,
      apiKey: credentialForRequest(request, provider, "OPENAI_API_KEY"),
      configuration: baseUrlConfig(request),
      ...options,
    });
  }
  return anthropicModelForProvider(request, provider, modelName, options);
}

function anthropicModelForProvider(request, provider, modelName, options) {
  if (provider === "anthropic") {
    return new ChatAnthropic({
      model: modelName,
      apiKey: credentialForRequest(request, provider, "ANTHROPIC_API_KEY"),
      ...options,
    });
  }
  if (provider === "vertex-anthropic") {
    return new ChatAnthropic({
      model: modelName,
      createClient: (clientOptions) => vertexAnthropicClient(request, clientOptions),
      ...options,
    });
  }
  return undefined;
}

// Claude on Google Vertex AI. The credential is GCP Application Default
// Credentials (google-auth-library), not an API key: the request's
// apiKey/apiKeyEnv slot carries the GCP project id, and the region comes from
// CLOUD_ML_REGION (defaulting to the global endpoint). Both stay optional —
// AnthropicVertex resolves a missing project id from the ADC credential.
function vertexAnthropicClient(request, clientOptions) {
  const { apiKey, dangerouslyAllowBrowser, ...options } = clientOptions ?? {};
  return new AnthropicVertex({
    ...options,
    projectId: vertexProjectId(request) ?? null,
    region: nonEmpty(process.env.CLOUD_ML_REGION) ?? "global",
  });
}

function vertexProjectId(request) {
  return (
    nonEmpty(request.apiKey) ??
    nonEmpty(process.env[request.apiKeyEnv ?? "ANTHROPIC_VERTEX_PROJECT_ID"]) ??
    nonEmpty(process.env.ANTHROPIC_VERTEX_PROJECT_ID)
  );
}

function oauthModelForProvider(request, provider, modelName) {
  const token = oauthAccessToken(provider);
  if (!token) return undefined;
  if (provider === "openai-codex") return oauthModelForRequest(provider, modelName, token, request);
  if (provider === "anthropic" && !apiKeyCredential(request, "ANTHROPIC_API_KEY")) {
    return oauthModelForRequest(provider, modelName, token, request);
  }
  return undefined;
}

export function credentialForRequest(request, provider, defaultEnv) {
  return (
    apiKeyCredential(request, defaultEnv) ??
    oauthAccessToken(provider)
  );
}

function apiKeyCredential(request, defaultEnv) {
  return nonEmpty(request.apiKey) ?? nonEmpty(process.env[request.apiKeyEnv ?? defaultEnv]);
}

export function oauthAccessToken(provider) {
  const entry = freshOauthCredentialBag()[oauthCredentialProvider(provider)];
  return nonEmpty(entry?.access);
}

function oauthCredentialProvider(provider) {
  return provider === "openai" ? "openai-codex" : provider;
}

export function oauthCredentialBag() {
  try {
    return JSON.parse(readFileSync(oauthCredentialsPath(), "utf8"));
  } catch {
    return {};
  }
}

function freshOauthCredentialBag() {
  const bag = oauthCredentialBag();
  return refreshExpiredAnthropicCredential(bag);
}

function refreshExpiredAnthropicCredential(bag) {
  const credential = bag.anthropic;
  if (!expiredOAuthCredential(credential)) return bag;
  const refreshed = refreshAnthropicCredentialSync(credential.refresh);
  if (!refreshed) return bag;
  const nextBag = { ...bag, anthropic: refreshed };
  writeOauthCredentialBag(nextBag);
  return nextBag;
}

function expiredOAuthCredential(credential) {
  return credential?.refresh && (!credential.access || Date.now() >= Number(credential.expires ?? 0) - 300_000);
}

function refreshAnthropicCredentialSync(refreshToken) {
  const script = `
const body = {
  grant_type: "refresh_token",
  refresh_token: process.env.KUZUSHI_ANTHROPIC_REFRESH_TOKEN,
  client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
  scope: "user:profile user:inference user:sessions:claude_code user:mcp_servers",
};
const response = await fetch("https://platform.claude.com/v1/oauth/token", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});
process.stdout.write(await response.text());
process.exitCode = response.ok ? 0 : 1;
`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    env: { ...process.env, KUZUSHI_ANTHROPIC_REFRESH_TOKEN: refreshToken },
    timeout: 120_000,
  });
  if (result.status !== 0) return undefined;
  return anthropicCredentialFromRefreshResponse(result.stdout, refreshToken);
}

function anthropicCredentialFromRefreshResponse(raw, priorRefresh) {
  try {
    const parsed = JSON.parse(raw);
    const access = nonEmpty(parsed.access_token);
    if (!access) return undefined;
    return {
      access,
      refresh: nonEmpty(parsed.refresh_token) ?? priorRefresh,
      expires: Date.now() + Math.max(1, Number(parsed.expires_in ?? 3600)) * 1000,
    };
  } catch {
    return undefined;
  }
}

export function writeOauthCredentialBag(bag) {
  const credentialsPath = oauthCredentialsPath();
  mkdirSync(path.dirname(credentialsPath), { recursive: true, mode: 0o700 });
  const tmp = `${credentialsPath}.tmp.${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(bag, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, credentialsPath);
  chmodSync(credentialsPath, 0o600);
}

export function oauthCredentialsPath() {
  const pathFromEnv = process.env.KUZUSHI_OAUTH_CREDENTIALS;
  return pathFromEnv || path.join(homedir(), ".kuzushi", "oauth-credentials.json");
}

function nonEmpty(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function modelOptions(request) {
  const options = {};
  const temperature = numericTemperature(request);
  const maxTokens = request.maxOutputTokens ?? request.max_output_tokens ?? request.maxTokens;
  if (temperature !== undefined) options.temperature = temperature;
  if (Number.isFinite(Number(maxTokens)) && Number(maxTokens) > 0) {
    options.maxTokens = Math.floor(Number(maxTokens));
  }
  return options;
}

function baseUrlConfig(request) {
  const baseURL = request.baseUrl ?? request.base_url;
  return baseURL ? { baseURL } : undefined;
}

function numericTemperature(request) {
  const raw = request?.temperature ?? request?.samplingTemperature ?? request?.sampling_temperature;
  if (raw === undefined || raw === null) return undefined;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 && value <= 2 ? value : undefined;
}

export function appendStructuredOutputContract(systemPrompt, structuredOutput) {
  const contract = structuredOutput ?? undefined;
  if (!contract) return String(systemPrompt ?? "");
  const name = contract.name ?? "structured_response";
  const schema = JSON.stringify(contract.schema ?? {}, null, 2);
  const strict = contract.strict ? "strict " : "";
  return `${systemPrompt ?? ""}\n\nStructured output contract:\nReturn only ${strict}JSON for \`${name}\`. Do not include markdown fences, prose, or trailing commentary.\nRequired JSON schema:\n${schema}`;
}

export function systemMessageForRequest(request, systemPrompt) {
  if (providerForRequest(request) !== "anthropic") return new SystemMessage(systemPrompt ?? "");
  const text = String(systemPrompt ?? "");
  if (!text.trim()) return new SystemMessage("");
  return new SystemMessage({ content: [cacheableTextBlock(text)] });
}

export function cacheableTextBlock(text) {
  return {
    type: "text",
    text,
    cache_control: { type: "ephemeral" },
  };
}

function providerForRequest(request) {
  try {
    return parseModelSpec(request.model)[0];
  } catch {
    return "";
  }
}

export function maybeParseJson(text) {
  if (!text) return undefined;
  const candidate = jsonCandidate(text);
  try {
    return JSON.parse(candidate);
  } catch {
    return parseEmbeddedJson(candidate);
  }
}

function jsonCandidate(text) {
  const trimmed = String(text).trim();
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  return fenced ? fenced[1].trim() : trimmed;
}

function parseEmbeddedJson(candidate) {
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start < 0 || end <= start) return undefined;
  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return undefined;
  }
}

export function messageText(message) {
  const content = message?.content;
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map(contentPartText).join("");
}

function contentPartText(part) {
  if (typeof part === "string") return part;
  return part?.text ?? part?.content ?? "";
}

export function usageFromMessage(message) {
  const usage = message?.usage_metadata ?? message?.response_metadata?.tokenUsage ?? {};
  const inputTokens = optionalTokenCount(
    usage.input_tokens ?? usage.promptTokens ?? usage.inputTokens,
  );
  const outputTokens = optionalTokenCount(
    usage.output_tokens ?? usage.completionTokens ?? usage.outputTokens,
  );
  const result = { inputTokens, outputTokens };
  const rawCost =
    usage.cost_usd ??
    usage.costUsd ??
    message?.response_metadata?.cost_usd ??
    message?.response_metadata?.costUsd;
  if (rawCost === undefined || rawCost === null) return result;
  const costUsd = Number(rawCost);
  if (!Number.isFinite(costUsd) || costUsd < 0) {
    throw new Error("provider usage cost must be a finite non-negative number");
  }
  return { ...result, costUsd };
}

function optionalTokenCount(raw) {
  if (raw === undefined || raw === null) return undefined;
  const count = Number(raw);
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error("provider token usage must be a non-negative safe integer");
  }
  return count;
}

export function isAiMessage(message) {
  return (
    message instanceof AIMessage ||
    message?._getType?.() === "ai" ||
    Array.isArray(message?.tool_calls)
  );
}

export function toolMessageForOutput(call, output) {
  if (output instanceof ToolMessage || output?._getType?.() === "tool") return output;
  const content = typeof output === "string" ? output : JSON.stringify(output ?? null);
  return new ToolMessage({
    tool_call_id: call.id ?? call.name,
    content,
  });
}
