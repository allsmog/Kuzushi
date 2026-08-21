import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { AnthropicVertex } from "@anthropic-ai/vertex-sdk";
import { ChatAnthropic } from "@langchain/anthropic";
import { AIMessage, SystemMessage, ToolMessage } from "@langchain/core/messages";
import { ChatOpenAI } from "@langchain/openai";
import { BridgePublicError } from "./errors.mjs";
import { oauthModelForRequest } from "./oauth-models.mjs";

export const DEFAULT_MAX_MODEL_TURNS = 12;
const OPENAI_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token";

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
      ...anthropicStreamingOptions(options),
      ...options,
    });
  }
  if (provider === "vertex-anthropic") {
    return new ChatAnthropic({
      model: modelName,
      createClient: (clientOptions) => vertexAnthropicClient(request, clientOptions),
      ...anthropicStreamingOptions(options),
      ...options,
    });
  }
  return undefined;
}

// The Anthropic SDK rejects non-streaming requests whose max_tokens implies a
// response that could outlive its 10-minute non-streaming ceiling, so large
// output budgets must go over the streaming transport (invoke() still returns
// one final message).
function anthropicStreamingOptions(options) {
  return options.maxTokens > 8192 ? { streaming: true } : {};
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
  if (provider === "openai-codex") return requiredOauthModel(request, provider, modelName);
  if (provider !== "anthropic") return undefined;
  if (apiKeyCredential(request, "ANTHROPIC_API_KEY")) return undefined;
  return optionalOauthModel(request, provider, modelName);
}

function requiredOauthModel(request, provider, modelName) {
  const model = optionalOauthModel(request, provider, modelName);
  if (!model) throw new BridgePublicError("authentication");
  return model;
}

function optionalOauthModel(request, provider, modelName) {
  const credential = oauthCredentialForRequest(request, provider);
  if (!credential) return undefined;
  return oauthModelForRequest(provider, modelName, credential.access, {
    ...request,
    oauthAccountId: credential.accountId,
  });
}

export function credentialForRequest(request, provider, defaultEnv) {
  const credential = apiKeyCredential(request, defaultEnv);
  if (!credential) throw new BridgePublicError("authentication");
  return credential;
}

function apiKeyCredential(request, defaultEnv) {
  return nonEmpty(request.apiKey) ?? nonEmpty(process.env[request.apiKeyEnv ?? defaultEnv]);
}

export function oauthAccessToken(request, provider) {
  return oauthCredentialForRequest(request, provider)?.access;
}

function oauthCredentialForRequest(request, provider) {
  const entry = freshOauthCredentialBag(request, provider)[oauthCredentialProvider(provider)];
  const access = nonEmpty(entry?.access) ?? allowedOauthEnvToken(request, provider);
  if (!access) return undefined;
  return {
    access,
    accountId: nonEmpty(entry?.accountId) ?? openAiAccountIdFromJwt(access),
  };
}

function oauthCredentialProvider(provider) {
  return provider === "openai" ? "openai-codex" : provider;
}

export function oauthCredentialBag(credentialsPath = oauthCredentialsPath()) {
  try {
    return JSON.parse(readFileSync(credentialsPath, "utf8"));
  } catch {
    return {};
  }
}

function freshOauthCredentialBag(request, provider) {
  const credentialsPath = requestOauthCredentialsPath(request);
  const bag = credentialsPath ? oauthCredentialBag(credentialsPath) : {};
  if (provider === "anthropic") {
    return refreshExpiredAnthropicCredential(bag, credentialsPath);
  }
  if (oauthCredentialProvider(provider) === "openai-codex") {
    return refreshExpiredOpenAiCredential(bag, credentialsPath);
  }
  return bag;
}

function refreshExpiredAnthropicCredential(bag, credentialsPath) {
  const credential = bag.anthropic;
  if (!expiredOAuthCredential(credential)) return bag;
  const refreshed = refreshAnthropicCredentialSync(credential.refresh);
  if (!refreshed) return bag;
  const nextBag = { ...bag, anthropic: refreshed };
  if (credentialsPath) writeOauthCredentialBag(nextBag, credentialsPath);
  return nextBag;
}

function refreshExpiredOpenAiCredential(bag, credentialsPath) {
  const credential = bag["openai-codex"];
  if (!expiredOAuthCredential(credential)) return bag;
  const refreshed = refreshOpenAiCredentialSync(credential.refresh);
  if (!refreshed) return bag;
  const nextBag = { ...bag, "openai-codex": refreshed };
  if (credentialsPath) writeOauthCredentialBag(nextBag, credentialsPath);
  return nextBag;
}

function requestOauthCredentialsPath(request) {
  return nonEmpty(request?.oauthCredentialsPath ?? request?.oauth_credentials_path);
}

function allowedOauthEnvToken(request, provider) {
  const allowed = request?.oauthAllowEnvToken ?? request?.oauth_allow_env_token;
  if (allowed !== true || provider !== "anthropic") return undefined;
  return nonEmpty(process.env.ANTHROPIC_OAUTH_TOKEN) ?? nonEmpty(process.env.ANTHROPIC_AUTH_TOKEN);
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

function refreshOpenAiCredentialSync(refreshToken) {
  const script = `
const body = new URLSearchParams({
  grant_type: "refresh_token",
  refresh_token: process.env.KUZUSHI_OPENAI_REFRESH_TOKEN,
  client_id: process.env.KUZUSHI_OPENAI_CLIENT_ID,
});
const response = await fetch(process.env.KUZUSHI_OPENAI_TOKEN_URL, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
  body: body.toString(),
});
process.stdout.write(await response.text());
process.exitCode = response.ok ? 0 : 1;
`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    env: {
      ...process.env,
      KUZUSHI_OPENAI_REFRESH_TOKEN: refreshToken,
      KUZUSHI_OPENAI_CLIENT_ID: OPENAI_OAUTH_CLIENT_ID,
      KUZUSHI_OPENAI_TOKEN_URL: OPENAI_OAUTH_TOKEN_URL,
    },
    timeout: 120_000,
  });
  if (result.status !== 0) return undefined;
  return openAiCredentialFromRefreshResponse(result.stdout, refreshToken);
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

export function openAiCredentialFromRefreshResponse(raw, priorRefresh, now = Date.now()) {
  try {
    const parsed = JSON.parse(raw);
    const access = nonEmpty(parsed.access_token);
    if (!access) return undefined;
    const accountId =
      openAiAccountIdFromJwt(parsed.id_token) ?? openAiAccountIdFromJwt(access);
    return {
      access,
      refresh: nonEmpty(parsed.refresh_token) ?? priorRefresh,
      expires: now + Math.max(1, Number(parsed.expires_in ?? 3600)) * 1000,
      ...(accountId ? { accountId } : {}),
    };
  } catch {
    return undefined;
  }
}

export function openAiAccountIdFromJwt(token) {
  if (!nonEmpty(token)) return undefined;
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    return (
      nonEmpty(claims.chatgpt_account_id) ??
      nonEmpty(claims["https://api.openai.com/auth"]?.chatgpt_account_id) ??
      nonEmpty(claims.organizations?.[0]?.id)
    );
  } catch {
    return undefined;
  }
}

export function writeOauthCredentialBag(bag, credentialsPath = oauthCredentialsPath()) {
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

// Adaptive-thinking-only Anthropic models reject sampling knobs client-side
// (@langchain/anthropic `validateInvocationParamCompatibility` throws before
// any HTTP call when temperature is set to a non-default value). Mirror its
// prefix list so a caller-pinned deterministic temperature (e.g. triage's
// 0.0) degrades to the provider default for these models instead of failing
// every bridge call.
const TEMPERATURE_LOCKED_MODEL_PREFIXES = [
  "claude-opus-4-7",
  "claude-opus-4-8",
  "claude-fable-5",
  "claude-orchid-5",
  "claude-orchid-preview",
];

function temperatureLockedModel(request) {
  const [, model] = parseModelSpec(request?.model ?? "");
  return TEMPERATURE_LOCKED_MODEL_PREFIXES.some((prefix) => model.startsWith(prefix));
}

// Agentic tool loops issue many back-to-back calls, so a burst-quota 429 in
// the middle of a graph run is routine; the SDK's default two retries give
// up long before a per-minute window resets and fail the whole run.
const MODEL_MAX_RETRIES = 8;

export function modelOptions(request) {
  const options = { maxRetries: MODEL_MAX_RETRIES };
  const temperature = numericTemperature(request);
  const maxTokens = request.maxOutputTokens ?? request.max_output_tokens ?? request.maxTokens;
  if (temperature !== undefined && !temperatureLockedModel(request)) {
    options.temperature = temperature;
  }
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

export function usageFromMessages(messages) {
  return (messages ?? []).filter(isAiMessage).reduce(addMessageUsage, emptyUsage());
}

export function bridgeUsageFields(usage) {
  const hasInput = usage.inputReportedCalls > 0;
  const hasOutput = usage.outputReportedCalls > 0;
  const hasCost = usage.costReportedCalls > 0;
  return {
    input_tokens: hasInput ? usage.inputTokens : undefined,
    output_tokens: hasOutput ? usage.outputTokens : undefined,
    cost_usd: hasCost ? usage.costUsd : undefined,
    input_reported_calls: usage.inputReportedCalls,
    output_reported_calls: usage.outputReportedCalls,
    cost_reported_calls: usage.costReportedCalls,
    model_calls: usage.modelCalls,
    cost_usd_exact: usage.modelCalls > 0 && usage.costReportedCalls === usage.modelCalls,
  };
}

export function bridgeQueryResult(messages, stopReason) {
  const text = messageText(messages.at(-1));
  return {
    ok: true,
    text,
    structured: maybeParseJson(text),
    ...bridgeUsageFields(usageFromMessages(messages)),
    truncated: isTruncatedStopReason(stopReason),
    stopReason,
  };
}

export function isTruncatedStopReason(reason) {
  return [
    "length",
    "max_tokens",
    "max_tokens_reached",
    "model_turn_limit",
    "mcp_tool_timeout",
    "observed_spend_incomplete",
    "observed_spend_exhausted",
    "forced_conclusion",
  ].includes(String(reason ?? ""));
}

export function interruptedQueryResult(messages, stopReason) {
  return {
    ok: true,
    text: "",
    ...bridgeUsageFields(usageFromMessages(messages)),
    truncated: true,
    stopReason,
  };
}

export function modelContinuationDecision(
  messages,
  observedSpendStopUsd,
  maxModelTurns = DEFAULT_MAX_MODEL_TURNS,
) {
  const usage = usageFromMessages(messages);
  validateMaxModelTurns(maxModelTurns);
  if (usage.modelCalls >= maxModelTurns) return "model_turn_limit";
  const stop = observedSpendStop(observedSpendStopUsd);
  if (stop === undefined) return "continue";
  return observedSpendDecision(usage, stop);
}

function validateMaxModelTurns(maxModelTurns) {
  if (!Number.isSafeInteger(maxModelTurns) || maxModelTurns < 1) {
    throw new Error("max model turns must be a positive safe integer");
  }
}

function observedSpendStop(raw) {
  if (raw === undefined || raw === null) return undefined;
  const stop = Number(raw);
  if (!Number.isFinite(stop) || stop <= 0) {
    throw new Error("observed spend stop must be a finite positive number");
  }
  return stop;
}

function observedSpendDecision(usage, stop) {
  if (usage.costReportedCalls !== usage.modelCalls) return "observed_spend_incomplete";
  return usage.costUsd >= stop ? "observed_spend_exhausted" : "continue";
}

function addMessageUsage(total, message) {
  const usage = usageFromMessage(message);
  return {
    inputTokens: checkedTokenSum(total.inputTokens, usage.inputTokens),
    outputTokens: checkedTokenSum(total.outputTokens, usage.outputTokens),
    inputReportedCalls: total.inputReportedCalls + Number(usage.inputTokens !== undefined),
    outputReportedCalls: total.outputReportedCalls + Number(usage.outputTokens !== undefined),
    costUsd: checkedCostSum(total.costUsd, usage.costUsd),
    costReportedCalls: total.costReportedCalls + Number(usage.costUsd !== undefined),
    modelCalls: total.modelCalls + 1,
  };
}

function emptyUsage() {
  return {
    inputTokens: 0,
    outputTokens: 0,
    inputReportedCalls: 0,
    outputReportedCalls: 0,
    costUsd: 0,
    costReportedCalls: 0,
    modelCalls: 0,
  };
}

function checkedTokenSum(total, value) {
  const next = total + (value ?? 0);
  if (!Number.isSafeInteger(next)) throw new Error("provider token usage aggregate overflowed");
  return next;
}

function checkedCostSum(total, value) {
  const next = total + (value ?? 0);
  if (!Number.isFinite(next) || next < 0) throw new Error("provider usage cost aggregate overflowed");
  return next;
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
