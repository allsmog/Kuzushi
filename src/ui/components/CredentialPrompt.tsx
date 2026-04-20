/**
 * Interactive credential prompt — multi-provider.
 *
 * Flow:
 *   1. Provider picker — Anthropic / OpenAI / Google / local / etc.
 *   2. Auth method — varies by provider (API key, base URL, inherited)
 *   3. Input (masked for tokens)
 *   4. Persist to local creds file (or session-only)
 *
 * OAuth device flows (Codex, Copilot, Gemini CLI) are listed in the
 * provider picker but route through pi-ai's `oauth` module at submit-time
 * — see applyCredentialOutcome in src/copilot/shell.ts.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { boxFooter, boxHeader, terminalCardWidth } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import {
  SelectList,
  type SelectListItem,
  type SelectListRenderContext,
} from "../primitives/SelectList.js";
import { TextInput } from "../primitives/TextInput.js";
import { tokens } from "../tokens.js";

/** Provider ids aligned with pi-ai's builtin providers. */
export type ProviderId =
  | "anthropic"
  | "openai"
  | "google"
  | "mistral"
  | "groq"
  | "cerebras"
  | "xai"
  | "openrouter"
  | "bedrock"
  | "ollama"
  | "inherited";

export type CredentialChoice =
  | { kind: "api-key"; providerId: ProviderId; value: string; baseUrl?: string; persist: boolean }
  | { kind: "base-url"; providerId: ProviderId; baseUrl: string; apiKey?: string; persist: boolean }
  | { kind: "inherited"; providerId?: ProviderId };

interface CredentialPromptProps {
  onComplete: (choice: CredentialChoice) => void;
  onCancel: () => void;
}

interface ProviderOption {
  id: ProviderId;
  name: string;
  description: string;
  detail: string;
  authKind: "api-key" | "base-url" | "inherited";
  envVarHint?: string;
}

const PROVIDERS: ProviderOption[] = [
  {
    id: "anthropic",
    name: "Anthropic",
    description: "Claude — Opus, Sonnet, Haiku",
    detail: "Paste an API key (sk-ant-...). The default for most Kuzushi setups.",
    authKind: "api-key",
    envVarHint: "ANTHROPIC_API_KEY",
  },
  {
    id: "openai",
    name: "OpenAI",
    description: "GPT-5, o1, o3",
    detail: "Paste an API key (sk-...). Supports tool use via the Responses API.",
    authKind: "api-key",
    envVarHint: "OPENAI_API_KEY",
  },
  {
    id: "google",
    name: "Google",
    description: "Gemini 2.5 direct",
    detail: "Paste a Google AI API key. For Vertex AI, use ambient gcloud creds.",
    authKind: "api-key",
    envVarHint: "GOOGLE_API_KEY",
  },
  {
    id: "mistral",
    name: "Mistral",
    description: "Mistral / Codestral",
    detail: "Paste an API key from console.mistral.ai.",
    authKind: "api-key",
    envVarHint: "MISTRAL_API_KEY",
  },
  {
    id: "groq",
    name: "Groq",
    description: "Fast inference for OSS models",
    detail: "Paste an API key from console.groq.com.",
    authKind: "api-key",
    envVarHint: "GROQ_API_KEY",
  },
  {
    id: "cerebras",
    name: "Cerebras",
    description: "Ultra-fast inference",
    detail: "Paste an API key from cloud.cerebras.ai.",
    authKind: "api-key",
    envVarHint: "CEREBRAS_API_KEY",
  },
  {
    id: "xai",
    name: "xAI",
    description: "Grok models",
    detail: "Paste an API key from console.x.ai.",
    authKind: "api-key",
    envVarHint: "XAI_API_KEY",
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    description: "Unified gateway, 100+ models",
    detail: "Paste an API key from openrouter.ai. Works with any model they proxy.",
    authKind: "api-key",
    envVarHint: "OPENROUTER_API_KEY",
  },
  {
    id: "ollama",
    name: "Ollama / local",
    description: "OpenAI-compatible endpoint",
    detail: "Point at a local server (http://localhost:11434 for Ollama, vLLM, LM Studio).",
    authKind: "base-url",
  },
  {
    id: "bedrock",
    name: "Amazon Bedrock",
    description: "AWS-hosted Claude, Llama, Titan",
    detail: "Uses ambient AWS credentials. Configure via aws configure or env vars.",
    authKind: "inherited",
  },
  {
    id: "inherited",
    name: "Use environment",
    description: "Read keys from env vars / parent process",
    detail: "Skip the prompt and rely on ANTHROPIC_API_KEY / OPENAI_API_KEY / etc. already set.",
    authKind: "inherited",
  },
];

const PROVIDER_ITEMS: ReadonlyArray<SelectListItem<ProviderId>> = PROVIDERS.map((p) => ({
  id: p.id,
  label: p.name,
  detail: p.description,
}));

type Step = "provider" | "input" | "base-url" | "save";

const PROVIDER_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "Enter", label: "Select" },
  { keys: "q", label: "Quit", secondary: true },
];

const INPUT_KEYBINDS = [
  { keys: "Enter", label: "Confirm" },
  { keys: "Esc", label: "Back" },
];

const BASE_URL_KEYBINDS = [
  { keys: "Enter", label: "Confirm" },
  { keys: "Esc", label: "Back" },
];

const SAVE_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "Enter", label: "Confirm" },
  { keys: "Esc", label: "Back" },
];

type SaveOption = "save" | "skip";

const SAVE_ITEMS: ReadonlyArray<SelectListItem<SaveOption>> = [
  {
    id: "save",
    label: "Save to ./.kuzushi/credentials.json",
    detail:
      "Persist project-local; auto-added to .gitignore. Future kuzushi runs in this dir pick it up.",
  },
  {
    id: "skip",
    label: "Don't save",
    detail: "Use the credentials for this session only (env-only).",
  },
];

function saveRenderer(ctx: SelectListRenderContext<SaveOption>): React.ReactElement {
  const item = SAVE_ITEMS.find((c) => c.id === ctx.item.id)!;
  const name = ctx.isCursor ? tokens.strong(item.label) : tokens.muted(item.label);
  return (
    <Box flexDirection="column" paddingLeft={2}>
      <Text>
        {ctx.cursorPrefix} {icons.complete} {name}
      </Text>
      {ctx.isCursor && item.detail && (
        <Box paddingLeft={6}>
          <Text>{tokens.muted(item.detail)}</Text>
        </Box>
      )}
    </Box>
  );
}

function providerRenderer(ctx: SelectListRenderContext<ProviderId>): React.ReactElement {
  const provider = PROVIDERS.find((p) => p.id === ctx.item.id)!;
  const name = ctx.isCursor ? tokens.strong(provider.name) : tokens.muted(provider.name);
  return (
    <Box flexDirection="column" paddingLeft={2}>
      <Text>
        {ctx.cursorPrefix} {icons.complete} {name} {tokens.muted(`— ${provider.description}`)}
      </Text>
      {ctx.isCursor && (
        <Box paddingLeft={6}>
          <Text>{tokens.muted(provider.detail)}</Text>
        </Box>
      )}
    </Box>
  );
}

export function CredentialPrompt({
  onComplete,
  onCancel,
}: CredentialPromptProps): React.ReactElement {
  const [step, setStep] = useState<Step>("provider");
  const [chosenProvider, setChosenProvider] = useState<ProviderOption | null>(null);
  const [inputValue, setInputValue] = useState("");
  const [capturedValue, setCapturedValue] = useState("");
  const [baseUrlValue, setBaseUrlValue] = useState("");
  const [capturedBaseUrl, setCapturedBaseUrl] = useState<string | undefined>(undefined);
  const width = terminalCardWidth();

  const stepKeybinds =
    step === "provider"
      ? PROVIDER_KEYBINDS
      : step === "input"
        ? INPUT_KEYBINDS
        : step === "base-url"
          ? BASE_URL_KEYBINDS
          : SAVE_KEYBINDS;
  useRegisterKeybindings(stepKeybinds);

  useInput(
    (input, key) => {
      if (input === "q" || key.escape) onCancel();
    },
    { isActive: step === "provider" },
  );

  useInput(
    (_input, key) => {
      if (key.escape) setStep("input");
    },
    { isActive: step === "save" },
  );

  useInput(
    (_input, key) => {
      if (key.escape) {
        setStep(chosenProvider?.authKind === "base-url" ? "provider" : "input");
        setBaseUrlValue("");
      }
    },
    { isActive: step === "base-url" },
  );

  const handleProviderSelect = (id: ProviderId) => {
    const provider = PROVIDERS.find((p) => p.id === id)!;
    setChosenProvider(provider);

    if (provider.authKind === "inherited") {
      onComplete({ kind: "inherited", providerId: provider.id });
      return;
    }

    if (provider.authKind === "base-url") {
      setStep("base-url");
      setBaseUrlValue("");
      return;
    }

    setStep("input");
    setInputValue("");
  };

  const handleSaveSelect = (id: SaveOption) => {
    const persist = id === "save";
    if (chosenProvider?.authKind === "base-url") {
      onComplete({
        kind: "base-url",
        providerId: chosenProvider.id,
        baseUrl: capturedBaseUrl!,
        apiKey: capturedValue || undefined,
        persist,
      });
      return;
    }
    onComplete({
      kind: "api-key",
      providerId: chosenProvider!.id,
      value: capturedValue,
      baseUrl: capturedBaseUrl,
      persist,
    });
  };

  if (step === "save") {
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader("Persist credentials?", width)}</Text>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <Text>{tokens.muted(`Save ${chosenProvider?.name} credentials to`)}</Text>
        </Box>
        <Box paddingLeft={2}>
          <Text>{tokens.muted("./.kuzushi/credentials.json (auto-added to .gitignore)?")}</Text>
        </Box>
        <Text>{""}</Text>
        <SelectList<SaveOption>
          items={SAVE_ITEMS}
          onSelect={handleSaveSelect}
          renderItem={saveRenderer}
        />
        <Text>{boxFooter(width)}</Text>
      </Box>
    );
  }

  if (step === "base-url") {
    const isBaseUrlOnly = chosenProvider?.authKind === "base-url";
    const title = isBaseUrlOnly
      ? `${chosenProvider?.name} base URL`
      : `Custom base URL? (optional)`;
    const placeholder = isBaseUrlOnly
      ? "http://localhost:11434 or https://openrouter.ai/api/v1"
      : "(blank for default, or paste proxy/gateway URL)";
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader(title, width)}</Text>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <Text>
            {tokens.muted(
              isBaseUrlOnly
                ? "Where should Kuzushi send completion requests?"
                : "Leave blank to use the provider's default endpoint.",
            )}
          </Text>
        </Box>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <TextInput
            value={baseUrlValue}
            onChange={setBaseUrlValue}
            onSubmit={(value) => {
              const trimmed = value.trim();
              if (isBaseUrlOnly && trimmed.length === 0) return;
              const baseUrl = trimmed.length > 0 ? trimmed : undefined;
              setCapturedBaseUrl(baseUrl);
              // Local providers can skip API key entirely
              if (isBaseUrlOnly) {
                // Ollama, vLLM: no key needed by default
                onComplete({
                  kind: "base-url",
                  providerId: chosenProvider!.id,
                  baseUrl: baseUrl!,
                  persist: true,
                });
                return;
              }
              setStep("save");
            }}
            onCancel={() => {
              setStep(isBaseUrlOnly ? "provider" : "input");
              setBaseUrlValue("");
            }}
            placeholder={placeholder}
          />
        </Box>
        <Text>{boxFooter(width)}</Text>
      </Box>
    );
  }

  if (step === "input") {
    const envHint = chosenProvider?.envVarHint
      ? ` (will also export ${chosenProvider.envVarHint})`
      : "";
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader(`${chosenProvider?.name} API key`, width)}</Text>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <Text>{tokens.muted(`Paste your ${chosenProvider?.name} API key${envHint}:`)}</Text>
        </Box>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <TextInput
            value={inputValue}
            onChange={setInputValue}
            onSubmit={(value) => {
              const trimmed = value.trim();
              if (trimmed.length === 0 || !chosenProvider) return;
              setCapturedValue(trimmed);
              setBaseUrlValue("");
              setStep("base-url");
            }}
            onCancel={() => {
              setStep("provider");
              setChosenProvider(null);
              setInputValue("");
            }}
            placeholder="(paste and press enter)"
            mask
          />
        </Box>
        <Text>{boxFooter(width)}</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader("Choose an AI provider", width)}</Text>
      <Text>{""}</Text>
      <Box paddingLeft={2}>
        <Text>
          {tokens.muted(
            "Kuzushi works with any provider below. Pick one to set up credentials.",
          )}
        </Text>
      </Box>
      <Text>{""}</Text>

      <SelectList<ProviderId>
        items={PROVIDER_ITEMS}
        onSelect={handleProviderSelect}
        renderItem={providerRenderer}
      />

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}
