/**
 * Interactive credential prompt for missing API tokens.
 *
 * Choose step delegates to the shared <SelectList> primitive with a
 * custom renderer that shows the detail line beneath the highlighted row.
 * Input step delegates to <TextInput>. Keybindings flow through
 * useRegisterKeybindings so the shared <KeybindFooter> stays accurate.
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

export type CredentialChoice =
  | { kind: "api-key"; value: string; baseUrl?: string; persist: boolean }
  | { kind: "oauth-token"; value: string; baseUrl?: string }
  | { kind: "inherited" };

interface CredentialPromptProps {
  onComplete: (choice: CredentialChoice) => void;
  onCancel: () => void;
}

interface ChoiceOption {
  id: "api-key" | "oauth-token" | "inherited";
  name: string;
  description: string;
  detail: string;
}

const CHOICES: ChoiceOption[] = [
  {
    id: "api-key",
    name: "API Key",
    description: "Paste an ANTHROPIC_API_KEY",
    detail: "Direct API key authentication (sk-ant-...)",
  },
  {
    id: "oauth-token",
    name: "OAuth Token",
    description: "Paste an ANTHROPIC_OAUTH_TOKEN",
    detail: "OAuth token from Claude CLI login or SSO",
  },
  {
    id: "inherited",
    name: "Inherited",
    description: "Use credentials from environment",
    detail: "Rely on Claude Code login or parent process credentials",
  },
];

const CHOICE_ITEMS: ReadonlyArray<SelectListItem<ChoiceOption["id"]>> = CHOICES.map((c) => ({
  id: c.id,
  label: c.name,
  detail: c.description,
}));

type Step = "choose" | "input" | "base-url" | "save";

const CHOOSE_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "Enter", label: "Select" },
  { keys: "q", label: "Quit", secondary: true },
];

const INPUT_KEYBINDS = [
  { keys: "Enter", label: "Confirm" },
  { keys: "Esc", label: "Back" },
];

const BASE_URL_KEYBINDS = [
  { keys: "Enter", label: "Confirm (blank = default)" },
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
      "Persist project-local; auto-added to .gitignore. Future kuzushi runs in this dir pick it up",
  },
  {
    id: "skip",
    label: "Don't save",
    detail: "Use the key for this session only (env-only)",
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

function chooseRenderer(ctx: SelectListRenderContext<ChoiceOption["id"]>): React.ReactElement {
  const opt = CHOICES.find((c) => c.id === ctx.item.id)!;
  const name = ctx.isCursor ? tokens.strong(opt.name) : tokens.muted(opt.name);
  return (
    <Box flexDirection="column" paddingLeft={2}>
      <Text>
        {ctx.cursorPrefix} {icons.complete} {name} {tokens.muted(opt.description)}
      </Text>
      {ctx.isCursor && (
        <Box paddingLeft={6}>
          <Text>{opt.detail}</Text>
        </Box>
      )}
    </Box>
  );
}

export function CredentialPrompt({
  onComplete,
  onCancel,
}: CredentialPromptProps): React.ReactElement {
  const [step, setStep] = useState<Step>("choose");
  const [chosenOption, setChosenOption] = useState<"api-key" | "oauth-token" | null>(null);
  const [inputValue, setInputValue] = useState("");
  const [capturedValue, setCapturedValue] = useState("");
  const [baseUrlValue, setBaseUrlValue] = useState("");
  const [capturedBaseUrl, setCapturedBaseUrl] = useState<string | undefined>(undefined);
  const width = terminalCardWidth();

  const stepKeybinds =
    step === "choose"
      ? CHOOSE_KEYBINDS
      : step === "input"
        ? INPUT_KEYBINDS
        : step === "base-url"
          ? BASE_URL_KEYBINDS
          : SAVE_KEYBINDS;
  useRegisterKeybindings(stepKeybinds);

  // Escape/q → cancel at the choose step. SelectList owns arrow/Enter keys.
  useInput(
    (input, key) => {
      if (input === "q" || key.escape) onCancel();
    },
    { isActive: step === "choose" },
  );

  // Esc → back to input on save step.
  useInput(
    (_input, key) => {
      if (key.escape) {
        setStep("input");
      }
    },
    { isActive: step === "save" },
  );

  // Esc → back to input from base-url step.
  useInput(
    (_input, key) => {
      if (key.escape) {
        setStep("input");
        setBaseUrlValue("");
      }
    },
    { isActive: step === "base-url" },
  );

  const handleSelect = (id: ChoiceOption["id"]) => {
    if (id === "inherited") {
      onComplete({ kind: "inherited" });
    } else {
      setChosenOption(id);
      setStep("input");
      setInputValue("");
    }
  };

  const handleSaveSelect = (id: SaveOption) => {
    onComplete({
      kind: "api-key",
      value: capturedValue,
      baseUrl: capturedBaseUrl,
      persist: id === "save",
    });
  };

  if (step === "save") {
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader("Persist API Key?", width)}</Text>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <Text>{tokens.muted("Save the key to ./.kuzushi/credentials.json (in the")}</Text>
        </Box>
        <Box paddingLeft={2}>
          <Text>{tokens.muted("dir kuzushi was launched from). Auto-added to .gitignore.")}</Text>
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
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader("Custom Base URL? (optional)", width)}</Text>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <Text>
            {tokens.muted("Leave blank to use Anthropic's default (https://api.anthropic.com).")}
          </Text>
        </Box>
        <Box paddingLeft={2}>
          <Text>{tokens.muted("Set this for proxies, gateways, or local endpoints.")}</Text>
        </Box>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <TextInput
            value={baseUrlValue}
            onChange={setBaseUrlValue}
            onSubmit={(value) => {
              const trimmed = value.trim();
              const baseUrl = trimmed.length > 0 ? trimmed : undefined;
              setCapturedBaseUrl(baseUrl);
              if (chosenOption === "api-key") {
                setStep("save");
                return;
              }
              onComplete({ kind: "oauth-token", value: capturedValue, baseUrl });
            }}
            onCancel={() => {
              setStep("input");
              setBaseUrlValue("");
            }}
            placeholder="(Enter to skip, or paste URL)"
          />
        </Box>
        <Text>{boxFooter(width)}</Text>
      </Box>
    );
  }

  if (step === "input") {
    const label = chosenOption === "api-key" ? "API Key" : "OAuth Token";
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader(`Enter ${label}`, width)}</Text>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <Text>{tokens.muted(`Paste your ${label} below:`)}</Text>
        </Box>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <TextInput
            value={inputValue}
            onChange={setInputValue}
            onSubmit={(value) => {
              const trimmed = value.trim();
              if (trimmed.length === 0 || !chosenOption) return;
              setCapturedValue(trimmed);
              setBaseUrlValue("");
              setStep("base-url");
            }}
            onCancel={() => {
              setStep("choose");
              setChosenOption(null);
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
      <Text>{boxHeader("Authentication Required", width)}</Text>
      <Text>{""}</Text>
      <Box paddingLeft={2}>
        <Text>{tokens.muted("No Anthropic credentials detected.")}</Text>
      </Box>
      <Box paddingLeft={2}>
        <Text>{tokens.muted("Choose how to authenticate:")}</Text>
      </Box>
      <Text>{""}</Text>

      <SelectList<ChoiceOption["id"]>
        items={CHOICE_ITEMS}
        onSelect={handleSelect}
        renderItem={chooseRenderer}
      />

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}
