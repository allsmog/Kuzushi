/**
 * Interactive credential prompt for missing API tokens.
 *
 * Shown when the Claude backend is selected but no ANTHROPIC_API_KEY or
 * ANTHROPIC_OAUTH_TOKEN is detected. Offers three choices:
 *
 *   1. Paste an API key
 *   2. Paste an OAuth token
 *   3. Use inherited mode (rely on parent-process env / Claude Code login)
 *
 * Choose step uses a bespoke custom-rendered menu (retained for the
 * selected-row detail summary). Input step delegates to the shared
 * <TextInput> primitive. Keybindings flow through useRegisterKeybindings so
 * the shared <KeybindFooter> reflects the active context.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { boxFooter, boxHeader, terminalCardWidth } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import { TextInput } from "../primitives/TextInput.js";
import { tokens } from "../tokens.js";

export type CredentialChoice =
  | { kind: "api-key"; value: string }
  | { kind: "oauth-token"; value: string }
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

type Step = "choose" | "input";

const CHOOSE_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "Enter", label: "Select" },
  { keys: "q", label: "Quit", secondary: true },
];

const INPUT_KEYBINDS = [
  { keys: "Enter", label: "Confirm" },
  { keys: "Esc", label: "Back" },
];

export function CredentialPrompt({
  onComplete,
  onCancel,
}: CredentialPromptProps): React.ReactElement {
  const [step, setStep] = useState<Step>("choose");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [chosenOption, setChosenOption] = useState<"api-key" | "oauth-token" | null>(null);
  const [inputValue, setInputValue] = useState("");
  const width = terminalCardWidth();

  useRegisterKeybindings(step === "choose" ? CHOOSE_KEYBINDS : INPUT_KEYBINDS);

  useInput(
    (input, key) => {
      if (input === "q" || key.escape) {
        onCancel();
        return;
      }
      if (key.upArrow) {
        setSelectedIndex((i) => Math.max(0, i - 1));
        return;
      }
      if (key.downArrow) {
        setSelectedIndex((i) => Math.min(CHOICES.length - 1, i + 1));
        return;
      }
      if (key.return) {
        const choice = CHOICES[selectedIndex]!;
        if (choice.id === "inherited") {
          onComplete({ kind: "inherited" });
        } else {
          setChosenOption(choice.id);
          setStep("input");
          setInputValue("");
        }
      }
    },
    { isActive: step === "choose" },
  );

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
              if (trimmed.length > 0 && chosenOption) {
                onComplete({ kind: chosenOption, value: trimmed });
              }
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

      {CHOICES.map((option, i) => {
        const isSelected = i === selectedIndex;
        const prefix = isSelected ? tokens.accent(icons.arrow) : " ";
        const name = isSelected ? tokens.strong(option.name) : tokens.muted(option.name);

        return (
          <Box key={option.id} flexDirection="column">
            <Box paddingLeft={2}>
              <Text>
                {prefix} {icons.complete} {name} {tokens.muted(option.description)}
              </Text>
            </Box>
            {isSelected && (
              <Box paddingLeft={6}>
                <Text>{option.detail}</Text>
              </Box>
            )}
          </Box>
        );
      })}

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}
