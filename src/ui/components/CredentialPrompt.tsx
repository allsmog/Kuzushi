/**
 * Interactive credential prompt for missing API tokens.
 *
 * Shown when the Claude backend is selected but no ANTHROPIC_API_KEY or
 * ANTHROPIC_OAUTH_TOKEN is detected.  Offers three choices:
 *
 *   1. Paste an API key
 *   2. Paste an OAuth token
 *   3. Use inherited mode (rely on parent-process env / Claude Code login)
 *
 *   ┌─ Authentication Required ──────────────────────────────┐
 *   │                                                        │
 *   │  No Anthropic credentials detected.                    │
 *   │  Choose how to authenticate:                           │
 *   │                                                        │
 *   │  > ◆ API Key          Paste an ANTHROPIC_API_KEY       │
 *   │    ◆ OAuth Token      Paste an ANTHROPIC_OAUTH_TOKEN   │
 *   │    ◆ Inherited        Use credentials from environment │
 *   │                                                        │
 *   │  [↑↓] navigate  [enter] select  [q] quit              │
 *   └────────────────────────────────────────────────────────┘
 */
import React, { useState } from "react";
import { Box, Text, useInput } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { boxHeader, boxFooter, terminalCardWidth } from "../format.js";

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

export function CredentialPrompt({ onComplete, onCancel }: CredentialPromptProps): React.ReactElement {
  const [step, setStep] = useState<Step>("choose");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [chosenOption, setChosenOption] = useState<"api-key" | "oauth-token" | null>(null);
  const [inputValue, setInputValue] = useState("");
  const width = terminalCardWidth();

  useInput((input, key) => {
    if (step === "choose") {
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
      return;
    }

    // Input step — collecting the token value
    if (key.escape) {
      setStep("choose");
      setChosenOption(null);
      setInputValue("");
      return;
    }

    if (key.return) {
      const trimmed = inputValue.trim();
      if (trimmed.length > 0) {
        onComplete({ kind: chosenOption!, value: trimmed });
      }
      return;
    }

    if (key.backspace || key.delete) {
      setInputValue((v) => v.slice(0, -1));
      return;
    }

    // Accumulate printable characters
    if (input && !key.ctrl && !key.meta) {
      setInputValue((v) => v + input);
    }
  });

  if (step === "input") {
    const label = chosenOption === "api-key" ? "API Key" : "OAuth Token";
    const masked = inputValue.length > 0
      ? inputValue.slice(0, 8) + "*".repeat(Math.max(0, inputValue.length - 8))
      : "";

    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader(`Enter ${label}`, width)}</Text>
        <Text>{""}</Text>
        <Text>{"  "}{chalk.dim(`Paste your ${label} below:`)}</Text>
        <Text>{""}</Text>
        <Text>{"  "}{chalk.redBright(icons.arrow)} {masked ? chalk.white(masked) : chalk.dim("(paste and press enter)")}</Text>
        <Text>{""}</Text>
        <Text>{"  "}{chalk.dim("[enter] confirm  [esc] back")}</Text>
        <Text>{boxFooter(width)}</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader("Authentication Required", width)}</Text>
      <Text>{""}</Text>
      <Text>{"  "}{chalk.dim("No Anthropic credentials detected.")}</Text>
      <Text>{"  "}{chalk.dim("Choose how to authenticate:")}</Text>
      <Text>{""}</Text>

      {CHOICES.map((option, i) => {
        const isSelected = i === selectedIndex;
        const prefix = isSelected ? chalk.redBright(icons.arrow) : " ";
        const name = isSelected ? chalk.white.bold(option.name) : chalk.dim(option.name);

        return (
          <Box key={i} flexDirection="column">
            <Text>{"  "}{prefix} {icons.complete} {name}  {chalk.dim(option.description)}</Text>
            {isSelected && (
              <Text>{"      "}{chalk.white(option.detail)}</Text>
            )}
          </Box>
        );
      })}

      <Text>{""}</Text>
      <Text>{"  "}{chalk.dim("[↑↓] navigate  [enter] select  [q] quit")}</Text>
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}
