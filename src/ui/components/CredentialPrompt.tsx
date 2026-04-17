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

const CHOICE_ITEMS: ReadonlyArray<SelectListItem<ChoiceOption["id"]>> = CHOICES.map(
  (c) => ({ id: c.id, label: c.name, detail: c.description }),
);

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

function chooseRenderer(
  ctx: SelectListRenderContext<ChoiceOption["id"]>,
): React.ReactElement {
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
  const width = terminalCardWidth();

  useRegisterKeybindings(step === "choose" ? CHOOSE_KEYBINDS : INPUT_KEYBINDS);

  // Escape/q → cancel at the choose step. SelectList owns arrow/Enter keys.
  useInput(
    (input, key) => {
      if (input === "q" || key.escape) onCancel();
    },
    { isActive: step === "choose" },
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

      <SelectList<ChoiceOption["id"]>
        items={CHOICE_ITEMS}
        onSelect={handleSelect}
        renderItem={chooseRenderer}
      />

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}
