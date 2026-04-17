/**
 * TextInput — controlled character-accumulation input.
 *
 * Replaces three bespoke implementations (CredentialPrompt, ContextIntake,
 * ThreatModelEditor, CommandInput) that all did
 * `setValue(v => v + input)` + `!key.ctrl && !key.meta` gating.
 */
import { Box, Text, useInput } from "ink";
import type { FC } from "react";
import { tokens } from "../tokens.js";

export interface TextInputProps {
  value: string;
  onChange: (next: string) => void;
  onSubmit?: (value: string) => void;
  onCancel?: () => void;
  placeholder?: string;
  mask?: boolean;
  maxLength?: number;
  isActive?: boolean;
  prefix?: string;
  prefixColor?: (s: string) => string;
  cursorChar?: string;
}

export const TextInput: FC<TextInputProps> = ({
  value,
  onChange,
  onSubmit,
  onCancel,
  placeholder,
  mask = false,
  maxLength,
  isActive = true,
  prefix = "> ",
  prefixColor = tokens.accent,
  cursorChar = "\u2588",
}) => {
  useInput(
    (input, key) => {
      if (key.return) {
        onSubmit?.(value);
        return;
      }
      if (key.escape) {
        onCancel?.();
        return;
      }
      if (key.backspace || key.delete) {
        if (value.length > 0) onChange(value.slice(0, -1));
        return;
      }
      if (key.ctrl || key.meta) return;
      if (!input) return;
      const next = value + input;
      if (typeof maxLength === "number" && next.length > maxLength) return;
      onChange(next);
    },
    { isActive },
  );

  const renderValue = () => {
    if (value.length === 0 && placeholder) {
      return tokens.muted(placeholder);
    }
    const display = mask ? "\u2022".repeat(value.length) : value;
    if (!isActive) return display;
    return display + tokens.accent(cursorChar);
  };

  return (
    <Box>
      <Text>
        {prefixColor(prefix)}
        {renderValue()}
      </Text>
    </Box>
  );
};
