/**
 * TextInput — controlled character-accumulation input.
 *
 * Replaces three bespoke implementations (CredentialPrompt, ContextIntake,
 * ThreatModelEditor, CommandInput) that all did
 * `setValue(v => v + input)` + `!key.ctrl && !key.meta` gating.
 */
import { Box, Text, useInput } from "ink";
import type { FC } from "react";
import { useEffect, useState } from "react";
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
  const [cursor, setCursor] = useState<number>(value.length);

  useEffect(() => {
    setCursor((prev) => Math.max(0, Math.min(prev, value.length)));
  }, [value]);

  const isCtrlChord = (input: string, letter: string, ctrl: boolean): boolean => {
    if (!ctrl) return false;
    const lower = letter.toLowerCase();
    const ctrlCode = String.fromCharCode(lower.charCodeAt(0) - 96);
    return input === lower || input === lower.toUpperCase() || input === ctrlCode;
  };

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
      if (key.leftArrow) {
        setCursor((c) => Math.max(0, c - 1));
        return;
      }
      if (key.rightArrow) {
        setCursor((c) => Math.min(value.length, c + 1));
        return;
      }
      if (isCtrlChord(input, "a", key.ctrl)) {
        setCursor(0);
        return;
      }
      if (isCtrlChord(input, "e", key.ctrl)) {
        setCursor(value.length);
        return;
      }
      if (isCtrlChord(input, "u", key.ctrl)) {
        onChange("");
        setCursor(0);
        return;
      }
      if (key.backspace) {
        if (value.length === 0 || cursor === 0) return;
        const next = value.slice(0, cursor - 1) + value.slice(cursor);
        onChange(next);
        setCursor((c) => Math.max(0, c - 1));
        return;
      }
      if (key.delete) {
        if (cursor >= value.length) return;
        const next = value.slice(0, cursor) + value.slice(cursor + 1);
        onChange(next);
        return;
      }
      if (key.ctrl || key.meta) return;
      if (!input) return;
      const next = value.slice(0, cursor) + input + value.slice(cursor);
      if (typeof maxLength === "number" && next.length > maxLength) return;
      onChange(next);
      setCursor((c) => c + input.length);
    },
    { isActive },
  );

  const renderValue = () => {
    if (value.length === 0 && placeholder) {
      return tokens.muted(placeholder);
    }
    const display = mask ? "\u2022".repeat(value.length) : value;
    if (!isActive) return display;
    const boundedCursor = Math.max(0, Math.min(cursor, display.length));
    const before = display.slice(0, boundedCursor);
    const currentChar = boundedCursor < display.length ? display[boundedCursor] : cursorChar;
    const after = boundedCursor < display.length ? display.slice(boundedCursor + 1) : "";
    return `${before}${tokens.accent(currentChar)}${after}`;
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
