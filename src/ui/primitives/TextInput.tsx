/**
 * TextInput — controlled character-accumulation input.
 *
 * Replaces three bespoke implementations (CredentialPrompt, ContextIntake,
 * ThreatModelEditor, CommandInput) that all did
 * `setValue(v => v + input)` + `!key.ctrl && !key.meta` gating.
 *
 * Editing key handling lives in `useTextEditor` so the same caret semantics
 * (arrows, Ctrl+A/E/U, mid-line backspace/delete) are shared with the
 * CopilotShell prompt.
 */
import { Box, Text } from "ink";
import type { FC } from "react";
import { useTextEditor } from "../hooks/useTextEditor.js";
import { useLayoutContext } from "../layout-context.js";
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
  cursorChar,
}) => {
  const { theme } = useLayoutContext();
  const { cursor } = useTextEditor({ value, onChange, onSubmit, onCancel, maxLength, isActive });
  const caretGlyph = cursorChar ?? theme.glyphs.textCursor;

  const renderValue = () => {
    if (value.length === 0 && placeholder) {
      return tokens.muted(placeholder);
    }
    const display = mask ? "•".repeat(value.length) : value;
    if (!isActive) return display;
    const boundedCursor = Math.max(0, Math.min(cursor, display.length));
    const before = display.slice(0, boundedCursor);
    const currentChar = boundedCursor < display.length ? display[boundedCursor] : caretGlyph;
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
