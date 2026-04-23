/**
 * useTextEditor — shared keyboard editing logic for any text-input surface.
 *
 * Extracted from `TextInput.tsx` and `CopilotShell.tsx`'s prompt handler,
 * which had duplicated cursor clamping, arrow navigation, ctrl-chord
 * detection, backspace, and Ctrl+A/E/U handling. Anything that accepts
 * free-form text and needs a caret should go through this hook.
 *
 * Returns the live cursor index plus a setter so callers can render a
 * cursor glyph (use `theme.glyphs.textCursor` for the visual character).
 */

import { useInput } from "ink";
import { useEffect, useState } from "react";
import { applyBackspace, isCtrlChord } from "./text-edit-actions.js";

export interface UseTextEditorProps {
  value: string;
  onChange: (next: string) => void;
  onSubmit?: (value: string) => void;
  onCancel?: () => void;
  /** Hard cap on input length (defensive — most callers don't set this). */
  maxLength?: number;
  /** When false, the underlying `useInput` is silenced (e.g. when blurred). */
  isActive?: boolean;
}

export interface UseTextEditorState {
  cursor: number;
  setCursor: (idx: number) => void;
}

export function useTextEditor({
  value,
  onChange,
  onSubmit,
  onCancel,
  maxLength,
  isActive = true,
}: UseTextEditorProps): UseTextEditorState {
  const [cursor, setCursor] = useState<number>(value.length);

  useEffect(() => {
    setCursor((prev) => Math.max(0, Math.min(prev, value.length)));
  }, [value]);

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
      // In Ink 5, the physical Backspace key on macOS/most terminals sends
      // \x7f and surfaces as `key.delete`, not `key.backspace`. Ctrl+H sends
      // \x08 and surfaces as `key.backspace`. Treat both as delete-left so
      // the user's intuition holds in either case.
      if (key.backspace || key.delete) {
        const edit = applyBackspace(value, cursor);
        if (!edit) return;
        onChange(edit.value);
        setCursor(edit.cursor);
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

  return { cursor, setCursor };
}
