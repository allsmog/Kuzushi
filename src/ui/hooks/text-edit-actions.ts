/**
 * Pure helpers for the shell prompt and TextInput primitive.
 *
 * `useTextEditor` and `CopilotShell` both run their own `useInput` callback
 * but need identical edit semantics. Putting the two non-trivial bits here
 * keeps them in lock-step and unit-testable.
 */

export interface TextEditState {
  value: string;
  cursor: number;
}

/**
 * Delete the character to the left of the cursor.
 * Returns `null` when there's nothing to delete (empty buffer or cursor at 0).
 */
export function applyBackspace(value: string, cursor: number): TextEditState | null {
  if (value.length === 0) return null;
  const c = Math.max(0, Math.min(cursor, value.length));
  if (c === 0) return null;
  return {
    value: value.slice(0, c - 1) + value.slice(c),
    cursor: c - 1,
  };
}

/**
 * Detect a Ctrl+letter chord. Some terminals deliver the letter ("a") while
 * others deliver the literal control byte ( for Ctrl+A); accept both.
 */
export function isCtrlChord(input: string, letter: string, ctrl: boolean): boolean {
  if (!ctrl) return false;
  const lower = letter.toLowerCase();
  const ctrlCode = String.fromCharCode(lower.charCodeAt(0) - 96);
  return input === lower || input === lower.toUpperCase() || input === ctrlCode;
}
