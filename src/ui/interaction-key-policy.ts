/**
 * Shared key-policy helpers for Ink interaction surfaces.
 *
 * The shell has a richer reducer, but modal/editor primitives need a small
 * common policy so Escape and Ctrl+C do not drift between setup, review, and
 * form flows. Invalid keys deliberately fall through as no-ops.
 */

import { isCtrlChord } from "./hooks/text-edit-actions.js";

export interface InteractionKey {
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
  tab?: boolean;
  return?: boolean;
  escape?: boolean;
  backspace?: boolean;
  delete?: boolean;
  upArrow?: boolean;
  downArrow?: boolean;
  leftArrow?: boolean;
  rightArrow?: boolean;
  pageUp?: boolean;
  pageDown?: boolean;
}

export function isAbortInput(input: string, key: InteractionKey): boolean {
  return isCtrlChord(input, "c", key.ctrl === true) || isCtrlChord(input, "d", key.ctrl === true);
}

export function isEscapeInput(_input: string, key: InteractionKey): boolean {
  return key.escape === true;
}

export function isCancelInput(input: string, key: InteractionKey): boolean {
  return isEscapeInput(input, key) || isAbortInput(input, key);
}

export function isPlainTextInput(input: string, key: InteractionKey): boolean {
  return Boolean(input) && key.ctrl !== true && key.meta !== true && key.tab !== true;
}
