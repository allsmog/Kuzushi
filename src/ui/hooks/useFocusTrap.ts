/**
 * useFocusTrap — keeps Tab focus cycling within a modal-like flow.
 *
 * IMPORTANT: Ink's `useFocusManager` has no container/scope concept, so true
 * DOM-style focus containment isn't achievable. This hook takes a pragmatic
 * approach:
 *   - On active: calls `enableFocus()` so focus navigation works.
 *   - Intercepts Tab/Shift+Tab and routes through `focusNext`/`focusPrevious`.
 *   - On Esc, invokes `onEscape` to allow the consumer to dismiss the modal.
 * Consumers are still responsible for `isActive`-gating any other `useInput`
 * handlers so keystrokes don't leak to background components.
 */
import { useFocusManager, useInput } from "ink";
import { useEffect } from "react";

export interface UseFocusTrapOptions {
  active: boolean;
  onEscape?: () => void;
}

export function useFocusTrap(options: UseFocusTrapOptions): void {
  const { active, onEscape } = options;
  const { enableFocus, focusNext, focusPrevious } = useFocusManager();

  useEffect(() => {
    if (active) enableFocus();
  }, [active, enableFocus]);

  useInput(
    (_input, key) => {
      if (key.tab && key.shift) {
        focusPrevious();
        return;
      }
      if (key.tab) {
        focusNext();
        return;
      }
      if (key.escape) {
        onEscape?.();
      }
    },
    { isActive: active },
  );
}
