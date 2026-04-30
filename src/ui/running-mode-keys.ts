/**
 * Running-mode keystroke routing.
 *
 * Pure function that maps a single keystroke + the current key flags into one
 * of the well-known running-mode actions. Extracted from `App.tsx`'s
 * `useInput` handler so it can be unit-tested — the bug worth locking is "no
 * digit key may ever map to abort, and no abort key may ever map to a tab
 * switch", since the previous shape of the handler made it easy to introduce
 * such a coupling by accident.
 */
import type { InteractionKey } from "./interaction-key-policy.js";
import { isAbortInput } from "./interaction-key-policy.js";

export type RunningKeyAction =
  | { kind: "abort" }
  | { kind: "cost-cap-continue" }
  | { kind: "cost-cap-abort" }
  | { kind: "switch-scan-view"; view: "pipeline" | "findings" | "cost" }
  | { kind: "toggle-heartbeat" }
  | { kind: "toggle-notice-rail" }
  | { kind: "none" };

export interface RunningKeyContext {
  costCapHalted: boolean;
}

export function resolveRunningKey(
  input: string,
  key: InteractionKey,
  ctx: RunningKeyContext,
): RunningKeyAction {
  if (ctx.costCapHalted) {
    // Order matters: abort chord beats bare "c", so a Ctrl+C while halted
    // aborts instead of being misread as the "continue" verb.
    if (input === "a" || isAbortInput(input, key)) return { kind: "cost-cap-abort" };
    if (input === "c") return { kind: "cost-cap-continue" };
    return { kind: "none" };
  }

  // Abort takes precedence over every plain-character mapping below — but
  // crucially it ONLY triggers on Ctrl+C / Ctrl+D, never on plain digits.
  if (isAbortInput(input, key)) return { kind: "abort" };

  // Tab cycle: digits 1/2/3 switch the running-scan sub-view. We require
  // the digit to be alone (no Ctrl/Meta) so a Ctrl-prefixed chord can never
  // accidentally collapse to a tab switch.
  if (key.ctrl !== true && key.meta !== true) {
    if (input === "1") return { kind: "switch-scan-view", view: "pipeline" };
    if (input === "2") return { kind: "switch-scan-view", view: "findings" };
    if (input === "3") return { kind: "switch-scan-view", view: "cost" };
    if (input === "m") return { kind: "toggle-heartbeat" };
    if (input === "n") return { kind: "toggle-notice-rail" };
  }
  return { kind: "none" };
}
