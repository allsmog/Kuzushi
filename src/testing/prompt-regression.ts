/**
 * Prompt regression harness — pins the compiled output of every system
 * prompt we ship so unintentional edits trip the test suite.
 *
 * Two layers of defence:
 *   1. SHA-256 hex hash of each prompt string → stable fingerprint that's
 *      easy to diff in a test expectation. When the prompt moves, the
 *      hash changes and the test fails; the developer updates the hash
 *      along with whatever other evidence (A/B scan, eval run) justifies
 *      the change.
 *   2. Optional snapshot file — teams that want a full text diff (for PR
 *      review) can enable by setting `KUZUSHI_PROMPT_SNAPSHOTS=1` when
 *      running vitest. The snapshot writer is the caller's responsibility
 *      via vitest's built-in `toMatchSnapshot()`.
 */

import { createHash } from "node:crypto";
import { CHEAP_VERIFY_SYSTEM_PROMPT } from "../bus/orchestrator/cheap-verify.js";

export interface PromptEntry {
  /** Stable identifier — file:symbol or short slug. */
  id: string;
  /** Rendered prompt string (already composed). */
  text: string;
  /** Short human description of the prompt's purpose. */
  description: string;
}

/**
 * The canonical list of system prompts subject to regression control.
 * Add an entry here when you ship a new constant prompt.
 */
export function listRegressionPrompts(): PromptEntry[] {
  return [
    {
      id: "cheap-verify.system",
      text: CHEAP_VERIFY_SYSTEM_PROMPT,
      description: "Cheap-verify single-turn gate prompt",
    },
  ];
}

/** SHA-256 hex fingerprint of a prompt string. */
export function promptHash(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Canonical { id: hash } map. Snapshot these in a test; when a prompt
 * moves, the hash changes and the developer updates the expected value
 * alongside the prompt edit.
 */
export function currentHashes(): Record<string, string> {
  const entries = listRegressionPrompts();
  const out: Record<string, string> = {};
  for (const e of entries) out[e.id] = promptHash(e.text);
  return out;
}
