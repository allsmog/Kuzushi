/**
 * Prompt regression harness — when a tracked system prompt changes, the
 * sha256 hash in the expected map below diverges from `currentHashes()`
 * and the test fails. Developer intentionally updates the expected value
 * alongside the prompt edit so every change surfaces in code review.
 *
 * Add a new entry to `listRegressionPrompts()` in
 * src/testing/prompt-regression.ts and mirror the expected hash here.
 */

import { describe, expect, it } from "vitest";
import {
  currentHashes,
  listRegressionPrompts,
  promptHash,
} from "../../src/testing/prompt-regression.js";

/**
 * Pinned hashes. Update intentionally when a prompt moves — reviewer sees
 * the diff in this file alongside the prompt diff.
 */
const EXPECTED_HASHES: Record<string, string> = {
  "cheap-verify.system": "746bf3b0ca727011d34270fa01a325fd4035175639725cae536cf286aac409d0",
};

describe("prompt regression hashes", () => {
  it("every tracked prompt has a pinned hash", () => {
    const tracked = listRegressionPrompts();
    const missing = tracked.filter((p) => !(p.id in EXPECTED_HASHES));
    expect(missing.map((p) => p.id)).toEqual([]);
  });

  it.each(listRegressionPrompts())("$id matches pinned hash", ({ id, text }) => {
    const actual = promptHash(text);
    const expected = EXPECTED_HASHES[id];
    expect(actual, `${id} changed — update EXPECTED_HASHES or revert the prompt edit`).toBe(
      expected,
    );
  });

  it("currentHashes() covers every pinned id (no orphan expectations)", () => {
    const actual = Object.keys(currentHashes()).sort();
    const pinned = Object.keys(EXPECTED_HASHES).sort();
    expect(actual).toEqual(pinned);
  });
});

describe("promptHash", () => {
  it("is deterministic + content-addressable", () => {
    expect(promptHash("hello")).toBe(promptHash("hello"));
    expect(promptHash("hello")).not.toBe(promptHash("Hello"));
    expect(promptHash("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("returns a 64-char hex string", () => {
    expect(promptHash("x")).toMatch(/^[a-f0-9]{64}$/);
  });
});
