import assert from "node:assert/strict";
import test from "node:test";
import { AIMessage } from "@langchain/core/messages";
import { bridgeQueryResult, isTruncatedStopReason } from "./model.mjs";

test("forced conclusions remain structured but are marked truncated", () => {
  const result = bridgeQueryResult(
    [new AIMessage('{"verdict":"confirmed"}')],
    "forced_conclusion",
  );

  assert.deepEqual(result.structured, { verdict: "confirmed" });
  assert.equal(result.stopReason, "forced_conclusion");
  assert.equal(result.truncated, true);
});

test("natural completion is not marked truncated", () => {
  assert.equal(isTruncatedStopReason(undefined), false);
  assert.equal(isTruncatedStopReason("stop"), false);
});
