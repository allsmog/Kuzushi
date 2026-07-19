import assert from "node:assert/strict";
import test from "node:test";
import { verificationPlan } from "./verify-repository.mjs";

test("quick verification is a strict subset of CI parity", () => {
  const quick = verificationPlan("quick").map(({ name }) => name);
  const ci = verificationPlan("ci").map(({ name }) => name);

  assert.deepEqual(ci.slice(0, quick.length), quick);
  assert.ok(ci.includes("rust-tests"));
  assert.ok(ci.includes("build-native"));
  assert.ok(ci.includes("pack-contract"));
  assert.ok(ci.includes("e2e"));
});

test("unknown verification modes fail closed", () => {
  assert.throws(() => verificationPlan("fast-ish"), /quick or ci/);
});
