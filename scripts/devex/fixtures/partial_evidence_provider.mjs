// Every request stays inside the owned transport fixture.
import assert from "node:assert/strict";
import "./base-provider.mjs";

const intercepted = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const prompt = JSON.parse(body.input[0].content);
  assert.equal(prompt.sourceInventory.enumerationComplete, false);
  assert.equal(prompt.sourceInventory.selectedMembershipKnown, true);
  assert.equal(prompt.sourceInventory.maxEntries, 100_000);
  assert.equal(prompt.source.files.length, 2);
  assert.ok(!JSON.stringify(prompt).includes("UNSELECTED_WIDE_SOURCE"));
  return intercepted(url, init);
};
