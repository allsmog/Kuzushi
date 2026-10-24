import assert from "node:assert/strict";
import test from "node:test";
import { decodedThreatContext, optionalThreatContext } from "./untrusted_context.mjs";

function framed(content, label = "threat-model-digest") {
  return `UNTRUSTED_DERIVED_BEGIN\nrecord_version=1\nkind=derived\nencoding=percent-v1\nlabel_bytes=${Buffer.byteLength(label)}\ncontent_bytes=${Buffer.byteLength(content)}\nlabel=${encodeURIComponent(label)}\ncontent=${encodeURIComponent(content)}\nUNTRUSTED_DERIVED_END`;
}

function request(text) {
  return { input: [{ content: [{ text }] }] };
}

test("offline assertions decode exact multiline Unicode context", () => {
  const text = "literal % and\nλ context";
  assert.equal(decodedThreatContext(request(framed(text))), text);
});

test("explicit omission remains distinct from unrelated framed content", () => {
  const body = request(framed("other source", "source-evidence"));
  assert.equal(optionalThreatContext(body), null);
  assert.throws(() => decodedThreatContext(body), /one framed threat-model digest/);
});

test("duplicate framed digests cannot pass fixture assertions", () => {
  assert.throws(
    () => optionalThreatContext(request(`${framed("one")}\n${framed("two")}`)),
    /duplicate/,
  );
});

test("truncated byte counts cannot pass fixture assertions", () => {
  const record = framed("λ").replace("content_bytes=2", "content_bytes=1");
  assert.throws(() => optionalThreatContext(request(record)));
});
