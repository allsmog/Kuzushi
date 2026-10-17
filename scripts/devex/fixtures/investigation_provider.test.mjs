import assert from "node:assert/strict";
import test from "node:test";
import { decodedThreatContext, responseOrdinal } from "./investigation_provider.mjs";

function body(content, bytes = Buffer.byteLength(content)) {
  const encoded = [...Buffer.from(content)]
    .map((byte) =>
      byte >= 0x20 && byte <= 0x7e && byte !== 0x25 && byte !== 0x5f
        ? String.fromCharCode(byte)
        : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`,
    )
    .join("");
  return {
    input: [
      {
        content: [
          {
            text: `UNTRUSTED_DERIVED_BEGIN\nrecord_version=1\nkind=derived\nencoding=percent-v1\nlabel_bytes=19\ncontent_bytes=${bytes}\nlabel=threat-model-digest\ncontent=${encoded}\nUNTRUSTED_DERIVED_END`,
          },
        ],
      },
    ],
  };
}

test("request verification decodes exact newlines, Unicode, underscores and percent bytes", () => {
  const text = "Owned context:\nReview \u754c_100% independently.";
  assert.equal(decodedThreatContext(body(text)), text);
});

test("request verification refuses missing framing and mismatched byte counts", () => {
  assert.throws(() => decodedThreatContext({ input: [{ content: "Unframed context" }] }));
  assert.throws(() => decodedThreatContext(body("Owned context", 1)));
});

test("request verification rejects ambiguous duplicate contexts", () => {
  const value = body("Owned context");
  value.input.push(...body("A different context").input);
  assert.throws(() => decodedThreatContext(value));
});

test("request verification rejects malformed UTF-8 framing", () => {
  const value = body("Owned context");
  value.input[0].content[0].text = value.input[0].content[0].text.replace(
    "content=Owned context",
    "content=%C3",
  );
  assert.throws(() => decodedThreatContext(value), URIError);
});

test("a canceled request consumes a call without becoming a discovery response", () => {
  assert.deepEqual(
    [0, 1, 2, 3].map((count) => responseOrdinal(count, false)),
    [0, 1, 2, 3],
  );
  assert.equal(responseOrdinal(3, true), 2);
  assert.equal(responseOrdinal(4, true), 3);
});
