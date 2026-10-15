import assert from "node:assert/strict";
import test from "node:test";
import { decodedThreatContext } from "./investigation_provider.mjs";

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
