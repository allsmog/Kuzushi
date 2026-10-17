// Decode the production framing only in offline request assertions.
import assert from "node:assert/strict";

export function decodedThreatContext(body) {
  const text = body.input
    .flatMap((message) => message.content ?? [])
    .map((part) => (typeof part === "string" ? part : (part.text ?? "")))
    .join("\n");
  const records = [
    ...text.matchAll(
      /UNTRUSTED_DERIVED_BEGIN\nrecord_version=1\nkind=derived\nencoding=percent-v1\nlabel_bytes=(\d+)\ncontent_bytes=(\d+)\nlabel=([^\n]*)\ncontent=([^\n]*)\nUNTRUSTED_DERIVED_END/g,
    ),
  ].filter((match) => decodeURIComponent(match[3]) === "threat-model-digest");
  assert.equal(records.length, 1, "The actual request must contain one framed threat-model digest");
  const [record] = records;
  const label = decodeURIComponent(record[3]);
  const content = decodeURIComponent(record[4]);
  assert.equal(Buffer.byteLength(label), Number(record[1]));
  assert.equal(Buffer.byteLength(content), Number(record[2]));
  return content;
}
