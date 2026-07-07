// Regenerates `structured_output_contract.golden` — the parity oracle for
// the Rust `append_structured_output_contract`.
//
//   node regenerate_structured_output_contract.mjs > structured_output_contract.golden
//   printf '\n' >> structured_output_contract.golden   # POSIX trailing newline
//
// The function body below is a VERBATIM copy of `appendStructuredOutputContract`
// in `scripts/langgraph-bridge/model.mjs`. It is dependency-free, so this stays
// runnable after the LangGraph bridge npm deps are removed. When the native
// runtime replaces the bridge, this golden proves the Rust port emits the exact
// same system-prompt suffix the bridge sent, byte-for-byte.
//
// The schema uses sorted keys and integer-only numbers on purpose: serde_json
// serializes map keys in BTreeMap order and renders `1.0` (not JS's `1`), so a
// sorted/integer schema is the subset where JSON.stringify(_, null, 2) and
// serde_json::to_string_pretty agree exactly.
function appendStructuredOutputContract(systemPrompt, structuredOutput) {
  const contract = structuredOutput ?? undefined;
  if (!contract) return String(systemPrompt ?? "");
  const name = contract.name ?? "structured_response";
  const schema = JSON.stringify(contract.schema ?? {}, null, 2);
  const strict = contract.strict ? "strict " : "";
  return `${systemPrompt ?? ""}\n\nStructured output contract:\nReturn only ${strict}JSON for \`${name}\`. Do not include markdown fences, prose, or trailing commentary.\nRequired JSON schema:\n${schema}`;
}

const schema = {
  additionalProperties: false,
  properties: {
    confidence: { maximum: 1, minimum: 0, type: "number" },
    rationale: { type: "string" },
    verdict: { enum: ["true_positive", "false_positive", "needs_review"], type: "string" },
  },
  required: ["verdict", "confidence", "rationale"],
  type: "object",
};

process.stdout.write(
  appendStructuredOutputContract("You are a triage agent.", {
    name: "kuzushi_triage_outcome",
    schema,
    strict: true,
  }),
);
