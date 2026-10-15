// Complete transport interception for one owned metadata relationship hypothesis. No network fallback.
import assert from "node:assert/strict";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "hypothesis-calls.jsonl");
globalThis.fetch = async (url, init) => {
  const observed = JSON.parse(init.body);
  appendFileSync(
    join(evidence, "hypothesis-attempts.jsonl"),
    `${JSON.stringify({
      origin: new URL(String(url)).origin,
      model: observed.model,
      reasoning: observed.reasoning,
      hypothesisInstruction: String(observed.instructions).includes("AttackChains"),
      syntheticConfirmation: JSON.stringify(observed.input).includes(
        "Synthetic acceptance solely for lesson UI testing",
      ),
      humanConfirmation: JSON.stringify(observed.input).includes("Author: human"),
      tools: observed.tools?.length ?? 0,
      liveProviderRequests: 0,
    })}\n`,
  );
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-pattern-fixture");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.match(body.instructions, /AttackChains/);
  const input = JSON.stringify(body.input);
  assert(input.includes("Confirmed findings available for composition"));
  assert(!body.tools?.length);
  const members = JSON.parse(readFileSync(join(evidence, "members.json"), "utf8"));
  for (const member of members) assert(input.includes(member));
  assert.ok(!existsSync(calls) || !readFileSync(calls, "utf8").trim());
  appendFileSync(
    calls,
    `${JSON.stringify({ model: body.model, liveProviderRequests: 0, toolCallsReturned: 0 })}\n`,
  );
  const text = JSON.stringify({
    chains: [
      {
        title: "Labeled greeting relationship hypothesis",
        members,
        attack_path: [
          "Which source evidence supports an interaction between these owned greetings?",
        ],
        cumulative_impact: "Unverified metadata association. No defect is claimed.",
        why_this_chain_matters: "Owned source-analysis workflow fixture only.",
        detection_difficulty: "Unknown without independent source review.",
      },
    ],
  });
  const events = [
    { type: "response.output_text.done", text },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};
