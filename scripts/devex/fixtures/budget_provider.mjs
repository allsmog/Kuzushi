// Every request is intercepted. The fixture also checks the live call allowance.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = dirname(fileURLToPath(import.meta.url));
const calls = join(directory, "budget-calls.jsonl");
const target = readFileSync(join(directory, "budget-target.txt"), "utf8").trim();
const quotaQuery = `import json,sqlite3,sys
from pathlib import Path
p=Path(sys.argv[1])/'.kuzushi/v3/index.sqlite3'
with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as db:
 a=json.loads(db.execute('select approval_json from investigation_allowance_revisions order by revision desc limit 1').fetchone()[0])
 print(json.dumps(a['limits']))`;

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-matrix-fixture");
  const body = JSON.parse(init.body);
  const count = existsSync(calls)
    ? readFileSync(calls, "utf8").trim().split("\n").filter(Boolean).length
    : 0;
  const limits = JSON.parse(
    execFileSync("python3", ["-B", "-c", quotaQuery, target], { encoding: "utf8" }),
  );
  assert.ok(count < 9, "The original finite plan has nine requests at most");
  assert.ok(
    count < limits.maxProviderCalls - limits.protectedReviewCalls,
    "The approved allowance must protect review before transport",
  );
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  const context = count < 3 ? "Alpha" : count < 6 ? "Beta" : "Gamma";
  const prompt = JSON.stringify(body.input);
  assert.ok(prompt.includes(context));
  if (count < 6) assert.ok(!prompt.includes("Gamma"));
  appendFileSync(
    calls,
    `${JSON.stringify({
      call: count + 1,
      context,
      freshSession: true,
      model: body.model,
      liveProviderRequests: 0,
    })}\n`,
  );
  const text = JSON.stringify({
    findings: [5, 7, 8].includes(count)
      ? []
      : [
          {
            ruleId: "labeled-budget-observation",
            title: "Labeled synthetic budget observation",
            filePath: "main.rs",
            startLine: 1,
            severity: "info",
            confidence: "low",
            message: "Synthetic budget fixture. No security defect is claimed.",
            evidence: "Owned greeting source, never executed.",
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
