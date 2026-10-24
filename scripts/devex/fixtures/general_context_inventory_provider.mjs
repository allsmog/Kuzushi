// Owned offline transport. Every fetch is intercepted, without network fallback.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const calls = join(evidence, "inventory-calls.jsonl");

globalThis.fetch = async (url, init) => {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  assert.ok(!existsSync(calls), "Only one initial request is authorized");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.ok(!body.tools?.length);
  assert.equal(body.previous_response_id, undefined);
  const text = body.input
    .flatMap((message) => message.content ?? [])
    .map((part) => (typeof part === "string" ? part : (part.text ?? "")))
    .join("\n");
  const frames = [
    ...text.matchAll(
      /UNTRUSTED_REPO_BEGIN\nrecord_version=1\nkind=repository\nencoding=percent-v1\nlabel_bytes=(\d+)\ncontent_bytes=(\d+)\nlabel=([^\n]*)\ncontent=([^\n]*)\nUNTRUSTED_REPO_END/g,
    ),
  ].filter((match) => decodeURIComponent(match[3]) === "repository-inventory");
  assert.equal(frames.length, 1);
  const frame = frames[0];
  const label = decodeURIComponent(frame[3]);
  const raw = decodeURIComponent(frame[4]);
  assert.equal(Buffer.byteLength(label), Number(frame[1]));
  assert.equal(Buffer.byteLength(raw), Number(frame[2]));
  const inventory = JSON.parse(raw);
  const expected = JSON.parse(readFileSync(join(evidence, "expected-inventory.json"), "utf8"));
  assert.deepEqual(inventory.listedPaths, expected.slice(0, 40));
  assert.equal(inventory.enumeration, "git-index");
  assert.equal(inventory.enumerationComplete, true);
  assert.equal(inventory.enumeratedFiles, expected.length);
  assert.equal(inventory.listedFiles, 40);
  assert.equal(inventory.unlistedFiles, expected.length - 40);
  assert.equal(inventory.completeRepositoryCoverage, false);
  assert.ok(inventory.listedPaths.includes(" literal 東京.rs"));
  assert.ok(!inventory.listedPaths.includes("ignored-note.txt"));
  assert.ok(!text.includes("PRIVATE_IGNORED_FIXTURE_MARKER"));
  assert.ok(!text.includes("Original receiver"));
  assert.equal(
    inventory.listedPathsSha256,
    `sha256:${createHash("sha256").update(JSON.stringify(inventory.listedPaths)).digest("hex")}`,
  );
  const grounding = text.match(
    /<untrusted-source label="attack-surface-map"[^>]*>\n([\s\S]*?)\n<\/untrusted-source>/,
  );
  assert.ok(grounding, "The real grounded-source section must reach the request");
  const groundedIds = [...grounding[1].matchAll(/^- id=([^\n]+?) ·/gm)].map((row) => row[1]);
  assert.equal(groundedIds.length, 2);
  appendFileSync(
    calls,
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      inventory,
      groundedIds,
      inputSha256: createHash("sha256").update(text).digest("hex"),
      interceptedRequests: 1,
      liveProviderRequests: 0,
      tools: 0,
    })}\n`,
  );
  const document = {
    version: "1",
    methodology: "stride",
    title: "Owned bounded filename context",
    systemContext:
      "Owned transport fixture over static source comments. A human reads the recorded source; no target source executes. Deployed architecture and vulnerabilities are not established.",
    dfd: {
      nodes: [
        {
          id: "source",
          name: "Declared source comments",
          type: "process",
          trustZone: "repository",
          description: "Holds an owned policy marker as static text in app.py.",
          purpose: "Make source-only investigation boundaries inspectable.",
          sourceRefs: ["app.py:1"],
          evidenceAnchors: [{ filePath: "app.py", startLine: 1 }],
        },
        {
          id: "reader",
          name: "Human reader",
          type: "external-entity",
          trustZone: "operator",
          purpose: "Reviews the source and its limitations.",
        },
      ],
      flows: [
        {
          id: "reading",
          sourceId: "source",
          targetId: "reader",
          description: "Declared reading of source text; no runtime flow proof.",
          trustBoundaryIds: [],
        },
      ],
      trustBoundaries: [],
    },
    threats: [],
    assets: [],
    attackSurface: {
      entryPoints: [
        {
          id: "owned-source-reading",
          name: "Declared source reading",
          path: "app.py",
          line: 1,
          targetElementIds: ["source"],
          description:
            "Owned source comment for a bounded reading action. This annotation establishes no runtime entry point or vulnerability.",
        },
      ],
      roleGates: [],
      externalSinks: [],
      trustedCallers: [],
    },
    deprioritized: groundedIds.map((entryPointId) => ({
      entryPointId,
      reason:
        "Owned static artifact supports an inventory demonstration. No deployed exposure or vulnerability is asserted.",
    })),
    openQuestions: [
      "Source comments and filename membership do not establish deployed runtime behavior.",
    ],
    summary: {},
  };
  const events = [
    { type: "response.output_text.done", text: JSON.stringify(document) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 3, output_tokens: 5 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
};
