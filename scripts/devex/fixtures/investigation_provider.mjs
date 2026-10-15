// Owned greeting fixture. Every transport request is intercepted, with no network fallback.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const evidence = dirname(fileURLToPath(import.meta.url));
const callsPath = join(evidence, "investigation-calls.jsonl");

const GREETING_NODES = [
  {
    id: "rust",
    type: "process",
    name: "Rust greeting writer",
    description: "Prints fixed greeting text",
    purpose: "Displays the owned fixture greeting",
    trustZone: "internal",
    evidenceAnchors: [{ filePath: "main.rs", startLine: 1 }],
  },
  {
    id: "python",
    type: "process",
    name: "Python greeting writer",
    description: "Prints fixed greeting text",
    purpose: "Displays an alternative owned fixture greeting",
    trustZone: "internal",
    evidenceAnchors: [{ filePath: "app.py", startLine: 1 }],
  },
  {
    id: "terminal",
    type: "external-entity",
    name: "Operator terminal",
    description: "Receives standard output",
    trustZone: "external",
  },
];
const GREETING_FLOWS = [
  {
    id: "rust-output",
    sourceId: "rust",
    targetId: "terminal",
    description: "Fixed greeting on standard output",
    trustBoundaryIds: [],
  },
  {
    id: "python-output",
    sourceId: "python",
    targetId: "terminal",
    description: "Alternative fixed greeting on standard output",
    trustBoundaryIds: [],
  },
];

function contextDocument() {
  const catalog = JSON.parse(
    readFileSync(join(evidence, "fixture-target/.kuzushi/entry-points.json"), "utf8"),
  );
  assert.ok(catalog.entryPoints.length, "Real preparation must produce grounded source surfaces");
  return {
    version: "2.0",
    title: "Owned greeting application",
    systemContext:
      "Two labeled alternative programs print fixed greetings to a terminal. Source is never executed during this test.",
    dfd: {
      nodes: GREETING_NODES,
      flows: GREETING_FLOWS,
      trustBoundaries: [],
    },
    threats: [],
    deprioritized: catalog.entryPoints.map((surface) => ({
      entryPointId: surface.id,
      reason: "Labeled owned greeting source. No security defect is claimed.",
    })),
    summary: { total: 0, bySeverity: {}, byCategory: {} },
    openQuestions: ["Packaging and caller environments are outside this fixture."],
  };
}

function observation(kind) {
  return {
    ruleId: `labeled-${kind}`,
    title: `Labeled ${kind} observation`,
    filePath: "main.rs",
    startLine: 1,
    severity: "info",
    confidence: "low",
    message: "Synthetic nondeterminism and triage fixture. No security defect is claimed.",
    evidence: "main.rs is owned greeting source; it is never executed.",
  };
}

function priorCalls() {
  return existsSync(callsPath)
    ? readFileSync(callsPath, "utf8").trim().split("\n").filter(Boolean).length
    : 0;
}

function recordDiagnostic(url, body, input) {
  appendFileSync(
    join(evidence, "transport-diagnostics.jsonl"),
    `${JSON.stringify({
      model: body.model,
      reasoning: body.reasoning,
      endpointMatches: String(url) === "https://chatgpt.com/backend-api/codex/responses",
      hasMainSource: input.includes("main.rs"),
      hasTitle: input.includes("Owned greeting application"),
      hasRustNode: input.includes("Rust greeting writer"),
      hasPythonNode: input.includes("Python greeting writer"),
      hasAssistantHistory: body.input.some((message) => message.role === "assistant"),
      previousResponse: body.previous_response_id ?? null,
    })}\n`,
  );
}

function assertRequest(url, init, body, input, count) {
  assert.equal(String(url), "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(init.headers.authorization, "Bearer offline-investigation-fixture");
  assert.ok(
    count < (cancellationProfile() ? 5 : 4),
    "Requests stay within the explicit fixture allowance",
  );
  assert.equal(body.model, "gpt-5.5");
  assert.deepEqual(body.reasoning, { effort: "medium" });
  assert.equal(body.previous_response_id, undefined);
  assert.ok(
    !body.input.some((message) => message.role === "assistant"),
    "Fresh discovery sessions",
  );
  assert.ok(input.includes("main.rs"));
  if (count > 0) {
    assert.ok(
      input.includes("Rust greeting writer"),
      "The selected Map's Rust component must reach discovery",
    );
    assert.ok(
      input.includes("Python greeting writer"),
      "The selected Map's Python component must reach discovery",
    );
  }
}

function recordAcceptedRequest(body, input, count) {
  appendFileSync(
    callsPath,
    `${JSON.stringify({
      call: count + 1,
      stage: count === 0 ? "map" : "scan",
      bridgePid: process.pid,
      model: body.model,
      reasoning: body.reasoning,
      inputSha256: createHash("sha256").update(input).digest("hex"),
      instructionsSha256: createHash("sha256").update(body.instructions).digest("hex"),
      frozenContextTextSha256: count === 0 ? null : requireSavedContext(body),
      tools: body.tools?.length ?? 0,
      liveProviderRequests: 0,
      toolCallsReturned: 0,
    })}\n`,
  );
}

function requireSavedContext(body) {
  const state = join(evidence, "fixture-target/.kuzushi/v3");
  const plan = readdirSync(join(state, "campaigns"))
    .map((name) => JSON.parse(readFileSync(join(state, "campaigns", name, "plan.json"), "utf8")))
    .find((value) => value.kind === "scan-batch");
  assert.ok(plan, "Discovery must belong to the fixed study");
  const hash = plan.baseInput.threatModelDigestRef.object.hash;
  const document = JSON.parse(
    readFileSync(join(state, "objects/blake3", hash.slice(0, 2), hash.slice(2, 4), hash), "utf8"),
  );
  const preview = document.preview;
  assert.equal(preview.origin, "frozen-study");
  const supplied = decodedThreatContext(body);
  assert.equal(supplied, preview.text, "The actual request must include the exact saved context");
  assert.equal(preview.sha256, `sha256:${createHash("sha256").update(preview.text).digest("hex")}`);
  return preview.sha256;
}

export function decodedThreatContext(body) {
  const text = body.input
    .flatMap((message) => message.content ?? [])
    .map((part) => (typeof part === "string" ? part : (part.text ?? "")))
    .join("\n");
  const records = text.matchAll(
    /UNTRUSTED_DERIVED_BEGIN\nrecord_version=1\nkind=derived\nencoding=percent-v1\nlabel_bytes=(\d+)\ncontent_bytes=(\d+)\nlabel=([^\n]*)\ncontent=([^\n]*)\nUNTRUSTED_DERIVED_END/g,
  );
  const record = [...records].find(
    (match) => decodeURIComponent(match[3]) === "threat-model-digest",
  );
  assert.ok(record, "The actual request must include the framed threat-model digest");
  const label = decodeURIComponent(record[3]);
  const content = decodeURIComponent(record[4]);
  assert.equal(Buffer.byteLength(label), Number(record[1]));
  assert.equal(Buffer.byteLength(content), Number(record[2]));
  return content;
}

function responseValue(count) {
  if (count === 0) return contextDocument();
  const findings =
    count === 1
      ? [observation("recurring"), observation("later-only")]
      : count === 2
        ? [observation("recurring")]
        : [observation("later-only")];
  return { findings };
}

function fixtureResponse(value) {
  const events = [
    { type: "response.output_text.done", text: JSON.stringify(value) },
    {
      type: "response.completed",
      response: { status: "completed", usage: { input_tokens: 2, output_tokens: 3 } },
    },
  ];
  return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""));
}

globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const input = JSON.stringify(body.input);
  recordDiagnostic(url, body, input);
  const count = priorCalls();
  assertRequest(url, init, body, input, count);
  recordAcceptedRequest(body, input, count);
  if (cancellationProfile() && count === 2) {
    writeFileSync(
      join(evidence, "cancellation-admitted.json"),
      JSON.stringify({
        bridgePid: process.pid,
        call: count + 1,
        responseReturned: false,
        liveProviderRequests: 0,
      }),
    );
    return holdForOperatorStop(init.signal);
  }
  return fixtureResponse(responseValue(responseOrdinal(count, cancellationProfile())));
};

function cancellationProfile() {
  return existsSync(join(evidence, "cancellation-profile.json"));
}

export function responseOrdinal(count, cancellation) {
  return cancellation && count > 2 ? count - 1 : count;
}

function holdForOperatorStop(signal) {
  return new Promise((_, reject) => {
    const timer = setTimeout(
      () => reject(new Error("Fixture expected operator Stop within 45 seconds")),
      45_000,
    );
    const abort = () => {
      clearTimeout(timer);
      reject(new Error("Owned intercepted request aborted"));
    };
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", abort, { once: true });
  });
}
