/**
 * Deterministic mock Anthropic Messages API server for smoke / benchmark tests.
 *
 * Starts an HTTP server that responds to POST /v1/messages with a canned
 * assistant response.  The triage pipeline only needs a plausible JSON reply
 * (verdict, confidence, reasoning) — this server always returns a
 * "needs_review" triage verdict so findings pass through without real LLM calls.
 *
 * Handles both non-streaming (`stream: false`) and streaming (`stream: true`)
 * requests — pi-ai / Anthropic SDK defaults to SSE streaming.
 *
 * Usage:
 *   node tests/fixtures/mock-anthropic-server.mjs
 *
 * The server prints the base URL to stdout on startup so callers can capture it:
 *   BASE_URL=$(node tests/fixtures/mock-anthropic-server.mjs &)
 */

import { createServer } from "node:http";

const CANNED_TEXT = JSON.stringify({
  verdict: "needs_review",
  confidence: 0.5,
  reasoning: "Synthetic response from mock server — no real LLM call was made.",
});

const MESSAGE_ID = "msg_fake_000";
const MODEL = "fake-model";

const CANNED_RESPONSE = {
  id: MESSAGE_ID,
  type: "message",
  role: "assistant",
  model: MODEL,
  stop_reason: "end_turn",
  stop_sequence: null,
  content: [{ type: "text", text: CANNED_TEXT }],
  usage: { input_tokens: 10, output_tokens: 20 },
};

function writeSse(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function respondStreaming(res) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  writeSse(res, "message_start", {
    type: "message_start",
    message: {
      id: MESSAGE_ID,
      type: "message",
      role: "assistant",
      model: MODEL,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 10, output_tokens: 0 },
    },
  });

  writeSse(res, "content_block_start", {
    type: "content_block_start",
    index: 0,
    content_block: { type: "text", text: "" },
  });

  writeSse(res, "content_block_delta", {
    type: "content_block_delta",
    index: 0,
    delta: { type: "text_delta", text: CANNED_TEXT },
  });

  writeSse(res, "content_block_stop", {
    type: "content_block_stop",
    index: 0,
  });

  writeSse(res, "message_delta", {
    type: "message_delta",
    delta: { stop_reason: "end_turn", stop_sequence: null },
    usage: { output_tokens: 20 },
  });

  writeSse(res, "message_stop", { type: "message_stop" });

  res.end();
}

function respondJson(res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(CANNED_RESPONSE));
}

const server = createServer((req, res) => {
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    let wantsStream = false;
    if (chunks.length > 0) {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        wantsStream = body.stream === true;
      } catch {
        // ignore — fall through to non-stream response
      }
    }
    if (wantsStream) respondStreaming(res);
    else respondJson(res);
  });
});

server.listen(0, "127.0.0.1", () => {
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  process.stdout.write(`${baseUrl}\n`);
});

process.on("SIGTERM", () => {
  server.close();
  process.exit(0);
});
process.on("SIGINT", () => {
  server.close();
  process.exit(0);
});
