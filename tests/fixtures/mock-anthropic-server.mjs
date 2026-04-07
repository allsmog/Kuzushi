/**
 * Deterministic mock Anthropic Messages API server for smoke / benchmark tests.
 *
 * Starts an HTTP server that responds to POST /v1/messages with a canned
 * assistant response.  The triage pipeline only needs a plausible JSON reply
 * (verdict, confidence, reasoning) — this server always returns a
 * "needs_review" triage verdict so findings pass through without real LLM calls.
 *
 * Usage:
 *   node tests/fixtures/mock-anthropic-server.mjs
 *
 * The server prints the base URL to stdout on startup so callers can capture it:
 *   BASE_URL=$(node tests/fixtures/mock-anthropic-server.mjs &)
 */

import { createServer } from "node:http";

const CANNED_RESPONSE = {
  id: "msg_fake_000",
  type: "message",
  role: "assistant",
  model: "fake-model",
  stop_reason: "end_turn",
  stop_sequence: null,
  content: [
    {
      type: "text",
      text: JSON.stringify({
        verdict: "needs_review",
        confidence: 0.5,
        reasoning: "Synthetic response from mock server — no real LLM call was made.",
      }),
    },
  ],
  usage: { input_tokens: 10, output_tokens: 20 },
};

const server = createServer((req, res) => {
  // Collect request body (we don't actually need it).
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(CANNED_RESPONSE));
  });
});

server.listen(0, "127.0.0.1", () => {
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  // Print the base URL so the caller can capture it.
  process.stdout.write(baseUrl + "\n");
});

// Shut down cleanly when the parent process exits.
process.on("SIGTERM", () => { server.close(); process.exit(0); });
process.on("SIGINT", () => { server.close(); process.exit(0); });
