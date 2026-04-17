#!/usr/bin/env node
/**
 * Example SSE client for `kuzushi scan --stream`.
 *
 * Usage:
 *   1. In one terminal:
 *      $ kuzushi scan ./repo --stream --stream-port 4455
 *   2. In another terminal:
 *      $ node examples/sse-client.mjs http://localhost:4455/events
 *
 * The server emits named SSE events for each pipeline phase. This script
 * subscribes to all of them, pretty-prints the payloads, and exits when the
 * server sends `event: done`.
 *
 * Event schema (payloads are JSON on the `data:` line):
 *
 *   connected              { message: string }
 *   scan:complete          { totalFindings: number }
 *   triage:result          { fingerprint, filePath, startLine, ruleId, severity,
 *                            message, cwe[], verdict, confidence, rationale,
 *                            costUsd, index, total }
 *   verification:result    { fingerprint, filePath, exploitable, confidence,
 *                            pocPayload?, attackVector?, costUsd }
 *   poc-harness:result     { fingerprint, filePath, scriptPath?, language?,
 *                            parsed?, skipped?, pocExecVerdict? }
 *   patch:complete         { fingerprint, status, iterations, costUsd }
 *   patch-verify:complete  { fingerprint, verified, depth }
 *   pipeline:complete      <PipelineStats>
 *   pipeline:error         { error: string, fatal: boolean }
 *   done                   { message: string }
 *
 * For a typed event schema, see src/bus/events.ts.
 */

import http from "node:http";
import { URL } from "node:url";

const url = new URL(process.argv[2] ?? "http://localhost:4455/events");

http
  .get(url, (res) => {
    if (res.statusCode !== 200) {
      console.error(`SSE server returned HTTP ${res.statusCode}`);
      process.exit(2);
    }
    res.setEncoding("utf-8");

    let buffer = "";
    res.on("data", (chunk) => {
      buffer += chunk;

      // SSE events are delimited by a blank line ("\n\n").
      let delimIdx;
      // biome-ignore lint/suspicious/noAssignInExpressions: SSE frame loop
      while ((delimIdx = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, delimIdx);
        buffer = buffer.slice(delimIdx + 2);
        handleFrame(frame);
      }
    });

    res.on("end", () => {
      console.log("--- stream ended ---");
    });
  })
  .on("error", (err) => {
    console.error(`connection error: ${err.message}`);
    process.exit(2);
  });

function handleFrame(frame) {
  const lines = frame.split("\n");
  let eventType = "message";
  let dataLines = [];
  for (const line of lines) {
    if (line.startsWith("event:")) eventType = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
  }
  if (dataLines.length === 0) return;

  let payload;
  try {
    payload = JSON.parse(dataLines.join("\n"));
  } catch {
    payload = dataLines.join("\n");
  }

  const stamp = new Date().toISOString();
  console.log(`[${stamp}] ${eventType} ${JSON.stringify(payload)}`);

  if (eventType === "done") {
    process.exit(0);
  }
}
