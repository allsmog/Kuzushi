#!/usr/bin/env node

import readline from "node:readline";

function extractFingerprint(prompt) {
  const quoted = prompt.match(/fingerprint["']?\s*[:=]\s*["']([^"'\n]+)["']/i);
  if (quoted?.[1]) {
    return quoted[1];
  }

  const labeled = prompt.match(/Fingerprint:\s*([^\s\n]+)/i);
  if (labeled?.[1]) {
    return labeled[1];
  }

  return "fake-fingerprint";
}

function extractResponse(prompt, schema) {
  const properties = schema?.properties ?? {};
  const fingerprint = extractFingerprint(prompt);

  if (Object.hasOwn(properties, "verification_steps")) {
    return {
      fingerprint,
      verdict: "tp",
      confidence: 0.91,
      rationale: "Deterministic ACP smoke adapter confirmed the finding for pipeline validation.",
      verification_steps: ["Review the reported sink and source in the fixture app."],
      fix_patch: null,
    };
  }

  if (Object.hasOwn(properties, "results")) {
    return {
      results: [
        {
          fingerprint,
          verdict: "tp",
          confidence: 0.91,
          rationale: "Deterministic ACP smoke adapter confirmed the finding for pipeline validation.",
          verification_steps: ["Review the reported sink and source in the fixture app."],
          fix_patch: null,
        },
      ],
    };
  }

  if (Object.hasOwn(properties, "poc_payload")) {
    return {
      fingerprint,
      exploitable: false,
      poc_payload: null,
      poc_description: "Smoke adapter does not perform exploit generation.",
      attack_vector: null,
      preconditions: [],
      confidence: 0.25,
    };
  }

  if (Object.hasOwn(properties, "findings")) {
    return { findings: [] };
  }

  if (Object.hasOwn(properties, "supplements")) {
    return { supplements: [] };
  }

  if (Object.hasOwn(properties, "variadicFormatFuncs")) {
    return {
      variadicFormatFuncs: [],
      sqlQueryTextArg0Callables: [],
      stdlibPackages: [],
    };
  }

  if (Object.hasOwn(properties, "regressions")) {
    return { regressions: [] };
  }

  return {};
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

rl.on("line", (line) => {
  if (!line.trim()) {
    return;
  }

  let request;
  try {
    request = JSON.parse(line);
  } catch {
    return;
  }

  const prompt = String(request?.params?.prompt ?? "");
  const schema = request?.params?.outputFormat?.schema;
  const response = {
    jsonrpc: "2.0",
    id: request.id,
    result: {
      content: [
        {
          type: "text",
          text: JSON.stringify(extractResponse(prompt, schema)),
        },
      ],
      stopReason: "end_turn",
      cost: {
        total: 0,
      },
    },
  };

  process.stdout.write(`${JSON.stringify(response)}\n`);
});
