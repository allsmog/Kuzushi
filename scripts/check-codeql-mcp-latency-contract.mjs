#!/usr/bin/env node

import { readFileSync } from "node:fs";

const contracts = [
  {
    file: "AGENTS.md",
    required: [
      "result memo for dependency-free local query selectors",
      "A memo hit skips `codeql database analyze`",
      "full content authentication of the database tree",
      "proportional to database size",
      "Pack selectors and imported local queries bypass the result memo",
    ],
  },
  {
    file: "CLAUDE.md",
    required: [
      "result memo for dependency-free local query selectors",
      "A memo hit skips `codeql database analyze`",
      "full content authentication of the database tree",
      "proportional to database size",
      "Pack selectors and imported local queries bypass the result memo",
    ],
  },
  {
    file: "docs/taint-iris-next.md",
    required: [
      "A memo hit skips CodeQL execution",
      "full content authentication of the database tree",
      "proportional to database size",
      "immutable, cross-platform server-lifetime filesystem snapshot",
      "full content hash on every request, including memo lookups",
    ],
  },
  {
    file: "crates/kuzushi-mcp-codeql/src/tools.rs",
    required: [
      "A memo hit skips CodeQL execution",
      "proportional to database size",
      "Recompute this identity for every request, including memo lookups",
      "not an immutable server-lifetime snapshot",
    ],
  },
];

const failures = [];
for (const contract of contracts) {
  const text = normalizedFile(contract.file);
  for (const phrase of contract.required) {
    if (!text.includes(phrase)) {
      failures.push(`${contract.file}: missing ${JSON.stringify(phrase)}`);
    }
  }
  if (text.includes("returns instantly")) {
    failures.push(`${contract.file}: promises an instant memo return`);
  }
  if (text.includes("Each tool spawns codeql")) {
    failures.push(`${contract.file}: claims every tool executes CodeQL`);
  }
}

if (failures.length > 0) {
  console.error("CodeQL MCP latency contract failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("CodeQL MCP latency contract passed");

function normalizedFile(file) {
  return readFileSync(file, "utf8")
    .replace(/^\s*\/\/!?\s?/gm, "")
    .replace(/\s+/g, " ");
}
