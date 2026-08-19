#!/usr/bin/env node

import { readFileSync } from "node:fs";

const contracts = [
  {
    file: "docs/modules.md",
    required: [
      "result memo for dependency-free local query selectors",
      "A memo hit skips `codeql database analyze`",
      "full content authentication of the database tree",
      "proportional to database size",
      "local queries with imports are rejected",
      "OS-sandboxed snapshot paths",
    ],
  },
  {
    file: "docs/taint-iris-next.md",
    required: [
      "A memo hit skips CodeQL execution",
      "full content authentication of the database tree",
      "proportional to database size",
      "read-only MCP sandbox",
      "Full source authentication still runs on every request, including memo lookups",
      "safely reclaim abandoned roots after a crash",
    ],
  },
  {
    file: "crates/kuzushi-mcp-codeql/src/tools.rs",
    required: [
      "A memo hit skips CodeQL execution",
      "proportional to database size",
      "Recompute this identity for every request, including memo lookups",
      "Imported local queries are rejected",
      "Abandoned server-session roots are reclaimed",
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
