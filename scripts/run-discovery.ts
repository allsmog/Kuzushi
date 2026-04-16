#!/usr/bin/env npx tsx

/**
 * Quick script to run the discovery pipeline against a repo and print results.
 * Usage: npx tsx scripts/run-discovery.ts <repo-path>
 */

import { ClaudeAgentRuntime } from "../src/agent-runtime/claude.js";
import { discoverRepoStructure } from "../src/discovery/repo-discovery.js";

const repoPath = process.argv[2];
if (!repoPath) {
  console.error("Usage: npx tsx scripts/run-discovery.ts <repo-path>");
  process.exit(1);
}

const runtime = new ClaudeAgentRuntime();

console.log(`\nRunning discovery on: ${repoPath}\n`);

const result = await discoverRepoStructure(repoPath, {
  maxModules: 30,
  runtime,
  model: "claude-sonnet-4-20250514",
});

console.log(`\n${"=".repeat(70)}`);
console.log(
  `Discovery result: ${result.modules.length} module(s), ${result.products.length} product(s)`,
);
console.log(`Cost: $${result.costUsd.toFixed(4)}`);
console.log(`Reasoning: ${result.reasoning}`);
console.log(`${"=".repeat(70)}\n`);

for (const m of result.modules) {
  console.log(`  ${m.name}`);
  console.log(`    path:       ${m.path}`);
  console.log(`    language:   ${m.language}`);
  console.log(`    kind:       ${m.moduleKind}`);
  console.log(`    evidence:   ${m.discoveryEvidence.join(", ")}`);
  if (m.includePaths && m.includePaths.length > 0) {
    console.log(`    includePaths (${m.includePaths.length}):`);
    for (const p of m.includePaths) {
      console.log(`      - ${p}`);
    }
  }
  console.log();
}

console.log(`\nProducts:`);
for (const p of result.products) {
  console.log(`  ${p.path} (${p.kind}) — ${p.children.length} children`);
}
