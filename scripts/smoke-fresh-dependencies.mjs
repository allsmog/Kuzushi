#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exerciseConsumerBridge } from "./consumer-bridge-smoke.mjs";

function run(label, command, args, options = {}) {
  const result = spawnSync(command, args, {
    ...options,
    encoding: "utf8",
    timeout: 300_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status !== 0)
    throw result.error ?? Error(`${label}: ${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

const root = mkdtempSync(join(tmpdir(), "kuzushi-fresh-dependencies-"));
try {
  const manifest = JSON.parse(readFileSync("package.json", "utf8"));
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({
      name: "kuzushi-consumer-contract",
      version: "0.0.0",
      private: true,
      type: "module",
      dependencies: manifest.dependencies,
    }),
  );
  cpSync("scripts/langgraph-bridge", join(root, "scripts/langgraph-bridge"), { recursive: true });
  cpSync("scripts/langgraph-bridge.mjs", join(root, "scripts/langgraph-bridge.mjs"));
  run(
    "fresh npm install",
    "npm",
    ["install", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
    { cwd: root },
  );
  const graph = JSON.parse(
    run("production dependency graph", "npm", ["ls", "--omit=dev", "--all", "--json"], {
      cwd: root,
    }),
  );
  exerciseConsumerBridge(root, run);
  const receipt = {
    version: manifest.version,
    resolvedAt: new Date().toISOString(),
    bridgeContracts: "passed",
    dependencyGraph: graph,
  };
  writeFileSync(
    process.env.KUZUSHI_DEPENDENCY_RECEIPT ?? "fresh-dependencies.json",
    `${JSON.stringify(receipt, null, 2)}\n`,
  );
  console.log("Fresh npm production graph and installed bridge contracts passed");
} finally {
  rmSync(root, { recursive: true, force: true });
}
