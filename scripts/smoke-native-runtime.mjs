#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import {
  nativeExecutableName,
  nativePlatformSlug,
  nativeRuntimePackages,
} from "./native-runtime-contract.mjs";

const root = process.cwd();
const runtimeDir = path.join(root, "native", nativePlatformSlug());
const cli = path.join(runtimeDir, nativeExecutableName("kuzushi"));
const isolatedEnvironment = { ...process.env, PATH: "" };
const mcpBackends = new Map([
  ["kuzushi-mcp-gtags", "gtags"],
  ["kuzushi-mcp-clang", "clang"],
  ["kuzushi-mcp-cpg", "cpg"],
  ["kuzushi-mcp-treesitter", "tree-sitter"],
  ["kuzushi-mcp-codeql", "codeql"],
  ["kuzushi-mcp-revng", "revng"],
  ["kuzushi-mcp-context", "context"],
  ["kuzushi-mcp-entry-points", "entry-points"],
  ["kuzushi-mcp-findings", "findings"],
  ["kuzushi-mcp-threat-model", "threat-model"],
  ["kuzushi-mcp-threat-intel", "threat-intel"],
  ["kuzushi-mcp-x-ray", "x-ray"],
]);
const livenessOnlyServers = new Set([
  "kuzushi-mcp-treesitter",
  "kuzushi-mcp-codeql",
  "kuzushi-mcp-context",
  "kuzushi-mcp-entry-points",
  "kuzushi-mcp-findings",
  "kuzushi-mcp-threat-model",
  "kuzushi-mcp-threat-intel",
  "kuzushi-mcp-x-ray",
]);

run(cli, ["--version"]);
for (const { binaryName } of nativeRuntimePackages) {
  if (binaryName === "kuzushi") continue;
  const backend = mcpBackends.get(binaryName);
  if (!backend) throw new Error(`missing MCP backend mapping for ${binaryName}`);
  const result = run(cli, ["mcp", "health", backend]);
  if (livenessOnlyServers.has(binaryName)) assertLivenessOnlyHealth(result.stdout, binaryName);
}

process.stdout.write(
  `native ${nativePlatformSlug()} CLI and every MCP sibling passed with an empty inherited PATH\n`,
);

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    env: isolatedEnvironment,
    encoding: "utf8",
  });
  if (!result.error && result.status === 0) return result;
  const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  throw result.error ?? new Error(`${command} ${args.join(" ")} failed: ${detail}`);
}

function assertLivenessOnlyHealth(stdout, binaryName) {
  const health = JSON.parse(stdout);
  if (health.processHealthy !== true || health.backendReadiness !== "not-probed") {
    throw new Error(
      `${binaryName} must report process liveness without claiming backend readiness`,
    );
  }
}
