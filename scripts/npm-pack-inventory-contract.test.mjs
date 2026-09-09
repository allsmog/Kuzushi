import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  packedInventoryFailures,
  safePackagePathFailures,
} from "./npm-pack-inventory-contract.mjs";
import { packagedRuntimeClosureFailures } from "./package-runtime-closure-contract.mjs";

const repo = process.cwd();

test("packed inventory accepts the exact regular-file list", () => {
  const packed = {
    files: [
      { path: "bin/kuzushi", size: 42 },
      { path: "package.json", size: 9 },
    ],
  };
  assert.deepEqual(packedInventoryFailures(packed, ["bin/kuzushi", "package.json"]), []);
});

test("packed inventory rejects missing, extra, duplicate, and invalid records", () => {
  const packed = {
    files: [
      { path: "package.json", size: 9 },
      { path: "package.json", size: 9 },
      { path: "test/fixture.mjs", size: -1 },
    ],
  };
  const failures = packedInventoryFailures(packed, ["package.json", "bin/kuzushi"]);
  assert.ok(failures.some((failure) => failure.includes("duplicate")));
  assert.ok(failures.some((failure) => failure.includes("nonnegative")));
  assert.ok(failures.some((failure) => failure.includes("misses bin/kuzushi")));
  assert.ok(failures.some((failure) => failure.includes("adds test/fixture.mjs")));
});

test("package paths reject traversal, platform separators, and local state", () => {
  for (const value of ["../secret", "bin\\tool.exe", "/etc/passwd", "lib/.kuzushi/run.json"]) {
    assert.notDeepEqual(safePackagePathFailures(value), [], value);
  }
  assert.deepEqual(safePackagePathFailures("scripts/langgraph-bridge/model.mjs"), []);
});

test("packaged LangGraph runtime closes over its relative module graph", () => {
  const packageEntries = JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8")).files;
  const readSource = (relativePath) => readFileSync(path.join(repo, relativePath), "utf8");
  assert.deepEqual(packagedRuntimeClosureFailures({ packageEntries, readSource }), []);

  for (const omitted of [
    "scripts/langgraph-bridge/confined-file-read.mjs",
    "scripts/langgraph-bridge/next-step-messages.mjs",
    "scripts/langgraph-bridge/response-stream.mjs",
    "scripts/langgraph-bridge/oauth-response-stream.mjs",
    "scripts/langgraph-bridge/tool-policy-handshake.mjs",
    "scripts/langgraph-bridge/grep-regex-worker.mjs",
  ]) {
    const failures = packagedRuntimeClosureFailures({
      packageEntries: packageEntries.filter((entry) => entry !== omitted),
      readSource,
    });
    assert.ok(
      failures.some((failure) => failure.includes(omitted)),
      `expected missing packaged dependency to be reported: ${omitted}`,
    );
  }
});
