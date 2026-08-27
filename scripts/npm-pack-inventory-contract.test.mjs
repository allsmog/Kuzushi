import assert from "node:assert/strict";
import test from "node:test";
import {
  packedInventoryFailures,
  safePackagePathFailures,
} from "./npm-pack-inventory-contract.mjs";

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
