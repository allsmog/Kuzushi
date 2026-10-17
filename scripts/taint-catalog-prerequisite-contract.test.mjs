import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { checkTuiPrereqChainPathHelpers } from "./artifact-manifest-contract.mjs";

const file = "crates/kuzushi-tui/src/app/prereq_chain/mod.rs";
const actual = readFileSync(file, "utf8");

function check(source) {
  const root = mkdtempSync(join(tmpdir(), "owned-catalog-contract-"));
  try {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), source);
    return checkTuiPrereqChainPathHelpers(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("current prerequisite contract keeps canonical paths without implicit catalog generation", () => {
  assert.deepEqual(check(actual), []);
});

test("restoring an implicit catalog prerequisite fails the contract", () => {
  assert(
    check(`fn taint_catalog_step() {}\n${actual}`).some((line) =>
      line.includes("implicit prerequisite"),
    ),
  );
});

test("losing the context path helper still fails the contract", () => {
  assert(
    check(
      actual.replaceAll("kuzushi_core::context_snapshot_path(target)", 'PathBuf::from("other")'),
    ).some((line) => line.includes("context_snapshot_path")),
  );
});
