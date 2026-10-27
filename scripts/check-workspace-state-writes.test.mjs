import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../", import.meta.url));
const checker = path.join(repository, "scripts/check-workspace-state-writes.mjs");
const optionStoreFile = "crates/kuzushi-core/src/options/option_store_persistence.rs";

function run(cwd) {
  return spawnSync(process.execPath, [checker], { cwd, encoding: "utf8", timeout: 20_000 });
}

function mutatedContract(replace) {
  const fixture = mkdtempSync(path.join(os.tmpdir(), "kuzushi-option-contract-"));
  try {
    const script = readFileSync(checker, "utf8");
    const files = new Set(
      [...script.matchAll(/"(crates\/[^"\n]+\.rs)"/g)].map((match) => match[1]),
    );
    for (const file of files) {
      const destination = path.join(fixture, file);
      mkdirSync(path.dirname(destination), { recursive: true });
      copyFileSync(path.join(repository, file), destination);
    }
    const destination = path.join(fixture, optionStoreFile);
    const original = readFileSync(destination, "utf8");
    const changed = replace(original);
    assert.notEqual(changed, original, "The mutation must change the actual contract source");
    writeFileSync(destination, changed);
    return run(fixture);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

test("current option storage preserves both explicit scope contracts", () => {
  const result = run(repository);
  assert.equal(result.status, 0, result.stderr);
});

test("generic option saves cannot substitute operator policy for workspace policy", () => {
  const result = mutatedContract((source) =>
    source.replace(
      "self.save_scoped_path(path, OptionScope::Workspace)",
      "self.save_scoped_path(path, OptionScope::Global)",
    ),
  );
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /save_to_path must delegate only to workspace-scoped persistence/);
});

test("global option saves cannot reapply repository policy to operator storage", () => {
  const result = mutatedContract((source) =>
    source.replace(
      ".save_scoped_path(global_path, OptionScope::Global)",
      ".save_scoped_path(global_path, OptionScope::Workspace)",
    ),
  );
  assert.equal(result.status, 1, result.stderr);
  assert.match(
    result.stderr,
    /save_persistent must save global values through operator-scoped persistence/,
  );
});

test("the shared option writer cannot bypass containment through raw filesystem writes", () => {
  const result = mutatedContract((source) =>
    source.replace(
      "crate::workspace::write_workspace_state_file(root, relative, body.as_bytes())",
      "std::fs::write(path, body.as_bytes())",
    ),
  );
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /save_scoped_path must not perform raw filesystem writes/);
});
