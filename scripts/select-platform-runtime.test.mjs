import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  changedPaths,
  selectionOutput,
  selectPlatformRuntime,
} from "./select-platform-runtime.mjs";

test("pure domain and documentation changes skip the platform matrix", () => {
  const selected = selectPlatformRuntime([
    "crates/kuzushi-core/src/findings/domain/severity.rs",
    "docs/modules.md",
  ]);
  assert.ok(Object.values(selected).every((value) => !value));
  assert.match(selectionOutput(selected), /^runtime=false\n/);
});

test("filesystem, process, terminal and launcher changes select their runtime suites", () => {
  for (const [file, suite] of [
    ["crates/kuzushi-mcp-common/src/read_capability/open/windows.rs", "mcp"],
    ["crates/kuzushi-codeindex/src/client.rs", "mcp"],
    ["crates/kuzushi-sandbox/src/lib.rs", "sandbox"],
    ["crates/kuzushi-core/src/fs_atomic.rs", "core"],
    ["crates/kuzushi-core/src/run_artifacts/stage_checkpoint.rs", "core"],
    ["crates/kuzushi-core/src/runtime/application/loop_checkpoint.rs", "core"],
    ["crates/kuzushi-core/src/worker_protocol.rs", "core"],
    ["crates/kuzushi-tui/src/event.rs", "terminal"],
    ["bin/kuzushi-rs.mjs", "launcher"],
  ]) {
    const selection = selectPlatformRuntime([file]);
    assert.equal(selection[suite], true, file);
    assert.equal(Object.values(selection).filter(Boolean).length, 1, file);
    assert.match(selectionOutput(selection), /^runtime=true\n/);
  }
});

test("shared dependencies and unknown diff history run every platform suite", () => {
  for (const paths of [null, ["Cargo.lock"], [".github/workflows/ci.yml"]]) {
    assert.ok(Object.values(selectPlatformRuntime(paths)).every(Boolean));
  }
  assert.equal(changedPaths("--no-index"), null);
  assert.equal(changedPaths("a".repeat(40), tmpdir()), null);
});

test("unmatched executable paths keep every platform suite enabled", () => {
  for (const file of [
    "crates/kuzushi-mcp-codeql/src/tools/snapshot_store/session_root.rs",
    "crates/kuzushi-mcp-clang/src/clangd/client.rs",
    "scripts/new-runtime-adapter.mjs",
  ]) {
    assert.ok(Object.values(selectPlatformRuntime([file])).every(Boolean), file);
  }
});

test("Git diff selection includes deleted files and both sides of renamed paths", (t) => {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-platform-selection-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const git = (...args) =>
    execFileSync("git", args, {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  git("init");
  git("config", "user.email", "platform-test@example.invalid");
  git("config", "user.name", "Platform fixture");
  writeFileSync(path.join(root, "old name.rs"), "old\n");
  git("add", ".");
  git("commit", "-m", "base");
  const base = git("rev-parse", "HEAD");
  git("mv", "old name.rs", "new name.rs");
  git("commit", "-m", "rename");
  assert.deepEqual(changedPaths(base, root).sort(), ["new name.rs", "old name.rs"]);
});
