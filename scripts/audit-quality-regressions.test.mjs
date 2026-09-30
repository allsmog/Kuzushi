import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { discoverNodeTests } from "./run-node-tests.mjs";

test("test discovery includes a newly added failing nested contract", (t) => {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-discovery-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, "bridge"));
  writeFileSync(
    path.join(root, "bridge", "new.test.mjs"),
    'import test from "node:test"; test("new", () => { throw Error("sentinel"); });',
  );
  const files = discoverNodeTests(root);
  const result = spawnSync(process.execPath, ["--test", ...files], {
    encoding: "utf8",
    env: { ...process.env, NODE_TEST_CONTEXT: undefined },
  });
  assert.equal(files.length, 1);
  assert.notEqual(result.status, 0);
  assert.match(result.stdout, /sentinel/);
});

test("mutation diff keeps both untracked files and propagates Git errors", {
  skip: process.platform === "win32",
}, (t) => {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-diff-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "--allow-empty",
      "-qm",
      "baseline",
    ],
    { cwd: root },
  );
  writeFileSync(path.join(root, "a.rs"), "fn a() {}\n");
  writeFileSync(path.join(root, "b.rs"), "fn b() {}\n");
  const source = readFileSync(new URL("./run-rust-mutations.sh", import.meta.url), "utf8");
  const helper = source.match(/write_change_diff\(\) \{[\s\S]*?\n\}/)[0];
  execFileSync("bash", ["-ec", `base=HEAD\n${helper}\nwrite_change_diff changes.diff`], {
    cwd: root,
  });
  const diff = readFileSync(path.join(root, "changes.diff"), "utf8");
  assert.match(diff, /b\/a.rs/);
  assert.match(diff, /b\/b.rs/);
  const failed = spawnSync(
    "bash",
    [
      "-ec",
      `base=HEAD\n${helper}\ngit() { if [[ "$*" == *--no-index* ]]; then return 42; else command git "$@"; fi; }\nwrite_change_diff failure.diff`,
    ],
    { cwd: root },
  );
  assert.equal(failed.status, 42);
});
