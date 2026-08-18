import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import {
  assertDemoReport,
  assertDoctorReport,
  commandRequiresShell,
  installedCommandPath,
  normalizePublishedVersion,
  parseJsonOutput,
  successfulCommandOutput,
} from "./smoke-published-release.mjs";

test("published version accepts a tag or npm version", () => {
  assert.equal(normalizePublishedVersion("v0.24.0-alpha.12"), "0.24.0-alpha.12");
  assert.equal(normalizePublishedVersion("0.24.0-alpha.12"), "0.24.0-alpha.12");
  assert.throws(() => normalizePublishedVersion("latest/../../bad"), /invalid published version/);
});

test("installed command path follows npm global-prefix layout", () => {
  assert.equal(installedCommandPath("/tmp/prefix", "kuzushi", "linux"), "/tmp/prefix/bin/kuzushi");
  assert.equal(
    installedCommandPath("C:\\prefix", "kuzushi", "win32"),
    path.join("C:\\prefix", "kuzushi.cmd"),
  );
  assert.equal(commandRequiresShell("linux"), false);
  assert.equal(commandRequiresShell("win32"), true);
});

test("JSON output parser rejects non-JSON output", () => {
  assert.deepEqual(parseJsonOutput("receipt", '{"ok":true}'), { ok: true });
  assert.throws(() => parseJsonOutput("receipt", "not-json"), /receipt did not emit JSON/);
});

test("command result validation preserves process failures", () => {
  assert.equal(successfulCommandOutput("ok", { status: 0, stdout: "done" }), "done");
  const spawnError = new Error("spawn failed");
  assert.throws(
    () => successfulCommandOutput("spawn", { error: spawnError }),
    (error) => error === spawnError,
  );
  assert.throws(
    () => successfulCommandOutput("exit", { status: 2, stdout: "out", stderr: "bad" }),
    /exit failed with exit 2/,
  );
});

test("doctor receipt requires every distribution-critical check", () => {
  const checks = [
    "target",
    "config",
    "state",
    "findings-db",
    "cpg",
    "treesitter",
    "LangGraph bridge",
  ].map((name) => ({ name, status: "ok" }));
  assert.doesNotThrow(() => assertDoctorReport({ summary: { fail: 0 }, checks }));
  assert.throws(
    () => assertDoctorReport({ summary: { fail: 0 }, checks: checks.slice(0, -1) }),
    /LangGraph bridge/,
  );
});

test("demo receipt requires a free completed finding-producing run", () => {
  const receipt = { ok: true, status: "completed", findingsCount: 2, costUsd: 0, errors: [] };
  assert.doesNotThrow(() => assertDemoReport(receipt));
  assert.throws(() => assertDemoReport({ ...receipt, findingsCount: 0 }), /no findings/);
  assert.throws(() => assertDemoReport({ ...receipt, costUsd: 0.01 }), /model cost/);
});
