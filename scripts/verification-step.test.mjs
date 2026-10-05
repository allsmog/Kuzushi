import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { captureVerificationStep } from "./verification-step.mjs";

test("a single failed summary run retains diagnostics, a bounded log and its digest", async () => {
  const directory = mkdtempSync(join(tmpdir(), "kuzushi-verify-"));
  try {
    const result = await captureVerificationStep(
      {
        name: "failing-check",
        command: process.execPath,
        args: [
          "-e",
          "process.stdout.write('FIRST DIAGNOSTIC\\n' + 'x'.repeat(2 * 1024 * 1024)); process.stderr.write('FINAL FAILURE\\n'); process.exitCode = 7;",
        ],
      },
      { cwd: directory, logDir: directory, summary: true },
    );
    assert.equal(result.status, 7);
    assert.equal(result.truncated, true);
    assert.ok(statSync(result.logPath).size <= 1024 * 1024);
    assert.match(readFileSync(result.logPath, "utf8"), /FIRST DIAGNOSTIC/);
    assert.match(result.failureTail, /FINAL FAILURE/);
    assert.equal(
      result.logSha256,
      createHash("sha256").update(readFileSync(result.logPath)).digest("hex"),
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
