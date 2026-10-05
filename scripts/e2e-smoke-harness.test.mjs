// Node contract tests are discovered under scripts/, so the guard for
// tests/e2e/run-smoke.sh lives here rather than beside the harness it covers.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repo = fileURLToPath(new URL("../", import.meta.url));
const smokeScript = path.join(repo, "tests", "e2e", "run-smoke.sh");

// A native CLI that cannot be executed is the exact shape of the Full CI e2e
// failure: GitHub's artifact round trip drops the executable bit, the wrapper
// dies with EACCES, and the harness had parked that message in a log file.
async function nonExecutableNativeBin() {
  const root = await mkdtemp(path.join(os.tmpdir(), "kuzushi-smoke-harness-"));
  const bin = path.join(root, "kuzushi");
  await writeFile(bin, "#!/bin/sh\nexit 0\n");
  await chmod(bin, 0o644);
  return { root, bin };
}

function runSmoke({ root, bin }) {
  return spawnSync("bash", [smokeScript], {
    encoding: "utf8",
    cwd: repo,
    env: {
      ...process.env,
      TEST_APP_DIR: path.join(root, "app"),
      TEST_LOG_DIR: path.join(root, "logs"),
      KUZUSHI_NATIVE_BIN: bin,
      KUZUSHI_CMD: "node bin/kuzushi-rs.mjs",
    },
  });
}

test("the native smoke harness discloses the step that failed and its captured log", async (t) => {
  const fixture = await nonExecutableNativeBin();
  t.after(() => rm(fixture.root, { recursive: true, force: true }));
  const result = runSmoke(fixture);

  assert.notEqual(result.status, 0, `smoke unexpectedly passed:\n${result.stdout}`);
  assert.match(result.stderr, /native smoke failed at line \d+ \(exit 1\)/);
  // The reporter echoes BASH_COMMAND, so the path stays in its source form.
  assert.match(result.stderr, /bin\/kuzushi-rs\.mjs" --help/);
  // The captured log, not just the command, has to reach the run page.
  assert.match(result.stderr, /wrapper-help\.log \(last \d+ lines\)/);
  assert.match(result.stderr, /EACCES/);
});
