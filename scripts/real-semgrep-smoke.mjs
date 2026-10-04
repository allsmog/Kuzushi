#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const expectedVersion = readFileSync(".github/requirements-ci.txt", "utf8").match(
  /^semgrep==([^\s]+)$/m,
)?.[1];
const environment = {
  ...process.env,
  SEMGREP_SEND_METRICS: "off",
  SEMGREP_ENABLE_VERSION_CHECK: "0",
};
function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: environment,
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error || result.status !== 0)
    throw result.error ?? Error(`${command} failed: ${result.stderr}`);
  return result.stdout;
}

const version = run("semgrep", ["--version"]).trim();
assert.equal(version, expectedVersion, "real scanner version must match the pinned CI requirement");
const root = mkdtempSync(join(tmpdir(), "kuzushi-real-semgrep-"));
try {
  const rule = join(root, "rules.yml");
  writeFileSync(
    rule,
    `rules:
  - id: audit-command-injection
    languages: [python]
    severity: ERROR
    message: Unsanitized shell invocation
    pattern: os.system($INPUT)
`,
  );
  const binary = resolve(process.env.KUZUSHI_NATIVE_BIN ?? "target/debug/kuzushi");
  for (const [name, source, count] of [
    ["vulnerable", "import os\nos.system(input())\n", 1],
    ["fixed", "import subprocess\nsubprocess.run(['printf', '%s', input()], check=True)\n", 0],
  ]) {
    const target = join(root, name);
    mkdirSync(target);
    writeFileSync(join(target, "app.py"), source);
    const report = JSON.parse(
      run(binary, [
        "--target",
        target,
        "run",
        "semgrep:scan",
        "--input",
        JSON.stringify({ config: rule }),
      ]),
    );
    assert.equal(report.status, "completed", JSON.stringify(report));
    assert.equal(report.data.count, count, name);
    assert.deepEqual(report.data.scanErrors ?? [], [], "scanner coverage must be complete");
    if (count) assert.equal(report.data.findings[0].start_line, 2);
  }
  console.log(
    JSON.stringify({
      scanner: "semgrep",
      version,
      vulnerableCount: 1,
      fixedCount: 0,
      localRules: true,
    }),
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}
