import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  diffForWorktree,
  fixtureIsApproved,
  formatFinding,
  parseArguments,
  scanDiff,
  scanLine,
} from "./check-secrets.mjs";

const patterned = (prefix, length) => {
  const alphabet = "Ab9Cd8Ef7Gh6Jk5Lm4Np3Qr2St1Uv0WxYz";
  return `${prefix}${alphabet.repeat(Math.ceil(length / alphabet.length)).slice(0, length)}`;
};

test("working-tree scan catches unstaged and untracked credentials while excluding deleted values", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-secret-worktree-"));
  try {
    gitFixture(directory, ["init"]);
    writeFileSync(path.join(directory, "config.txt"), 'api_key = "<placeholder>"\n');
    gitFixture(directory, ["add", "config.txt"]);
    gitFixture(directory, ["commit", "-m", "initial fixture"]);
    writeFileSync(path.join(directory, "config.txt"), `api_key = "${patterned("", 28)}"\n`);
    writeFileSync(path.join(directory, "new.txt"), `token=${patterned("ghp_", 40)}\n`);
    const findings = scanDiff(diffForWorktree("HEAD", directory));
    assert.deepEqual(findings.map((finding) => finding.path).sort(), ["config.txt", "new.txt"]);
    writeFileSync(path.join(directory, "config.txt"), 'api_key = "<replacement>"\n');
    assert.deepEqual(
      scanDiff(diffForWorktree("HEAD", directory)).map((finding) => finding.path),
      ["new.txt"],
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function gitFixture(directory, args) {
  const result = spawnSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "-c",
      "commit.gpgsign=false",
      ...args,
    ],
    { cwd: directory, encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
}

test("detects representative provider and platform credentials", () => {
  const github = patterned("ghp_", 40);
  const aws = `AKIA${"Q1W2E3R4T5Y6U7I8"}`;
  const openai = patterned("sk-proj-", 40);
  const anthropic = patterned("sk-ant-api03-", 32);

  assert.deepEqual(scanLine(`token=${github}`), ["GitHub token"]);
  assert.deepEqual(scanLine(`AWS_ACCESS_KEY_ID=${aws}`), ["AWS access key"]);
  assert.deepEqual(scanLine(`OPENAI_API_KEY=${openai}`), ["OpenAI or compatible API key"]);
  assert.deepEqual(scanLine(`ANTHROPIC_API_KEY=${anthropic}`), ["Anthropic API or OAuth key"]);
});

test("detects private keys, generic assignments, and credential-bearing URLs", () => {
  const privateKeyHeader = ["-----BEGIN ", "PRIVATE KEY-----"].join("");
  const encryptedPrivateKeyHeader = ["-----BEGIN ENCRYPTED ", "PRIVATE KEY-----"].join("");
  const secret = patterned("", 28);

  assert.deepEqual(scanLine(privateKeyHeader), ["private key"]);
  assert.deepEqual(scanLine(encryptedPrivateKeyHeader), ["private key"]);
  assert.deepEqual(scanLine(`client_secret = "${secret}"`), ["credential assignment"]);
  assert.deepEqual(scanLine(`postgres://user:${secret}@db.example.invalid/app`), [
    "credential-bearing connection URL",
  ]);
});

test("ignores placeholders and ordinary source text", () => {
  assert.deepEqual(scanLine('api_key = "replace_me_with_your_api_key"'), []);
  assert.deepEqual(scanLine("let token_count = findings.len();"), []);
});

test("scans only added lines and keeps accurate new-file line numbers", () => {
  const github = patterned("ghp_", 40);
  const deleted = patterned("sk-proj-", 40);
  const diff = [
    "diff --git a/src/config.rs b/src/config.rs",
    "--- a/src/config.rs",
    "+++ b/src/config.rs",
    "@@ -10,2 +10,3 @@",
    `-${deleted}`,
    "+safe = true",
    `+token = ${github}`,
    " context",
  ].join("\n");

  assert.deepEqual(scanDiff(diff), [{ path: "src/config.rs", line: 11, rule: "GitHub token" }]);
});

test("only exact approved fixture bytes bypass their intentional patterns", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-secret-fixture-"));
  const relative = "tests/fixtures/secret-scan/leaks/tokens.env";
  const fixture = path.join(directory, relative);
  const github = ["ghp_", "ABCdefGHIjklMNOpqrSTUvwxYZ0123456789"].join("");
  const contents = [
    "# Synthetic tokens. None are real credentials. Stripe / Google / OpenAI",
    "# / Slack detectors are exercised by inline-string cases in",
    "# secret-scan.test.ts (assembled at test time) to keep this fixture file",
    "# from tripping third-party secret-scanning blocklists on push.",
    `GITHUB_TOKEN=${github}`,
    "",
  ].join("\n");
  const diff = [
    `diff --git a/${relative} b/${relative}`,
    "--- /dev/null",
    `+++ b/${relative}`,
    "@@ -0,0 +1 @@",
    `+GITHUB_TOKEN=${github}`,
  ].join("\n");

  try {
    mkdirSync(path.dirname(fixture), { recursive: true });
    writeFileSync(fixture, contents);
    assert.equal(fixtureIsApproved(relative, directory), true);
    assert.deepEqual(
      scanDiff(diff, (candidate) => fixtureIsApproved(candidate, directory)),
      [],
    );

    writeFileSync(fixture, `${contents}# changed\n`);
    assert.equal(fixtureIsApproved(relative, directory), false);
    assert.deepEqual(
      scanDiff(diff, (candidate) => fixtureIsApproved(candidate, directory)),
      [{ path: relative, line: 1, rule: "GitHub token" }],
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("whole current repository scan accepts only hash-approved synthetic secret fixtures", () => {
  const scan = spawnSync(
    process.execPath,
    [
      "scripts/check-secrets.mjs",
      "--base",
      "0000000000000000000000000000000000000000",
      "--worktree",
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );

  assert.equal(scan.status, 0, `${scan.stdout}\n${scan.stderr}`);
});

test("defaults to the repository quality base and permits explicit overrides", () => {
  assert.deepEqual(parseArguments([], { KUZUSHI_CRAP_RISK_BASE_REF: "base-sha" }), {
    base: "base-sha",
    head: "HEAD",
  });
  assert.deepEqual(
    parseArguments(["--base", "main", "--head", "feature"], {
      KUZUSHI_CRAP_RISK_BASE_REF: "ignored",
    }),
    { base: "main", head: "feature" },
  );
  assert.throws(() => parseArguments(["--head"], {}), /non-empty base and head/);
});

test("diagnostics never contain the credential value", () => {
  const secret = patterned("ghp_", 40);
  const output = formatFinding({ path: "src/config.rs", line: 7, rule: "GitHub token" }, false);

  assert.match(output, /credential value redacted/);
  assert.doesNotMatch(output, new RegExp(secret));
});
