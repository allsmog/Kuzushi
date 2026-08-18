import assert from "node:assert/strict";
import test from "node:test";

import { formatFinding, parseArguments, scanDiff, scanLine } from "./check-secrets.mjs";

const patterned = (prefix, length) => {
  const alphabet = "Ab9Cd8Ef7Gh6Jk5Lm4Np3Qr2St1Uv0WxYz";
  return prefix + alphabet.repeat(Math.ceil(length / alphabet.length)).slice(0, length);
};

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
  const secret = patterned("", 28);

  assert.deepEqual(scanLine(privateKeyHeader), ["private key"]);
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

test("does not reject the product's intentional secret-scanner fixtures", () => {
  const github = patterned("ghp_", 40);
  const diff = [
    [
      "diff --git a/tests/fixtures/secret-scan/leaks/github.env",
      "b/tests/fixtures/secret-scan/leaks/github.env",
    ].join(" "),
    "--- /dev/null",
    "+++ b/tests/fixtures/secret-scan/leaks/github.env",
    "@@ -0,0 +1 @@",
    `+GITHUB_TOKEN=${github}`,
  ].join("\n");

  assert.deepEqual(scanDiff(diff), []);
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
