import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

const RULES = [
  {
    name: "private key",
    pattern: /-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    candidate: (match) => match[0],
    allowPlaceholders: false,
  },
  {
    name: "GitHub token",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "GitHub fine-grained token",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{50,255}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "AWS access key",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "OpenAI or compatible API key",
    pattern: /\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "Anthropic API or OAuth key",
    pattern: /\bsk-ant-(?:api|oat)\d+-[A-Za-z0-9_-]{20,}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "Google API key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "Slack token",
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "Stripe live secret",
    pattern: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "SendGrid API key",
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    candidate: (match) => match[0],
  },
  {
    name: "credential assignment",
    pattern:
      /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password|passwd)\b\s*[:=]\s*["'`]([^"'`\s]{20,})["'`]/gi,
    candidate: (match) => match[1],
  },
  {
    name: "credential-bearing connection URL",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/]+:([^@\s/]{8,})@/gi,
    candidate: (match) => match[1],
  },
];

const APPROVED_FIXTURE_HASHES = new Map([
  [".env.example", "6866628bba6a4fe45f8b3b7e81a03f503402a7bb3a19507e641e005d8c58fc2c"],
  [
    "crates/kuzushi-cli/tests/dep_hygiene_cli.rs",
    "86eeb1b6be5ad0bc480a358064f7134f629e457edc3524e6237a7dc9a3a0ce35",
  ],
  [
    "crates/kuzushi-core/src/demo.rs",
    "1b8f52e6529c42b477c5cbba1150fa370b3a5c6b3f2427cfd5da0c5528a6bc8f",
  ],
  [
    "crates/kuzushi-core/src/modules/application/sast_scan/run_sast_scan.rs",
    "0f260824ebc92176061de18c86bfd9b850497634f88cefb13296f2c16653468f",
  ],
  [
    "crates/kuzushi-core/src/run_lifecycle/tests.rs",
    "131219df6433af054b3858de47bd391cc6803ad377b202adc7130a379efa6836",
  ],
  [
    "crates/kuzushi-core/src/scan/engines/secret_scan/applies_size_binary_and_severity_filters.rs",
    "561b4c1765f7d7f4455f6f9fa30447dc759a805d69c6f8071fdd8f547aeec670",
  ],
  [
    "crates/kuzushi-core/src/scan/engines/secret_scan/cancellation_stops_native_scan.rs",
    "dd358c5b342e170ebf162e2689da0cb0da3a91e6d845c221287c5801ba1440a6",
  ],
  [
    "crates/kuzushi-core/src/scan/engines/secret_scan/classify_token.rs",
    "a22d6b899ce1f0eb4ef68659d480842f3781835228d1bde69ae4dd658900717d",
  ],
  [
    "crates/kuzushi-core/src/scan/engines/secret_scan/tests.rs",
    "fb98c947dcc299125fbe9321729df8fda1998da91f3c3f38dc030626e6dfa0ac",
  ],
  [
    "tests/fixtures/secret-scan/leaks/aws-keys.env",
    "263c194120335221f1647a7bb6f0d762dce39947771c5a46e0c8c7a4d4c59b63",
  ],
  [
    "tests/fixtures/secret-scan/leaks/key.pem",
    "cd2d2bf18494e900c83dfeadc75f12211ee5f9c96c3c008ffeca3f95e0e48e6e",
  ],
  [
    "tests/fixtures/secret-scan/leaks/placeholder.cfg",
    "14ada17e99a880d874d6c6d101a177576dfaad8525a7d04c7bb8d4df2e51609e",
  ],
  [
    "tests/fixtures/secret-scan/leaks/tokens.env",
    "8b7aafb8a4101c17211828b66ddc10bd93c358d6a5b443307ce4c2e6ef0861f9",
  ],
]);

function isPlaceholder(value) {
  const lower = value.toLowerCase();
  return (
    /[<>{}]/.test(value) ||
    value.includes("${") ||
    /^\*+$/.test(value) ||
    [
      "example",
      "placeholder",
      "dummy",
      "changeme",
      "replace-me",
      "replace_me",
      "not-a-real",
      "not_real",
      "fake-token",
      "test-token",
    ].some((marker) => lower.includes(marker))
  );
}

export function scanLine(line) {
  const matches = new Set();
  for (const rule of RULES) {
    for (const match of line.matchAll(rule.pattern)) {
      const candidate = rule.candidate(match);
      if (rule.allowPlaceholders !== false && isPlaceholder(candidate)) {
        continue;
      }
      matches.add(rule.name);
    }
  }
  return [...matches];
}

export function fixtureIsApproved(path, cwd = process.cwd()) {
  const expected = APPROVED_FIXTURE_HASHES.get(path);
  if (!expected) {
    return false;
  }
  try {
    const actual = createHash("sha256")
      .update(readFileSync(resolve(cwd, path)))
      .digest("hex");
    return actual === expected;
  } catch {
    return false;
  }
}
