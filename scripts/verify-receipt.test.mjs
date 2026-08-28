import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  expectedPlanDigest,
  parseArguments,
  receiptAgeMs,
  receiptDigest,
  receiptFailures,
} from "./verify-receipt.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const verifier = path.join(scriptDirectory, "verify-receipt.mjs");
const COMMIT = "1111111111111111111111111111111111111111";
const OTHER_COMMIT = "2222222222222222222222222222222222222222";
const skipWithoutSsh = { skip: process.platform === "win32" || !hasSshKeygen() };

test("canonical serialization ignores key order and formatting", () => {
  const left = { b: [1, { d: null, c: 2 }], a: "x" };
  const right = { a: "x", b: [1, { c: 2, d: null }] };

  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(receiptDigest(left), receiptDigest(right));
  assert.notEqual(receiptDigest(left), receiptDigest({ ...left, a: "y" }));
  assert.match(receiptDigest(left), /^[0-9a-f]{64}$/);
});

test("receipt age is null when the timestamp is unreadable", () => {
  assert.equal(receiptAgeMs({}, Date.now()), null);
  assert.equal(receiptAgeMs({ finishedAt: "not-a-date" }, Date.now()), null);
  assert.equal(
    receiptAgeMs(
      { finishedAt: "2026-01-01T00:00:00.000Z" },
      Date.parse("2026-01-01T01:00:00.000Z"),
    ),
    3_600_000,
  );
});

test("a sound receipt has no failures", () => {
  assert.deepEqual(receiptFailures(soundReceipt(), checkContext()), []);
});

test("every dishonest receipt is refused with a named reason", () => {
  const cases = [
    [{ commit: OTHER_COMMIT }, /attests commit .*, not /],
    [{ ok: false }, /reports ok=false/],
    [{ dirty: true }, /dirty=true/],
    [{ dirty: null }, /dirty=null/],
    [{ driftedDuringRun: true }, /driftedDuringRun=true/],
    [{ driftedDuringRun: undefined }, /driftedDuringRun=undefined/],
    [{ steps: [{ name: "tests", status: 1, signal: null }] }, /step tests did not pass/],
    [{ steps: [{ name: "tests", status: 0, signal: "SIGTERM" }] }, /step tests did not pass/],
    [{ steps: [] }, /records no verification steps/],
    [{ plan: { mode: "quick", digest: "deadbeef" } }, /plan digest deadbeef does not match/],
    [{ plan: { mode: "lenient", digest: "deadbeef" } }, /unknown plan mode lenient/],
    [{ plan: undefined }, /records no plan mode or digest/],
    [{ finishedAt: "2026-01-01T00:00:00.000Z" }, /past the 24h limit/],
    [{ finishedAt: undefined }, /no parseable finishedAt/],
  ];

  for (const [override, expected] of cases) {
    const failures = receiptFailures({ ...soundReceipt(), ...override }, checkContext());
    assert.ok(
      failures.some((failure) => expected.test(failure)),
      `expected ${expected} in ${JSON.stringify(failures)}`,
    );
  }
});

test("argument parsing rejects unknown flags and dangling values", () => {
  assert.deepEqual(parseArguments(["verify", "--commit", COMMIT]), {
    subcommand: "verify",
    commit: COMMIT,
  });
  assert.deepEqual(parseArguments(["sign", "--allowed-signers", "/tmp/a"]), {
    subcommand: "sign",
    allowedSigners: "/tmp/a",
  });
  assert.throws(() => parseArguments(["verify", "--force"]), /unknown verify-receipt option/);
  assert.throws(() => parseArguments(["verify", "--commit"]), /--commit requires a value/);
});

test("sign then verify round-trips against a throwaway key", skipWithoutSsh, () => {
  withSigningFixture((fixture) => {
    const signed = run(["sign", "--receipt", fixture.receiptPath, "--key", fixture.keyPath]);
    assert.equal(signed.status, 0, signed.stderr);
    assert.match(signed.stdout, /allowed_signers entry for this key/);

    const verified = run(verifyArgs(fixture, COMMIT));
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stdout, /^verify-receipt: OK 1111/);
    assert.match(verified.stdout, /clean tree, 2 steps passed/);
  });
});

test("verify refuses a receipt that attests a different commit", skipWithoutSsh, () => {
  withSigningFixture((fixture) => {
    run(["sign", "--receipt", fixture.receiptPath, "--key", fixture.keyPath]);
    const verified = run(verifyArgs(fixture, OTHER_COMMIT));

    assert.equal(verified.status, 1);
    assert.match(verified.stderr, /REFUSED 2222/);
    assert.match(verified.stderr, /attests commit 1111.*, not 2222/);
  });
});

test("verify refuses tampered steps, a dirty tree, and a stale receipt", skipWithoutSsh, () => {
  const cases = [
    [{ steps: [{ name: "tests", status: 1, signal: null }] }, /step tests did not pass/],
    [{ dirty: true }, /dirty=true/],
    [{ driftedDuringRun: true }, /the tree moved or was dirty during the run/],
    [{ finishedAt: "2026-01-01T00:00:00.000Z" }, /past the 24h limit/],
    [{ plan: { mode: "quick", digest: "0".repeat(64) } }, /plan digest 0000.*does not match/],
  ];

  for (const [override, expected] of cases) {
    withSigningFixture((fixture) => {
      // Re-sign after tampering: the receipt is refused on its own contents,
      // not merely because the signature stopped matching.
      writeFileSync(
        fixture.receiptPath,
        JSON.stringify({ ...soundReceipt(), ...override }, null, 2),
      );
      run(["sign", "--receipt", fixture.receiptPath, "--key", fixture.keyPath]);
      const verified = run(verifyArgs(fixture, COMMIT));

      assert.equal(verified.status, 1, verified.stdout);
      assert.match(verified.stderr, expected);
    });
  }
});

test("verify refuses a receipt signed by an untrusted key", skipWithoutSsh, () => {
  withSigningFixture((fixture) => {
    const stranger = generateKey(fixture.directory, "stranger");
    run(["sign", "--receipt", fixture.receiptPath, "--key", stranger]);
    const verified = run(verifyArgs(fixture, COMMIT));

    assert.equal(verified.status, 1);
    assert.match(verified.stderr, /signature is not valid for receipt-test@example\.invalid/);
  });
});

test("verify refuses when no signer is trusted at all", skipWithoutSsh, () => {
  withSigningFixture((fixture) => {
    run(["sign", "--receipt", fixture.receiptPath, "--key", fixture.keyPath]);
    const empty = path.join(fixture.directory, "empty_signers");
    writeFileSync(empty, "# no keys trusted yet\n");
    const verified = run([
      "verify",
      "--commit",
      COMMIT,
      "--receipt",
      fixture.receiptPath,
      "--allowed-signers",
      empty,
      "--principal",
      "receipt-test@example.invalid",
    ]);

    assert.equal(verified.status, 1);
    assert.match(verified.stderr, /trusts nobody yet/);
  });
});

test("verify refuses an unsigned receipt", skipWithoutSsh, () => {
  withSigningFixture((fixture) => {
    const verified = run(verifyArgs(fixture, COMMIT));

    assert.equal(verified.status, 1);
    assert.match(verified.stderr, /no signature at .*\.sig/);
    assert.match(verified.stderr, /pnpm verify:quick:summary && pnpm verify:receipt:sign/);
  });
});

test("sign refuses to guess a key when none is configured", skipWithoutSsh, () => {
  withSigningFixture((fixture) => {
    const signed = spawnSync(
      process.execPath,
      [verifier, "sign", "--receipt", fixture.receiptPath],
      {
        cwd: fixture.directory,
        encoding: "utf8",
        env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
      },
    );

    assert.equal(signed.status, 1);
    assert.match(signed.stderr, /no SSH signing key configured/);
  });
});

function soundReceipt() {
  return {
    mode: "quick",
    startedAt: "2026-08-28T00:00:00.000Z",
    commit: COMMIT,
    tree: "3333333333333333333333333333333333333333",
    dirty: false,
    driftedDuringRun: false,
    toolchain: {
      rustc: "rustc 1.90.0 (host aarch64-apple-darwin)",
      node: "v26.3.0",
      pnpm: "10.30.0",
    },
    host: "darwin-arm64",
    plan: { mode: "quick", digest: expectedPlanDigest("quick") },
    exceptions: ["Mode quick did not run: clippy."],
    steps: [
      { name: "secrets", status: 0, signal: null },
      { name: "tests", status: 0, signal: null },
    ],
    ok: true,
    finishedAt: new Date().toISOString(),
  };
}

function checkContext() {
  return { commit: COMMIT, now: Date.now(), maxAgeMs: 24 * 3_600_000 };
}

function verifyArgs(fixture, commit) {
  return [
    "verify",
    "--commit",
    commit,
    "--receipt",
    fixture.receiptPath,
    "--allowed-signers",
    fixture.allowedSigners,
    "--principal",
    "receipt-test@example.invalid",
  ];
}

function run(args) {
  return spawnSync(process.execPath, [verifier, ...args], { encoding: "utf8" });
}

function withSigningFixture(callback) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-receipt-sign-"));
  try {
    const keyPath = generateKey(directory, "owner");
    const allowedSigners = path.join(directory, "allowed_signers");
    const publicKey = readFileSync(`${keyPath}.pub`, "utf8").trim();
    writeFileSync(allowedSigners, `receipt-test@example.invalid ${publicKey}\n`);
    const receiptPath = path.join(directory, "kuzushi-verify-receipt.json");
    writeFileSync(receiptPath, JSON.stringify(soundReceipt(), null, 2));
    callback({ directory, keyPath, allowedSigners, receiptPath });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function generateKey(directory, name) {
  const keyPath = path.join(directory, name);
  const result = spawnSync(
    "ssh-keygen",
    ["-q", "-t", "ed25519", "-N", "", "-C", `${name}@example.invalid`, "-f", keyPath],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  return keyPath;
}

function hasSshKeygen() {
  return spawnSync("ssh-keygen", ["-Y", "sign", "-h"], { encoding: "utf8" }).error === undefined;
}
