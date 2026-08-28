#!/usr/bin/env node
// Signs and checks the local merge-gate receipt produced by
// scripts/verify-repository.mjs.
//
// This is trust-on-owner, not enforcement. A valid receipt proves that somebody
// holding the signing key ran the plan on a clean tree at a named commit; it
// does not prove the plan is sufficient, and `git push --no-verify` bypasses
// the hook that consumes it. See docs/quality/local-verify-receipt.md.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { planDigest, verificationPlan } from "./verify-repository.mjs";

const SIGNATURE_NAMESPACE = "kuzushi-verify";
const DEFAULT_MAX_AGE_HOURS = 24;
const HOUR_MS = 3_600_000;
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_ALLOWED_SIGNERS = path.join(REPOSITORY_ROOT, ".github", "allowed_signers");
const PRODUCE_RECEIPT_HINT =
  "produce one with: pnpm verify:quick:summary && pnpm verify:receipt:sign";

// --- pure core -------------------------------------------------------------

// Key-sorted serialization, so a receipt that is reformatted or re-serialized
// still hashes to the value its signature covers.
export function canonicalJson(value) {
  if (value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const fields = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${fields.join(",")}}`;
  }
  return JSON.stringify(value);
}

export function receiptDigest(receipt) {
  return createHash("sha256").update(canonicalJson(receipt)).digest("hex");
}

export function expectedPlanDigest(mode) {
  return planDigest(verificationPlan(mode));
}

export function receiptAgeMs(receipt, now) {
  const finished = Date.parse(receipt.finishedAt ?? "");
  return Number.isNaN(finished) ? null : now - finished;
}

// Every honest reason a receipt must not vouch for `commit`. The signature is
// checked separately because that needs ssh-keygen; everything here is pure.
export function receiptFailures(receipt, { commit, now, maxAgeMs }) {
  return [
    ...outcomeFailures(receipt),
    ...stepFailures(receipt.steps),
    ...treeFailures(receipt, commit),
    ...planFailures(receipt.plan),
    ...ageFailures(receipt, now, maxAgeMs),
  ];
}

function outcomeFailures(receipt) {
  return receipt.ok === true ? [] : [`receipt reports ok=${receipt.ok}`];
}

function stepFailures(steps) {
  if (!Array.isArray(steps) || steps.length === 0) return ["receipt records no verification steps"];
  return steps
    .filter((entry) => entry.status !== 0 || entry.signal)
    .map(
      (entry) => `step ${entry.name} did not pass (status=${entry.status}, signal=${entry.signal})`,
    );
}

function treeFailures(receipt, commit) {
  const dirty =
    receipt.dirty === false
      ? []
      : [`receipt records dirty=${receipt.dirty}; the verified tree must be clean`];
  const wrongCommit =
    receipt.commit === commit
      ? []
      : [`receipt attests commit ${receipt.commit ?? "(none)"}, not ${commit}`];
  return [...dirty, ...wrongCommit];
}

function planFailures(plan) {
  if (!plan?.mode || !plan?.digest) return ["receipt records no plan mode or digest"];
  const expected = knownPlanDigest(plan.mode);
  if (expected === null) return [`receipt claims unknown plan mode ${plan.mode}`];
  if (plan.digest === expected) return [];
  return [`plan digest ${plan.digest} does not match the current ${plan.mode} plan ${expected}`];
}

function knownPlanDigest(mode) {
  try {
    return expectedPlanDigest(mode);
  } catch {
    return null;
  }
}

function ageFailures(receipt, now, maxAgeMs) {
  const age = receiptAgeMs(receipt, now);
  if (age === null) return ["receipt has no parseable finishedAt timestamp"];
  if (age < 0) return [`receipt finishedAt ${receipt.finishedAt} is in the future`];
  if (age <= maxAgeMs) return [];
  return [`receipt is ${hours(age)}h old, past the ${hours(maxAgeMs)}h limit`];
}

function hours(milliseconds) {
  return Math.round((milliseconds / HOUR_MS) * 10) / 10;
}

const FLAGS = new Set([
  "--receipt",
  "--key",
  "--commit",
  "--allowed-signers",
  "--principal",
  "--max-age",
]);

export function parseArguments(argv) {
  const [subcommand, ...rest] = argv;
  const options = { subcommand };
  for (let index = 0; index < rest.length; index += 1) {
    const flag = rest[index];
    if (!FLAGS.has(flag)) throw new Error(`unknown verify-receipt option: ${flag}`);
    index += 1;
    if (rest[index] === undefined) throw new Error(`${flag} requires a value`);
    options[optionName(flag)] = rest[index];
  }
  return options;
}

function optionName(flag) {
  return flag.replace(/^--/, "").replace(/-(\w)/g, (_, letter) => letter.toUpperCase());
}

// --- adapters --------------------------------------------------------------

function gitConfig(key) {
  const result = spawnSync("git", ["config", "--get", key], { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "";
}

function defaultReceiptPath() {
  const result = spawnSync("git", ["rev-parse", "--absolute-git-dir"], { encoding: "utf8" });
  if (result.status !== 0)
    throw new Error("cannot locate the git directory; pass --receipt <path>");
  return path.join(result.stdout.trim(), "kuzushi-verify-receipt.json");
}

function readReceipt(file) {
  if (!existsSync(file))
    throw new Error(`no verification receipt at ${file}; ${PRODUCE_RECEIPT_HINT}`);
  return JSON.parse(readFileSync(file, "utf8"));
}

// Resolve the SSH private key git already signs with, or say plainly that there
// is none. We never guess a key: an unconfigured repository has no signer, and
// inventing one would forge the only trust anchor this gate has.
function resolveSigningKey(explicit) {
  if (explicit) return explicit;
  const configured = gitConfig("user.signingkey");
  if (gitConfig("gpg.format") !== "ssh" || !configured) {
    throw new Error(
      "no SSH signing key configured (git config gpg.format=ssh plus user.signingkey); pass --key <private-key-path>",
    );
  }
  if (!existsSync(configured)) {
    throw new Error(
      `git user.signingkey ${configured} is not a readable key file; pass --key <path>`,
    );
  }
  return configured;
}

function signDigest(digest, keyPath) {
  const result = spawnSync(
    "ssh-keygen",
    ["-Y", "sign", "-n", SIGNATURE_NAMESPACE, "-f", keyPath, "-"],
    { input: digest, encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(`ssh-keygen could not sign the receipt: ${(result.stderr ?? "").trim()}`);
  }
  return result.stdout;
}

function signatureFailures(digest, { signatureFile, allowedSigners, principal }) {
  const unavailable = signingInputFailures(signatureFile, allowedSigners);
  if (unavailable.length > 0) return unavailable;
  const result = spawnSync(
    "ssh-keygen",
    [
      "-Y",
      "verify",
      "-f",
      allowedSigners,
      "-I",
      principal,
      "-n",
      SIGNATURE_NAMESPACE,
      "-s",
      signatureFile,
    ],
    { input: digest, encoding: "utf8" },
  );
  if (result.status === 0) return [];
  return [`signature is not valid for ${principal}: ${(result.stderr ?? "").trim()}`];
}

function signingInputFailures(signatureFile, allowedSigners) {
  if (!existsSync(signatureFile))
    return [`no signature at ${signatureFile}; ${PRODUCE_RECEIPT_HINT}`];
  if (!existsSync(allowedSigners)) return [`no allowed signers file at ${allowedSigners}`];
  if (trustsNobody(allowedSigners)) {
    return [
      `${allowedSigners} trusts nobody yet; add the owner key (see docs/quality/local-verify-receipt.md)`,
    ];
  }
  return [];
}

function trustsNobody(allowedSigners) {
  return !readFileSync(allowedSigners, "utf8").split(/\r?\n/).some(isSignerEntry);
}

function isSignerEntry(line) {
  const trimmed = line.trim();
  return trimmed.length > 0 && !trimmed.startsWith("#");
}

// --- subcommands -----------------------------------------------------------

function sign(options) {
  const receiptPath = options.receipt ?? defaultReceiptPath();
  const receipt = readReceipt(receiptPath);
  const keyPath = resolveSigningKey(options.key);
  const signatureFile = `${receiptPath}.sig`;
  writeFileSync(signatureFile, signDigest(receiptDigest(receipt), keyPath));
  process.stdout.write(`signed ${receiptPath} -> ${signatureFile}\n`);
  reportTrustLine(keyPath);
  return 0;
}

// The allowed_signers entry the owner must add for this key to be trusted.
// Printing it is the only way to avoid hand-assembling the OpenSSH format.
function reportTrustLine(keyPath) {
  const result = spawnSync("ssh-keygen", ["-y", "-f", keyPath], { encoding: "utf8" });
  if (result.status !== 0) return;
  const principal = gitConfig("user.email") || "<your-git-email>";
  process.stdout.write(
    `allowed_signers entry for this key:\n${principal} ${result.stdout.trim()}\n`,
  );
}

function verify(options) {
  if (!options.commit) throw new Error("verify requires --commit <sha>");
  const receiptPath = options.receipt ?? defaultReceiptPath();
  const receipt = readReceipt(receiptPath);
  const failures = [
    ...receiptFailures(receipt, {
      commit: options.commit,
      now: Date.now(),
      maxAgeMs: maxAgeMsFrom(options.maxAge),
    }),
    ...signatureFailures(receiptDigest(receipt), {
      signatureFile: `${receiptPath}.sig`,
      allowedSigners: options.allowedSigners ?? DEFAULT_ALLOWED_SIGNERS,
      principal: options.principal || gitConfig("user.email") || "unknown",
    }),
  ];
  return reportVerdict(failures, receipt, options.commit);
}

function maxAgeMsFrom(value) {
  const requested = Number(value ?? DEFAULT_MAX_AGE_HOURS) * HOUR_MS;
  if (!Number.isFinite(requested) || requested <= 0) {
    throw new Error(`--max-age must be a positive number of hours, got ${value}`);
  }
  return requested;
}

function reportVerdict(failures, receipt, commit) {
  if (failures.length > 0) {
    process.stderr.write(`verify-receipt: REFUSED ${commit}\n`);
    for (const failure of failures) process.stderr.write(`  - ${failure}\n`);
    return 1;
  }
  process.stdout.write(
    `verify-receipt: OK ${commit} — signed ${receipt.plan.mode} receipt, clean tree, ${receipt.steps.length} steps passed, ${receipt.exceptions?.length ?? 0} stated exceptions\n`,
  );
  return 0;
}

const SUBCOMMANDS = { sign, verify };

function main() {
  const options = parseArguments(process.argv.slice(2));
  const handler = SUBCOMMANDS[options.subcommand];
  if (!handler) {
    throw new Error(
      `usage: verify-receipt.mjs <sign|verify> [options] (got ${options.subcommand})`,
    );
  }
  process.exitCode = handler(options);
}

if (process.argv[1]?.endsWith("verify-receipt.mjs")) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`verify-receipt: ${error.message}\n`);
    process.exitCode = 1;
  }
}
